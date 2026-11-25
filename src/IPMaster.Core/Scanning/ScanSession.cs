using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Channels;
using IPMaster.Core.Targets;
using Microsoft.Extensions.Logging;

namespace IPMaster.Core.Scanning;

public enum ScanState
{
    Running,
    Paused,
    Stopping,
    Completed,
    Cancelled,
    Faulted,
}

public readonly record struct ScanProgress(
    ScanState State,
    ulong Total,
    bool TotalIsExact,
    ulong Processed,
    ulong Online,
    int ActiveWorkers,
    int PendingEnrichment,
    TimeSpan Elapsed);

public sealed record ScanSummary(ScanState State, ulong Processed, ulong Online, TimeSpan Elapsed, string? Error);

/// <summary>
/// One running scan. Pipeline: lazy plan enumeration → bounded address channel → N liveness workers
/// (publish immediately) → bounded enrichment channel → M enrichment workers. Each enrichment kind has its own
/// budget (DNS, NetBIOS, TCP connections, service probes, Windows management calls) and blocking OS calls that
/// overrun their timeout are abandoned and capped. Cancellation is cooperative; nothing is aborted.
/// </summary>
public sealed class ScanSession : IDisposable
{
    private const int EnrichmentQueueCapacity = 4096;
    private const int PerDevicePortParallelism = 32;
    private const int MaxAbandonedWindowsCalls = 32;
    private static long s_revision; // process-wide so rescans always supersede earlier snapshots

    private readonly ScanRequest _request;
    private readonly ScanSettings _s;
    private readonly IScanResultSink _sink;
    private readonly ScanProbes _probes;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly CancellationTokenSource _cts;
    private readonly PauseGate _gate = new();
    private readonly SemaphoreSlim _dnsSlots;
    private readonly SemaphoreSlim _netBiosSlots = new(64, 64);
    private readonly SemaphoreSlim _portSlots;
    private readonly SemaphoreSlim _serviceSlots = new(64, 64);
    private readonly SemaphoreSlim _windowsSlots;
    private readonly SemaphoreSlim _neighborLock = new(1, 1);
    private readonly Channel<AddressKey> _addresses;
    private readonly Channel<EnrichItem> _enrich;
    private readonly long _startTimestamp;
    private readonly IReadOnlyList<int> _tcpPorts;
    private readonly string? _tcpPortError;
    private (long Timestamp, IReadOnlyList<NeighborEntry> Entries)? _neighbors;
    private long _processed;
    private long _online;
    private int _active;
    private int _pendingEnrichment;
    private int _abandonedDns;
    private int _abandonedWindows;
    private volatile ScanState _finalState = ScanState.Running;
    private long _endTimestamp;
    private readonly TaskCompletionSource<ScanSummary> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);

    internal ScanSession(ScanRequest request, IScanResultSink sink, ScanProbes probes, TimeProvider time, ILogger logger,
        CancellationToken external)
    {
        _request = request;
        _s = request.Settings;
        _sink = sink;
        _probes = probes;
        _time = time;
        _logger = logger;
        _cts = CancellationTokenSource.CreateLinkedTokenSource(external);
        _dnsSlots = new SemaphoreSlim(_s.DnsConcurrency, _s.DnsConcurrency);
        _portSlots = new SemaphoreSlim(_s.PortConcurrency, _s.PortConcurrency);
        _windowsSlots = new SemaphoreSlim(_s.WindowsConcurrency, _s.WindowsConcurrency);
        _addresses = Channel.CreateBounded<AddressKey>(new BoundedChannelOptions(Math.Max(16, _s.MaxConcurrency * 2))
        {
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
        _enrich = Channel.CreateBounded<EnrichItem>(new BoundedChannelOptions(EnrichmentQueueCapacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
        });
        if (_s.ScanTcpPorts)
        {
            if (PortList.TryParse(_s.TcpPorts, out var ports, out var error)) _tcpPorts = ports;
            else
            {
                _tcpPorts = [];
                _tcpPortError = error;
            }
        }
        else
        {
            _tcpPorts = [];
        }

        _startTimestamp = time.GetTimestamp();
    }

    public Task<ScanSummary> Completion => _completion.Task;

    public bool IsPaused => _gate.IsPaused;

    public ScanProgress Progress
    {
        get
        {
            var state = _finalState;
            if (state == ScanState.Running)
            {
                if (_cts.IsCancellationRequested) state = ScanState.Stopping;
                else if (_gate.IsPaused) state = ScanState.Paused;
            }

            var end = Interlocked.Read(ref _endTimestamp);
            var elapsed = _time.GetElapsedTime(_startTimestamp, end == 0 ? _time.GetTimestamp() : end);
            return new ScanProgress(state, _request.ExactCount ?? _request.Plan.RawCount, _request.ExactCount.HasValue,
                (ulong)Interlocked.Read(ref _processed), (ulong)Interlocked.Read(ref _online),
                Volatile.Read(ref _active), Volatile.Read(ref _pendingEnrichment), elapsed);
        }
    }

    public void Pause() => _gate.Pause();

    public void Resume() => _gate.Resume();

    public void Stop()
    {
        try
        {
            _cts.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // already finished
        }
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
        _dnsSlots.Dispose();
        _netBiosSlots.Dispose();
        _portSlots.Dispose();
        _serviceSlots.Dispose();
        _windowsSlots.Dispose();
        _neighborLock.Dispose();
    }

    internal void Begin() => _ = RunAsync();

    private static long NextRevision() => Interlocked.Increment(ref s_revision);

    private async Task RunAsync()
    {
        var ct = _cts.Token;
        string? error = null;
        try
        {
            await WarmUpIPv6NeighborsAsync(ct).ConfigureAwait(false);
            var producer = Task.Run(() => ProduceAsync(ct), CancellationToken.None);
            var workers = new Task[_s.MaxConcurrency];
            for (var i = 0; i < workers.Length; i++) workers[i] = Task.Run(() => LivenessWorkerAsync(ct), CancellationToken.None);
            var enrichers = new Task[_s.EnrichmentConcurrency];
            for (var i = 0; i < enrichers.Length; i++) enrichers[i] = Task.Run(() => EnrichmentWorkerAsync(ct), CancellationToken.None);

            await producer.ConfigureAwait(false);
            await Task.WhenAll(workers).ConfigureAwait(false);
            _enrich.Writer.TryComplete();
            await Task.WhenAll(enrichers).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // stopped
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _logger.LogError(ex, "Scan failed");
        }
        finally
        {
            _enrich.Writer.TryComplete();
            // Items still queued after cancellation are finalised as Cancelled so no row stays "pending".
            while (_enrich.Reader.TryRead(out var leftover)) Finalize(leftover, ObservationState.Cancelled, countedPending: true);
        }

        Interlocked.Exchange(ref _endTimestamp, _time.GetTimestamp());
        _finalState = error is not null ? ScanState.Faulted
            : ct.IsCancellationRequested ? ScanState.Cancelled
            : ScanState.Completed;
        var p = Progress;
        _completion.TrySetResult(new ScanSummary(_finalState, p.Processed, p.Online, p.Elapsed, error));
    }

    /// <summary>Resolving IPv6 addresses of IPv4 devices needs them in the neighbour cache: one multicast echo to
    /// ff02::1 per local interface makes link-local neighbours answer (and resolve us), populating the cache.</summary>
    private async Task WarmUpIPv6NeighborsAsync(CancellationToken ct)
    {
        if (!_s.ResolveIPv6 || _request.IPv6ScopeIds.Count == 0 || !_probes.Icmp.Capability.Available) return;
        var pings = _request.IPv6ScopeIds.Select(scope =>
            _probes.Icmp.PingAsync(new IPAddress(IPAddress.Parse("ff02::1").GetAddressBytes(), scope), TimeSpan.FromSeconds(1), ct));
        try
        {
            await Task.WhenAll(pings).WaitAsync(TimeSpan.FromSeconds(2), _time, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is TimeoutException or PingException or InvalidOperationException or NotSupportedException)
        {
            _logger.LogDebug(ex, "IPv6 multicast warm-up failed");
        }
    }

    private async Task ProduceAsync(CancellationToken ct)
    {
        try
        {
            foreach (var key in _request.Plan.Enumerate(_s.RandomOrder, _request.Seed))
            {
                await _gate.WaitAsync(ct).ConfigureAwait(false);
                await _addresses.Writer.WriteAsync(key, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // stop producing
        }
        finally
        {
            _addresses.Writer.TryComplete();
        }
    }

    private async Task LivenessWorkerAsync(CancellationToken ct)
    {
        try
        {
            while (await _addresses.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                while (_addresses.Reader.TryRead(out var key))
                {
                    await _gate.WaitAsync(ct).ConfigureAwait(false);
                    Interlocked.Increment(ref _active);
                    try
                    {
                        await ProcessAsync(key, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Probe failed for {Address}", key);
                    }
                    finally
                    {
                        Interlocked.Decrement(ref _active);
                        Interlocked.Increment(ref _processed);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // stopping
        }
    }

    private async Task ProcessAsync(AddressKey key, CancellationToken ct)
    {
        var started = _time.GetUtcNow();
        var startTs = _time.GetTimestamp();
        var deadline = _s.DeviceDeadlineSeconds > 0 ? TimeSpan.FromSeconds(_s.DeviceDeadlineSeconds) : Timeout.InfiniteTimeSpan;
        using var deadlineCts = deadline == Timeout.InfiniteTimeSpan ? new CancellationTokenSource() : new CancellationTokenSource(deadline, _time);
        using var deviceCts = CancellationTokenSource.CreateLinkedTokenSource(ct, deadlineCts.Token);
        var address = key.ToIPAddress();

        LivenessOutcome live;
        try
        {
            live = await ProbeLivenessAsync(key, address, deviceCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException) when (deadlineCts.IsCancellationRequested)
        {
            live = new LivenessOutcome(DeviceStatus.TimedOut, PingMethod.None, default, "Device deadline expired.");
        }

        var online = live.Status == DeviceStatus.Online;
        if (online) Interlocked.Increment(ref _online);

        var result = InitialResult(key, live, started, online);
        var known = _request.KnownAddresses?.Contains(key) == true;
        // Unresponsive-but-analysed devices are shown when inactive devices are displayed, when the address is
        // already listed (rescans), or when enrichment finds something.
        var publishNow = online || _s.DisplayInactiveDevices || known;
        if (!result.HasPending)
        {
            if (publishNow) _sink.OnDevice(result with { IsComplete = true });
            return;
        }

        if (publishNow) _sink.OnDevice(result);
        var remaining = deadline == Timeout.InfiniteTimeSpan ? deadline : deadline - _time.GetElapsedTime(startTs);
        if (remaining != Timeout.InfiniteTimeSpan && remaining <= TimeSpan.Zero)
        {
            Finalize(new EnrichItem(result, remaining, publishNow), ObservationState.Timeout, countedPending: false);
            return;
        }

        Interlocked.Increment(ref _pendingEnrichment);
        try
        {
            await _enrich.Writer.WriteAsync(new EnrichItem(result, remaining, publishNow), ct).ConfigureAwait(false);
        }
        catch
        {
            // Cancelled while waiting for room in the full queue: the row may already be published with Pending fields,
            // and the leftover drain only sees queued items, so finalise it here (review C-02).
            Finalize(new EnrichItem(result, remaining, publishNow), ObservationState.Cancelled, countedPending: true);
            throw;
        }
    }

    private DeviceResult InitialResult(AddressKey key, LivenessOutcome live, DateTimeOffset started, bool online)
    {
        var now = _time.GetUtcNow();
        var s = _s;
        var analyse = online || s.AnalyseUnresponsive;
        var hasMac = live.Reply.Mac is not null;
        var wantNetBiosName = s.ResolveHostNames; // every mode falls back to NetBIOS when DNS has no name (D-085)
        var wantNetBios = analyse && !key.IsV6 && (wantNetBiosName || s.LookupWorkgroup || (s.ResolveMac && !hasMac && s.MacMethods.Contains(MacMethod.NetBios)));
        var wantMac = analyse && s.ResolveMac && !hasMac;
        var windows = analyse && s.AnyWorkstationLookup;

        static Observation<T> P<T>(bool wanted) => wanted ? Observation<T>.Pending : Observation<T>.NotRequested;

        return new DeviceResult
        {
            Key = key,
            Status = live.Status,
            RespondedTo = live.Method,
            RoundTrip = live.Reply.RoundTrip,
            Ttl = live.Method switch
            {
                PingMethod.Icmp when live.Reply.Ttl is { } ttl => Observation<int>.Ok(ttl, now),
                PingMethod.Icmp => Observation<int>.Of(ObservationState.Unsupported, now, "TTL not reported by this platform."),
                PingMethod.Arp => Observation<int>.Of(ObservationState.Unsupported, now, "ARP replies carry no TTL."),
                _ => Observation<int>.Of(ObservationState.NoResponse, now),
            },
            Mac = live.Reply.Mac is { } mac ? Observation<PhysicalAddress>.Ok(mac, now) : P<PhysicalAddress>(wantMac),
            MacSource = hasMac ? MacSource.Arp : MacSource.None,
            HostName = P<HostNameInfo>(analyse && s.ResolveHostNames),
            PingStats = P<PingStatistics>(online && s.DeterminePacketLossAndJitter),
            NetBios = P<NetBiosInfo>(wantNetBios),
            Vendor = P<string>(analyse && s.LookupVendor && (hasMac || s.ResolveMac)),
            IPv6Addresses = P<IReadOnlyList<IPAddress>>(analyse && s.ResolveIPv6 && !key.IsV6 && (hasMac || s.ResolveMac)),
            TcpPorts = P<IReadOnlyList<PortResult>>(analyse && s.ScanTcpPorts),
            UdpPorts = P<IReadOnlyList<PortResult>>(analyse && s.ScanUdpPorts && s.UdpServiceIds.Count > 0),
            Banners = P<IReadOnlyList<ServiceBanner>>(analyse && s.GrabBanners && s.BannerServiceIds.Count > 0),
            RtspStreams = P<IReadOnlyList<string>>(analyse && s.FindRtspStreams),
            Tls = P<TlsCertificateInfo>(analyse && s.TlsCertificateInfo),
            Workgroup = P<string>(windows && s.LookupWorkgroup),
            OsVersion = P<string>(windows && s.LookupWindowsVersion),
            Accounts = P<IReadOnlyList<string>>(windows && s.EnumerateAccounts),
            LoggedOnUsers = P<IReadOnlyList<string>>(windows && s.LookupLoggedOnUsers),
            LoggedOnSids = P<IReadOnlyList<string>>(windows && s.LookupLoggedOnSids),
            RemoteTime = P<DateTimeOffset>(windows && s.LookupRemoteTime),
            InstalledApps = P<IReadOnlyList<InstalledApplication>>(windows && s.ListInstalledApplications),
            Monitors = P<IReadOnlyList<MonitorInfo>>(windows && s.LookupMonitors),
            TerminalSessions = P<IReadOnlyList<TerminalSession>>(windows && s.ListTerminalSessions),
            Shares = P<IReadOnlyList<ShareInfo>>(analyse && s.ScanShares),
            Location = P<GeoLocation>(analyse && s.Geolocation && PublicAddress.IsPublic(key.ToIPAddress())),
            Queries = analyse && _request.Queries is { IsEmpty: false } plan ? plan.Pending() : DeviceResult.NoQueries,
            LastScanned = started,
            LastSeen = online ? now : null,
            Revision = NextRevision(),
        };
    }

    private async Task<LivenessOutcome> ProbeLivenessAsync(AddressKey key, IPAddress address, CancellationToken ct)
    {
        var timeout = TimeSpan.FromMilliseconds(_s.PingTimeoutMs);
        var useIcmp = _s.PingMethod is PingMethodSetting.Icmp or PingMethodSetting.Both;
        var useArp = _s.PingMethod is PingMethodSetting.Arp or PingMethodSetting.Both;
        string? arpReason = null;
        if (useArp)
        {
            arpReason = ArpUnavailableReason(key);
            if (arpReason is not null) useArp = false;
        }

        if (useIcmp && !_probes.Icmp.Capability.Available) useIcmp = false;
        if (!useIcmp && !useArp)
        {
            return new LivenessOutcome(DeviceStatus.Unsupported, PingMethod.None, default,
                arpReason ?? _probes.Icmp.Capability.Description);
        }

        ProbeReply last = default;
        var answeredNo = false; // at least one probe really went out and got no reply
        for (var attempt = 0; attempt < _s.PingAttempts; attempt++)
        {
            // "Both" runs ICMP and ARP side by side: an offline host costs max(ICMP, ARP) per attempt, not the sum (D-084).
            var icmp = useIcmp ? _probes.Icmp.PingAsync(address, timeout, ct) : null;
            var arp = useArp ? _probes.Arp.ArpAsync(address, timeout, ct) : null;
            if (icmp is not null) // awaited first so an ICMP answer keeps its RTT/TTL
            {
                last = await icmp.ConfigureAwait(false);
                answeredNo |= last.State is ObservationState.NoResponse or ObservationState.Timeout;
                if (last.IsAlive) return new LivenessOutcome(DeviceStatus.Online, PingMethod.Icmp, last, null);
            }

            if (arp is not null)
            {
                last = await arp.ConfigureAwait(false);
                answeredNo |= last.State is ObservationState.NoResponse or ObservationState.Timeout;
                if (last.IsAlive) return new LivenessOutcome(DeviceStatus.Online, PingMethod.Arp, last, null);
            }
        }

        // A local failure (probe exception, no resources, saturated ARP queue) says nothing about the device: reporting it
        // as Offline would feed false misses, LEAVE events and offline history samples (review C-03).
        if (!answeredNo)
        {
            return new LivenessOutcome(DeviceStatus.Unsupported, PingMethod.None, last with { RoundTrip = null, Ttl = null, Mac = null },
                "Liveness could not be tested: " + (last.Detail ?? "local probe failure") + ".");
        }

        return new LivenessOutcome(DeviceStatus.Offline, PingMethod.None, last with { RoundTrip = null, Ttl = null, Mac = null }, last.Detail);
    }

    private string? ArpUnavailableReason(AddressKey key)
    {
        if (key.IsV6) return "ARP applies to IPv4 only.";
        if (!_probes.Arp.Capability.Available) return _probes.Arp.Capability.Description;
        if (!_s.AllowArpOutsideSubnet && !IsInLocalSubnet(key)) return "Address is outside the local subnets (enable 'Allow ARP outside current subnet').";
        return null;
    }

    private bool IsInLocalSubnet(AddressKey key)
    {
        foreach (var s in _request.LocalSubnets)
        {
            if (s.Network.IsV6) continue;
            var mask = AddressKey.MaskFor(s.PrefixLength, false);
            if ((key.Value & mask) == (s.Network.Value & mask)) return true;
        }

        return false;
    }

    private async Task EnrichmentWorkerAsync(CancellationToken ct)
    {
        try
        {
            while (await _enrich.Reader.WaitToReadAsync(ct).ConfigureAwait(false))
            {
                while (_enrich.Reader.TryRead(out var item))
                {
                    try
                    {
                        await _gate.WaitAsync(ct).ConfigureAwait(false);
                        await EnrichAsync(item, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        Finalize(item, ObservationState.Cancelled, countedPending: true);
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Enrichment failed for {Address}", item.Result.Key);
                        Finalize(item, ObservationState.Failed, countedPending: true);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // stopping; leftovers are finalised by RunAsync
        }
    }

    private async Task EnrichAsync(EnrichItem item, CancellationToken ct)
    {
        using var deadlineCts = item.Remaining == Timeout.InfiniteTimeSpan ? new CancellationTokenSource() : new CancellationTokenSource(item.Remaining, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, deadlineCts.Token);
        var token = linked.Token;
        var r = item.Result;
        var address = r.Key.ToIPAddress();

        // Group A: independent stages, each with its own budget.
        var netBiosTask = Pending(r.NetBios) ? Guard(() => QueryNetBiosAsync(address, token), deadlineCts) : Task.FromResult(r.NetBios);
        var hostTask = Pending(r.HostName) ? Guard(() => ResolveHostNameAsync(address, netBiosTask, token), deadlineCts) : Task.FromResult(r.HostName);
        var statsTask = Pending(r.PingStats) ? Guard(() => MeasureStatisticsAsync(address, token), deadlineCts) : Task.FromResult(r.PingStats);
        var macTask = Pending(r.Mac) ? GuardMac(r.Key, address, netBiosTask, deadlineCts, token) : Task.FromResult((r.Mac, r.MacSource));
        var tcpTask = Pending(r.TcpPorts) ? Guard(() => ScanTcpAsync(address, token), deadlineCts) : Task.FromResult(r.TcpPorts);
        var udpTask = Pending(r.UdpPorts) ? Guard(() => ScanUdpAsync(address, token), deadlineCts) : Task.FromResult(r.UdpPorts);
        var bannerTask = Pending(r.Banners) ? Guard(() => GrabBannersAsync(address, token), deadlineCts) : Task.FromResult(r.Banners);
        var rtspTask = Pending(r.RtspStreams) ? Guard(() => FindRtspAsync(address, token), deadlineCts) : Task.FromResult(r.RtspStreams);
        var tlsTask = Pending(r.Tls) ? Guard(() => GetTlsAsync(address, token), deadlineCts) : Task.FromResult(r.Tls);
        var windowsTask = WindowsAsync(r, address, deadlineCts, token);
        var geoTask = Pending(r.Location) ? Guard(() => LocateAsync(address, token), deadlineCts) : Task.FromResult(r.Location);

        await Task.WhenAll(netBiosTask, hostTask, statsTask, macTask, tcpTask, udpTask, bannerTask, rtspTask, tlsTask, windowsTask, geoTask).ConfigureAwait(false);
        var (mac, macSource) = await macTask.ConfigureAwait(false);

        // Group B: depends on the MAC address.
        var now = _time.GetUtcNow();
        var vendor = Pending(r.Vendor) ? LookupVendor(mac, now) : r.Vendor;
        var ipv6 = Pending(r.IPv6Addresses)
            ? await Guard(() => FindIPv6Async(mac, token), deadlineCts).ConfigureAwait(false)
            : r.IPv6Addresses;
        ct.ThrowIfCancellationRequested();

        var netBios = await netBiosTask.ConfigureAwait(false);
        var final = (await windowsTask.ConfigureAwait(false))(r) with
        {
            HostName = await hostTask.ConfigureAwait(false),
            PingStats = await statsTask.ConfigureAwait(false),
            NetBios = netBios,
            Mac = mac,
            MacSource = macSource,
            Vendor = vendor,
            IPv6Addresses = ipv6,
            TcpPorts = await tcpTask.ConfigureAwait(false),
            UdpPorts = await udpTask.ConfigureAwait(false),
            Banners = await bannerTask.ConfigureAwait(false),
            RtspStreams = await rtspTask.ConfigureAwait(false),
            Tls = await tlsTask.ConfigureAwait(false),
            Location = await geoTask.ConfigureAwait(false),
        };

        // Group C: remote queries (separate budget; they may read every column above via Input.Column).
        if (_request.Queries is { } plan && final.Queries.Values.Any(q => q.State == ObservationState.Pending))
        {
            try
            {
                final = final with { Queries = await plan.RunAsync(final, token).ConfigureAwait(false) };
            }
            catch (OperationCanceledException) when (deadlineCts.IsCancellationRequested && !_cts.IsCancellationRequested)
            {
                final = final.FinalizePending(ObservationState.Timeout, _time.GetUtcNow(), "Device deadline expired.");
            }
        }

        // Portable fallback: the NetBIOS group name is the workgroup/domain when Windows lookups are unavailable.
        if (final.Workgroup.State is not (ObservationState.Success or ObservationState.NotRequested) && netBios.HasValue
            && netBios.Value!.Domain is { Length: > 0 } domain)
        {
            final = final with { Workgroup = Observation<string>.Ok(domain, now) with { Detail = "NetBIOS" } };
        }

        final = final.FinalizePending(ObservationState.Failed, now) with { IsComplete = true, Revision = NextRevision() };
        Interlocked.Decrement(ref _pendingEnrichment);
        if (item.Published || final.Status == DeviceStatus.Online || FoundSomething(final)) _sink.OnDevice(final);
    }

    private static bool FoundSomething(DeviceResult d) =>
        d.HostName.HasValue || d.Mac.HasValue || d.NetBios.HasValue || (d.TcpPorts.HasValue && d.TcpPorts.Value!.Count > 0)
        || (d.UdpPorts.HasValue && d.UdpPorts.Value!.Any(p => p.State == PortState.Open)) || (d.Banners.HasValue && d.Banners.Value!.Count > 0)
        || d.Shares.HasValue || d.Workgroup.HasValue;

    private static bool Pending<T>(Observation<T> o) => o.State == ObservationState.Pending;

    private void Finalize(EnrichItem item, ObservationState state, bool countedPending)
    {
        var final = item.Result.FinalizePending(state, _time.GetUtcNow()) with { IsComplete = true, Revision = NextRevision() };
        if (countedPending) Interlocked.Decrement(ref _pendingEnrichment);
        if (item.Published) _sink.OnDevice(final);
    }

    private async Task<Observation<T>> Guard<T>(Func<Task<Observation<T>>> stage, CancellationTokenSource deadline)
    {
        try
        {
            return await stage().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !_cts.IsCancellationRequested)
        {
            return Observation<T>.Of(ObservationState.Timeout, _time.GetUtcNow(), "Device deadline expired.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "Enrichment stage failed");
            return Observation<T>.Of(ObservationState.Failed, _time.GetUtcNow(), ex.Message);
        }
    }

    // ---------- host names ----------
    private async Task<Observation<HostNameInfo>> ResolveHostNameAsync(IPAddress address, Task<Observation<NetBiosInfo>> netBios, CancellationToken ct)
    {
        if (_s.HostNameMode == HostNameMode.NetBiosOnly) return NetBiosName(await netBios.ConfigureAwait(false));

        var dns = await ReverseDnsAsync(address, ct).ConfigureAwait(false);
        if (dns.State != ObservationState.Success)
        {
            var nb = NetBiosName(await netBios.ConfigureAwait(false));
            if (nb.HasValue) return nb;
        }

        return dns;
    }

    private Observation<HostNameInfo> NetBiosName(Observation<NetBiosInfo> nb)
    {
        var now = _time.GetUtcNow();
        if (nb.HasValue && nb.Value!.ComputerName is { Length: > 0 } name) return Observation<HostNameInfo>.Ok(new HostNameInfo(name, null), now) with { Detail = "NetBIOS" };
        return nb.State == ObservationState.Success ? Observation<HostNameInfo>.Of(ObservationState.Empty, now) : Observation<HostNameInfo>.Of(nb.State, now, nb.Detail);
    }

    private async Task<Observation<HostNameInfo>> ReverseDnsAsync(IPAddress address, CancellationToken ct)
    {
        await _dnsSlots.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var timeout = TimeSpan.FromMilliseconds(_s.DnsTimeoutMs);
            var (state, name, detail) = await BoundedLookupAsync(() => _probes.Dns.ReverseLookupAsync(address, ct), timeout, ct).ConfigureAwait(false);
            var now = _time.GetUtcNow();
            if (state != ObservationState.Success) return Observation<HostNameInfo>.Of(state, now, detail);
            if (string.IsNullOrWhiteSpace(name) || IPAddress.TryParse(name, out _)) return Observation<HostNameInfo>.Of(ObservationState.Empty, now);

            bool? confirmed = null;
            if (_s.DoubleReverseLookup)
            {
                var (fstate, addrs, _) = await BoundedLookupAsync(() => _probes.Dns.ForwardLookupAsync(name, ct), timeout, ct).ConfigureAwait(false);
                if (fstate == ObservationState.Success) confirmed = addrs!.Any(a => AddressKey.From(a) == AddressKey.From(address) || a.Equals(address));
                else if (fstate is ObservationState.Empty or ObservationState.NoResponse or ObservationState.Failed) confirmed = false;
            }

            return Observation<HostNameInfo>.Ok(new HostNameInfo(HostNameFormatter.Format(name, _s.HostNameMode), confirmed), now);
        }
        finally
        {
            _dnsSlots.Release();
        }
    }

    /// <summary>
    /// Runs a lookup with a timeout. A lookup that times out keeps running inside the OS resolver, so it
    /// is counted as abandoned until it really finishes; when too many are abandoned, new lookups fail fast.
    /// </summary>
    private async Task<(ObservationState State, T? Value, string? Detail)> BoundedLookupAsync<T>(Func<Task<T>> start, TimeSpan timeout, CancellationToken ct)
    {
        if (Volatile.Read(ref _abandonedDns) >= _s.MaxAbandonedDnsLookups)
        {
            return (ObservationState.Timeout, default, "Resolver saturated by slow lookups.");
        }

        Task<T> task;
        try
        {
            task = start();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (ObservationState.Failed, default, ex.Message);
        }

        try
        {
            var value = await task.WaitAsync(timeout, _time, ct).ConfigureAwait(false);
            if (value is null) return (ObservationState.Empty, default, null);
            if (value is Array { Length: 0 }) return (ObservationState.Empty, default, null);
            return (ObservationState.Success, value, null);
        }
        catch (TimeoutException)
        {
            AbandonDns(task);
            return (ObservationState.Timeout, default, $"No answer within {timeout.TotalMilliseconds:0} ms.");
        }
        catch (OperationCanceledException)
        {
            if (!task.IsCompleted) AbandonDns(task);
            throw;
        }
        catch (System.Net.Sockets.SocketException ex) when (ex.SocketErrorCode is System.Net.Sockets.SocketError.HostNotFound or System.Net.Sockets.SocketError.NoData)
        {
            return (ObservationState.Empty, default, null);
        }
        catch (Exception ex)
        {
            return (ObservationState.Failed, default, ex.Message);
        }
    }

    private void AbandonDns(Task task)
    {
        Interlocked.Increment(ref _abandonedDns);
        _ = task.ContinueWith(t =>
        {
            _ = t.Exception; // observe
            Interlocked.Decrement(ref _abandonedDns);
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    // ---------- statistics ----------
    private async Task<Observation<PingStatistics>> MeasureStatisticsAsync(IPAddress address, CancellationToken ct)
    {
        if (!_probes.Icmp.Capability.Available)
        {
            return Observation<PingStatistics>.Of(ObservationState.Unsupported, _time.GetUtcNow(), _probes.Icmp.Capability.Description);
        }

        var timeout = TimeSpan.FromMilliseconds(_s.PingTimeoutMs);
        var rtts = new List<TimeSpan>(_s.LossProbeCount);
        var sent = 0;
        for (var i = 0; i < _s.LossProbeCount; i++)
        {
            if (i > 0 && _s.LossProbeIntervalMs > 0) await Task.Delay(TimeSpan.FromMilliseconds(_s.LossProbeIntervalMs), _time, ct).ConfigureAwait(false);
            sent++;
            var reply = await _probes.Icmp.PingAsync(address, timeout, ct).ConfigureAwait(false);
            if (reply.IsAlive && reply.RoundTrip is { } rtt) rtts.Add(rtt);
        }

        return Observation<PingStatistics>.Ok(PingStatisticsCalculator.Compute(sent, rtts), _time.GetUtcNow());
    }

    // ---------- NetBIOS, MAC, vendor, IPv6 ----------
    private async Task<Observation<NetBiosInfo>> QueryNetBiosAsync(IPAddress address, CancellationToken ct)
    {
        await _netBiosSlots.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var info = await _probes.NetBios.QueryAsync(address, TimeSpan.FromMilliseconds(_s.NetBiosTimeoutMs), ct).ConfigureAwait(false);
            var now = _time.GetUtcNow();
            return info is null ? Observation<NetBiosInfo>.Of(ObservationState.NoResponse, now, "No NetBIOS reply.") : Observation<NetBiosInfo>.Ok(info, now);
        }
        finally
        {
            _netBiosSlots.Release();
        }
    }

    private async Task<(Observation<PhysicalAddress> Mac, MacSource Source)> GuardMac(AddressKey key, IPAddress address,
        Task<Observation<NetBiosInfo>> netBios, CancellationTokenSource deadline, CancellationToken ct)
    {
        var source = MacSource.None;
        var obs = await Guard(async () =>
        {
            var notes = new List<string>();
            foreach (var method in _s.MacMethods)
            {
                switch (method)
                {
                    case MacMethod.Arp:
                    {
                        var neighbor = (await NeighborsAsync(ct).ConfigureAwait(false))
                            .FirstOrDefault(n => AddressKey.From(n.Address) == key || n.Address.Equals(address));
                        if (neighbor is not null)
                        {
                            source = MacSource.NeighborCache;
                            return Observation<PhysicalAddress>.Ok(neighbor.Mac, _time.GetUtcNow());
                        }

                        var reason = ArpUnavailableReason(key);
                        if (reason is null)
                        {
                            var reply = await _probes.Arp.ArpAsync(address, TimeSpan.FromMilliseconds(_s.PingTimeoutMs), ct).ConfigureAwait(false);
                            if (reply.Mac is { } m)
                            {
                                source = MacSource.Arp;
                                return Observation<PhysicalAddress>.Ok(m, _time.GetUtcNow());
                            }

                            notes.Add("ARP: no reply");
                        }
                        else
                        {
                            notes.Add("ARP: " + reason);
                        }

                        break;
                    }

                    case MacMethod.NetBios:
                    {
                        if (key.IsV6)
                        {
                            notes.Add("NetBIOS: IPv4 only");
                            break;
                        }

                        var nb = await netBios.ConfigureAwait(false);
                        if (nb.HasValue && nb.Value!.Mac is { } m && m.GetAddressBytes().Any(b => b != 0))
                        {
                            source = MacSource.NetBios;
                            return Observation<PhysicalAddress>.Ok(m, _time.GetUtcNow());
                        }

                        notes.Add("NetBIOS: " + (nb.State == ObservationState.NotRequested ? "not queried" : nb.Detail ?? "no MAC in reply"));
                        break;
                    }

                    case MacMethod.Wmi:
                    {
                        if (_probes.WindowsExtras is not { } x)
                        {
                            notes.Add("WMI: needs a Windows scanner");
                            break;
                        }

                        var o = await Blocking(() => x.GetMacViaWmi(address, _request.WorkstationCredential, TimeSpan.FromMilliseconds(_s.WindowsTimeoutMs), _time.GetUtcNow()),
                            deadline, ct).ConfigureAwait(false);
                        if (o.HasValue)
                        {
                            source = MacSource.Wmi;
                            return o;
                        }

                        notes.Add("WMI: " + (o.Detail ?? Results.ObservationText.StateName(o.State)));
                        break;
                    }

                    case MacMethod.RouterMib:
                    {
                        if (_probes.RouterArp is null || _request.Routers.Count == 0 || key.IsV6)
                        {
                            notes.Add(key.IsV6 ? "Router MIB: IPv4 only" : "Router MIB: no router configured or detected");
                            break;
                        }

                        foreach (var router in _request.Routers)
                        {
                            var table = await RouterTableAsync(router, ct).ConfigureAwait(false);
                            if (table is not null && table.TryGetValue(address, out var mac))
                            {
                                source = MacSource.RouterMib;
                                return Observation<PhysicalAddress>.Ok(mac, _time.GetUtcNow()) with { Detail = "router " + router };
                            }
                        }

                        notes.Add("Router MIB: not in the routers' ARP tables");
                        break;
                    }
                }
            }

            return Observation<PhysicalAddress>.Of(ObservationState.Empty, _time.GetUtcNow(), string.Join("; ", notes));
        }, deadline).ConfigureAwait(false);
        return (obs, source);
    }

    private async Task<IReadOnlyList<NeighborEntry>> NeighborsAsync(CancellationToken ct)
    {
        if (!_probes.Neighbors.Capability.Available) return [];
        var cached = _neighbors;
        if (cached is { } c && _time.GetElapsedTime(c.Timestamp) < TimeSpan.FromSeconds(2)) return c.Entries;
        await _neighborLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            cached = _neighbors;
            if (cached is { } c2 && _time.GetElapsedTime(c2.Timestamp) < TimeSpan.FromSeconds(2)) return c2.Entries;
            var entries = await _probes.Neighbors.SnapshotAsync(ct).ConfigureAwait(false);
            _neighbors = (_time.GetTimestamp(), entries);
            return entries;
        }
        finally
        {
            _neighborLock.Release();
        }
    }

    private Observation<string> LookupVendor(Observation<PhysicalAddress> mac, DateTimeOffset now)
    {
        if (!mac.HasValue) return Observation<string>.Of(ObservationState.Empty, now, "No MAC address.");
        var bytes = mac.Value!.GetAddressBytes();
        if (bytes.Length > 0 && (bytes[0] & 0x02) != 0) return Observation<string>.Ok("(locally administered address)", now);
        if (!_probes.Vendors.Capability.Available) return Observation<string>.Of(ObservationState.Unsupported, now, _probes.Vendors.Capability.Description);
        var v = _probes.Vendors.Lookup(mac.Value);
        return v is null ? Observation<string>.Of(ObservationState.Empty, now, "OUI not in database.") : Observation<string>.Ok(v, now);
    }

    private async Task<Observation<IReadOnlyList<IPAddress>>> FindIPv6Async(Observation<PhysicalAddress> mac, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (!mac.HasValue) return Observation<IReadOnlyList<IPAddress>>.Of(ObservationState.Empty, now, "No MAC address.");
        if (!_probes.Neighbors.Capability.Available) return Observation<IReadOnlyList<IPAddress>>.Of(ObservationState.Unsupported, now, _probes.Neighbors.Capability.Description);
        var list = (await NeighborsAsync(ct).ConfigureAwait(false))
            .Where(n => n.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !n.Address.IsIPv6Multicast && n.Mac.Equals(mac.Value))
            .Select(n => n.Address)
            .Distinct()
            .ToList();
        return list.Count == 0 ? Observation<IReadOnlyList<IPAddress>>.Of(ObservationState.Empty, now) : Observation<IReadOnlyList<IPAddress>>.Ok(list, now);
    }

    // ---------- ports and services ----------
    private async Task<Observation<IReadOnlyList<PortResult>>> ScanTcpAsync(IPAddress address, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (_tcpPortError is not null) return Observation<IReadOnlyList<PortResult>>.Of(ObservationState.Failed, now, _tcpPortError);
        var ports = _s.RandomPortOrder ? _tcpPorts.OrderBy(_ => Random.Shared.Next()).ToList() : _tcpPorts;
        var open = new ConcurrentBag<PortResult>();
        int closed = 0, filtered = 0, failed = 0;
        string? failure = null;
        var timeout = TimeSpan.FromMilliseconds(_s.PortTimeoutMs);
        await Parallel.ForEachAsync(ports, new ParallelOptions { MaxDegreeOfParallelism = PerDevicePortParallelism, CancellationToken = ct }, async (port, t) =>
        {
            await _portSlots.WaitAsync(t).ConfigureAwait(false);
            try
            {
                var r = await _probes.Tcp.ProbeAsync(address, port, timeout, t).ConfigureAwait(false);
                switch (r.State)
                {
                    case PortState.Open:
                        open.Add(r with { Service = PortList.ServiceName(port) });
                        break;
                    case PortState.Closed:
                        Interlocked.Increment(ref closed);
                        break;
                    case PortState.Failed or PortState.Unsupported:
                        // local failure, not an answer from the device (review C-10)
                        Interlocked.Increment(ref failed);
                        Interlocked.CompareExchange(ref failure, r.Detail ?? r.State.ToString(), null);
                        break;
                    default:
                        Interlocked.Increment(ref filtered);
                        break;
                }
            }
            finally
            {
                _portSlots.Release();
            }
        }).ConfigureAwait(false);
        var list = open.OrderBy(p => p.Port).ToList();
        if (failed == ports.Count && ports.Count > 0)
        {
            return Observation<IReadOnlyList<PortResult>>.Of(ObservationState.Failed, _time.GetUtcNow(), $"No port could be probed (local error: {failure}).");
        }

        return Observation<IReadOnlyList<PortResult>>.Ok(list, _time.GetUtcNow()) with
        {
            Detail = $"{list.Count} open, {closed} closed, {filtered} filtered of {ports.Count}" + (failed > 0 ? $"; {failed} could not be probed (local error: {failure})" : ""),
        };
    }

    private async Task<Observation<IReadOnlyList<PortResult>>> ScanUdpAsync(IPAddress address, CancellationToken ct)
    {
        var services = UdpServices.All.Where(s => _s.UdpServiceIds.Contains(s.Id, StringComparer.OrdinalIgnoreCase)).ToList();
        var timeout = TimeSpan.FromMilliseconds(_s.ServiceTimeoutMs);
        var tasks = services.Select(async s =>
        {
            await _serviceSlots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                return (await _probes.Udp.ProbeAsync(address, s, _s.SnmpProbeCommunity, timeout, ct).ConfigureAwait(false)).Port;
            }
            finally
            {
                _serviceSlots.Release();
            }
        });
        IReadOnlyList<PortResult> results = (await Task.WhenAll(tasks).ConfigureAwait(false)).OrderBy(p => p.Port).ToList();
        return Observation<IReadOnlyList<PortResult>>.Ok(results, _time.GetUtcNow());
    }

    private async Task<Observation<IReadOnlyList<ServiceBanner>>> GrabBannersAsync(IPAddress address, CancellationToken ct)
    {
        var timeout = TimeSpan.FromMilliseconds(_s.ServiceTimeoutMs);
        var jobs = new List<Func<Task<ServiceBanner?>>>();
        foreach (var id in _s.BannerServiceIds)
        {
            if (BannerServices.Find(id) is not { } service) continue;
            if (service.Protocol == PortProtocol.Udp)
            {
                var udp = UdpServices.All.FirstOrDefault(u => u.Id == service.Id) ?? new UdpService(service.Id, service.Name, service.Ports[0]);
                jobs.Add(async () => (await _probes.Udp.ProbeAsync(address, udp, _s.SnmpProbeCommunity, timeout, ct).ConfigureAwait(false)).Banner);
            }
            else
            {
                foreach (var port in service.Ports) jobs.Add(() => _probes.Service.GrabTcpBannerAsync(address, service, port, timeout, ct));
            }
        }

        var results = await Task.WhenAll(jobs.Select(async job =>
        {
            await _serviceSlots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                return await job().ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return null;
            }
            finally
            {
                _serviceSlots.Release();
            }
        })).ConfigureAwait(false);
        var banners = results.OfType<ServiceBanner>().OrderBy(b => b.Port).ToList();
        var now = _time.GetUtcNow();
        return banners.Count == 0 ? Observation<IReadOnlyList<ServiceBanner>>.Of(ObservationState.Empty, now) : Observation<IReadOnlyList<ServiceBanner>>.Ok(banners, now);
    }

    private async Task<Observation<IReadOnlyList<string>>> FindRtspAsync(IPAddress address, CancellationToken ct)
    {
        await _serviceSlots.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var streams = await _probes.Service.FindRtspStreamsAsync(address, 554, TimeSpan.FromMilliseconds(_s.ServiceTimeoutMs), ct).ConfigureAwait(false);
            var now = _time.GetUtcNow();
            return streams.Count == 0 ? Observation<IReadOnlyList<string>>.Of(ObservationState.Empty, now) : Observation<IReadOnlyList<string>>.Ok(streams, now);
        }
        finally
        {
            _serviceSlots.Release();
        }
    }

    private async Task<Observation<TlsCertificateInfo>> GetTlsAsync(IPAddress address, CancellationToken ct)
    {
        await _serviceSlots.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var cert = await _probes.Service.GetCertificateAsync(address, 443, TimeSpan.FromMilliseconds(_s.ServiceTimeoutMs), ct).ConfigureAwait(false);
            var now = _time.GetUtcNow();
            return cert is null ? Observation<TlsCertificateInfo>.Of(ObservationState.NoResponse, now, "No TLS service on port 443.") : Observation<TlsCertificateInfo>.Ok(cert, now);
        }
        finally
        {
            _serviceSlots.Release();
        }
    }

    private async Task<Observation<GeoLocation>> LocateAsync(IPAddress address, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (_probes.Geo is null) return Observation<GeoLocation>.Of(ObservationState.Unsupported, now, "No geolocation provider configured.");
        var cap = _probes.Geo.Capability(_s);
        if (!cap.Available) return Observation<GeoLocation>.Of(ObservationState.Unsupported, now, cap.Description);
        await _serviceSlots.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var g = await _probes.Geo.LocateAsync(address, _s, ct).ConfigureAwait(false);
            return g is null ? Observation<GeoLocation>.Of(ObservationState.Empty, _time.GetUtcNow()) : Observation<GeoLocation>.Ok(g, _time.GetUtcNow());
        }
        finally
        {
            _serviceSlots.Release();
        }
    }

    // ---------- Windows management ----------
    private async Task<Func<DeviceResult, DeviceResult>> WindowsAsync(DeviceResult r, IPAddress address, CancellationTokenSource deadline, CancellationToken ct)
    {
        var wanted = Pending(r.Workgroup) || Pending(r.OsVersion) || Pending(r.Accounts) || Pending(r.LoggedOnUsers)
                     || Pending(r.LoggedOnSids) || Pending(r.RemoteTime) || Pending(r.InstalledApps) || Pending(r.Shares)
                     || Pending(r.Monitors) || Pending(r.TerminalSessions);
        if (!wanted) return d => d;

        var now = _time.GetUtcNow();
        string? unavailable = null;
        var state = ObservationState.Unsupported;
        if (!_probes.Windows.Capability.Available) unavailable = _probes.Windows.Capability.Description;
        else if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) unavailable = "Windows lookups support IPv4 targets only in this build.";
        else
        {
            try
            {
                var timeout = TimeSpan.FromMilliseconds(_s.PortTimeoutMs);
                var smb = await _probes.Tcp.ProbeAsync(address, 445, timeout, ct).ConfigureAwait(false);
                if (smb.State != PortState.Open) smb = await _probes.Tcp.ProbeAsync(address, 139, timeout, ct).ConfigureAwait(false);
                if (smb.State != PortState.Open)
                {
                    unavailable = "SMB (TCP 445/139) is not reachable.";
                    state = ObservationState.NoResponse;
                }
            }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested && !_cts.IsCancellationRequested)
            {
                unavailable = "Device deadline expired.";
                state = ObservationState.Timeout;
            }
        }

        if (unavailable is not null)
        {
            var s = state;
            var u = unavailable;
            return d => d with
            {
                Workgroup = Pending(d.Workgroup) ? Observation<string>.Of(s, now, u) : d.Workgroup,
                OsVersion = Pending(d.OsVersion) ? Observation<string>.Of(s, now, u) : d.OsVersion,
                Accounts = Pending(d.Accounts) ? Observation<IReadOnlyList<string>>.Of(s, now, u) : d.Accounts,
                LoggedOnUsers = Pending(d.LoggedOnUsers) ? Observation<IReadOnlyList<string>>.Of(s, now, u) : d.LoggedOnUsers,
                LoggedOnSids = Pending(d.LoggedOnSids) ? Observation<IReadOnlyList<string>>.Of(s, now, u) : d.LoggedOnSids,
                RemoteTime = Pending(d.RemoteTime) ? Observation<DateTimeOffset>.Of(s, now, u) : d.RemoteTime,
                InstalledApps = Pending(d.InstalledApps) ? Observation<IReadOnlyList<InstalledApplication>>.Of(s, now, u) : d.InstalledApps,
                Shares = Pending(d.Shares) ? Observation<IReadOnlyList<ShareInfo>>.Of(s, now, u) : d.Shares,
                Monitors = Pending(d.Monitors) ? Observation<IReadOnlyList<MonitorInfo>>.Of(s, now, u) : d.Monitors,
                TerminalSessions = Pending(d.TerminalSessions) ? Observation<IReadOnlyList<TerminalSession>>.Of(s, now, u) : d.TerminalSessions,
            };
        }

        var host = address.ToString();
        var w = _probes.Windows;
        var x = _probes.WindowsExtras;

        // WKS-07: a stored credential opens an authenticated SMB session for the calls below (current account otherwise).
        var (session, sessionError) = await SessionAsync(_request.WorkstationCredential, host, deadline, ct).ConfigureAwait(false);
        Observation<IReadOnlyList<string>> accounts, users, sids;
        Observation<string> workgroup, os;
        Observation<DateTimeOffset> time;
        Observation<IReadOnlyList<InstalledApplication>> apps;
        Observation<IReadOnlyList<MonitorInfo>> monitors;
        Observation<IReadOnlyList<TerminalSession>> sessions;
        using (session)
        {
            Observation<T> Denied<T>(Observation<T> o) => Pending(o) ? Observation<T>.Of(sessionError!.Value.State, now, sessionError.Value.Detail) : o;
            if (sessionError is not null)
            {
                workgroup = Denied(r.Workgroup);
                os = Denied(r.OsVersion);
                accounts = Denied(r.Accounts);
                users = Denied(r.LoggedOnUsers);
                sids = Denied(r.LoggedOnSids);
                time = Denied(r.RemoteTime);
                apps = Denied(r.InstalledApps);
                monitors = Denied(r.Monitors);
                sessions = Denied(r.TerminalSessions);
            }
            else
            {
                workgroup = Pending(r.Workgroup) ? await Blocking(() => w.GetWorkgroup(host, now), deadline, ct).ConfigureAwait(false) : r.Workgroup;
                os = Pending(r.OsVersion) ? await Blocking(() => w.GetWindowsVersion(host, now), deadline, ct).ConfigureAwait(false) : r.OsVersion;
                accounts = Pending(r.Accounts) ? FilterAccounts(await Blocking(() => w.GetAccounts(host, now), deadline, ct).ConfigureAwait(false)) : r.Accounts;
                users = Pending(r.LoggedOnUsers) ? FilterAccounts(await Blocking(() => w.GetLoggedOnUsers(host, now), deadline, ct).ConfigureAwait(false)) : r.LoggedOnUsers;
                sids = Pending(r.LoggedOnSids) ? await Blocking(() => w.GetLoggedOnSids(host, now), deadline, ct).ConfigureAwait(false) : r.LoggedOnSids;
                time = Pending(r.RemoteTime) ? await Blocking(() => w.GetRemoteTime(host, now), deadline, ct).ConfigureAwait(false) : r.RemoteTime;
                apps = Pending(r.InstalledApps) ? await Blocking(() => w.GetInstalledApplications(host, now), deadline, ct).ConfigureAwait(false) : r.InstalledApps;
                monitors = !Pending(r.Monitors) ? r.Monitors
                    : x is null ? Observation<IReadOnlyList<MonitorInfo>>.Of(ObservationState.Unsupported, now, "Monitor lookup needs a Windows scanner.")
                    : await Blocking(() => x.GetMonitors(host, now), deadline, ct).ConfigureAwait(false);
                sessions = !Pending(r.TerminalSessions) ? r.TerminalSessions
                    : x is null ? Observation<IReadOnlyList<TerminalSession>>.Of(ObservationState.Unsupported, now, "Terminal sessions need a Windows scanner.")
                    : await Blocking(() => x.GetTerminalSessions(host, now), deadline, ct).ConfigureAwait(false);
            }
        }

        var shares = r.Shares;
        if (Pending(r.Shares))
        {
            var (shareSession, shareError) = await SessionAsync(_request.SharesCredential, host, deadline, ct).ConfigureAwait(false);
            using (shareSession)
            {
                shares = shareError is { } e
                    ? Observation<IReadOnlyList<ShareInfo>>.Of(e.State, now, e.Detail)
                    : await Blocking(() => w.GetShares(host, _s.ShareTypes, _s.ShareDiskSpace, _s.ShareSecurity, _s.ShareWriteCheck, now, ct), deadline, ct,
                        timeoutMultiplier: 3).ConfigureAwait(false);
            }
        }

        return d => d with
        {
            Workgroup = workgroup,
            OsVersion = os,
            Accounts = accounts,
            LoggedOnUsers = users,
            LoggedOnSids = sids,
            RemoteTime = time,
            InstalledApps = apps,
            Shares = shares,
            Monitors = monitors,
            TerminalSessions = sessions,
        };
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<IPAddress, Lazy<Task<IReadOnlyDictionary<IPAddress, PhysicalAddress>?>>> _routerTables = new();

    /// <summary>Each router's ARP table is walked once per scan (MAC-04); failures are cached as null and noted once.</summary>
    private Task<IReadOnlyDictionary<IPAddress, PhysicalAddress>?> RouterTableAsync(IPAddress router, CancellationToken ct) =>
        _routerTables.GetOrAdd(router, r => new Lazy<Task<IReadOnlyDictionary<IPAddress, PhysicalAddress>?>>(async () =>
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(30));
                return await _probes.RouterArp!.ArpTableAsync(r, _s.RouterMibCommunity, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !_cts.IsCancellationRequested)
            {
                if (_logger.IsEnabled(LogLevel.Information)) _logger.LogInformation("Router MIB query of {Router} failed: {Message}", r, ex.Message);
                return null;
            }
        })).Value.WaitAsync(ct);

    /// <summary>Opens the IPC$ session for a stored credential (bounded like every Windows call).</summary>
    private async Task<(IDisposable? Session, (ObservationState State, string Detail)? Error)> SessionAsync(Security.ResolvedCredential? credential, string host,
        CancellationTokenSource deadline, CancellationToken ct)
    {
        if (credential is null) return (null, null);
        if (_probes.WindowsExtras is not { } x) return (null, (ObservationState.Unsupported, "Stored credentials need a Windows scanner."));
        var o = await Blocking<IDisposable?>(() =>
        {
            try
            {
                return Observation<IDisposable?>.Ok(x.OpenSession(host, credential), _time.GetUtcNow());
            }
            catch (UnauthorizedAccessException ex)
            {
                return Observation<IDisposable?>.Of(ObservationState.AccessDenied, _time.GetUtcNow(), ex.Message);
            }
            catch (IOException ex)
            {
                return Observation<IDisposable?>.Of(ObservationState.NoResponse, _time.GetUtcNow(), ex.Message);
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                return Observation<IDisposable?>.Of(ObservationState.Failed, _time.GetUtcNow(), ex.Message);
            }
        }, deadline, ct).ConfigureAwait(false);
        return o.State == ObservationState.Success ? (o.Value, null) : (null, (o.State, $"Credential {credential.UserName}: {o.Detail}"));
    }

    private Observation<IReadOnlyList<string>> FilterAccounts(Observation<IReadOnlyList<string>> o)
    {
        if (!o.HasValue) return o;
        IEnumerable<string> list = o.Value!;
        if (_s.ExcludedAccounts.Count > 0)
        {
            list = list.Where(a => !_s.ExcludedAccounts.Any(p => Wildcard.IsMatch(p.Trim(), a, ignoreCase: true)));
        }

        if (_s.OmitDuplicateAccounts) list = list.Distinct(StringComparer.OrdinalIgnoreCase);
        return o with { Value = list.ToList() };
    }

    /// <summary>Runs a blocking Windows call on the thread pool under the Windows budget. A call that overruns its
    /// timeout is abandoned (it keeps its pool thread until the OS returns) and counted; past the cap, calls fail fast.</summary>
    private async Task<Observation<T>> Blocking<T>(Func<Observation<T>> call, CancellationTokenSource deadline, CancellationToken ct, int timeoutMultiplier = 1)
    {
        if (Volatile.Read(ref _abandonedWindows) >= MaxAbandonedWindowsCalls)
        {
            return Observation<T>.Of(ObservationState.Timeout, _time.GetUtcNow(), "Too many unresponsive Windows management calls.");
        }

        try
        {
            await _windowsSlots.WaitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !_cts.IsCancellationRequested)
        {
            return Observation<T>.Of(ObservationState.Timeout, _time.GetUtcNow(), "Device deadline expired.");
        }

        // Dedicated thread: blocking management calls on pool threads starve the scan's async workers (D-084).
        var task = Task.Factory.StartNew(() =>
        {
            try
            {
                return call();
            }
            finally
            {
                ReleaseWindowsSlot(); // an abandoned call can end after the session was disposed (review C-15)
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            return await task.WaitAsync(TimeSpan.FromMilliseconds((double)_s.WindowsTimeoutMs * timeoutMultiplier), _time, ct).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            Interlocked.Increment(ref _abandonedWindows);
            _ = task.ContinueWith(t =>
            {
                DisposeAbandoned(t);
                Interlocked.Decrement(ref _abandonedWindows);
            }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return Observation<T>.Of(ObservationState.Timeout, _time.GetUtcNow(), "Windows management call timed out.");
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !_cts.IsCancellationRequested)
        {
            _ = task.ContinueWith(DisposeAbandoned, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return Observation<T>.Of(ObservationState.Timeout, _time.GetUtcNow(), "Device deadline expired.");
        }
        catch (OperationCanceledException)
        {
            _ = task.ContinueWith(DisposeAbandoned, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Observation<T>.Of(ObservationState.Failed, _time.GetUtcNow(), ex.Message);
        }
    }

    /// <summary>A blocking call that finished after it was abandoned may still have produced a resource (an authenticated IPC$
    /// session): dispose it so nothing stays open after the scan (review C-15).</summary>
    private void ReleaseWindowsSlot()
    {
        try
        {
            _windowsSlots.Release();
        }
        catch (ObjectDisposedException)
        {
            // the scan session is gone; its budget no longer matters
        }
    }

    private static void DisposeAbandoned<T>(Task<Observation<T>> t)
    {
        _ = t.Exception;
        if (t.IsCompletedSuccessfully && t.Result.Value is IDisposable d) d.Dispose();
    }

    private readonly record struct LivenessOutcome(DeviceStatus Status, PingMethod Method, ProbeReply Reply, string? Detail);

    private sealed record EnrichItem(DeviceResult Result, TimeSpan Remaining, bool Published);
}
