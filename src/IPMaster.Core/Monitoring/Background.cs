using System.Net.NetworkInformation;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Monitoring;

public enum BackgroundMode
{
    /// <summary>Scan for previously undiscovered devices only.</summary>
    New,

    /// <summary>Rescan already discovered devices only.</summary>
    Known,

    Both,
}

public enum BackgroundEventType
{
    Join,
    Leave,
    NewMac,
    IpChange,
}

public enum SmtpSecurity
{
    /// <summary>Unencrypted (manual "Regular").</summary>
    None,

    /// <summary>Secure to regular port (STARTTLS).</summary>
    StartTls,

    /// <summary>Secure to dedicated port (implicit TLS).</summary>
    Tls,
}

/// <summary>Per-event notification actions (BKG-04).</summary>
public sealed record EventActions
{
    public bool Enabled { get; set; }

    public bool Balloon { get; set; } = true;

    public bool PlaySound { get; set; }

    public string SoundFile { get; set; } = "";

    public bool Launch { get; set; }

    /// <summary>Command line; <c>[Column Name]</c> and <c>[event]</c> are replaced.</summary>
    public string LaunchCommand { get; set; } = "";

    public bool LogToFile { get; set; }

    public string LogFile { get; set; } = "";

    public bool Email { get; set; }

    public string EmailTo { get; set; } = "";

    public bool Webhook { get; set; }

    public string WebhookUrl { get; set; } = "";
}

public sealed record SmtpSettings
{
    public string Host { get; set; } = "";

    public int Port { get; set; } = 587;

    public SmtpSecurity Security { get; set; } = SmtpSecurity.StartTls;

    /// <summary>Credential Manager entry for SMTP AUTH; null = no authentication.</summary>
    public Guid? CredentialId { get; set; }

    public string From { get; set; } = "";
}

/// <summary>Background scanning, Browsing-tab clearing, events and file output (BKG-01..06).</summary>
public sealed record BackgroundSettings
{
    public BackgroundMode Mode { get; set; } = BackgroundMode.Both;

    /// <summary>Liveness workers of a background round (own budget, lower than interactive scans).</summary>
    public int Concurrency { get; set; } = 32;

    /// <summary>Pause between the end of a round and the start of the next.</summary>
    public double RoundDelayMinutes { get; set; } = 5;

    /// <summary>A device leaves after this many consecutive complete rounds without an answer (debounce, BKG-05).</summary>
    public int LeaveAfterMisses { get; set; } = 2;

    /// <summary>Browsing › Clear information about offline devices.</summary>
    public bool ClearOffline { get; set; }

    /// <summary>Column ids kept when clearing (IP, MAC and response time are always kept).</summary>
    public IReadOnlyList<string> KeepOnOffline { get; set; } = ["hostName"];

    public EventActions Join { get; set; } = new();

    public EventActions Leave { get; set; } = new();

    public EventActions NewMac { get; set; } = new();

    public EventActions IpChange { get; set; } = new();

    public SmtpSettings Smtp { get; set; } = new();

    public bool SaveAfterRound { get; set; }

    public string OutputFile { get; set; } = "";

    public EventActions For(BackgroundEventType t) => t switch
    {
        BackgroundEventType.Join => Join,
        BackgroundEventType.Leave => Leave,
        BackgroundEventType.NewMac => NewMac,
        _ => IpChange,
    };
}

public sealed record BackgroundEvent(BackgroundEventType Type, DateTimeOffset At, AddressKey Address, PhysicalAddress? Mac, string Message, DeviceResult? Device)
{
    public static string Code(BackgroundEventType t) => t switch
    {
        BackgroundEventType.Join => "JOIN",
        BackgroundEventType.Leave => "LEAVE",
        BackgroundEventType.NewMac => "NEWMAC",
        _ => "IPCHANGE",
    };
}

/// <summary>
/// Turns background rounds into events (BKG-03/05). The first complete round (or <see cref="Seed"/>) is the baseline and
/// raises nothing. JOIN: an address answers that was not online. LEAVE: an online address missed
/// <c>leaveAfterMisses</c> consecutive <b>complete</b> rounds in which it was eligible (scanned). NEWMAC: a MAC never seen
/// before. IPCHANGE: a known MAC answers from another address. Incomplete or cancelled rounds update arrivals only and
/// never count misses, so a stopped round cannot produce a mass LEAVE.
/// </summary>
public sealed class ChangeDetector(int leaveAfterMisses = 2)
{
    private sealed class State
    {
        public bool Online;
        public int Misses;

        /// <summary>The device as last seen online: a LEAVE event names it, not the bare unanswered result (review C-05).</summary>
        public DeviceResult? LastOnline;
    }

    private readonly Dictionary<AddressKey, State> _state = [];
    private readonly Dictionary<string, HashSet<AddressKey>> _macToAddresses = new(StringComparer.Ordinal);
    private readonly int _leaveAfter = Math.Max(1, leaveAfterMisses);

    public bool HasBaseline { get; private set; }

    public IReadOnlyCollection<AddressKey> Online => _state.Where(kv => kv.Value.Online).Select(kv => kv.Key).ToList();

    /// <summary>Uses already displayed results as the baseline.</summary>
    public void Seed(IEnumerable<DeviceResult> devices)
    {
        ArgumentNullException.ThrowIfNull(devices);
        foreach (var d in devices)
        {
            var online = d.Status == DeviceStatus.Online;
            _state[d.Key] = new State { Online = online, LastOnline = online ? d : null }; // LEAVE keeps the name and MAC
            if (d.Mac.HasValue && online)
            {
                if (!_macToAddresses.TryGetValue(Mac(d.Mac.Value!), out var set)) _macToAddresses[Mac(d.Mac.Value!)] = set = [];
                set.Add(d.Key);
            }
        }

        HasBaseline = true;
    }

    public IReadOnlyList<BackgroundEvent> ApplyRound(IEnumerable<DeviceResult> results, Func<AddressKey, bool> eligible, bool complete, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(eligible);
        var events = new List<BackgroundEvent>();
        var quiet = !HasBaseline;
        var seen = new HashSet<AddressKey>();
        foreach (var d in results.Where(r => r.Status == DeviceStatus.Online))
        {
            seen.Add(d.Key);
            if (!_state.TryGetValue(d.Key, out var st))
            {
                st = new State();
                _state[d.Key] = st;
            }

            if (!st.Online && !quiet) events.Add(new BackgroundEvent(BackgroundEventType.Join, at, d.Key, d.Mac.Value, $"{Label(d)} joined the network.", d));
            st.Online = true;
            st.Misses = 0;
            st.LastOnline = d;
        }

        // MACs: one MAC may legitimately answer from several addresses (routers, aliases, duplicate-MAC devices).
        // IPCHANGE only when a known MAC answers from an address it never used before AND none of its previous
        // addresses answered with it in this round; otherwise the address set just grows.
        foreach (var group in results.Where(r => r.Status == DeviceStatus.Online && r.Mac.HasValue).GroupBy(r => Mac(r.Mac.Value!)))
        {
            var now = group.Select(r => r.Key).ToHashSet();
            var first = group.First();
            if (!_macToAddresses.TryGetValue(group.Key, out var known))
            {
                if (!quiet) events.Add(new BackgroundEvent(BackgroundEventType.NewMac, at, first.Key, first.Mac.Value, $"New MAC address {Formats.Mac(first.Mac.Value!)} at {first.Key}.", first));
                _macToAddresses[group.Key] = now;
                continue;
            }

            if (!known.Overlaps(now) && !quiet)
            {
                events.Add(new BackgroundEvent(BackgroundEventType.IpChange, at, first.Key, first.Mac.Value,
                    $"{Formats.Mac(first.Mac.Value!)} moved from {string.Join(", ", known.Order())} to {string.Join(", ", now.Order())}.", first));
                known.Clear();
            }

            known.UnionWith(now);
        }

        if (complete)
        {
            // Only an explicit "no reply" is a miss; Unsupported/TimedOut/Cancelled results carry no evidence (review C-03).
            var undetermined = results.Where(r => r.Status is not (DeviceStatus.Online or DeviceStatus.Offline)).Select(r => r.Key).ToHashSet();
            foreach (var (key, st) in _state)
            {
                if (!st.Online || seen.Contains(key) || !eligible(key) || undetermined.Contains(key)) continue;
                st.Misses++;
                if (st.Misses < _leaveAfter) continue;
                st.Online = false;
                if (!quiet)
                {
                    var last = st.LastOnline ?? results.FirstOrDefault(r => r.Key == key);
                    events.Add(new BackgroundEvent(BackgroundEventType.Leave, at, key, last?.Mac.Value, $"{(last is null ? key.ToString() : Label(last))} left the network.", last));
                }
            }

            HasBaseline = true;
        }

        return events;
    }

    private static string Mac(PhysicalAddress m) => m.ToString();

    private static string Label(DeviceResult d) =>
        d.HostName.HasValue ? $"{d.HostName.Value!.Name} ({d.Key})" : d.Key.ToString();
}

/// <summary>Browsing › Clear information about offline devices (BKG-02). IP, MAC and response time are always kept.</summary>
public static class OfflineClearer
{
    public static DeviceResult Clear(DeviceResult d, IReadOnlyCollection<string> keepColumnIds)
    {
        ArgumentNullException.ThrowIfNull(d);
        ArgumentNullException.ThrowIfNull(keepColumnIds);
        bool Keep(string id) => keepColumnIds.Contains(id, StringComparer.OrdinalIgnoreCase);
        static Observation<T> N<T>() => Observation<T>.NotRequested;
        return d with
        {
            HostName = Keep("hostName") ? d.HostName : N<HostNameInfo>(),
            Vendor = Keep("vendor") ? d.Vendor : N<string>(),
            NetBios = Keep("netbios") ? d.NetBios : N<NetBiosInfo>(),
            Workgroup = Keep("workgroup") ? d.Workgroup : N<string>(),
            OsVersion = Keep("os") ? d.OsVersion : N<string>(),
            TcpPorts = Keep("tcpPorts") ? d.TcpPorts : N<IReadOnlyList<PortResult>>(),
            UdpPorts = Keep("udpPorts") ? d.UdpPorts : N<IReadOnlyList<PortResult>>(),
            Banners = Keep("banners") ? d.Banners : N<IReadOnlyList<ServiceBanner>>(),
            Shares = Keep("shares") ? d.Shares : N<IReadOnlyList<ShareInfo>>(),
            Accounts = N<IReadOnlyList<string>>(),
            LoggedOnUsers = N<IReadOnlyList<string>>(),
            LoggedOnSids = N<IReadOnlyList<string>>(),
            InstalledApps = N<IReadOnlyList<InstalledApplication>>(),
            Monitors = N<IReadOnlyList<MonitorInfo>>(),
            TerminalSessions = N<IReadOnlyList<TerminalSession>>(),
            Queries = Keep("queries") ? d.Queries : DeviceResult.NoQueries,
        };
    }

    /// <summary>Expands <c>[Column Name]</c> and <c>[event]</c> in a launch command or message template.</summary>
    public static string Expand(string template, BackgroundEvent e, IReadOnlyList<ResultColumn> columns, ColumnFormat format)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(columns);
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < template.Length; i++)
        {
            if (template[i] == '[' && template.IndexOf(']', i + 1) is var close and > 0)
            {
                var name = template[(i + 1)..close];
                if (name.Equals("event", StringComparison.OrdinalIgnoreCase))
                {
                    sb.Append(BackgroundEvent.Code(e.Type));
                    i = close;
                    continue;
                }

                var col = columns.FirstOrDefault(c => string.Equals(c.Header, name, StringComparison.OrdinalIgnoreCase) || string.Equals(c.Id, name, StringComparison.OrdinalIgnoreCase));
                if (col is not null)
                {
                    sb.Append(e.Device is null ? (col.Id == "ip" ? e.Address.ToString() : "") : Management.BatchFile.SafeArgument(col.Text(e.Device, format))); // review C-07
                    i = close;
                    continue;
                }
            }

            sb.Append(template[i]);
        }

        return sb.ToString();
    }
}

public sealed record BackgroundRound(int Number, DateTimeOffset StartedAt, TimeSpan Elapsed, bool Complete, IReadOnlyList<DeviceResult> Results, IReadOnlyList<BackgroundEvent> Events)
{
    /// <summary>What this round actually scanned (exclusions included): history coverage must use it (review C-04).</summary>
    public TargetPlan? Plan { get; init; }
}

/// <summary>
/// Runs background rounds until stopped (BKG-01): asks the caller for a scan request per round, waits for completion,
/// applies <see cref="ChangeDetector"/>, raises <see cref="RoundCompleted"/>, then waits the configured delay.
/// </summary>
public sealed class BackgroundScanner : IDisposable
{
    private readonly ScanEngine _engine;
    private readonly Func<BackgroundMode, IReadOnlySet<AddressKey>, CancellationToken, Task<ScanRequest?>> _requests;
    private readonly TimeProvider _time;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private ScanSession? _session;

    public BackgroundScanner(ScanEngine engine, Func<BackgroundMode, IReadOnlySet<AddressKey>, CancellationToken, Task<ScanRequest?>> requests, TimeProvider? time = null)
    {
        _engine = engine ?? throw new ArgumentNullException(nameof(engine));
        _requests = requests ?? throw new ArgumentNullException(nameof(requests));
        _time = time ?? TimeProvider.System;
    }

    public ChangeDetector Detector { get; private set; } = new();

    public BackgroundSettings Settings { get; set; } = new();

    public bool IsRunning => _loop is { IsCompleted: false };

    /// <summary>The round loop: completes when stopped, when a round cannot be built, or faults on an unexpected error.</summary>
    public Task Completion => _loop ?? Task.CompletedTask;

    public int Round { get; private set; }

    public DateTimeOffset? NextRoundAt { get; private set; }

    /// <summary>Receives each finished round (on a thread-pool thread).</summary>
    public event EventHandler<BackgroundRound>? RoundCompleted;

    /// <summary>Per-device results while a round runs (for live display).</summary>
    public IScanResultSink? LiveSink { get; set; }

    public void Start(IEnumerable<DeviceResult>? baseline = null)
    {
        if (IsRunning) return;
        Detector = new ChangeDetector(Settings.LeaveAfterMisses);
        if (baseline is not null)
        {
            var list = baseline.ToList();
            if (list.Count > 0) Detector.Seed(list);
        }

        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _loop = Task.Run(() => LoopAsync(ct), CancellationToken.None);
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        _session?.Stop();
        if (_loop is not null)
        {
            try
            {
                await _loop.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private async Task LoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var known = Detector.Online.ToHashSet();
            var request = await _requests(Settings.Mode, known, ct).ConfigureAwait(false);
            if (request is null) return;
            request = request with { Settings = request.Settings with { MaxConcurrency = Math.Clamp(Settings.Concurrency, 1, 1024) } };
            var sink = new RoundSink(LiveSink);
            var started = _time.GetUtcNow();
            var ts = _time.GetTimestamp();
            using (var session = _engine.Start(request, sink, ct))
            {
                _session = session;
                var summary = await session.Completion.ConfigureAwait(false);
                _session = null;
                var complete = summary.State == ScanState.Completed;
                var results = sink.Results;
                var plan = request.Plan;
                var events = Detector.ApplyRound(results, k => Eligible(k, plan, request.KnownAddresses), complete, _time.GetUtcNow());
                Round++;
                RoundCompleted?.Invoke(this, new BackgroundRound(Round, started, _time.GetElapsedTime(ts), complete, results, events) { Plan = plan });
            }

            if (ct.IsCancellationRequested) return;
            var delay = TimeSpan.FromMinutes(Math.Clamp(Settings.RoundDelayMinutes, 0, 1440));
            NextRoundAt = _time.GetUtcNow() + delay;
            try
            {
                await Task.Delay(delay, _time, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>An address counts toward LEAVE only when this round's plan covered it.</summary>
    private static bool Eligible(AddressKey key, TargetPlan plan, IReadOnlySet<AddressKey>? known) =>
        known?.Contains(key) == true || plan.Contains(key);

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
    }

    private sealed class RoundSink(IScanResultSink? forward) : IScanResultSink
    {
        private readonly Dictionary<AddressKey, DeviceResult> _latest = [];

        public List<DeviceResult> Results
        {
            get
            {
                lock (_latest) return _latest.Values.ToList();
            }
        }

        public void OnDevice(DeviceResult result)
        {
            lock (_latest)
            {
                if (!_latest.TryGetValue(result.Key, out var old) || result.Revision >= old.Revision) _latest[result.Key] = result;
            }

            forward?.OnDevice(result);
        }
    }
}
