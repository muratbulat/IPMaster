using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Wifi;

/// <summary>Thread-safe fixed-capacity history; the oldest entry is dropped when full.</summary>
public sealed class BoundedHistory<T>(int capacity)
{
    private readonly Queue<T> _items = new();
    private readonly object _lock = new();

    public int Capacity { get; } = Math.Max(1, capacity);

    public int Count
    {
        get
        {
            lock (_lock) return _items.Count;
        }
    }

    public void Add(T item)
    {
        lock (_lock)
        {
            if (_items.Count == Capacity) _items.Dequeue();
            _items.Enqueue(item);
        }
    }

    public IReadOnlyList<T> Snapshot()
    {
        lock (_lock) return _items.ToArray();
    }

    public void Clear()
    {
        lock (_lock) _items.Clear();
    }
}

/// <summary>
/// One monitoring sample. <see cref="Interval"/> is the measured time since the previous sample (null for the first), so
/// a slow driver call shows as a longer interval instead of being hidden. Gateway and DNS values are null when not
/// measured; <see cref="GatewayLost"/> is a real lost ping, never a local probe failure.
/// </summary>
public sealed record WifiSample(
    DateTimeOffset At,
    Observation<WifiConnection> Connection,
    IPAddress? Gateway,
    double? GatewayRttMs,
    bool GatewayLost,
    double? DnsMs,
    string? DnsDetail,
    TimeSpan? Interval)
{
    public WifiConnection? Connected => Connection.HasValue ? Connection.Value : null;
}

public enum WifiEventKind
{
    Connected,
    Disconnected,
    Roamed,
    ChannelChanged,
}

public sealed record WifiEvent(
    DateTimeOffset At,
    WifiEventKind Kind,
    string Ssid,
    PhysicalAddress? From,
    PhysicalAddress? To,
    int? FromChannel,
    int? ToChannel,
    int? RssiBefore,
    int? RssiAfter,
    TimeSpan? Interruption,
    string Detail);

/// <summary>
/// Connection and roaming events from consecutive samples (D-097). A BSSID change within one SSID is a roam; a gap with
/// no connection is a disconnect, and the reconnect records the interruption length. A roam faster than the sampling
/// interval shows no interruption: that is a limit of sampling, stated in the detail.
/// </summary>
public sealed class RoamingTracker(int capacity = 1000)
{
    private readonly BoundedHistory<WifiEvent> _events = new(capacity);
    private readonly object _lock = new();
    private WifiConnection? _last;
    private int? _lastRssi;
    private DateTimeOffset? _lastAt;
    private DateTimeOffset? _downSince;
    private WifiConnection? _beforeDown;
    private bool _seen;

    public IReadOnlyList<WifiEvent> Events => _events.Snapshot();

    public void Observe(DateTimeOffset at, WifiConnection? c)
    {
        lock (_lock)
        {
            var rssi = c?.RssiDbm;
            if (c is null)
            {
                if (_last is not null)
                {
                    _beforeDown = _last;
                    _downSince = at;
                    _events.Add(new WifiEvent(at, WifiEventKind.Disconnected, _last.Ssid, _last.Bssid, null, _last.Channel, null, _lastRssi, null, null,
                        "connection lost"));
                }
            }
            else if (_last is null)
            {
                TimeSpan? gap = _downSince is { } d ? at - d : null;
                var prev = _beforeDown;
                var detail = !_seen ? "connected when monitoring started"
                    : prev is null ? "connected"
                    : prev.Ssid != c.Ssid ? $"connected to another network (was {prev.Ssid})"
                    : prev.Bssid.Equals(c.Bssid) ? "reconnected to the same access point"
                    : "reconnected to a different access point (roam through a disconnect)";
                _events.Add(new WifiEvent(at, WifiEventKind.Connected, c.Ssid, prev?.Bssid, c.Bssid, prev?.Channel, c.Channel, null, rssi, gap, detail));
                _downSince = null;
                _beforeDown = null;
            }
            else if (!_last.Bssid.Equals(c.Bssid))
            {
                var detail = _last.Ssid != c.Ssid ? $"switched network {_last.Ssid} → {c.Ssid}" : "roamed between access points";
                if (_last.Band != c.Band && _last.Band != WifiBand.Unknown && c.Band != WifiBand.Unknown)
                    detail += $"; band {WifiChannels.BandName(_last.Band)} → {WifiChannels.BandName(c.Band)}";
                if (_lastAt is { } la) detail += $"; no disconnect seen between samples {(at - la).TotalSeconds:0.#} s apart";
                _events.Add(new WifiEvent(at, WifiEventKind.Roamed, c.Ssid, _last.Bssid, c.Bssid, _last.Channel, c.Channel, _lastRssi, rssi, null, detail));
            }
            else if (_last.Channel != c.Channel && _last.Channel is not null && c.Channel is not null)
            {
                _events.Add(new WifiEvent(at, WifiEventKind.ChannelChanged, c.Ssid, c.Bssid, c.Bssid, _last.Channel, c.Channel, _lastRssi, rssi, null,
                    "the access point changed channel (for example a DFS radar event)"));
            }

            _seen = true;
            _last = c;
            _lastRssi = rssi;
            _lastAt = at;
        }
    }

    public int Roams => Events.Count(e => e.Kind == WifiEventKind.Roamed || (e.Kind == WifiEventKind.Connected && e.From is not null && e.To is not null && !e.From.Equals(e.To)));

    public int Disconnects => Events.Count(e => e.Kind == WifiEventKind.Disconnected);

    /// <summary>A → B → A within <paramref name="within"/>: a sign of overlapping cells with similar signal.</summary>
    public int PingPongs(TimeSpan within)
    {
        var roams = Events.Where(e => e.Kind == WifiEventKind.Roamed).ToList();
        var n = 0;
        for (var i = 1; i < roams.Count; i++)
        {
            if (roams[i].To?.Equals(roams[i - 1].From) == true && roams[i].At - roams[i - 1].At <= within) n++;
        }

        return n;
    }

    /// <summary>Gateway pings sent and lost from <paramref name="before"/> before to <paramref name="after"/> after the event.</summary>
    public static (int Sent, int Lost) GatewayImpact(WifiEvent e, IReadOnlyList<WifiSample> samples, TimeSpan before, TimeSpan after)
    {
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(samples);
        var near = samples.Where(s => s.At >= e.At - before && s.At <= e.At + after && (s.GatewayRttMs is not null || s.GatewayLost)).ToList();
        return (near.Count, near.Count(s => s.GatewayLost));
    }
}

/// <summary>
/// Live Wi-Fi monitoring (D-097): one loop samples the connection, pings the adapter's gateway and times a DNS query each
/// interval. History is bounded; <see cref="StopAsync"/> waits for the loop; Start after Stop starts fresh history.
/// A probe that fails locally (exception) is recorded as not measured, never as a lost ping.
/// </summary>
public sealed class WifiMonitor(IWifiProvider wifi, IIcmpProbe icmp, TimeProvider time, int capacity = 3600)
{
    private readonly object _lock = new();
    private Func<Task>? _cancel; // owns the run's CancellationTokenSource (CA1001: no disposable field)
    private Task _loop = Task.CompletedTask;

    /// <summary>Times one DNS query; returns milliseconds or null with a reason. Null delegate: DNS not measured.</summary>
    public Func<CancellationToken, Task<(double? Ms, string Detail)>>? DnsProbe { get; set; }

    public BoundedHistory<WifiSample> History { get; } = new(capacity);

    public RoamingTracker Roaming { get; private set; } = new();

    public bool Running
    {
        get
        {
            lock (_lock) return _cancel is not null;
        }
    }

    /// <summary>Raised on the sampling thread after each sample.</summary>
    public event Action<WifiSample>? Sampled;

    public void Start(Guid adapter, TimeSpan interval)
    {
        if (interval < TimeSpan.FromMilliseconds(250)) throw new ArgumentOutOfRangeException(nameof(interval), "The interval must be at least 250 ms.");
        lock (_lock)
        {
            if (_cancel is not null) throw new InvalidOperationException("Monitoring is already running.");
            if (!_loop.IsCompleted) throw new InvalidOperationException("The previous monitoring run is still stopping.");
            History.Clear();
            Roaming = new RoamingTracker();
            var cts = new CancellationTokenSource();
            var ct = cts.Token;
            var loop = Task.Run(() => RunAsync(adapter, interval, ct), CancellationToken.None);
            _loop = loop;
            _cancel = async () =>
            {
                await cts.CancelAsync().ConfigureAwait(false);
                try
                {
                    await loop.ConfigureAwait(false);
                }
                finally
                {
                    cts.Dispose();
                }
            };
        }
    }

    public async Task StopAsync()
    {
        Func<Task>? cancel;
        Task loop;
        lock (_lock)
        {
            cancel = _cancel;
            loop = _loop;
            _cancel = null;
        }

        await (cancel?.Invoke() ?? loop).ConfigureAwait(false);
    }

    private async Task RunAsync(Guid adapter, TimeSpan interval, CancellationToken ct)
    {
        using var timer = new PeriodicTimer(interval, time);
        DateTimeOffset? previous = null;
        try
        {
            do
            {
                var sample = await SampleAsync(adapter, interval, previous, ct).ConfigureAwait(false);
                previous = sample.At;
                History.Add(sample);
                Roaming.Observe(sample.At, sample.Connected);
                Sampled?.Invoke(sample);
            }
            while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    public async Task<WifiSample> SampleAsync(Guid adapter, TimeSpan interval, DateTimeOffset? previous, CancellationToken ct)
    {
        var at = time.GetUtcNow();
        var connection = await wifi.ConnectionAsync(adapter, ct).ConfigureAwait(false);
        IPAddress? gateway = null;
        if (connection.HasValue)
        {
            var adapters = await wifi.AdaptersAsync(ct).ConfigureAwait(false);
            gateway = adapters.HasValue ? adapters.Value!.FirstOrDefault(a => a.Id == adapter)?.Gateway : null;
        }

        var timeout = TimeSpan.FromMilliseconds(Math.Clamp(interval.TotalMilliseconds * 0.8, 200, 2000));
        var ping = gateway is null ? Task.FromResult<ProbeReply?>(null) : PingAsync(gateway, timeout, ct);
        var dns = connection.HasValue && DnsProbe is { } probe ? DnsAsync(probe, ct) : Task.FromResult<(double?, string?)>((null, null));
        await Task.WhenAll(ping, dns).ConfigureAwait(false);
        var reply = await ping.ConfigureAwait(false);
        var (dnsMs, dnsDetail) = await dns.ConfigureAwait(false);
        double? rtt = reply is { IsAlive: true } r ? r.RoundTrip?.TotalMilliseconds ?? 0 : null;
        var lost = reply is { State: ObservationState.NoResponse or ObservationState.Timeout };
        return new WifiSample(at, connection, gateway, rtt, lost, dnsMs, dnsDetail, previous is { } p ? at - p : null);
    }

    private async Task<ProbeReply?> PingAsync(IPAddress gateway, TimeSpan timeout, CancellationToken ct)
    {
        try
        {
            return await icmp.PingAsync(gateway, timeout, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    private static async Task<(double?, string?)> DnsAsync(Func<CancellationToken, Task<(double? Ms, string Detail)>> probe, CancellationToken ct)
    {
        try
        {
            var (ms, detail) = await probe(ct).ConfigureAwait(false);
            return (ms, detail);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return (null, ex.Message);
        }
    }

    /// <summary>Gateway loss/latency/jitter with the live-monitor formulas (D-060) over the given samples.</summary>
    public static MonitorSnapshot GatewayStats(IReadOnlyList<WifiSample> samples, MonitoringSettings settings)
    {
        ArgumentNullException.ThrowIfNull(samples);
        var window = samples.Where(s => s.GatewayRttMs is not null || s.GatewayLost).Select(s => new MonitorSample(s.At, s.GatewayRttMs)).ToList();
        return MonitorMetrics.Compute(window, settings);
    }
}

/// <summary>
/// Successive scans merged per BSSID (D-097): a BSS missing from one scan (a beacon not heard in time) stays visible for
/// <c>maxAge</c>. Bounded: at most <paramref name="capacity"/> BSSIDs, the least recently seen dropped first.
/// </summary>
public sealed class WifiScanBook(int capacity = 2000)
{
    private readonly Dictionary<string, WifiBss> _latest = new(StringComparer.Ordinal);
    private readonly object _lock = new();

    public int Scans { get; private set; }

    public int Count
    {
        get
        {
            lock (_lock) return _latest.Count;
        }
    }

    public void Add(IReadOnlyList<WifiBss> scan)
    {
        ArgumentNullException.ThrowIfNull(scan);
        lock (_lock)
        {
            Scans++;
            foreach (var b in scan) _latest[WifiFormat.Bssid(b.Bssid)] = b;
            if (_latest.Count > capacity)
            {
                foreach (var key in _latest.OrderBy(kv => kv.Value.SeenAt).Take(_latest.Count - capacity).Select(kv => kv.Key).ToList()) _latest.Remove(key);
            }
        }
    }

    public IReadOnlyList<WifiBss> Current(DateTimeOffset now, TimeSpan maxAge)
    {
        lock (_lock) return _latest.Values.Where(b => now - b.SeenAt <= maxAge).OrderByDescending(b => b.RssiDbm).ToList();
    }

    public void Clear()
    {
        lock (_lock)
        {
            _latest.Clear();
            Scans = 0;
        }
    }
}
