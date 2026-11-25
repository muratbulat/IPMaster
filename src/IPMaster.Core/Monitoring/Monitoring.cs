using System.Collections.Concurrent;
using System.Net;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Monitoring;

public enum LinkQuality
{
    Unknown,
    Good,
    Degraded,
    Critical,
}

/// <summary>Monitoring tab (MON-03). Formulas are in <see cref="MonitorMetrics"/> and D-060.</summary>
public sealed record MonitoringSettings
{
    /// <summary>Monitor every discovered online device automatically.</summary>
    public bool MonitorAll { get; set; }

    public int IntervalMs { get; set; } = 1000;

    public int PingTimeoutMs { get; set; } = 1000;

    /// <summary>Latency at or below this is Good (ms).</summary>
    public int GoodLatencyMs { get; set; } = 50;

    /// <summary>Latency above this is Critical (ms).</summary>
    public int CriticalLatencyMs { get; set; } = 200;

    public double GoodLossPercent { get; set; } = 1;

    public double CriticalLossPercent { get; set; } = 10;

    /// <summary>Window for loss and jitter (samples = seconds at the default interval).</summary>
    public int WindowSamples { get; set; } = 60;

    /// <summary>This many consecutive lost pings make the device Critical (down) regardless of the window.</summary>
    public int DownAfterLost { get; set; } = 3;

    /// <summary>Upper bound on simultaneously monitored devices (bounded work).</summary>
    public int MaxDevices { get; set; } = 500;

    public bool ShowLatency { get; set; } = true;

    public bool ShowHistory { get; set; } = true;

    public bool ShowLoss { get; set; } = true;

    public bool ShowJitter { get; set; } = true;

    public bool ShowQuality { get; set; } = true;
}

public readonly record struct MonitorSample(DateTimeOffset At, double? RttMs)
{
    public bool Lost => RttMs is null;
}

public sealed record MonitorSnapshot(
    double? LatencyMs,
    double LossPercent,
    double? JitterMs,
    LinkQuality Quality,
    int Samples,
    IReadOnlyList<MonitorSample> Recent);

/// <summary>Thread-safe fixed-size ring buffer of samples (1 h at 1 s by default, MON-03).</summary>
public sealed class MonitorSeries(int capacity = MonitorSeries.DefaultCapacity)
{
    public const int DefaultCapacity = 3600;

    private readonly MonitorSample[] _buffer = new MonitorSample[Math.Max(1, capacity)];
    private readonly object _lock = new();
    private int _next;
    private int _count;
    private int _probeErrors;

    public int Capacity => _buffer.Length;

    /// <summary>Local probe failures (exception, unsupported, denied): not samples, so they never count as loss.</summary>
    public int ProbeErrors => Volatile.Read(ref _probeErrors);

    /// <summary>Why the latest attempt failed locally; null once a real sample (reply or no reply) arrives.</summary>
    public string? LastError { get; private set; }

    public void AddProbeError(string detail)
    {
        lock (_lock)
        {
            _probeErrors++;
            LastError = detail;
        }
    }

    public int Count
    {
        get
        {
            lock (_lock) return _count;
        }
    }

    public void Add(MonitorSample s)
    {
        lock (_lock)
        {
            _buffer[_next] = s;
            LastError = null;
            _next = (_next + 1) % _buffer.Length;
            if (_count < _buffer.Length) _count++;
        }
    }

    /// <summary>The newest <paramref name="max"/> samples, oldest first.</summary>
    public IReadOnlyList<MonitorSample> Last(int max)
    {
        lock (_lock)
        {
            var n = Math.Min(max, _count);
            var result = new MonitorSample[n];
            for (var i = 0; i < n; i++) result[i] = _buffer[(_next - n + i + _buffer.Length) % _buffer.Length];
            return result;
        }
    }

    public IReadOnlyList<MonitorSample> Since(DateTimeOffset from) => Last(_count).Where(s => s.At >= from).ToList();
}

/// <summary>
/// D-060 formulas over the last <see cref="MonitoringSettings.WindowSamples"/> samples:
/// latency = newest received RTT (null when the newest ping was lost); loss % = 100 × lost ÷ samples;
/// jitter = mean |RTTᵢ − RTTᵢ₋₁| over consecutive received samples (RFC 3550 without smoothing, as D-007);
/// quality = Critical when the last <c>DownAfterLost</c> pings were lost, latency &gt; critical or loss ≥ critical;
/// Good when latency ≤ good and loss ≤ good; Degraded otherwise; Unknown without samples.
/// </summary>
public static class MonitorMetrics
{
    public static MonitorSnapshot Compute(IReadOnlyList<MonitorSample> window, MonitoringSettings s)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(s);
        if (window.Count == 0) return new MonitorSnapshot(null, 0, null, LinkQuality.Unknown, 0, window);
        var lost = window.Count(x => x.Lost);
        var loss = 100.0 * lost / window.Count;
        var latency = window[^1].RttMs;
        double? jitter = null;
        double sum = 0;
        var pairs = 0;
        for (var i = 1; i < window.Count; i++)
        {
            if (window[i].RttMs is { } a && window[i - 1].RttMs is { } b)
            {
                sum += Math.Abs(a - b);
                pairs++;
            }
        }

        if (pairs > 0) jitter = sum / pairs;
        var down = window.Count >= s.DownAfterLost && window.TakeLast(Math.Max(1, s.DownAfterLost)).All(x => x.Lost);
        LinkQuality q;
        if (down || (latency is { } l1 && l1 > s.CriticalLatencyMs) || loss >= s.CriticalLossPercent) q = LinkQuality.Critical;
        else if ((latency is null || latency <= s.GoodLatencyMs) && loss <= s.GoodLossPercent) q = latency is null ? LinkQuality.Degraded : LinkQuality.Good;
        else q = LinkQuality.Degraded;
        return new MonitorSnapshot(latency, loss, jitter, q, window.Count, window);
    }

    public static LinkQuality Classify(double? rttMs, MonitoringSettings s) => rttMs switch
    {
        null => LinkQuality.Critical,
        var r when r <= s.GoodLatencyMs => LinkQuality.Good,
        var r when r > s.CriticalLatencyMs => LinkQuality.Critical,
        _ => LinkQuality.Degraded,
    };
}

/// <summary>
/// Live monitoring (MON-01): one scheduler pings every monitored address once per interval, each on its own schedule,
/// with at most 64 probes at once (D-087), and keeps a ring buffer per address. Stopping a device keeps its series until <see cref="Forget"/>, so open windows keep their
/// history (MON-05).
/// </summary>
public sealed class LiveMonitor : IDisposable
{
    private readonly IIcmpProbe _icmp;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<AddressKey, MonitorSeries> _series = new();
    private readonly ConcurrentDictionary<AddressKey, byte> _active = new();
    private readonly ConcurrentDictionary<AddressKey, byte> _stoppedByUser = new();
    private readonly SemaphoreSlim _slots = new(64, 64);
    private readonly object _gate = new();
    private CancellationTokenSource _cts = new();
    private Task? _loop;
    private bool _disposed;
    private volatile bool _paused;
    private volatile bool _automaticSuppressed;

    public LiveMonitor(IIcmpProbe icmp, TimeProvider? time = null)
    {
        _icmp = icmp ?? throw new ArgumentNullException(nameof(icmp));
        _time = time ?? TimeProvider.System;
    }

    public MonitoringSettings Settings { get; set; } = new();

    /// <summary>Raised at most once per interval with the addresses probed since the last time.</summary>
    public event EventHandler<IReadOnlyList<AddressKey>>? Updated;

    public IReadOnlyCollection<AddressKey> Active => _active.Keys.ToList();

    public bool IsMonitored(AddressKey key) => _active.ContainsKey(key);

    public MonitorSeries? Series(AddressKey key) => _series.GetValueOrDefault(key);

    /// <returns>False when the device limit is reached.</returns>
    public bool Start(AddressKey key)
    {
        _stoppedByUser.TryRemove(key, out _);
        if (!_active.ContainsKey(key) && _active.Count >= Math.Max(1, Settings.MaxDevices)) return false;
        _series.GetOrAdd(key, _ => new MonitorSeries());
        _active[key] = 0;
        EnsureLoop();
        return true;
    }

    /// <summary>
    /// Monitor All: starts a device unless the user stopped it (a manual <see cref="Start"/> undoes that) or stopped all
    /// monitoring (<see cref="StopAllAsync"/>, until <see cref="ResumeAutomatic"/>).
    /// </summary>
    public bool StartAutomatic(AddressKey key) => !_automaticSuppressed && !_stoppedByUser.ContainsKey(key) && Start(key);

    /// <summary>True while no new probe is started (<see cref="Pause"/>); devices and history are kept.</summary>
    public bool IsPaused => _paused;

    /// <summary>True after the user stopped all monitoring: Monitor All does not enrol arriving devices.</summary>
    public bool AutomaticSuppressed => _automaticSuppressed;

    /// <summary>Starts no new probes; running probes finish. Devices, schedules and history stay (D-100).</summary>
    public void Pause() => _paused = true;

    public void Resume() => _paused = false;

    /// <summary>
    /// The user's "Stop All Monitoring" (D-100): stops every device like <see cref="StopAsync"/> (history kept) and keeps
    /// Monitor All from enrolling arriving devices again until <see cref="ResumeAutomatic"/>. The Monitor All setting
    /// itself is not changed. A manual <see cref="Start"/> still works.
    /// </summary>
    public Task StopAllAsync()
    {
        _automaticSuppressed = true;
        _paused = false;
        return StopAsync();
    }

    /// <summary>Lets Monitor All enrol devices again after <see cref="StopAllAsync"/>.</summary>
    public void ResumeAutomatic() => _automaticSuppressed = false;

    public void Stop(AddressKey key)
    {
        _active.TryRemove(key, out _);
        _stoppedByUser[key] = 0;
    }

    /// <summary>Drops the stored series (after clearing results, unless a window still needs it).</summary>
    public void Forget(AddressKey key)
    {
        _active.TryRemove(key, out _);
        _stoppedByUser.TryRemove(key, out _);
        _series.TryRemove(key, out _);
    }

    public MonitorSnapshot? Snapshot(AddressKey key) =>
        _series.TryGetValue(key, out var s) ? MonitorMetrics.Compute(s.Last(Math.Max(1, Settings.WindowSamples)), Settings) : null;

    /// <summary>
    /// Monitored devices sampled less often than the interval (last two samples more than 1.5 intervals apart): their
    /// probe takes longer than the interval, or every probe slot was busy (D-087).
    /// </summary>
    public int LaggingCount()
    {
        var limit = TimeSpan.FromMilliseconds(Interval.TotalMilliseconds * 1.5);
        return _active.Keys.Count(k => _series.TryGetValue(k, out var s) && s.Last(2) is [var a, var b] && b.At - a.At > limit);
    }

    /// <summary>Stops every device and completes when no probe is running any more; <see cref="Start"/> works again afterwards.</summary>
    public async Task StopAsync()
    {
        Task? loop;
        CancellationTokenSource cts;
        lock (_gate)
        {
            if (_disposed) return;
            _active.Clear();
            (loop, cts) = (_loop, _cts);
            _loop = null;
            _cts = new CancellationTokenSource();
        }

        await cts.CancelAsync().ConfigureAwait(false);
        if (loop is not null) await loop.ConfigureAwait(false);
        cts.Dispose();
    }

    private TimeSpan Interval => TimeSpan.FromMilliseconds(Math.Max(200, Settings.IntervalMs));

    private void EnsureLoop()
    {
        lock (_gate)
        {
            if (_disposed) return;
            var ct = _cts.Token;
            _loop ??= Task.Run(() => LoopAsync(ct));
        }
    }

    /// <summary>
    /// Per-device schedule (D-087): every device has its own due time and the earliest due device gets the next free
    /// probe slot, so a silent device waiting for its timeout never delays the others. A device is never probed twice at
    /// once; one that falls behind resumes at "now + interval" (samples are skipped, not bunched up).
    /// </summary>
    private async Task LoopAsync(CancellationToken ct)
    {
        var due = new Dictionary<AddressKey, long>();
        var running = new Dictionary<AddressKey, Task>();
        var done = new ConcurrentQueue<AddressKey>();
        var lastRaise = _time.GetTimestamp();
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var iv = (long)(Interval.TotalSeconds * _time.TimestampFrequency);
                var now = _time.GetTimestamp();
                foreach (var k in running.Where(r => r.Value.IsCompleted).Select(r => r.Key).ToList()) running.Remove(k);
                var active = _active.Keys.ToHashSet();
                foreach (var k in due.Keys.Where(k => !active.Contains(k)).ToList()) due.Remove(k);
                foreach (var k in _paused ? Enumerable.Empty<AddressKey>() : active.Where(k => !running.ContainsKey(k)).OrderBy(k => due.GetValueOrDefault(k)))
                {
                    var at = due.GetValueOrDefault(k);
                    if (at > now) break; // ordered by due time: nothing later is due either
                    if (!_slots.Wait(0, CancellationToken.None)) break; // non-blocking: all 64 slots busy
                    due[k] = at > 0 && at + iv > now ? at + iv : now + iv;
                    running[k] = PingAsync(k, done, ct);
                }

                if (!done.IsEmpty && _time.GetElapsedTime(lastRaise) >= Interval)
                {
                    var keys = new HashSet<AddressKey>();
                    while (done.TryDequeue(out var k)) keys.Add(k);
                    lastRaise = _time.GetTimestamp();
                    Updated?.Invoke(this, keys.ToList());
                }

                await Task.Delay(Tick, _time, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // stopping
        }

        await Task.WhenAll(running.Values).ConfigureAwait(false); // stopped means no probe is left running
    }

    private static readonly TimeSpan Tick = TimeSpan.FromMilliseconds(50);

    /// <summary>Probes one device; the caller already holds a slot. Never throws.</summary>
    private async Task PingAsync(AddressKey key, ConcurrentQueue<AddressKey> done, CancellationToken ct)
    {
        try
        {
            var reply = await _icmp.PingAsync(key.ToIPAddress(), TimeSpan.FromMilliseconds(Math.Clamp(Settings.PingTimeoutMs, 100, 10_000)), ct).ConfigureAwait(false);
            if (!_series.TryGetValue(key, out var s)) return;
            if (reply.IsAlive) s.Add(new MonitorSample(_time.GetUtcNow(), reply.RoundTrip?.TotalMilliseconds ?? 0));
            else if (reply.State is ObservationState.NoResponse or ObservationState.Timeout) s.Add(new MonitorSample(_time.GetUtcNow(), null));
            else s.AddProbeError(reply.Detail ?? reply.State.ToString()); // local failure: no evidence about the device
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return; // stopping: no sample
        }
        catch (Exception ex) // one address must not end the shared loop
        {
            if (_series.TryGetValue(key, out var s)) s.AddProbeError(ex.Message);
        }
        finally
        {
            _slots.Release();
        }

        done.Enqueue(key);
    }

    /// <summary>Synchronous fallback; shutdown awaits <see cref="StopAsync"/> first, so this normally finds no loop.</summary>
    public void Dispose()
    {
        Task? loop;
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            loop = _loop;
            _cts.Cancel();
        }

        try
        {
            loop?.Wait(TimeSpan.FromSeconds(3));
        }
        catch (AggregateException)
        {
        }

        if (loop is null || loop.IsCompleted)
        {
            _cts.Dispose();
            _slots.Dispose(); // only when no probe can still release a slot
        }
    }
}

/// <summary>One hop of a traced route (MON-04).</summary>
public sealed record RouteHop(int Ttl, IPAddress? Address, double? RttMs);

public interface IRouteTracer
{
    /// <summary>ICMP echo with increasing TTL until the destination answers or <paramref name="maxHops"/>.</summary>
    Task<IReadOnlyList<RouteHop>> TraceAsync(IPAddress destination, int maxHops, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Monitoring column group (MON-02); empty cells for devices that are not monitored.</summary>
public static class MonitorColumns
{
    public static string Bullet(LinkQuality q) => q switch
    {
        LinkQuality.Good => "🟢",
        LinkQuality.Degraded => "🟡",
        LinkQuality.Critical => "🔴",
        _ => "⚪",
    };

    public static IEnumerable<Results.ResultColumn> For(LiveMonitor monitor)
    {
        ArgumentNullException.ThrowIfNull(monitor);
        var s = monitor.Settings;
        MonitorSnapshot? Snap(DeviceResult d) => monitor.Series(d.Key) is null ? null : monitor.Snapshot(d.Key);
        string Ms(double? v) => v is { } x ? (x < 1 ? "<1 ms" : $"{x:0} ms") : "";
        if (s.ShowLatency) yield return new("m:latency", "Latency", Results.ColumnKind.Number, (d, _) => monitor.Series(d.Key)?.LastError is not null ? "probe error" : Snap(d) is { } n ? (n.LatencyMs is null && n.Samples > 0 ? "lost" : Ms(n.LatencyMs)) : "", d => Snap(d)?.LatencyMs);
        if (s.ShowHistory) yield return new("m:history", "History", Results.ColumnKind.Text, (d, _) => Snap(d) is { } n ? HistoryText.Sparkline(n.Recent.Select(x => x.RttMs).ToList()) : "");
        if (s.ShowLoss) yield return new("m:loss", "Loss", Results.ColumnKind.Number, (d, _) => Snap(d) is { Samples: > 0 } n ? $"{n.LossPercent:0.#} %" : "", d => Snap(d)?.LossPercent);
        if (s.ShowJitter) yield return new("m:jitter", "Jitter", Results.ColumnKind.Number, (d, _) => Snap(d) is { } n ? Ms(n.JitterMs) : "", d => Snap(d)?.JitterMs);
        if (s.ShowQuality) yield return new("m:quality", "Quality", Results.ColumnKind.Text, (d, _) => Snap(d) is { } n ? $"{Bullet(n.Quality)} {n.Quality}" : "", d => (int?)Snap(d)?.Quality);
    }
}
