using System.Net;
using IPMaster.Core.Monitoring;

namespace IPMaster.Core.Tools;

public sealed record HopStats(int Ttl, IPAddress? Address, IReadOnlyList<IPAddress> AddressesSeen, int Sent, int Lost, double? LastMs, double? AverageMs, double? MinMs,
    double? MaxMs, double? JitterMs, string Note)
{
    public double LossPercent => Sent == 0 ? 0 : 100.0 * Lost / Sent;
}

public sealed record PathChange(DateTimeOffset At, int Ttl, IPAddress? Before, IPAddress After);

/// <summary>
/// Continuous traceroute statistics (D-093). Bounded: at most 64 hops, 16 addresses per hop, 1,000 change events and
/// 3,600 end-to-end samples. A hop that drops replies while later hops answer is ICMP rate limiting at that router, not
/// forwarding loss; only loss that continues to the destination is reported as possible forwarding loss.
/// </summary>
public sealed class PathTracker(IPAddress destination)
{
    public const int MaxHops = 64;
    public const int MaxAddressesPerHop = 16;
    public const int MaxChanges = 1000;
    public const int MaxSamples = 3600;

    private sealed class Hop
    {
        public readonly List<IPAddress> Seen = [];
        public IPAddress? Last;
        public int Sent;
        public int Lost;
        public double? LastMs;
        public double Sum;
        public double? Min;
        public double? Max;
        public double JitterSum;
        public int JitterCount;
    }

    private readonly Dictionary<int, Hop> _hops = [];
    private readonly List<PathChange> _changes = [];
    private readonly List<MonitorSample> _endToEnd = [];
    private readonly object _lock = new();

    public IPAddress Destination { get; } = destination ?? throw new ArgumentNullException(nameof(destination));

    public int Traces { get; private set; }

    public void Add(IReadOnlyList<RouteHop> trace, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(trace);
        lock (_lock)
        {
            Traces++;
            foreach (var r in trace.Where(r => r.Ttl is >= 1 and <= MaxHops))
            {
                if (!_hops.TryGetValue(r.Ttl, out var h)) _hops[r.Ttl] = h = new Hop();
                h.Sent++;
                if (r.RttMs is not { } ms)
                {
                    h.Lost++;
                }
                else
                {
                    if (h.LastMs is { } prev)
                    {
                        h.JitterSum += Math.Abs(ms - prev);
                        h.JitterCount++;
                    }

                    h.LastMs = ms;
                    h.Sum += ms;
                    h.Min = h.Min is { } mn ? Math.Min(mn, ms) : ms;
                    h.Max = h.Max is { } mx ? Math.Max(mx, ms) : ms;
                }

                if (r.Address is { } a)
                {
                    // a new address at a known hop is a path change; alternating known addresses (ECMP) are not reported again
                    if (!h.Seen.Contains(a))
                    {
                        if (h.Seen.Count > 0 && _changes.Count < MaxChanges) _changes.Add(new PathChange(at, r.Ttl, h.Last, a));
                        if (h.Seen.Count < MaxAddressesPerHop) h.Seen.Add(a);
                    }

                    h.Last = a;
                }
            }

            var reached = trace.FirstOrDefault(r => Destination.Equals(r.Address));
            _endToEnd.Add(new MonitorSample(at, reached?.RttMs));
            if (_endToEnd.Count > MaxSamples) _endToEnd.RemoveAt(0);
        }
    }

    public IReadOnlyList<PathChange> Changes
    {
        get
        {
            lock (_lock) return _changes.ToList();
        }
    }

    /// <summary>End-to-end samples (lost when the destination did not answer within the trace).</summary>
    public IReadOnlyList<MonitorSample> EndToEnd
    {
        get
        {
            lock (_lock) return _endToEnd.ToList();
        }
    }

    public double EndToEndLossPercent
    {
        get
        {
            lock (_lock) return _endToEnd.Count == 0 ? 0 : 100.0 * _endToEnd.Count(s => s.Lost) / _endToEnd.Count;
        }
    }

    public IReadOnlyList<HopStats> Hops
    {
        get
        {
            lock (_lock)
            {
                var ordered = _hops.OrderBy(kv => kv.Key).ToList();
                var loss = ordered.Select(kv => kv.Value.Sent == 0 ? 0 : 100.0 * kv.Value.Lost / kv.Value.Sent).ToList();
                return ordered.Select((kv, i) =>
                {
                    var h = kv.Value;
                    var answered = h.Sent - h.Lost;
                    return new HopStats(kv.Key, h.Last, h.Seen.ToList(), h.Sent, h.Lost, h.LastMs, answered > 0 ? h.Sum / answered : null, h.Min, h.Max,
                        h.JitterCount > 0 ? h.JitterSum / h.JitterCount : null, Note(i, loss, h));
                }).ToList();
            }
        }
    }

    private string Note(int i, List<double> loss, Hop h)
    {
        var parts = new List<string>();
        if (h.Seen.Count > 1) parts.Add($"{h.Seen.Count} addresses (path change or load balancing)");
        if (loss[i] < 1) return string.Join("; ", parts);
        var isDestination = h.Last is { } a && a.Equals(Destination);
        var later = loss.Skip(i + 1).ToList();
        if (isDestination) parts.Add("end-to-end loss");
        else if (h.Lost == h.Sent && later.Count > 0 && later.Min() < 100) parts.Add("no replies from this router (ICMP filtered); traffic passes it");
        else if (later.Count > 0 && later.Min() < loss[i] - 5) parts.Add("replies dropped here only: ICMP rate limiting at this router, not forwarding loss");
        else if (later.Count > 0) parts.Add("loss continues to later hops: possible forwarding loss at or after this hop");
        else parts.Add("no reply beyond this hop (destination not reached)");
        return string.Join("; ", parts);
    }
}

public enum MtuProbe
{
    /// <summary>The packet arrived and was answered.</summary>
    Reply,

    /// <summary>"Fragmentation needed" (DF set, packet too big), locally or from a router.</summary>
    TooBig,

    /// <summary>No answer within the timeout.</summary>
    NoReply,

    /// <summary>The probe could not be sent (unsupported platform, local error).</summary>
    Error,
}

public sealed record PathMtuResult(int? Mtu, bool AtLeast, int Probes, string Evidence);

/// <summary>
/// Path MTU discovery with "don't fragment" pings (D-093): binary search on the IPv4 packet size between
/// <see cref="Minimum"/> and the start size. "Fragmentation needed" is evidence; silent loss of only the large packets
/// suggests a PMTU black hole (the router's ICMP message is filtered). No reply at any size: unknown, never guessed.
/// </summary>
public static class PathMtu
{
    public const int Minimum = 576;
    public const int IcmpOverhead = 28; // IPv4 header 20 + ICMP echo header 8

    public static async Task<PathMtuResult> DiscoverAsync(Func<int, CancellationToken, Task<MtuProbe>> probe, int startSize, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(probe);
        var probes = 0;
        var tooBig = false;
        var silent = false;

        async Task<MtuProbe> Try(int size)
        {
            // one retry on silence: a single lost ping must not shrink the MTU
            for (var attempt = 0; ; attempt++)
            {
                probes++;
                var r = await probe(size, ct).ConfigureAwait(false);
                if (r != MtuProbe.NoReply || attempt == 1) return r;
            }
        }

        var high = Math.Max(startSize, Minimum);
        var first = await Try(high).ConfigureAwait(false);
        if (first == MtuProbe.Error) return new(null, false, probes, "The probe could not be sent (don't-fragment pings are not supported here).");
        if (first == MtuProbe.Reply) return new(high, true, probes, $"A {high}-byte packet with don't-fragment set was answered: the path MTU is at least {high} bytes (the largest size tested).");
        var low = Minimum;
        var small = await Try(low).ConfigureAwait(false);
        if (small != MtuProbe.Reply)
        {
            return new(null, false, probes, small == MtuProbe.TooBig
                ? $"Even {low}-byte packets were refused as too big: check the local interface."
                : "The destination does not answer pings (even small ones): the path MTU cannot be measured with ICMP.");
        }

        tooBig |= first == MtuProbe.TooBig;
        silent |= first == MtuProbe.NoReply;
        while (high - low > 1)
        {
            var mid = (low + high) / 2;
            var r = await Try(mid).ConfigureAwait(false);
            if (r == MtuProbe.Reply) low = mid;
            else
            {
                high = mid;
                tooBig |= r == MtuProbe.TooBig;
                silent |= r == MtuProbe.NoReply;
            }
        }

        var evidence = tooBig && !silent
            ? "Larger packets were refused with 'fragmentation needed'."
            : silent && !tooBig
                ? "Larger packets were dropped silently (no 'fragmentation needed' message): a possible PMTU black hole, or a firewall dropping large ICMP."
                : "Larger packets were refused or dropped.";
        return new(low, false, probes, $"Path MTU {low} bytes (largest don't-fragment packet answered; ping payload {low - IcmpOverhead} bytes). {evidence}");
    }
}
