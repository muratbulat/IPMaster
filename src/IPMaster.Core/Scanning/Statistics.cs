namespace IPMaster.Core.Scanning;

/// <summary>
/// Packet loss and jitter formulas (D-007).
/// Loss % = 100 × (sent − received) / sent.
/// Jitter = mean absolute difference between round-trip times of consecutive received replies
/// (RFC 3550-style packet delay variation without smoothing); undefined with fewer than two replies.
/// </summary>
public static class PingStatisticsCalculator
{
    public static PingStatistics Compute(int sent, IReadOnlyList<TimeSpan> receivedRoundTrips)
    {
        ArgumentNullException.ThrowIfNull(receivedRoundTrips);
        if (sent < receivedRoundTrips.Count) throw new ArgumentException("More replies than requests.");
        TimeSpan? avg = receivedRoundTrips.Count == 0
            ? null
            : TimeSpan.FromTicks((long)receivedRoundTrips.Average(r => r.Ticks));
        TimeSpan? jitter = null;
        if (receivedRoundTrips.Count >= 2)
        {
            long sum = 0;
            for (var i = 1; i < receivedRoundTrips.Count; i++) sum += Math.Abs((receivedRoundTrips[i] - receivedRoundTrips[i - 1]).Ticks);
            jitter = TimeSpan.FromTicks(sum / (receivedRoundTrips.Count - 1));
        }

        return new PingStatistics(sent, receivedRoundTrips.Count, jitter, avg);
    }
}

public static class HostNameFormatter
{
    public static string Format(string name, HostNameMode mode)
    {
        ArgumentNullException.ThrowIfNull(name);
        var n = name.TrimEnd('.');
        if (mode != HostNameMode.ShortName) return n;
        if (System.Net.IPAddress.TryParse(n, out _)) return n;
        var dot = n.IndexOf('.', StringComparison.Ordinal);
        return dot > 0 ? n[..dot] : n;
    }
}
