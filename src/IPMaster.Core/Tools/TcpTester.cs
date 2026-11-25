using System.Globalization;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Tools;

/// <summary>Why a TCP connection attempt ended. These are connection failures, not packet loss.</summary>
public enum TcpOutcome
{
    Connected,
    Refused,
    Timeout,
    DnsFailure,
    BindFailure,
    Unreachable,
    Cancelled,
    Error,
}

public sealed record TcpTarget(string Host, int Port)
{
    public string Key => $"{Host}:{Port.ToString(CultureInfo.InvariantCulture)}";
}

/// <summary>One attempt: DNS and connect are timed separately; the connection is closed without sending any payload.</summary>
public sealed record TcpAttempt(
    TcpTarget Target,
    DateTimeOffset At,
    string? ConnectedTo,
    string? LocalEndpoint,
    TimeSpan? DnsDuration,
    TimeSpan? ConnectDuration,
    TcpOutcome Outcome,
    string? SocketError,
    string Detail);

/// <summary>Per target:port statistics with a bounded history (D-074).</summary>
public sealed class TcpTargetStats
{
    public const int MaxHistory = 500;

    private readonly Queue<TcpAttempt> _history = new();

    public TcpTargetStats(TcpTarget target) => Target = target;

    public TcpTarget Target { get; }

    public int Attempts { get; private set; }

    public int Successes { get; private set; }

    public int Failures { get; private set; }

    public int ConsecutiveFailures { get; private set; }

    public TcpAttempt? Last { get; private set; }

    public DateTimeOffset? LastSuccess { get; private set; }

    public DateTimeOffset? LastFailure { get; private set; }

    public double? MinMs { get; private set; }

    public double? MaxMs { get; private set; }

    private double _sumMs;

    public double? AverageMs => Successes == 0 ? null : _sumMs / Successes;

    public IReadOnlyList<TcpAttempt> History => [.. _history];

    public void Add(TcpAttempt a)
    {
        ArgumentNullException.ThrowIfNull(a);
        if (a.Outcome == TcpOutcome.Cancelled) return; // not a result
        Attempts++;
        Last = a;
        if (a.Outcome == TcpOutcome.Connected)
        {
            Successes++;
            ConsecutiveFailures = 0;
            LastSuccess = a.At;
            if (a.ConnectDuration is { } d)
            {
                var ms = d.TotalMilliseconds;
                _sumMs += ms;
                MinMs = MinMs is null ? ms : Math.Min(MinMs.Value, ms);
                MaxMs = MaxMs is null ? ms : Math.Max(MaxMs.Value, ms);
            }
        }
        else
        {
            Failures++;
            ConsecutiveFailures++;
            LastFailure = a.At;
        }

        _history.Enqueue(a);
        while (_history.Count > MaxHistory) _history.Dequeue();
    }
}

public static class TcpTestPlan
{
    /// <summary>Upper bound of target × port combinations in one run.</summary>
    public const int MaxCombinations = 1024;

    /// <summary>Hosts (names or addresses; comma, space or newline separated) × ports ("80, 443, 8000-8010").</summary>
    public static bool TryBuild(string? hosts, string? ports, out IReadOnlyList<TcpTarget> targets, out string error)
    {
        targets = [];
        var hostList = (hosts ?? "").Split([',', ';', ' ', '\r', '\n', '\t'], StringSplitOptions.RemoveEmptyEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (hostList.Count == 0)
        {
            error = "Enter at least one host name or IP address.";
            return false;
        }

        if (!PortList.TryParse(ports, out var portList, out error)) return false;
        if (portList.Count == 0)
        {
            error = "Enter at least one port (1–65535), e.g. 443 or 80, 443, 8000-8010.";
            return false;
        }

        var count = (long)hostList.Count * portList.Count;
        if (count > MaxCombinations)
        {
            error = string.Create(CultureInfo.InvariantCulture, $"{hostList.Count} host(s) × {portList.Count} port(s) = {count} combinations; the limit is {MaxCombinations}.");
            return false;
        }

        targets = hostList.SelectMany(h => portList.Select(p => new TcpTarget(h.Trim('[', ']'), p))).ToList();
        error = "";
        return true;
    }

    public static string Describe(TcpOutcome o) => o switch
    {
        TcpOutcome.Connected => "Connected",
        TcpOutcome.Refused => "Refused (port closed)",
        TcpOutcome.Timeout => "Timeout (no answer)",
        TcpOutcome.DnsFailure => "DNS failure",
        TcpOutcome.BindFailure => "Source address unusable",
        TcpOutcome.Unreachable => "Unreachable (routing)",
        TcpOutcome.Cancelled => "Cancelled",
        _ => "Error",
    };
}
