using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

public enum NtpOutcome
{
    Ok,
    KissOfDeath,
    Invalid,
    Timeout,
    Unreachable,
    DnsFailure,
    Cancelled,
}

public sealed record NtpSample(
    NtpOutcome Outcome,
    string Detail,
    NtpPacket? Packet,
    DateTime T1,
    DateTime? T2,
    DateTime? T3,
    DateTime? T4,
    TimeSpan? Offset,
    TimeSpan? Delay,
    int IgnoredReplies);

public sealed record NtpServerResult(string Server, string Address, IReadOnlyList<NtpSample> Samples)
{
    public IReadOnlyList<NtpSample> Good => Samples.Where(s => s.Outcome == NtpOutcome.Ok).ToList();

    /// <summary>The sample with the lowest delay is the most trustworthy offset estimate.</summary>
    public NtpSample? Best => Good.OrderBy(s => s.Delay).FirstOrDefault();

    public TimeSpan? Jitter
    {
        get
        {
            var g = Good;
            if (g.Count < 2) return null;
            var mean = g.Average(s => s.Offset!.Value.TotalMilliseconds);
            return TimeSpan.FromMilliseconds(Math.Sqrt(g.Average(s => Math.Pow(s.Offset!.Value.TotalMilliseconds - mean, 2))));
        }
    }
}

public sealed record NtpOptions
{
    public int Port { get; init; } = 123;

    public int Samples { get; init; } = 4;

    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(2);

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);
}

/// <summary>
/// NTP Time Checker (D-078): SNTP-style client queries; compares the local clock with servers and never changes it.
/// Each request carries a random transmit nonce; replies whose origin does not match are ignored. A Kiss-o'-Death
/// stops further queries to that server.
/// </summary>
public static class NtpChecker
{
    public const int MaxServers = 8;
    public const int MaxSamples = 8;

    /// <summary>Clock used for T1 (tests inject a skewed clock); T4 = T1 + monotonic elapsed time.</summary>
    public static async Task<NtpServerResult> QueryAsync(string server, NtpOptions o, Action<NtpSample>? onSample, CancellationToken ct, Func<DateTime>? clock = null)
    {
        ArgumentNullException.ThrowIfNull(o);
        clock ??= () => DateTime.UtcNow;
        var name = (server ?? "").Trim();
        var samples = new List<NtpSample>();
        IPAddress address;
        try
        {
            if (!IPAddress.TryParse(name.Trim('[', ']'), out address!))
            {
                var all = await Dns.GetHostAddressesAsync(name, ct).ConfigureAwait(false);
                address = all.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? all.FirstOrDefault()
                          ?? throw new SocketException((int)SocketError.HostNotFound);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new NtpServerResult(name, "", [Fail(NtpOutcome.Cancelled, "Cancelled.", clock())]);
        }
        catch (SocketException ex)
        {
            return new NtpServerResult(name, "", [Fail(NtpOutcome.DnsFailure, $"{ex.SocketErrorCode}: the name could not be resolved.", clock())]);
        }

        var count = Math.Clamp(o.Samples, 1, MaxSamples);
        using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(new IPEndPoint(address, o.Port), ct).ConfigureAwait(false); // connected: only datagrams from this endpoint are delivered
        var buffer = new byte[512];
        for (var i = 0; i < count; i++)
        {
            if (i > 0)
            {
                try
                {
                    await Task.Delay(o.Interval, ct).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }

            var sample = await OneAsync(socket, buffer, o.Timeout, clock, ct).ConfigureAwait(false);
            samples.Add(sample);
            onSample?.Invoke(sample);
            if (sample.Outcome is NtpOutcome.KissOfDeath or NtpOutcome.Cancelled or NtpOutcome.Unreachable) break;
        }

        return new NtpServerResult(name, address.ToString(), samples);
    }

    private static NtpSample Fail(NtpOutcome o, string detail, DateTime t1, int ignored = 0, NtpPacket? p = null) => new(o, detail, p, t1, null, null, null, null, null, ignored);

    private static async Task<NtpSample> OneAsync(Socket socket, byte[] buffer, TimeSpan timeout, Func<DateTime> clock, CancellationToken ct)
    {
        var nonce = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        var request = NtpPacket.Request(nonce);
        var ignored = 0;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var t1 = clock();
        var sw = Stopwatch.StartNew();
        try
        {
            await socket.SendAsync(request, SocketFlags.None, cts.Token).ConfigureAwait(false);
            while (true)
            {
                var n = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
                var elapsed = sw.Elapsed;
                var p = NtpPacket.TryParse(buffer.AsSpan(0, n));
                if (p is null || p.Origin != nonce)
                {
                    ignored++; // not an answer to this request: keep waiting until the timeout
                    continue;
                }

                if (p.Problem(nonce) is { } invalid) return Fail(NtpOutcome.Invalid, "Unusable reply: " + invalid + ".", t1, ignored, p);
                if (p.IsKissOfDeath)
                {
                    var meaning = p.KissCode switch
                    {
                        "RATE" => "the server asks for fewer requests; no further queries are sent to it now",
                        "DENY" or "RSTR" => "the server refuses access to this client",
                        "INIT" or "STEP" => "the server is not synchronized yet",
                        _ => "the server will not answer this request",
                    };
                    return Fail(NtpOutcome.KissOfDeath, $"Kiss-o'-Death {p.KissCode}: {meaning}.", t1, ignored, p);
                }

                var t4 = t1 + elapsed;
                var t2 = NtpTime.ToDateTime(p.Receive, t1);
                var t3 = NtpTime.ToDateTime(p.Transmit, t1);
                var detail = p.Leap == NtpLeap.Unsynchronized ? "The server reports itself unsynchronized (leap indicator 3); its time may be wrong." : "";
                var delay = NtpMath.Delay(t1, t2, t3, t4);
                if (delay < TimeSpan.Zero) detail = (detail + " Negative round-trip delay: the server's timestamps are inconsistent.").Trim();
                return new NtpSample(p.Leap == NtpLeap.Unsynchronized ? NtpOutcome.Invalid : NtpOutcome.Ok, detail, p, t1, t2, t3, t4, NtpMath.Offset(t1, t2, t3, t4), delay, ignored);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Fail(NtpOutcome.Cancelled, "Cancelled.", t1, ignored);
        }
        catch (OperationCanceledException)
        {
            return Fail(NtpOutcome.Timeout, string.Create(CultureInfo.InvariantCulture, $"No valid reply within {timeout.TotalSeconds:0.#} s")
                                            + (ignored > 0 ? string.Create(CultureInfo.InvariantCulture, $" ({ignored} non-matching datagram(s) ignored).") : "."), t1, ignored);
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused or SocketError.HostUnreachable or SocketError.NetworkUnreachable)
        {
            return Fail(NtpOutcome.Unreachable, ex.SocketErrorCode == SocketError.ConnectionReset ? "Port unreachable: no NTP service answers on this address." : ex.SocketErrorCode.ToString(), t1, ignored);
        }
    }

    public static string Report(IEnumerable<NtpServerResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine("NTP check — the local clock was only compared, never changed.");
        foreach (var r in results)
        {
            sb.AppendLine();
            sb.AppendLine(c, $"== {r.Server}{(r.Address.Length > 0 && r.Address != r.Server ? " (" + r.Address + ")" : "")} ==");
            if (r.Best is { } best)
            {
                var p = best.Packet!;
                sb.AppendLine(c, $"Offset: {best.Offset!.Value.TotalMilliseconds:+0.000;-0.000} ms — {NtpMath.Describe(best.Offset.Value)} (lowest-delay sample)");
                sb.Append(c, $"Round-trip delay: {best.Delay!.Value.TotalMilliseconds:0.000} ms");
                if (r.Jitter is { } j) sb.Append(c, $"; jitter {j.TotalMilliseconds:0.000} ms over {r.Good.Count} samples");
                sb.AppendLine();
                sb.AppendLine(c, $"Stratum {p.Stratum}, reference {p.ReferenceId}, version {p.Version}, leap {p.Leap}, precision 2^{p.Precision} s");
                sb.AppendLine(c, $"Root delay {p.RootDelay.TotalMilliseconds:0.###} ms, root dispersion {p.RootDispersion.TotalMilliseconds:0.###} ms");
                sb.AppendLine(c, $"Server reference time: {NtpTime.ToDateTime(p.Reference, best.T1):yyyy-MM-dd HH:mm:ss.fff} UTC");
            }

            foreach (var (s, i) in r.Samples.Select((s, i) => (s, i + 1)))
            {
                sb.Append(c, $"  #{i} {s.Outcome}");
                if (s.Offset is { } off) sb.Append(c, $" offset {off.TotalMilliseconds:+0.000;-0.000} ms, delay {s.Delay!.Value.TotalMilliseconds:0.000} ms");
                if (s.T2 is { } t2) sb.Append(c, $" (T1 {s.T1:HH:mm:ss.ffffff}, T2 {t2:HH:mm:ss.ffffff}, T3 {s.T3:HH:mm:ss.ffffff}, T4 {s.T4:HH:mm:ss.ffffff})");
                if (s.Detail.Length > 0) sb.Append(" — ").Append(s.Detail);
                sb.AppendLine();
            }
        }

        return sb.ToString();
    }
}
