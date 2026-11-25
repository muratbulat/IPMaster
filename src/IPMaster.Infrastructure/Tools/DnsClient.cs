using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

public enum DnsTransport
{
    UdpWithTcpFallback,
    Udp,
    Tcp,
}

public sealed record DnsQueryOptions
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Extra UDP attempts after a timeout (0–5). Never more than one TCP attempt.</summary>
    public int Retries { get; init; } = 1;

    public bool Recursion { get; init; } = true;

    public DnsTransport Transport { get; init; } = DnsTransport.UdpWithTcpFallback;
}

public enum DnsOutcome
{
    /// <summary>A reply arrived; look at its RCODE (NOERROR may still be empty).</summary>
    Reply,
    Timeout,
    NetworkError,
    Malformed,
    Cancelled,
}

public sealed record DnsQueryResult(IPEndPoint Server, string Name, ushort Type, DnsOutcome Outcome, DnsMessage? Message, string Transport,
    TimeSpan Duration, string Detail, bool FellBackToTcp)
{
    /// <summary>Answers of the requested type (after CNAME following, see <see cref="DnsClient.ResolveAsync"/>).</summary>
    public IReadOnlyList<DnsRecord> Records => Message?.Answers.Where(r => r.Type == Type).ToList() ?? [];

    /// <summary>NXDOMAIN, empty NOERROR, SERVFAIL, REFUSED… or the transport outcome.</summary>
    public string Status => Outcome switch
    {
        DnsOutcome.Reply when Message!.Rcode == 0 && Message.Answers.Count == 0 => "NOERROR (no data)",
        DnsOutcome.Reply => Message!.RcodeName,
        DnsOutcome.Timeout => "TIMEOUT",
        DnsOutcome.Cancelled => "CANCELLED",
        DnsOutcome.Malformed => "MALFORMED REPLY",
        _ => "NETWORK ERROR",
    };
}

/// <summary>
/// Direct DNS queries to a chosen server (D-073): UDP with retries on timeout, TCP when the reply is truncated (or on
/// request). The OS resolver (cache, hosts file, LLMNR) is separate: <see cref="OsResolveAsync"/>.
/// </summary>
public static class DnsClient
{
    public const int MaxCnameHops = 8;

    public static async Task<DnsQueryResult> QueryAsync(IPEndPoint server, string name, ushort type, DnsQueryOptions options, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(options);
        var sw = Stopwatch.StartNew();
        var id = (ushort)Random.Shared.Next(1, 65536);
        byte[] query;
        try
        {
            query = DnsWire.BuildQuery(id, name, type, options.Recursion);
        }
        catch (ArgumentException ex)
        {
            return new DnsQueryResult(server, name, type, DnsOutcome.Malformed, null, "", sw.Elapsed, ex.Message, false);
        }

        try
        {
            if (options.Transport == DnsTransport.Tcp)
            {
                var tcp = await TcpAsync(server, query, id, options.Timeout, ct).ConfigureAwait(false);
                return new DnsQueryResult(server, name, type, DnsOutcome.Reply, tcp, "TCP", sw.Elapsed, "", false);
            }

            DnsMessage? udp = null;
            for (var attempt = 0; attempt <= Math.Clamp(options.Retries, 0, 5) && udp is null; attempt++)
            {
                udp = await UdpAsync(server, query, id, name, type, options.Timeout, ct).ConfigureAwait(false);
            }

            if (udp is null) return new DnsQueryResult(server, name, type, DnsOutcome.Timeout, null, "UDP", sw.Elapsed, $"No reply within {options.Timeout.TotalSeconds:0.#} s ({Math.Clamp(options.Retries, 0, 5) + 1} attempt(s)).", false);
            if (udp.Truncated && options.Transport == DnsTransport.UdpWithTcpFallback)
            {
                var tcp = await TcpAsync(server, query, id, options.Timeout, ct).ConfigureAwait(false);
                return new DnsQueryResult(server, name, type, DnsOutcome.Reply, tcp, "TCP (after truncated UDP reply)", sw.Elapsed, "", true);
            }

            return new DnsQueryResult(server, name, type, DnsOutcome.Reply, udp, "UDP", sw.Elapsed, udp.Truncated ? "Reply truncated (TC); TCP fallback is off." : "", false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new DnsQueryResult(server, name, type, DnsOutcome.Cancelled, null, "", sw.Elapsed, "Cancelled.", false);
        }
        catch (TimeoutException ex)
        {
            return new DnsQueryResult(server, name, type, DnsOutcome.Timeout, null, "TCP", sw.Elapsed, ex.Message, false);
        }
        catch (FormatException ex)
        {
            return new DnsQueryResult(server, name, type, DnsOutcome.Malformed, null, "", sw.Elapsed, ex.Message, false);
        }
        catch (Exception ex) when (ex is SocketException or IOException)
        {
            return new DnsQueryResult(server, name, type, DnsOutcome.NetworkError, null, options.Transport == DnsTransport.Tcp ? "TCP" : "UDP", sw.Elapsed, ex is SocketException se ? $"{se.SocketErrorCode}: {se.Message}" : ex.Message, false);
        }
    }

    /// <summary>One UDP attempt: replies with another ID or question are ignored (spoofing / late replies); null on timeout.</summary>
    private static async Task<DnsMessage?> UdpAsync(IPEndPoint server, byte[] query, ushort id, string name, ushort type, TimeSpan timeout, CancellationToken ct)
    {
        using var socket = new Socket(server.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        await socket.ConnectAsync(server, ct).ConfigureAwait(false);
        await socket.SendAsync(query, SocketFlags.None, ct).ConfigureAwait(false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        var buffer = new byte[4096];
        while (true)
        {
            int n;
            try
            {
                n = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return null;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                throw new SocketException((int)SocketError.ConnectionRefused); // ICMP port unreachable: nothing listens there
            }

            if (!DnsWire.TryParse(buffer.AsSpan(0, n), out var m, out _) || m.Id != id || !m.IsResponse) continue;
            if (m.Questions.Count > 0 && (!string.Equals(m.Questions[0].Name.TrimEnd('.'), name.Trim().TrimEnd('.'), StringComparison.OrdinalIgnoreCase) || m.Questions[0].Type != type)) continue;
            return m;
        }
    }

    private static async Task<DnsMessage> TcpAsync(IPEndPoint server, byte[] query, ushort id, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        using var socket = new Socket(server.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(server, cts.Token).ConfigureAwait(false);
            var framed = new byte[query.Length + 2];
            BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)query.Length);
            query.CopyTo(framed, 2);
            await socket.SendAsync(framed, SocketFlags.None, cts.Token).ConfigureAwait(false);
            var len = new byte[2];
            await ReadExactAsync(socket, len, cts.Token).ConfigureAwait(false);
            var body = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
            await ReadExactAsync(socket, body, cts.Token).ConfigureAwait(false);
            var m = DnsWire.Parse(body);
            if (m.Id != id) throw new FormatException("TCP reply with a different query ID.");
            return m;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException($"No TCP reply within {timeout.TotalSeconds:0.#} s.");
        }
    }

    private static async Task ReadExactAsync(Socket s, byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await s.ReceiveAsync(buffer.AsMemory(read), SocketFlags.None, ct).ConfigureAwait(false);
            if (n == 0) throw new IOException("The server closed the TCP connection early.");
            read += n;
        }
    }

    /// <summary>
    /// Query that follows a CNAME chain when the answer has the alias but not the requested type (non-recursive or partial
    /// answers): at most <see cref="MaxCnameHops"/> extra queries, loops detected. Returns every step for the report.
    /// </summary>
    public static async Task<(IReadOnlyList<DnsQueryResult> Steps, string? ChainProblem)> ResolveAsync(IPEndPoint server, string name, ushort type, DnsQueryOptions options, CancellationToken ct)
    {
        var steps = new List<DnsQueryResult>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { name.Trim().TrimEnd('.') };
        var current = name;
        for (var hop = 0; hop <= MaxCnameHops; hop++)
        {
            var r = await QueryAsync(server, current, type, options, ct).ConfigureAwait(false);
            steps.Add(r);
            if (r.Outcome != DnsOutcome.Reply || r.Message!.Rcode != 0 || type == (ushort)DnsType.CNAME || r.Records.Count > 0) return (steps, null);
            // follow the last alias in the answer section
            var alias = r.Message.Answers.Where(a => a.Type == (ushort)DnsType.CNAME).Select(a => a.Data).LastOrDefault();
            if (alias is null) return (steps, null);
            var target = alias.TrimEnd('.');
            if (!seen.Add(target)) return (steps, $"CNAME loop: {target} was already visited.");
            current = target;
        }

        return (steps, $"CNAME chain longer than {MaxCnameHops} hops; stopped.");
    }

    /// <summary>DNS servers configured on the up interfaces (what the OS resolver would ask).</summary>
    public static IReadOnlyList<IPAddress> SystemServers()
    {
        try
        {
            return NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(n => n.GetIPProperties().DnsAddresses)
                .Where(a => !(a.IsIPv6SiteLocal && a.ToString().StartsWith("fec0:0:0:ffff", StringComparison.Ordinal))) // deprecated well-known placeholders
                .Distinct().ToList();
        }
        catch (NetworkInformationException)
        {
            return [];
        }
    }

    /// <summary>The operating system's resolver (cache, hosts file, suffix search, LLMNR/mDNS) — not a direct DNS query.</summary>
    public static async Task<(IReadOnlyList<IPAddress> Addresses, string Detail, TimeSpan Duration)> OsResolveAsync(string name, TimeSpan timeout, CancellationToken ct)
    {
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            var a = await Dns.GetHostAddressesAsync(name, cts.Token).ConfigureAwait(false);
            return (a, a.Length == 0 ? "No addresses." : "", sw.Elapsed);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ([], "Timeout (the OS resolver call may still finish in the background).", sw.Elapsed);
        }
        catch (SocketException ex)
        {
            return ([], $"{ex.SocketErrorCode}: {ex.Message}", sw.Elapsed);
        }
    }
}
