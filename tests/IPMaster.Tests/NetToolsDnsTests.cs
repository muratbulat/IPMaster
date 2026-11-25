using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Scripted DNS server on 127.0.0.1 (UDP and TCP, same port). Test-only.</summary>
internal sealed class DnsFixture : IAsyncDisposable
{
    public delegate byte[]? Responder(ushort id, string name, ushort type, bool tcp);

    private readonly Socket _udp = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    private readonly TcpListener _tcp;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _udpLoop;
    private readonly Task _tcpLoop;

    public DnsFixture(Responder responder)
    {
        Respond = responder;
        _udp.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        _tcp = new TcpListener(IPAddress.Loopback, ((IPEndPoint)_udp.LocalEndPoint!).Port);
        _tcp.Start();
        _udpLoop = Task.Run(UdpLoopAsync);
        _tcpLoop = Task.Run(TcpLoopAsync);
    }

    public Responder Respond { get; }

    public IPEndPoint EndPoint => (IPEndPoint)_udp.LocalEndPoint!;

    public int UdpQueries;
    public int TcpQueries;

    private async Task UdpLoopAsync()
    {
        var buf = new byte[1024];
        while (!_cts.IsCancellationRequested)
        {
            SocketReceiveFromResult r;
            try
            {
                r = await _udp.ReceiveFromAsync(buf, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), _cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            Interlocked.Increment(ref UdpQueries);
            var (id, name, type) = ParseQuery(buf.AsSpan(0, r.ReceivedBytes));
            if (Respond(id, name, type, false) is { } reply) await _udp.SendToAsync(reply, SocketFlags.None, r.RemoteEndPoint);
        }
    }

    private async Task TcpLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient c;
            try
            {
                c = await _tcp.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            using (c)
            {
                Interlocked.Increment(ref TcpQueries);
                var s = c.GetStream();
                var len = new byte[2];
                await s.ReadExactlyAsync(len);
                var body = new byte[BinaryPrimitives.ReadUInt16BigEndian(len)];
                await s.ReadExactlyAsync(body);
                var (id, name, type) = ParseQuery(body);
                if (Respond(id, name, type, true) is { } reply)
                {
                    var framed = new byte[reply.Length + 2];
                    BinaryPrimitives.WriteUInt16BigEndian(framed, (ushort)reply.Length);
                    reply.CopyTo(framed, 2);
                    await s.WriteAsync(framed);
                }
            }
        }
    }

    private static (ushort Id, string Name, ushort Type) ParseQuery(ReadOnlySpan<byte> q)
    {
        var id = BinaryPrimitives.ReadUInt16BigEndian(q);
        var arr = q.ToArray();
        var pos = 12;
        var name = DnsWire.ReadName(arr, ref pos);
        return (id, name.TrimEnd('.'), BinaryPrimitives.ReadUInt16BigEndian(arr.AsSpan(pos)));
    }

    /// <summary>Encodes a reply; answer owners use a compression pointer to the question name (offset 12).</summary>
    public static byte[] Reply(ushort id, string qname, ushort qtype, int rcode, bool tc, params (ushort Type, uint Ttl, byte[] Data)[] answers)
    {
        var b = new List<byte>();
        void U16(int v)
        {
            b.Add((byte)(v >> 8));
            b.Add((byte)v);
        }

        U16(id);
        U16(0x8000 | 0x0100 | 0x0080 | (tc ? 0x0200 : 0) | rcode);
        U16(1);
        U16(answers.Length);
        U16(0);
        U16(0);
        DnsWire.WriteName(b, qname);
        U16(qtype);
        U16(1);
        foreach (var (type, ttl, data) in answers)
        {
            U16(0xC00C);
            U16(type);
            U16(1);
            b.Add((byte)(ttl >> 24));
            b.Add((byte)(ttl >> 16));
            b.Add((byte)(ttl >> 8));
            b.Add((byte)ttl);
            U16(data.Length);
            b.AddRange(data);
        }

        return [.. b];
    }

    public static byte[] Name(string n)
    {
        var l = new List<byte>();
        DnsWire.WriteName(l, n);
        return [.. l];
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _udp.Dispose();
        _tcp.Stop();
        await Task.WhenAll(_udpLoop, _tcpLoop);
    }
}

public class NetToolsDnsTests
{
    private static byte[] Txt(string s) => [(byte)s.Length, .. Encoding.ASCII.GetBytes(s)];

    private static readonly DnsQueryOptions Fast = new() { Timeout = TimeSpan.FromMilliseconds(400), Retries = 1 };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task A_record_over_udp_with_compression()
    {
        await using var f = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, 0, false, (1, 300, [192, 0, 2, 7]), (1, 300, [192, 0, 2, 8])));
        var r = await DnsClient.QueryAsync(f.EndPoint, "www.lab.test", (ushort)DnsType.A, Fast, Ct);
        Assert.Equal(DnsOutcome.Reply, r.Outcome);
        Assert.Equal("UDP", r.Transport);
        Assert.Equal(["192.0.2.7", "192.0.2.8"], r.Records.Select(x => x.Data));
        Assert.Equal("www.lab.test.", r.Records[0].Name);
        Assert.Equal(300u, r.Records[0].Ttl);
        Assert.Contains("rd", r.Message!.Flags, StringComparison.Ordinal);
        Assert.Contains("ra", r.Message.Flags, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Truncated_udp_reply_falls_back_to_tcp()
    {
        await using var f = new DnsFixture((id, n, t, tcp) => tcp
            ? DnsFixture.Reply(id, n, t, 0, false, Enumerable.Range(1, 40).Select(i => ((ushort)16, 60u, Txt("record-" + i.ToString("D3", System.Globalization.CultureInfo.InvariantCulture) + "-padding-x"))).ToArray())
            : DnsFixture.Reply(id, n, t, 0, true));
        var r = await DnsClient.QueryAsync(f.EndPoint, "big.lab.test", (ushort)DnsType.TXT, Fast, Ct);
        Assert.True(r.FellBackToTcp, r.Outcome + ": " + r.Detail);
        Assert.StartsWith("TCP", r.Transport, StringComparison.Ordinal);
        Assert.Equal(40, r.Records.Count);
        Assert.Equal(1, f.TcpQueries);

        var noFallback = await DnsClient.QueryAsync(f.EndPoint, "big.lab.test", (ushort)DnsType.TXT, Fast with { Transport = DnsTransport.Udp }, Ct);
        Assert.True(noFallback.Message!.Truncated);
        Assert.Contains("TCP fallback is off", noFallback.Detail, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(3, "NXDOMAIN")]
    [InlineData(2, "SERVFAIL")]
    [InlineData(5, "REFUSED")]
    [InlineData(0, "NOERROR (no data)")]
    public async Task Response_codes_are_distinguished(int rcode, string status)
    {
        await using var f = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, rcode, false));
        var r = await DnsClient.QueryAsync(f.EndPoint, "x.lab.test", (ushort)DnsType.A, Fast, Ct);
        Assert.Equal(DnsOutcome.Reply, r.Outcome);
        Assert.Equal(status, r.Status);
    }

    [Fact]
    public async Task Silent_server_is_a_timeout_after_retries()
    {
        await using var f = new DnsFixture((_, _, _, _) => null);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await DnsClient.QueryAsync(f.EndPoint, "x.lab.test", (ushort)DnsType.A, Fast with { Retries = 2 }, Ct);
        Assert.Equal(DnsOutcome.Timeout, r.Outcome);
        Assert.Equal(3, f.UdpQueries);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Cancellation_is_reported_as_cancelled()
    {
        await using var f = new DnsFixture((_, _, _, _) => null);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(150);
        var r = await DnsClient.QueryAsync(f.EndPoint, "x.lab.test", (ushort)DnsType.A, Fast with { Timeout = TimeSpan.FromSeconds(10) }, cts.Token);
        Assert.Equal(DnsOutcome.Cancelled, r.Outcome);
    }

    [Fact]
    public async Task Reply_with_another_id_is_ignored()
    {
        await using var f = new DnsFixture((id, n, t, _) => DnsFixture.Reply((ushort)(id ^ 0xFFFF), n, t, 0, false, (1, 1, [10, 0, 0, 1])));
        var r = await DnsClient.QueryAsync(f.EndPoint, "x.lab.test", (ushort)DnsType.A, Fast with { Retries = 0 }, Ct);
        Assert.Equal(DnsOutcome.Timeout, r.Outcome);
    }

    [Fact]
    public async Task Cname_chain_is_followed_and_loops_are_detected()
    {
        await using var chain = new DnsFixture((id, n, t, _) => n switch
        {
            "a.lab.test" => DnsFixture.Reply(id, n, t, 0, false, (5, 60, DnsFixture.Name("b.lab.test"))),
            "b.lab.test" => DnsFixture.Reply(id, n, t, 0, false, (1, 60, [192, 0, 2, 9])),
            _ => DnsFixture.Reply(id, n, t, 3, false),
        });
        var (steps, problem) = await DnsClient.ResolveAsync(chain.EndPoint, "a.lab.test", (ushort)DnsType.A, Fast, Ct);
        Assert.Null(problem);
        Assert.Equal(2, steps.Count);
        Assert.Equal("192.0.2.9", steps[^1].Records.Single().Data);

        await using var loop = new DnsFixture((id, n, t, _) => n == "x.lab.test"
            ? DnsFixture.Reply(id, n, t, 0, false, (5, 60, DnsFixture.Name("y.lab.test")))
            : DnsFixture.Reply(id, n, t, 0, false, (5, 60, DnsFixture.Name("x.lab.test"))));
        var (_, loopProblem) = await DnsClient.ResolveAsync(loop.EndPoint, "x.lab.test", (ushort)DnsType.A, Fast, Ct);
        Assert.Contains("loop", loopProblem, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Record_types_are_formatted()
    {
        byte[] U16(int v) => [(byte)(v >> 8), (byte)v];
        var mx = DnsFixture.Reply(1, "lab.test", 15, 0, false,
            (15, 60, [.. U16(10), .. DnsFixture.Name("mail.lab.test")]),
            (33, 60, [.. U16(0), .. U16(5), .. U16(5060), .. DnsFixture.Name("sip.lab.test")]),
            (6, 60, [.. DnsFixture.Name("ns1.lab.test"), .. DnsFixture.Name("hostmaster.lab.test"), 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5]),
            (257, 60, [0, 5, .. Encoding.ASCII.GetBytes("issue"), .. Encoding.ASCII.GetBytes("ca.example")]),
            (28, 60, [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            (99, 60, [1, 2]));
        var m = DnsWire.Parse(mx);
        Assert.Equal("10 mail.lab.test.", m.Answers[0].Data);
        Assert.Equal("0 5 5060 sip.lab.test.", m.Answers[1].Data);
        Assert.Equal("ns1.lab.test. hostmaster.lab.test. 1 2 3 4 5", m.Answers[2].Data);
        Assert.Equal("0 issue \"ca.example\"", m.Answers[3].Data);
        Assert.Equal("2001:db8::1", m.Answers[4].Data);
        Assert.Equal(@"\# 2 0102", m.Answers[5].Data);
    }

    [Fact]
    public void Compression_pointer_loops_and_truncation_are_rejected()
    {
        var header = new byte[] { 0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0 };
        byte[] selfPointer = [.. header, 0xC0, 12, 0, 1, 0, 1];
        Assert.False(DnsWire.TryParse(selfPointer, out _, out var e1));
        Assert.Contains("pointer", e1, StringComparison.Ordinal);
        Assert.False(DnsWire.TryParse(header.AsSpan(0, 8), out _, out _));
        byte[] shortLabel = [.. header, 5, (byte)'a', 0];
        Assert.False(DnsWire.TryParse(shortLabel, out _, out _));
    }

    [Fact]
    public void Ptr_names_are_generated()
    {
        Assert.Equal("25.10.168.192.in-addr.arpa.", DnsWire.PtrName(IPAddress.Parse("192.168.10.25")));
        Assert.Equal("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", DnsWire.PtrName(IPAddress.Parse("2001:db8::1")));
    }

    [Fact]
    public void Server_comparison_ignores_order_and_reports_ttl_separately()
    {
        DnsRecord A(string ip, uint ttl) => new("www.lab.test.", 1, 1, ttl, ip);
        Assert.Equal(RecordSetComparison.Identical, DnsCompare.Compare([A("192.0.2.1", 60), A("192.0.2.2", 60)], [A("192.0.2.2", 60), A("192.0.2.1", 60)]).Result);
        var ttl = DnsCompare.Compare([A("192.0.2.1", 60)], [A("192.0.2.1", 30)]);
        Assert.Equal(RecordSetComparison.SameRecordsDifferentTtl, ttl.Result);
        Assert.Single(ttl.TtlDifferences);
        var diff = DnsCompare.Compare([A("192.0.2.1", 60)], [A("192.0.2.3", 60)]);
        Assert.Equal(RecordSetComparison.Different, diff.Result);
        Assert.Single(diff.OnlyInFirst);
        Assert.Single(diff.OnlyInSecond);
    }

    [Fact]
    public void Forward_reverse_classification()
    {
        var fwd = new Dictionary<string, (int?, IReadOnlyList<string>)>
        {
            ["host.lab.test."] = (0, ["192.0.2.7"]),
            ["other.lab.test."] = (0, ["192.0.2.99"]),
            ["broken.lab.test."] = (null, []),
        };
        Assert.Equal(ReverseCheck.Confirmed, DnsForwardReverse.Classify("192.0.2.7", 0, ["host.lab.test."], fwd).Result);
        Assert.Equal(ReverseCheck.Mismatch, DnsForwardReverse.Classify("192.0.2.7", 0, ["other.lab.test."], fwd).Result);
        Assert.Equal(ReverseCheck.MissingPtr, DnsForwardReverse.Classify("192.0.2.7", 3, [], fwd).Result);
        Assert.Equal(ReverseCheck.Inconclusive, DnsForwardReverse.Classify("192.0.2.7", null, [], fwd).Result);
        Assert.Equal(ReverseCheck.Inconclusive, DnsForwardReverse.Classify("192.0.2.7", 0, ["broken.lab.test."], fwd).Result);
    }
}

public class NetToolsDnsDiagnosticsTests
{
    private static readonly DnsQueryOptions Fast = new() { Timeout = TimeSpan.FromMilliseconds(400), Retries = 0 };

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Theory]
    [InlineData("192.0.2.53", "192.0.2.53:53")]
    [InlineData("192.0.2.53:5353", "192.0.2.53:5353")]
    [InlineData("2001:db8::53", "[2001:db8::53]:53")]
    [InlineData("[2001:db8::53]:5353", "[2001:db8::53]:5353")]
    public void Server_lists_parse_with_default_port(string text, string expected)
    {
        Assert.True(DnsDiagnostics.TryParseServers(text, 53, out var s, out var e), e);
        Assert.Equal(expected, s.Single().ToString());
    }

    [Fact]
    public void Bad_server_entry_is_reported()
    {
        Assert.False(DnsDiagnostics.TryParseServers("192.0.2.53, dns.example", 53, out _, out var e));
        Assert.Contains("dns.example", e, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Compare_servers_reports_differences_and_ttl()
    {
        await using var a = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, 0, false, (1, 300, [192, 0, 2, 1]), (1, 300, [192, 0, 2, 2])));
        await using var b = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, 0, false, (1, 60, [192, 0, 2, 2]), (1, 60, [192, 0, 2, 1])));
        await using var c = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, 0, false, (1, 300, [192, 0, 2, 9])));
        var (report, summary) = await DnsDiagnostics.CompareAsync("www.lab.test", DnsType.A, [a.EndPoint, b.EndPoint, c.EndPoint], Fast, Ct);
        Assert.Contains("same records, different TTLs", report, StringComparison.Ordinal);
        Assert.Contains("different records", report, StringComparison.Ordinal);
        Assert.Contains("1 server(s) differ", summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Forward_reverse_check_confirms_matching_ptr()
    {
        await using var f = new DnsFixture((id, n, t, _) => (n, t) switch
        {
            ("host.lab.test", 1) => DnsFixture.Reply(id, n, t, 0, false, (1, 60, [192, 0, 2, 7])),
            ("host.lab.test", 28) => DnsFixture.Reply(id, n, t, 0, false),
            ("7.2.0.192.in-addr.arpa", 12) => DnsFixture.Reply(id, n, t, 0, false, (12, 60, DnsFixture.Name("host.lab.test"))),
            _ => DnsFixture.Reply(id, n, t, 3, false),
        });
        var (report, summary) = await DnsDiagnostics.ForwardReverseAsync("host.lab.test", f.EndPoint, Fast, Ct);
        Assert.Equal("1 Confirmed", summary);
        Assert.Contains("192.0.2.7: Confirmed", report, StringComparison.Ordinal);
    }

    [Fact]
    public void Auto_type_generates_ptr_names()
    {
        Assert.Equal(("7.2.0.192.in-addr.arpa.", (ushort)DnsType.PTR), DnsDiagnostics.Normalize("192.0.2.7", null));
        Assert.Equal(("www.lab.test", (ushort)DnsType.MX), DnsDiagnostics.Normalize("www.lab.test", DnsType.MX));
    }
}
