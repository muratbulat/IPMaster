using System.Net;
using System.Net.Sockets;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

public class NetToolsSyslogParserTests
{
    private static readonly DateTime Received = new(2026, 11, 17, 9, 0, 0, DateTimeKind.Utc);

    private static SyslogMessage P(string s) => SyslogParser.Parse(Encoding.UTF8.GetBytes(s), Received, "192.0.2.10", "UDP");

    [Fact]
    public void Rfc5424_with_structured_data_and_bom()
    {
        var m = P("<165>1 2026-11-17T08:59:58.123+01:00 router-1 sshd 4711 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\\\"lication\" note=\"a\\]b\"][x@1 k=\"v\"] ﻿Login ok");
        Assert.Equal(SyslogFormat.Rfc5424, m.Format);
        Assert.Equal((20, 5), (m.Facility, m.Severity)); // local4.notice
        Assert.Equal("local4", m.FacilityName);
        Assert.Equal("Notice", m.SeverityName);
        Assert.Equal(new DateTimeOffset(2026, 11, 17, 8, 59, 58, 123, TimeSpan.FromHours(1)), m.Timestamp);
        Assert.Equal(("router-1", "sshd", "4711", "ID47"), (m.Host, m.AppName, m.ProcId, m.MsgId));
        Assert.Equal("[exampleSDID@32473 iut=\"3\" eventSource=\"App\\\"lication\" note=\"a\\]b\"][x@1 k=\"v\"]", m.StructuredData);
        Assert.Equal("Login ok", m.Message);
    }

    [Fact]
    public void Rfc5424_nil_values_and_no_message()
    {
        var m = P("<34>1 - - - - - -");
        Assert.Equal(SyslogFormat.Rfc5424, m.Format);
        Assert.Null(m.Timestamp);
        Assert.Equal(("", "", "", "", "", ""), (m.Host, m.AppName, m.ProcId, m.MsgId, m.StructuredData, m.Message));
        Assert.Equal((4, 2), (m.Facility, m.Severity));
    }

    [Fact]
    public void Rfc3164_bsd_format_with_tag_and_pid()
    {
        var m = P("<13>Nov  7 08:15:02 fw01 kernel[123]: DROP IN=eth0 SRC=192.0.2.1");
        Assert.Equal(SyslogFormat.Rfc3164, m.Format);
        Assert.Equal(new DateTime(2026, 11, 7, 8, 15, 2), m.Timestamp!.Value.DateTime);
        Assert.Equal(("fw01", "kernel", "123"), (m.Host, m.AppName, m.ProcId));
        Assert.Equal("DROP IN=eth0 SRC=192.0.2.1", m.Message);

        var noHost = P("<30>Dec 31 23:59:59 cron: job done");
        Assert.Equal(2025, noHost.Timestamp!.Value.Year); // December received in November: more than a month ahead, so last year
        Assert.Equal(("", "cron"), (noHost.Host, noHost.AppName));
    }

    [Fact]
    public void Missing_or_invalid_priority_and_unknown_formats_keep_the_raw_text()
    {
        var a = P("just some text");
        Assert.True(a.PriorityMissing);
        Assert.Equal((1, 5), (a.Facility, a.Severity));
        Assert.Equal(SyslogFormat.Unknown, a.Format);
        Assert.Equal("just some text", a.Message);
        Assert.True(P("<192>1 - - - - - -").PriorityMissing); // > 191
        Assert.True(P("<013>text").PriorityMissing); // leading zero
        Assert.Equal(SyslogFormat.Unknown, P("<14>1 not-a-time host app - - -").Format);
        Assert.Equal(SyslogFormat.Unknown, P("<14>1 - h a p m [unterminated").Format);
    }
}

public class NetToolsSyslogFramingTests
{
    private static List<string> Feed(SyslogStreamDecoder d, params string[] chunks) =>
        chunks.SelectMany(c => d.Push(Encoding.UTF8.GetBytes(c))).Select(Encoding.UTF8.GetString).ToList();

    [Fact]
    public void Octet_counting_across_chunk_boundaries()
    {
        var d = new SyslogStreamDecoder();
        Assert.Equal(["<13>hello w"], Feed(d, "11 <13>hel", "lo w"));
        Assert.Equal(0, d.Pending);
        var e = new SyslogStreamDecoder();
        Assert.Equal(["<13>hello", "<13>a\nb"], Feed(e, "9 <13>hel", "lo7 <13>a\nb"));
        Assert.Equal(0, e.Pending);
    }

    [Fact]
    public void Newline_framing_with_crlf_nul_and_empty_lines()
    {
        var d = new SyslogStreamDecoder();
        Assert.Equal(["<13>one", "<13>two", "<13>three", "42x starts with a digit"], Feed(d, "<13>one\r\n\n<13>tw", "o\0<13>three\n", "42x starts with a digit\n"));
        Assert.Equal(0, d.Pending);
    }

    [Fact]
    public void Oversized_frames_are_skipped_and_counted_in_both_framings()
    {
        var d = new SyslogStreamDecoder(maxFrameBytes: 10);
        Assert.Equal(["<13>ok"], Feed(d, "20 <13>1234567890123456", "6 <13>ok"));
        Assert.Equal(1, d.Oversized);
        Assert.Equal(["<13>fine"], Feed(d, "<13>this line is too long\n<13>fine\n"));
        Assert.Equal(2, d.Oversized);
        Assert.True(d.Pending <= 10);
    }
}

public class NetToolsSyslogReceiverTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static SyslogListenOptions Loopback(int capacity = 1000) => new() { Address = IPAddress.Loopback, UdpPort = 0, TcpPort = 0, QueueCapacity = capacity };

    private static async Task<List<SyslogMessage>> Take(SyslogReceiver r, int count)
    {
        var list = new List<SyslogMessage>();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(TimeSpan.FromSeconds(5));
        while (list.Count < count) list.Add(await r.Messages.ReadAsync(cts.Token));
        return list;
    }

    [Fact]
    public async Task Udp_and_tcp_messages_arrive_parsed_with_source_and_transport()
    {
        await using var r = SyslogReceiver.Start(Loopback());
        using (var udp = new UdpClient())
        {
            await udp.SendAsync(Encoding.UTF8.GetBytes("<11>1 2026-11-17T09:00:00Z sw1 app - - - over udp"), new IPEndPoint(IPAddress.Loopback, r.UdpPort), Ct);
        }

        using (var tcp = new TcpClient())
        {
            await tcp.ConnectAsync(IPAddress.Loopback, r.TcpPort, Ct);
            var s = tcp.GetStream();
            var octet = "<11>1 - sw2 app - - - tcp1";
            await s.WriteAsync(Encoding.UTF8.GetBytes($"{Encoding.UTF8.GetByteCount(octet)} {octet}<11>Nov 17 09:00:00 sw2 app: tcp2\n"), Ct);
        }

        var got = await Take(r, 3);
        Assert.Contains(got, m => m is { Transport: "UDP", Host: "sw1", Message: "over udp", Source: "127.0.0.1" });
        Assert.Contains(got, m => m is { Transport: "TCP", Host: "sw2", Message: "tcp1", Format: SyslogFormat.Rfc5424 });
        Assert.Contains(got, m => m is { Transport: "TCP", Message: "tcp2", Format: SyslogFormat.Rfc3164 });
        Assert.Equal(3, r.Stats.Received);
    }

    [Fact]
    public async Task Full_queue_drops_and_counts_instead_of_growing()
    {
        await using var r = SyslogReceiver.Start(Loopback(capacity: 5) with { EnableTcp = false });
        using var udp = new UdpClient();
        for (var i = 0; i < 20; i++) await udp.SendAsync(Encoding.UTF8.GetBytes($"<14>message {i}"), new IPEndPoint(IPAddress.Loopback, r.UdpPort), Ct);
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (r.Stats.Received < 20 && DateTime.UtcNow < deadline) await Task.Delay(20, Ct);
        Assert.Equal(20, r.Stats.Received);
        Assert.Equal(15, r.Stats.Dropped);
        Assert.Equal(5, r.Messages.Count);
    }

    [Fact]
    public async Task Stop_releases_both_ports_immediately()
    {
        var r = SyslogReceiver.Start(Loopback());
        var (u, t) = (r.UdpPort, r.TcpPort);
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, t, Ct); // an open connection must not keep the port
        await r.DisposeAsync();
        await using var again = SyslogReceiver.Start(new SyslogListenOptions { Address = IPAddress.Loopback, UdpPort = u, TcpPort = t });
        Assert.Equal((u, t), (again.UdpPort, again.TcpPort));
    }

    [Fact]
    public async Task Port_in_use_fails_with_nothing_left_bound()
    {
        using var blocker = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)blocker.Client.LocalEndPoint!).Port;
        var tcpProbe = new TcpListener(IPAddress.Loopback, 0);
        tcpProbe.Start();
        var tcpPort = ((IPEndPoint)tcpProbe.LocalEndpoint).Port;
        tcpProbe.Stop();
        var ex = Assert.Throws<SocketException>(() => SyslogReceiver.Start(new SyslogListenOptions { Address = IPAddress.Loopback, UdpPort = port, TcpPort = tcpPort }));
        Assert.Equal(SocketError.AddressAlreadyInUse, ex.SocketErrorCode);
        await using var tcpOnly = SyslogReceiver.Start(new SyslogListenOptions { Address = IPAddress.Loopback, EnableUdp = false, TcpPort = tcpPort }); // TCP was not left bound
        Assert.Equal(tcpPort, tcpOnly.TcpPort);
    }

    [Fact]
    public async Task Tcp_connections_beyond_the_limit_are_rejected()
    {
        await using var r = SyslogReceiver.Start(Loopback() with { EnableUdp = false, MaxTcpConnections = 2 });
        var clients = new List<TcpClient>();
        try
        {
            for (var i = 0; i < 4; i++)
            {
                var c = new TcpClient();
                await c.ConnectAsync(IPAddress.Loopback, r.TcpPort, Ct);
                clients.Add(c);
            }

            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (r.Stats.RejectedConnections < 2 && DateTime.UtcNow < deadline) await Task.Delay(20, Ct);
            Assert.Equal(2, r.Stats.RejectedConnections);
            Assert.Equal(2, r.Stats.TcpConnections);
        }
        finally
        {
            clients.ForEach(c => c.Dispose());
        }
    }
}

public class NetToolsSyslogYearTests
{
    [Fact]
    public void Bsd_year_wraps_at_new_year_in_both_directions()
    {
        var newYearsEve = SyslogParser.Parse("<13>Jan  1 00:00:05 h a: x"u8, new DateTime(2026, 12, 31, 23, 59, 0, DateTimeKind.Utc), "s", "UDP");
        Assert.Equal(2027, newYearsEve.Timestamp!.Value.Year); // sender's clock already in the new year
        var newYearsDay = SyslogParser.Parse("<13>Dec 31 23:59:55 h a: x"u8, new DateTime(2027, 1, 1, 0, 0, 3, DateTimeKind.Utc), "s", "UDP");
        Assert.Equal(2026, newYearsDay.Timestamp!.Value.Year);
    }
}
