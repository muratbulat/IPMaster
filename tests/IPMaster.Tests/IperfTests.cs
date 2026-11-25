using System.Globalization;
using IPMaster.Core.Tools;
using IPMaster.Desktop.Views;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Synthetic iperf output shaped like iperf3 3.20 --json-stream / -J and iperf2 2.2.1 CSV (D-108).</summary>
internal static class IperfFixtures
{
    private static string F(double v) => v.ToString("R", CultureInfo.InvariantCulture);

    public static string Start(int streams, bool reverse = false, bool bidir = false, string protocol = "TCP") =>
        "{\"event\":\"start\",\"data\":{\"connected\":[{\"socket\":5,\"local_host\":\"192.0.2.10\",\"local_port\":50000,\"remote_host\":\"192.0.2.20\",\"remote_port\":5201}],\"version\":\"iperf 3.20\",\"test_start\":{\"protocol\":\"" + protocol + "\",\"num_streams\":" + streams.ToString(CultureInfo.InvariantCulture) + ",\"duration\":10,\"reverse\":" + (reverse ? "1" : "0") + ",\"bidir\":" + (bidir ? "1" : "0") + "}}}";

    public static string Sum(double start, double bps, bool sender, long? retr = null, bool udpRecv = false)
    {
        var bytes = (long)(bps / 8);
        var extra = (retr is { } r ? $",\"retransmits\":{r}" : "") + (udpRecv ? ",\"jitter_ms\":0.012,\"lost_packets\":3,\"packets\":100000,\"lost_percent\":0.003" : "");
        return $$"""{"start":{{F(start)}},"end":{{F(start + 1)}},"seconds":1,"bytes":{{bytes}},"bits_per_second":{{F(bps)}}{{extra}},"omitted":false,"sender":{{(sender ? "true" : "false")}}}""";
    }

    public static string Interval(string sum, string? reverseSum = null) =>
        $$$"""{"event":"interval","data":{"streams":[],"sum":{{{sum}}}{{{(reverseSum is null ? "" : $",\"sum_bidir_reverse\":{reverseSum}")}}}}}""";

    public static string EndSums(double sentBps, double recvBps, long bytes, long? retr, bool sender, string suffix = "") =>
        $$"""
        "sum_sent{{suffix}}":{"start":0,"end":10,"seconds":10,"bytes":{{bytes}},"bits_per_second":{{F(sentBps)}}{{(retr is { } r ? $",\"retransmits\":{r}" : "")}},"sender":{{(sender ? "true" : "false")}}},
        "sum_received{{suffix}}":{"start":0,"end":10.0002,"seconds":10.0002,"bytes":{{bytes - 1000}},"bits_per_second":{{F(recvBps)}},"sender":{{(sender ? "true" : "false")}}}
        """.ReplaceLineEndings("");

    public static string End(string sums) => "{\"event\":\"end\",\"data\":{" + sums + ",\"cpu_utilization_percent\":{\"host_total\":71.5,\"remote_total\":64.25}}}";

    /// <summary>100G-class TCP upload, 8 streams: intervals 92–98 Gbps, receiver average 95.4 Gbps over 10 s.</summary>
    public static string Tcp100G()
    {
        var lines = new List<string> { Start(8) };
        for (var i = 0; i < 10; i++) lines.Add(Interval(Sum(i, 92e9 + (i % 4 * 2e9), true, 10 + i)));
        lines.Add(End(EndSums(95.5e9, 95.4e9, 119_250_000_000, 145, true)));
        return string.Join('\n', lines) + "\n";
    }
}

public class IperfEngineTests
{
    [Theory]
    [InlineData("iperf 3.20 (cJSON 1.7.15)\nLinux host 6.18 x86_64", IperfEngineKind.Iperf3, "3.20", true, true, true)]
    [InlineData("iperf 3.16", IperfEngineKind.Iperf3, "3.16", false, true, true)]
    [InlineData("iperf 3.9 (cJSON 1.7.13)", IperfEngineKind.Iperf3, "3.9", false, true, false)]
    [InlineData("iperf 3.6", IperfEngineKind.Iperf3, "3.6", false, false, false)]
    [InlineData("iperf version 2.2.1 (4 Nov 2024) pthreads", IperfEngineKind.Iperf2, "2.2.1", false, false, true)]
    public void Versions_and_capabilities(string output, IperfEngineKind kind, string version, bool jsonStream, bool bidir, bool multi)
    {
        var e = Iperf.ParseVersion("/usr/bin/iperf", output)!;
        Assert.Equal(kind, e.Kind);
        Assert.Equal(version, e.VersionText);
        Assert.Equal(jsonStream, e.JsonStream);
        Assert.Equal(bidir, e.Bidirectional);
        Assert.Equal(multi || kind == IperfEngineKind.Iperf2, e.MultiThreaded);
    }

    [Theory]
    [InlineData("")]
    [InlineData("nmap 7.95")]
    [InlineData("iperf 4.0")]
    public void Unknown_executables_are_not_engines(string output) => Assert.Null(Iperf.ParseVersion("x", output));

    private static readonly IperfEngine V320 = Iperf.ParseVersion("iperf3", "iperf 3.20")!;
    private static readonly IperfEngine V315 = Iperf.ParseVersion("iperf3", "iperf 3.15")!;
    private static readonly IperfEngine V2 = Iperf.ParseVersion("iperf", "iperf version 2.2.1")!;

    [Fact]
    public void Iperf3_arguments_by_mode()
    {
        var o = new IperfOptions { Server = "192.0.2.20", Port = 5201, Seconds = 30, Streams = 32 };
        Assert.Equal(["-c", "192.0.2.20", "-p", "5201", "-t", "30", "-P", "32", "-i", "1", "--json-stream"], Iperf.ClientArguments(V320, o));
        Assert.Contains("-J", Iperf.ClientArguments(V315, o)); // no JSON stream before 3.17
        Assert.Contains("-R", Iperf.ClientArguments(V320, o with { Direction = IperfDirection.Download }));
        var bidir = Iperf.ClientArguments(V320, o with { Direction = IperfDirection.Bidirectional });
        Assert.Contains("--bidir", bidir);
        Assert.DoesNotContain("-R", bidir); // reverse and bidirectional are different modes
        var udp = Iperf.ClientArguments(V320, o with { Protocol = IperfProtocol.Udp, UdpBitsPerStream = 2_500_000_000 });
        Assert.Equal("2500000000", udp[udp.ToList().IndexOf("-b") + 1]);
        var adv = Iperf.ClientArguments(V320, o with { WindowBytes = 4 * 1024 * 1024, OmitSeconds = 2, BindAddress = "192.0.2.10" });
        Assert.Equal(["-w", "4194304"], adv.SkipWhile(a => a != "-w").Take(2));
        Assert.Equal(["-O", "2"], adv.SkipWhile(a => a != "-O").Take(2));
        Assert.Equal(["-B", "192.0.2.10"], adv.SkipWhile(a => a != "-B").Take(2));
        Assert.Equal("2001:db8::20", Iperf.ClientArguments(V320, o with { Server = "[2001:db8::20]" })[1]); // brackets removed, one argument
    }

    [Fact]
    public void Iperf2_never_gets_iperf3_options()
    {
        var o = new IperfOptions { Server = "server.example", Port = 5001, Streams = 4, Protocol = IperfProtocol.Udp, UdpBitsPerStream = 100_000_000 };
        var a = Iperf.ClientArguments(V2, o);
        Assert.Equal(["-y", "C"], a.SkipWhile(x => x != "-y").Take(2));
        foreach (var only3 in new[] { "-J", "--json-stream", "--bidir", "-O", "-C", "-Z" }) Assert.DoesNotContain(only3, a);
        Assert.Contains("-V", Iperf.ClientArguments(V2, o with { Server = "2001:db8::1" })); // iperf2 needs -V for IPv6
        Assert.Equal(["-s", "-p", "5001", "-u", "-i", "1", "-y", "C"], Iperf.ServerArguments(V2, 5001, "", udp: true));
        Assert.Equal(["-s", "-p", "5201", "-B", "192.0.2.10", "-J"], Iperf.ServerArguments(V320, 5201, "192.0.2.10", udp: false));
    }

    [Fact]
    public void Invalid_parameters_are_rejected_before_the_engine_starts()
    {
        var ok = new IperfOptions { Server = "192.0.2.20" };
        Assert.Empty(Iperf.Validate(V320, ok, server: false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Server = "" }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Server = "-s" }, false)); // never an option disguised as a host
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Server = "a b" }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Streams = 0 }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Streams = 129 }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Port = 70000 }, false));
        Assert.NotEmpty(Iperf.Validate(V2, ok with { Direction = IperfDirection.Bidirectional }, false));
        Assert.NotEmpty(Iperf.Validate(V2, ok with { OmitSeconds = 2 }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Protocol = IperfProtocol.Udp, UdpBitsPerStream = 0 }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { BindAddress = "not-an-ip" }, false));
        Assert.NotEmpty(Iperf.Validate(V320, ok with { Congestion = "bbr; rm" }, false));
        Assert.Empty(Iperf.Validate(V320, new IperfOptions { Server = "" }, server: true)); // the server needs no target
    }

    [Fact]
    public void High_rate_tests_need_a_confirmation()
    {
        Assert.False(Iperf.NeedsRateWarning(new IperfOptions { Streams = 4 }));
        Assert.True(Iperf.NeedsRateWarning(new IperfOptions { Streams = 32 }));
        Assert.False(Iperf.NeedsRateWarning(new IperfOptions { Protocol = IperfProtocol.Udp, Streams = 4, UdpBitsPerStream = 100_000_000 }));
        Assert.True(Iperf.NeedsRateWarning(new IperfOptions { Protocol = IperfProtocol.Udp, Streams = 4, UdpBitsPerStream = 250_000_000 })); // 1 Gbps in total
        Assert.All(Iperf.Presets, p => Assert.InRange(p.Streams, 1, 64)); // presets never set a rate limit
    }
}

public class IperfParserTests
{
    [Fact]
    public void Tcp_100G_stream_is_aggregated_with_64_bit_counters()
    {
        var run = Parse(IperfFixtures.Tcp100G());
        Assert.True(run.Ended);
        Assert.Equal(8, run.Streams);
        Assert.Equal(10, run.Series(true).Count);
        Assert.Equal(98e9, run.Peak(true));
        Assert.Equal(95.4e9, run.Average(true)); // the receiver's rate, not the sender's
        Assert.Equal(119_249_999_000L, run.Transferred(true)); // > 2^32: no 32-bit overflow
        Assert.Equal(145, run.Result(true)!.Retransmits);
        Assert.Equal(95.5e9, run.Result(true)!.SenderBitsPerSecond);
        Assert.Equal(71.5, run.CpuLocal);
        Assert.False(run.HasDirection(false));
        Assert.Equal("95.4 Gbps", Iperf.Rate(run.Average(true)));
        Assert.Equal("119 GB", Iperf.Bytes(run.Transferred(true)));
    }

    [Fact]
    public void Tcp_200G_and_very_large_transfers()
    {
        var text = string.Join('\n', IperfFixtures.Start(64), IperfFixtures.Interval(IperfFixtures.Sum(0, 2.05e11, true)),
            IperfFixtures.End(IperfFixtures.EndSums(2.01e11, 2.0e11, 9_000_000_000_000_000, 0, true)));
        var run = Parse(text);
        Assert.Equal("200 Gbps", Iperf.Rate(run.Average(true)));
        Assert.Equal("205 Gbps", Iperf.Rate(run.Peak(true)));
        Assert.Equal(8_999_999_999_999_000L, run.Transferred(true));
        Assert.Equal("9.00 PB", Iperf.Bytes(run.Transferred(true))); // 9 × 10^15 bytes
    }

    [Fact]
    public void Reverse_test_is_download()
    {
        var text = string.Join('\n', IperfFixtures.Start(4, reverse: true), IperfFixtures.Interval(IperfFixtures.Sum(0, 19e9, false)),
            IperfFixtures.End(IperfFixtures.EndSums(19.1e9, 19.0e9, 4_780_000_000, 2, false)));
        var run = Parse(text);
        Assert.False(run.HasDirection(true));
        Assert.Equal(19.0e9, run.Average(false));
        Assert.Equal(2, run.Result(false)!.Retransmits);
    }

    [Fact]
    public void Bidirectional_keeps_two_directions_and_never_sums_them()
    {
        var text = string.Join('\n', IperfFixtures.Start(2, bidir: true),
            IperfFixtures.Interval(IperfFixtures.Sum(0, 8e9, true), IperfFixtures.Sum(0, 14e9, false)),
            IperfFixtures.Interval(IperfFixtures.Sum(1, 7.6e9, true), IperfFixtures.Sum(1, 14.2e9, false)),
            IperfFixtures.End(IperfFixtures.EndSums(7.63e9, 7.60e9, 1_910_000_000, 0, true) + "," + IperfFixtures.EndSums(14.19e9, 14.15e9, 3_550_000_000, 0, false, "_bidir_reverse")));
        var run = Parse(text);
        Assert.Equal(7.60e9, run.Average(true));
        Assert.Equal(14.15e9, run.Average(false));
        Assert.Equal(2, run.Series(true).Count);
        Assert.Equal(2, run.Series(false).Count);
        Assert.Equal(2, run.Results.Count);
        Assert.Equal(8e9, run.Peak(true)); // each direction its own peak
    }

    [Fact]
    public void Udp_jitter_and_loss_come_from_the_receiver()
    {
        var end = """{"event":"end","data":{"sum":{"start":0,"end":10,"seconds":10,"bytes":1250000000,"bits_per_second":1000000000,"jitter_ms":0.031,"lost_packets":3,"packets":100000,"lost_percent":0.003,"sender":true},"sum_sent":{"start":0,"end":10,"seconds":10,"bytes":1250000000,"bits_per_second":1000000000,"jitter_ms":0,"lost_packets":0,"packets":100000,"lost_percent":0,"sender":true},"sum_received":{"start":0,"end":10,"seconds":10,"bytes":1249962500,"bits_per_second":999970000,"jitter_ms":0.031,"lost_packets":3,"packets":100000,"lost_percent":0.003,"sender":false}}}""";
        var run = Parse(string.Join('\n', IperfFixtures.Start(1, protocol: "UDP"), IperfFixtures.Interval(IperfFixtures.Sum(0, 1e9, true)), end));
        var r = run.Result(true)!;
        Assert.Equal(0.031, r.JitterMs);
        Assert.Equal(3, r.LostPackets);
        Assert.Equal(100000, r.Packets);
        Assert.Equal(0.003, r.LostPercent);
        Assert.Null(r.Retransmits);
        Assert.Contains("Jitter:", Iperf.Summary(Info(IperfProtocol.Udp), run), StringComparison.Ordinal);
    }

    [Fact]
    public void Udp_reverse_uses_test_start_not_the_end_sender_flag()
    {
        // iperf3 3.20 marks UDP sum_sent "sender":true even when the server sent (-R)
        var end = """{"event":"end","data":{"sum_sent":{"bytes":100,"bits_per_second":50000000,"seconds":2,"sender":true},"sum_received":{"bytes":99,"bits_per_second":49900000,"jitter_ms":0.008,"lost_packets":0,"packets":8641,"seconds":2,"sender":false}}}""";
        var run = Parse(IperfFixtures.Start(1, reverse: true, protocol: "UDP") + "\n" + end);
        Assert.False(run.HasDirection(true));
        Assert.Equal(49.9e6, run.Average(false));
    }

    [Fact]
    public void Errors_partial_and_malformed_output()
    {
        var refused = Parse("""
            {"event":"error","data":"unable to connect to server - server may have stopped running or use a different port, firewall issue, etc.: Connection refused"}
            {"event":"end","data":{}}
            """);
        Assert.Contains("Connection refused", refused.Error, StringComparison.Ordinal);
        Assert.Empty(refused.Results);

        // cut in the middle of the end event (process stopped): the intervals stay, no final result is invented
        var full = IperfFixtures.Tcp100G();
        var (objects, rest) = Iperf.SplitJson(full[..^40]);
        var run = new IperfRun();
        foreach (var o in objects) Iperf.ApplyJson(run, o);
        Assert.Equal(10, run.Series(true).Count);
        Assert.False(run.Ended);
        Assert.Empty(run.Results);
        Assert.StartsWith("{\"event\":\"end\"", rest, StringComparison.Ordinal);
        Assert.Equal("94.6 Gbps", Iperf.Rate(run.Average(true))); // mean of the received intervals (92, 94, 96, 98, …)
        Assert.Null(run.Result(true)?.Retransmits);

        Assert.False(Iperf.ApplyJson(new IperfRun(), "{\"event\":\"interval\",\"data\":"));
        Assert.False(Iperf.ApplyJson(new IperfRun(), "not json"));
        var odd = new IperfRun();
        Assert.True(Iperf.ApplyJson(odd, """{"event":"interval","data":{"sum":{"bits_per_second":"fast"}}}"""));
        Assert.Equal(0, odd.Intervals[0].BitsPerSecond); // wrong type: no value, never a parsed string
    }

    [Fact]
    public void Final_json_report_and_server_reports_split_into_objects()
    {
        const string twoReports = """
            {
                "start": { "connected": [{ "local_host": "192.0.2.20", "local_port": 5201, "remote_host": "192.0.2.10", "remote_port": 50000 }], "version": "iperf 3.20", "test_start": { "protocol": "TCP", "num_streams": 2, "reverse": 0 } },
                "intervals": [{ "sum": { "start": 0, "end": 1, "bytes": 1250000000, "bits_per_second": 1e10, "sender": false } }],
                "end": { "sum_sent": { "bytes": 0, "bits_per_second": 0, "seconds": 1, "sender": false }, "sum_received": { "bytes": 1250000000, "bits_per_second": 9.99e9, "seconds": 1, "sender": false } }
            }
            {
                "start": { "connected": [], "version": "iperf 3.20" }, "intervals": [], "end": {}, "error": "interrupt - the server has terminated by signal Interrupt(2)"
            }
            """;
        var (objects, rest) = Iperf.SplitJson(twoReports);
        Assert.Equal(2, objects.Count);
        Assert.Equal("", rest.Trim());
        var first = new IperfRun();
        Iperf.ApplyJson(first, objects[0]);
        Assert.Equal("192.0.2.10", first.Connections[0].RemoteHost);
        Assert.Equal(9.99e9, first.Average(true));
        var (inString, _) = Iperf.SplitJson("""{"error":"brace } in text {"}""");
        Assert.Single(inString);
    }

    [Fact]
    public void Iperf2_csv_sums_streams_and_reads_the_final_report()
    {
        const string csv = """
            20261126021952,192.0.2.10,47984,192.0.2.20,5001,2,0.0-1.0,607912000,4863296000
            20261126021952,192.0.2.10,47970,192.0.2.20,5001,1,0.0-1.0,525598784,4204790272
            20261126021952,192.0.2.10,0,192.0.2.20,5001,-1,0.0-1.0,1133510784,9068086272
            20261126021953,192.0.2.10,0,192.0.2.20,5001,-1,1.0-2.0,1222377472,9779019776
            20261126021953,192.0.2.10,0,192.0.2.20,5001,-1,0.0-2.0,2355888256,9423553024
            """;
        var run = new IperfRun();
        foreach (var l in csv.Split('\n')) Assert.True(Iperf.ApplyIperf2Csv(run, l, 2, 1, upload: true));
        Assert.Equal(2, run.Series(true).Count); // only the sum lines
        Assert.Equal(9779019776, run.Peak(true));
        Assert.Equal(9423553024, run.Average(true));
        Assert.Equal(2355888256, run.Transferred(true));
        Assert.Equal(2, run.Connections.Count);
        Assert.Null(run.Result(true)!.Retransmits); // iperf2 CSV has none: not reported, not zero
    }

    [Fact]
    public void Iperf2_udp_receiver_report_and_not_reported_values()
    {
        var recv = new IperfRun();
        Assert.True(Iperf.ApplyIperf2Csv(recv, "20261126021957,192.0.2.20,48037,192.0.2.10,5001,1,0.0-2.0,13109460,52433461,0.010,2,8918,0.022,0", 1, 1, upload: false));
        Assert.Equal((0.010, 2L, 8918L), (recv.Result(false)!.JitterMs!.Value, recv.Result(false)!.LostPackets!.Value, recv.Result(false)!.Packets!.Value));
        var sender = new IperfRun();
        Assert.True(Iperf.ApplyIperf2Csv(sender, "20261126021957,192.0.2.10,48037,192.0.2.20,5001,1,0.0-2.0,13109460,52429949,-nan,0,-1,-0.000,0", 1, 1, upload: true));
        Assert.Null(sender.Result(true)!.JitterMs); // "-nan" and the sender's own zeros are not measurements
        Assert.Null(sender.Result(true)!.LostPackets);
        Assert.False(Iperf.ApplyIperf2Csv(new IperfRun(), "[  1] tcp connect to 192.0.2.20 port 5001 failed (Connection refused)", 1, 1, true));
    }

    [Theory]
    [InlineData(87.6e9, "87.6 Gbps")]
    [InlineData(100e9, "100 Gbps")]
    [InlineData(1.5e12, "1.50 Tbps")]
    [InlineData(950e6, "950 Mbps")]
    [InlineData(9.99e3, "9.99 Kbps")]
    [InlineData(12, "12.0 bps")]
    public void Rates_use_automatic_units(double bps, string text) => Assert.Equal(text, Iperf.Rate(bps));

    [Fact]
    public void Units_and_inputs()
    {
        Assert.Equal("N/A", Iperf.Rate(null)); // never 0 for missing data
        Assert.Equal("N/A", Iperf.Bytes(null));
        Assert.Equal("108 GB", Iperf.Bytes(108_000_000_000));
        Assert.Equal(100_000_000L, Iperf.ParseRate("100M"));
        Assert.Equal(2_500_000_000L, Iperf.ParseRate("2.5G"));
        Assert.Equal(25_000_000_000L, Iperf.ParseRate("25 Gbps"));
        Assert.Null(Iperf.ParseRate("fast"));
        Assert.Null(Iperf.ParseRate("-5M"));
        Assert.Equal(4L * 1024 * 1024, IperfWindow.ParseBytes("4M"));
        Assert.Equal(250e9, IperfChart.Nice(220e9));
        Assert.Equal(1e11, IperfChart.Nice(95e9));
    }

    [Fact]
    public void Exports_hold_full_values_and_the_raw_report()
    {
        var run = Parse(IperfFixtures.Tcp100G());
        var info = Info(IperfProtocol.Tcp);
        var summary = Iperf.Summary(info, run);
        foreach (var s in new[] { "iperf3 3.20", "192.0.2.20:5201", "TCP", "Streams:        8", "95.4 Gbps", "Retransmits:  145", "Completed" }) Assert.Contains(s, summary, StringComparison.Ordinal);
        var csv = Iperf.IntervalsCsv(run).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(11, csv.Length);
        Assert.Equal("Upload,0,1,11500000000,92000000000,10,,,,0", csv[1]); // complete values, invariant culture
        using var doc = System.Text.Json.JsonDocument.Parse(Iperf.Json(info, run, ["{\"raw\":1}"]));
        Assert.Equal(95.4e9, doc.RootElement.GetProperty("results")[0].GetProperty("averageBitsPerSecond").GetDouble());
        Assert.Equal(119_249_999_000L, doc.RootElement.GetProperty("results")[0].GetProperty("transferredBytes").GetInt64());
        Assert.Equal(1, doc.RootElement.GetProperty("engineReport").GetArrayLength());
    }

    internal static IperfRun Parse(string text)
    {
        var run = new IperfRun();
        foreach (var o in Iperf.SplitJson(text).Objects) Iperf.ApplyJson(run, o);
        return run;
    }

    private static Iperf.ReportInfo Info(IperfProtocol p) => new(DateTimeOffset.Now, Iperf.ParseVersion("iperf3", "iperf 3.20")!,
        new IperfOptions { Server = "192.0.2.20", Port = 5201, Streams = 8, Seconds = 10, Protocol = p }, IperfState.Completed, "");
}

/// <summary>Scripted engine: writes the given output in chunks, then exits; or waits until stopped.</summary>
internal sealed class FakeIperf(IperfEngine engine, string output, int exitCode = 0, bool waitForStop = false) : IIperfService
{
    public readonly List<IReadOnlyList<string>> Started = [];
    public FakeProcess? Last { get; private set; }

    public Task<IReadOnlyList<IperfEngine>> DetectAsync(string configuredPath, CancellationToken ct) => Task.FromResult<IReadOnlyList<IperfEngine>>([engine]);

    public Task<IperfEngine?> ProbeAsync(string path, CancellationToken ct) => Task.FromResult<IperfEngine?>(engine);

    public IIperfProcess Start(IperfEngine e, IReadOnlyList<string> arguments, Action<string> stdout, Action<string> stderr)
    {
        Started.Add(arguments);
        Last = new FakeProcess(output, exitCode, waitForStop, stdout);
        return Last;
    }

    internal sealed class FakeProcess : IIperfProcess
    {
        private readonly TaskCompletionSource<int> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FakeProcess(string output, int code, bool wait, Action<string> stdout)
        {
            for (var i = 0; i < output.Length; i += 700) stdout(output.Substring(i, Math.Min(700, output.Length - i))); // chunks split JSON objects
            if (!wait) _done.TrySetResult(code);
        }

        public bool Stopped { get; private set; }

        public Task<int> Completion => _done.Task;

        public void Stop()
        {
            Stopped = true;
            _done.TrySetResult(-1);
        }

        public void Dispose() => Stop();
    }
}

[Collection("Headless UI")]
public class IperfWindowTests
{
    private static readonly IperfEngine Engine = Iperf.ParseVersion("iperf3", "iperf 3.20")!;

    private static async Task<IperfWindow> OpenAsync(FakeIperf fake)
    {
        var w = new IperfWindow(HeadlessUi.Vm, fake, null);
        w.Show();
        w.SetEnginesForTest([Engine]);
        for (var i = 0; i < 5; i++)
        {
            UiDesignSystemTests.Dispatch();
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }

        return w;
    }

    private static async Task Settle()
    {
        for (var i = 0; i < 10; i++)
        {
            UiDesignSystemTests.Dispatch();
            await Task.Delay(10, TestContext.Current.CancellationToken);
        }
    }

    private static string Text(Avalonia.Controls.Window w) =>
        string.Join("\n", Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(w).OfType<Avalonia.Controls.TextBlock>().Where(t => t.IsEffectivelyVisible).Select(t => t.Text));

    [Fact]
    public Task Opening_starts_nothing_and_a_completed_100G_test_renders() => HeadlessUi.RunAsync(async () =>
    {
        foreach (var variant in new[] { Avalonia.Styling.ThemeVariant.Light, Avalonia.Styling.ThemeVariant.Dark })
        {
            HeadlessUi.SetTheme(variant);
            var fake = new FakeIperf(Engine, IperfFixtures.Tcp100G());
            var w = await OpenAsync(fake);
            try
            {
                Assert.Empty(fake.Started); // never starts on its own
                Assert.Contains("Live intervals.", Text(w), StringComparison.Ordinal); // capabilities shown
                Assert.DoesNotContain("UDP rate", Text(w), StringComparison.Ordinal); // UDP-only row hidden for TCP
                Assert.Equal(IperfState.Ready, w.State);
                HeadlessUi.Snapshot(w, $"iPerf ready - {variant}");
                w.SetInputs("100g-server.lab.example.com", 8, IperfDirection.Upload);
                await w.RunAsync(Engine, new IperfOptions { Server = "100g-server.lab.example.com", Streams = 8, Seconds = 10 }, server: false);
                await Settle();
                Assert.Equal(IperfState.Completed, w.State);
                Assert.Contains("95.4 Gbps", Text(w), StringComparison.Ordinal);
                Assert.Contains("145", Text(w), StringComparison.Ordinal);
                HeadlessUi.Snapshot(w, $"iPerf 100G completed - {variant}");
                w.Width = w.MinWidth;
                w.Height = w.MinHeight;
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(w, $"iPerf 100G completed - {variant} - minimum size");
                UiDesignSystemTests.AssertNoActionCutOff(w, "iPerf");
            }
            finally
            {
                w.Close();
            }
        }

        HeadlessUi.SetTheme(Avalonia.Styling.ThemeVariant.Default);
    });

    [Fact]
    public Task Bidirectional_and_udp_results_render() => HeadlessUi.RunAsync(async () =>
    {
        var bidir = string.Join('\n', IperfFixtures.Start(2, bidir: true),
            IperfFixtures.Interval(IperfFixtures.Sum(0, 8e9, true), IperfFixtures.Sum(0, 14e9, false)),
            IperfFixtures.Interval(IperfFixtures.Sum(1, 7.6e9, true), IperfFixtures.Sum(1, 14.2e9, false)),
            IperfFixtures.End(IperfFixtures.EndSums(7.63e9, 7.60e9, 1_910_000_000, 0, true) + "," + IperfFixtures.EndSums(14.19e9, 14.15e9, 3_550_000_000, 0, false, "_bidir_reverse")));
        var w = await OpenAsync(new FakeIperf(Engine, bidir));
        try
        {
            await w.RunAsync(Engine, new IperfOptions { Server = "2001:db8::20", Streams = 2, Seconds = 2, Direction = IperfDirection.Bidirectional }, false);
            await Settle();
            Assert.Contains("↑ 7.60 Gbps  ↓ 14.2 Gbps", Text(w), StringComparison.Ordinal); // two directions, never one summed figure
            HeadlessUi.Snapshot(w, "iPerf bidirectional");
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public Task Stop_keeps_measurements_and_ends_the_owned_process() => HeadlessUi.RunAsync(async () =>
    {
        var partial = string.Join('\n', IperfFixtures.Start(8), IperfFixtures.Interval(IperfFixtures.Sum(0, 40e9, true)), IperfFixtures.Interval(IperfFixtures.Sum(1, 41e9, true))) + "\n";
        var fake = new FakeIperf(Engine, partial, waitForStop: true);
        var w = await OpenAsync(fake);
        try
        {
            var run = w.RunAsync(Engine, new IperfOptions { Server = "192.0.2.20", Streams = 8, Seconds = 30 }, false);
            await Settle();
            Assert.Equal(IperfState.Running, w.State);
            w.StopProcess(user: true);
            await run;
            await Settle();
            Assert.True(fake.Last!.Stopped);
            Assert.Equal(IperfState.Stopped, w.State);
            Assert.Equal(2, w.Run.Intervals.Count); // received measurements are kept
            Assert.Empty(w.Run.Results); // no final report invented
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public Task Failure_and_server_mode() => HeadlessUi.RunAsync(async () =>
    {
        var refused = "{\"event\":\"error\",\"data\":\"unable to connect to server: Connection refused\"}\n{\"event\":\"end\",\"data\":{}}\n";
        var w = await OpenAsync(new FakeIperf(Engine, refused, exitCode: 1));
        try
        {
            await w.RunAsync(Engine, new IperfOptions { Server = "192.0.2.99" }, false);
            await Settle();
            Assert.Equal(IperfState.Failed, w.State);
            Assert.Contains("Connection refused", Text(w), StringComparison.Ordinal);
            HeadlessUi.Snapshot(w, "iPerf failed");
        }
        finally
        {
            w.Close();
        }

        var report = """{"start":{"connected":[{"local_host":"192.0.2.20","local_port":5201,"remote_host":"192.0.2.10","remote_port":50000}],"version":"iperf 3.20","test_start":{"protocol":"TCP","num_streams":4,"reverse":0}},"intervals":[],"end":{"sum_received":{"bytes":12500000000,"bits_per_second":1e10,"seconds":10,"sender":false}}}""";
        var fake = new FakeIperf(Engine, report, waitForStop: true);
        w = await OpenAsync(fake);
        try
        {
            w.UseServerMode();
            var run = w.RunAsync(Engine, new IperfOptions { Port = 5201 }, server: true);
            await Settle();
            Assert.Equal(["-s", "-p", "5201", "-J"], fake.Started[0]);
            var t = Assert.Single(w.ServerTests);
            Assert.Equal(("192.0.2.10:50000", "10.0 Gbps"), (t.Client, t.Throughput));
            HeadlessUi.Snapshot(w, "iPerf server");
            w.Close(); // closing stops the server it started
            await run;
            Assert.True(fake.Last!.Stopped);
        }
        finally
        {
            w.Close();
        }
    });
}

public class IperfProcessTests
{
    [Fact]
    public async Task Stop_ends_the_child_process_it_started()
    {
        // a long-running stand-in for an engine; only this process is ended
        var (exe, args) = OperatingSystem.IsWindows() ? (Path.Combine(Environment.SystemDirectory, "ping.exe"), new[] { "-n", "60", "127.0.0.1" }) : ("/bin/sleep", new[] { "60" });
        var engine = new IperfEngine(IperfEngineKind.Iperf3, exe, new Version(3, 20), "3.20");
        var output = new System.Text.StringBuilder();
        using var p = new IperfService().Start(engine, args, s => { lock (output) output.Append(s); }, _ => { });
        await Task.Delay(300, TestContext.Current.CancellationToken);
        Assert.False(p.Completion.IsCompleted);
        p.Stop();
        var done = await Task.WhenAny(p.Completion, Task.Delay(10_000, TestContext.Current.CancellationToken));
        Assert.Same(p.Completion, done);
    }

    [Fact]
    public async Task Missing_executables_are_reported()
    {
        var svc = new IperfService();
        Assert.Null(await svc.ProbeAsync(Path.Combine(Path.GetTempPath(), "no-such-iperf3.exe"), TestContext.Current.CancellationToken));
        Assert.Throws<InvalidOperationException>(() => svc.Start(new IperfEngine(IperfEngineKind.Iperf3, Path.Combine(Path.GetTempPath(), "no-such-iperf3.exe"), new Version(3, 20), "3.20"), ["-v"], _ => { }, _ => { }));
    }
}
