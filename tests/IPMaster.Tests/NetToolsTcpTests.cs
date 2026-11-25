using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

public class NetToolsTcpTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly TcpRunOptions Fast = new() { Timeout = TimeSpan.FromMilliseconds(500) };

    [Fact]
    public async Task Connects_records_endpoints_and_sends_no_payload()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var received = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync(Ct);
            var buf = new byte[16];
            return await c.GetStream().ReadAsync(buf, Ct); // 0 = closed without data
        });
        var a = await new TcpConnectionTester().AttemptAsync(new TcpTarget("127.0.0.1", port), Fast, null, Ct);
        Assert.Equal(TcpOutcome.Connected, a.Outcome);
        Assert.Equal($"127.0.0.1:{port}", a.ConnectedTo);
        Assert.StartsWith("127.0.0.1:", a.LocalEndpoint, StringComparison.Ordinal);
        Assert.NotNull(a.ConnectDuration);
        Assert.Null(a.DnsDuration); // literal address: no DNS step
        Assert.Equal(0, await received.WaitAsync(TimeSpan.FromSeconds(5), Ct));
        listener.Stop();
    }

    [Fact]
    public async Task Closed_port_is_refused()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        var a = await new TcpConnectionTester().AttemptAsync(new TcpTarget("127.0.0.1", port), Fast with { Timeout = TimeSpan.FromSeconds(5) }, null, Ct); // Windows retries a reset SYN for ~2 s before reporting refused
        Assert.Equal(TcpOutcome.Refused, a.Outcome);
        Assert.Equal("ConnectionRefused", a.SocketError);
    }

    [Fact]
    public async Task Silent_target_times_out()
    {
        var tester = new TcpConnectionTester(connector: (_, _, ct) => Task.Delay(Timeout.Infinite, ct));
        var a = await tester.AttemptAsync(new TcpTarget("192.0.2.1", 443), Fast, null, Ct);
        Assert.Equal(TcpOutcome.Timeout, a.Outcome);
    }

    [Fact]
    public async Task Dns_failure_and_dns_once_per_run()
    {
        var calls = 0;
        var failing = new TcpConnectionTester(resolver: (_, _) => throw new SocketException((int)SocketError.HostNotFound));
        var a = await failing.AttemptAsync(new TcpTarget("nope.lab.test", 80), Fast, null, Ct);
        Assert.Equal(TcpOutcome.DnsFailure, a.Outcome);
        Assert.Equal("HostNotFound", a.SocketError);

        var counting = new TcpConnectionTester(
            resolver: (_, _) =>
            {
                Interlocked.Increment(ref calls);
                return Task.FromResult(new[] { IPAddress.Loopback });
            },
            connector: (_, _, _) => Task.CompletedTask);
        var cache = new ConcurrentDictionary<string, IPAddress[]>();
        for (var i = 0; i < 3; i++) await counting.AttemptAsync(new TcpTarget("host.lab.test", 80), Fast, cache, Ct);
        Assert.Equal(1, calls);
        for (var i = 0; i < 2; i++) await counting.AttemptAsync(new TcpTarget("host.lab.test", 80), Fast, null, Ct);
        Assert.Equal(3, calls);
    }

    [Fact]
    public async Task Non_local_source_address_is_a_bind_failure()
    {
        var a = await new TcpConnectionTester().AttemptAsync(new TcpTarget("127.0.0.1", 9), Fast with { Source = IPAddress.Parse("192.0.2.123") }, null, Ct);
        Assert.Equal(TcpOutcome.BindFailure, a.Outcome);
    }

    [Fact]
    public async Task Continuous_rounds_never_overlap_per_target()
    {
        var active = 0;
        var peak = 0;
        var tester = new TcpConnectionTester(connector: async (_, _, ct) =>
        {
            var now = Interlocked.Increment(ref active);
            int p;
            while (now > (p = Volatile.Read(ref peak)) && Interlocked.CompareExchange(ref peak, now, p) != p) { }
            await Task.Delay(250, ct);
            Interlocked.Decrement(ref active);
        });
        var results = 0;
        var skipped = 0;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(1100);
        await tester.RunAsync([new TcpTarget("127.0.0.1", 1)], Fast with { Continuous = true, Interval = TimeSpan.FromMilliseconds(50), Timeout = TimeSpan.FromSeconds(5) },
            _ => Interlocked.Increment(ref results), _ => Interlocked.Increment(ref skipped), cts.Token);
        Assert.Equal(1, peak);
        Assert.InRange(results, 2, 5);
        Assert.True(skipped > 5, $"skipped {skipped}");
    }

    [Fact]
    public void Plan_combinations_are_validated()
    {
        Assert.True(TcpTestPlan.TryBuild("a.lab.test, 192.0.2.1", "80, 443, 8000-8002", out var t, out var e), e);
        Assert.Equal(10, t.Count);
        Assert.False(TcpTestPlan.TryBuild(string.Join(",", Enumerable.Range(1, 300).Select(i => $"h{i}")), "1-10", out _, out var big));
        Assert.Contains("limit", big, StringComparison.Ordinal);
        Assert.False(TcpTestPlan.TryBuild("", "80", out _, out _));
        Assert.False(TcpTestPlan.TryBuild("h", "70000", out _, out _));
    }

    [Fact]
    public void Statistics_track_consecutive_failures_and_durations()
    {
        var s = new TcpTargetStats(new TcpTarget("h", 1));
        TcpAttempt A(TcpOutcome o, double ms = 0) => new(s.Target, DateTimeOffset.Now, null, null, null, o == TcpOutcome.Connected ? TimeSpan.FromMilliseconds(ms) : null, o, null, "");
        s.Add(A(TcpOutcome.Connected, 10));
        s.Add(A(TcpOutcome.Timeout));
        s.Add(A(TcpOutcome.Refused));
        Assert.Equal(2, s.ConsecutiveFailures);
        s.Add(A(TcpOutcome.Connected, 30));
        s.Add(A(TcpOutcome.Cancelled)); // not counted
        Assert.Equal(0, s.ConsecutiveFailures);
        Assert.Equal(4, s.Attempts);
        Assert.Equal(20, s.AverageMs);
        Assert.Equal(10, s.MinMs);
        Assert.Equal(30, s.MaxMs);
        for (var i = 0; i < TcpTargetStats.MaxHistory + 50; i++) s.Add(A(TcpOutcome.Connected, 1));
        Assert.Equal(TcpTargetStats.MaxHistory, s.History.Count);
    }
}
