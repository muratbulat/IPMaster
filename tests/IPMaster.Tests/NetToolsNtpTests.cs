using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Scripted NTP server on 127.0.0.1 (UDP). Test-only.</summary>
internal sealed class NtpFixture : IAsyncDisposable
{
    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public NtpFixture()
    {
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try
                {
                    r = await _udp.ReceiveAsync(_cts.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

                Requests++;
                var request = NtpPacket.TryParse(r.Buffer)!;
                if (Silent) continue;
                var now = DateTime.UtcNow + Skew;
                var t2 = NtpTime.FromDateTime(now);
                if (Spoof) await Send(r.RemoteEndPoint, request.Transmit ^ 0xFFFF, NtpLeap.NoWarning, 2, t2);
                await Task.Delay(ServerHold);
                var t3 = NtpTime.FromDateTime(DateTime.UtcNow + Skew);
                if (Kiss is { } code)
                {
                    var raw = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(System.Text.Encoding.ASCII.GetBytes(code));
                    await _udp.SendAsync(NtpPacket.Encode(new NtpPacket(NtpLeap.Unsynchronized, 4, 4, 0, 6, -20, TimeSpan.Zero, TimeSpan.Zero, raw, 0, request.Transmit, 0, 0)),
                        r.RemoteEndPoint, _cts.Token);
                    continue;
                }

                await Send(r.RemoteEndPoint, request.Transmit, Unsynchronized ? NtpLeap.Unsynchronized : NtpLeap.NoWarning, 2, t2, t3);
            }
        });
    }

    private async Task Send(IPEndPoint to, ulong origin, NtpLeap leap, int stratum, ulong t2, ulong? t3 = null)
    {
        var p = new NtpPacket(leap, 4, 4, stratum, 6, -23, TimeSpan.FromMilliseconds(12.5), TimeSpan.FromMilliseconds(30), 0xC0000201, t2, origin, t2, t3 ?? t2);
        await _udp.SendAsync(NtpPacket.Encode(p), to, _cts.Token);
    }

    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

    public TimeSpan Skew { get; init; }

    public TimeSpan ServerHold { get; init; } = TimeSpan.FromMilliseconds(5);

    public string? Kiss { get; init; }

    public bool Silent { get; init; }

    public bool Spoof { get; init; }

    public bool Unsynchronized { get; init; }

    public int Requests { get; private set; }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _udp.Dispose();
        await _loop;
    }
}

public class NetToolsNtpTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static NtpOptions Fast(NtpFixture f, int samples = 1) => new() { Port = f.Port, Samples = samples, Interval = TimeSpan.FromMilliseconds(50), Timeout = TimeSpan.FromSeconds(1) };

    [Fact]
    public void Offset_and_delay_follow_rfc5905()
    {
        var t0 = new DateTime(2026, 11, 17, 12, 0, 0, DateTimeKind.Utc);
        var t1 = t0;
        var t2 = t0.AddMilliseconds(1000);
        var t3 = t0.AddMilliseconds(1100);
        var t4 = t0.AddMilliseconds(200);
        Assert.Equal(TimeSpan.FromMilliseconds(950), NtpMath.Offset(t1, t2, t3, t4)); // ((1000) + (1100 - 200)) / 2
        Assert.Equal(TimeSpan.FromMilliseconds(100), NtpMath.Delay(t1, t2, t3, t4)); // 200 - 100
        Assert.Equal(TimeSpan.FromMilliseconds(-950), NtpMath.Offset(t2, t1, t4, t3)); // mirrored: local ahead
        Assert.Contains("behind", NtpMath.Describe(TimeSpan.FromMilliseconds(950)), StringComparison.Ordinal);
        Assert.Contains("ahead", NtpMath.Describe(TimeSpan.FromSeconds(-2)), StringComparison.Ordinal);
    }

    [Fact]
    public void Timestamps_round_trip_and_handle_the_2036_era_rollover()
    {
        var t = new DateTime(2026, 11, 17, 8, 30, 15, 250, DateTimeKind.Utc);
        var ts = NtpTime.FromDateTime(t);
        Assert.Equal(2_208_988_800UL + (ulong)new DateTimeOffset(t).ToUnixTimeSeconds(), ts >> 32); // seconds since 1900 = 1900→1970 + Unix time
        Assert.True(Math.Abs((NtpTime.ToDateTime(ts, t) - t).TotalMilliseconds) < 0.001);

        var after = new DateTime(2036, 2, 7, 6, 28, 20, DateTimeKind.Utc); // 4 s after the era-0 rollover
        var wire = NtpTime.FromDateTime(after);
        Assert.Equal(4UL, wire >> 32);
        Assert.Equal(after, NtpTime.ToDateTime(wire, after.AddDays(-3)));
        Assert.Equal(new DateTime(1900, 1, 1, 0, 0, 4, DateTimeKind.Utc), NtpTime.ToDateTime(wire, new DateTime(1900, 1, 2, 0, 0, 0, DateTimeKind.Utc)));
        Assert.Equal(TimeSpan.FromSeconds(1.5), NtpTime.FromShort(0x0001_8000));
    }

    [Fact]
    public void Replies_are_validated_against_the_request()
    {
        var reply = new NtpPacket(NtpLeap.NoWarning, 4, 4, 2, 6, -20, TimeSpan.Zero, TimeSpan.Zero, 0, 1, 42, 5, 6);
        Assert.Null(reply.Problem(42));
        Assert.Contains("origin", reply.Problem(43), StringComparison.Ordinal);
        Assert.Contains("mode 3", (reply with { Mode = 3 }).Problem(42), StringComparison.Ordinal);
        Assert.Contains("stratum 16", (reply with { Stratum = 16 }).Problem(42), StringComparison.Ordinal);
        Assert.Contains("zero", (reply with { Transmit = 0 }).Problem(42), StringComparison.Ordinal);
        var parsed = NtpPacket.TryParse(NtpPacket.Encode(reply))!;
        Assert.Equal(reply, parsed);
        Assert.Equal("192.0.2.1", (reply with { ReferenceIdRaw = 0xC0000201 }).ReferenceId);
        Assert.Null(NtpPacket.TryParse(new byte[47]));
        var request = NtpPacket.TryParse(NtpPacket.Request(0x1122334455667788))!;
        Assert.Equal((4, 3, 0x1122334455667788UL), (request.Version, request.Mode, request.Transmit));
    }

    [Fact]
    public async Task Skewed_server_offset_is_measured_and_local_clock_untouched()
    {
        await using var f = new NtpFixture { Skew = TimeSpan.FromSeconds(5), ServerHold = TimeSpan.FromMilliseconds(30) };
        var before = DateTime.UtcNow;
        var r = await NtpChecker.QueryAsync("127.0.0.1", Fast(f, 3), null, Ct);
        Assert.Equal(3, r.Good.Count);
        var best = r.Best!;
        Assert.InRange(best.Offset!.Value.TotalMilliseconds, 4950, 5050);
        Assert.InRange(best.Delay!.Value.TotalMilliseconds, -1, 30); // server hold time is excluded from the delay
        Assert.Equal(2, best.Packet!.Stratum);
        Assert.NotNull(r.Jitter);
        Assert.True(Math.Abs((DateTime.UtcNow - before).TotalSeconds) < 5); // nothing stepped the clock
        Assert.Contains("behind the server", NtpChecker.Report([r]), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Injected_local_clock_shows_a_local_clock_ahead()
    {
        await using var f = new NtpFixture();
        var r = await NtpChecker.QueryAsync("127.0.0.1", Fast(f), null, Ct, () => DateTime.UtcNow.AddSeconds(3));
        Assert.InRange(r.Best!.Offset!.Value.TotalSeconds, -3.05, -2.95);
    }

    [Fact]
    public async Task Kiss_of_death_rate_stops_further_queries()
    {
        await using var f = new NtpFixture { Kiss = "RATE" };
        var r = await NtpChecker.QueryAsync("127.0.0.1", Fast(f, 4), null, Ct);
        var s = Assert.Single(r.Samples);
        Assert.Equal(NtpOutcome.KissOfDeath, s.Outcome);
        Assert.Contains("RATE", s.Detail, StringComparison.Ordinal);
        Assert.Equal(1, f.Requests);
        Assert.Null(r.Best);
    }

    [Fact]
    public async Task Spoofed_origin_is_ignored_and_the_real_reply_used()
    {
        await using var f = new NtpFixture { Spoof = true, Skew = TimeSpan.FromSeconds(2) };
        var r = await NtpChecker.QueryAsync("127.0.0.1", Fast(f), null, Ct);
        var s = Assert.Single(r.Samples);
        Assert.Equal(NtpOutcome.Ok, s.Outcome);
        Assert.Equal(1, s.IgnoredReplies);
        Assert.InRange(s.Offset!.Value.TotalSeconds, 1.95, 2.05);
    }

    [Fact]
    public async Task Unsynchronized_server_is_not_trusted()
    {
        await using var f = new NtpFixture { Unsynchronized = true };
        var r = await NtpChecker.QueryAsync("127.0.0.1", Fast(f), null, Ct);
        Assert.Equal(NtpOutcome.Invalid, r.Samples.Single().Outcome);
        Assert.Null(r.Best);
    }

    [Fact]
    public async Task Silent_server_times_out_closed_port_is_unreachable_and_cancel_is_reported()
    {
        await using var f = new NtpFixture { Silent = true };
        var t = await NtpChecker.QueryAsync("127.0.0.1", Fast(f) with { Timeout = TimeSpan.FromMilliseconds(400) }, null, Ct);
        Assert.Equal(NtpOutcome.Timeout, t.Samples.Single().Outcome);

        var closed = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)closed.Client.LocalEndPoint!).Port;
        closed.Dispose();
        var u = await NtpChecker.QueryAsync("127.0.0.1", new NtpOptions { Port = port, Samples = 1, Timeout = TimeSpan.FromSeconds(2) }, null, Ct);
        Assert.Contains(u.Samples.Single().Outcome, new[] { NtpOutcome.Unreachable, NtpOutcome.Timeout });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(150);
        var c = await NtpChecker.QueryAsync("127.0.0.1", Fast(f) with { Timeout = TimeSpan.FromSeconds(10) }, null, cts.Token);
        Assert.Equal(NtpOutcome.Cancelled, c.Samples.Single().Outcome);
    }
}

public class HostPortTests
{
    [Theory]
    [InlineData("ntp.lab.test:1123", "ntp.lab.test", 1123)]
    [InlineData("192.0.2.5:123", "192.0.2.5", 123)]
    [InlineData("[2001:db8::1]:5123", "2001:db8::1", 5123)]
    public void Explicit_ports_are_split(string input, string host, int port) => Assert.Equal((host, port), HostPort.Split(input));

    [Theory]
    [InlineData("ntp.lab.test")]
    [InlineData("2001:db8::1")]
    [InlineData("host:0")]
    [InlineData("host:70000")]
    [InlineData("")]
    public void Bare_hosts_and_invalid_ports_use_the_default(string input) => Assert.Null(HostPort.Split(input));
}
