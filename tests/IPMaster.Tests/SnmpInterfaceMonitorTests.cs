using System.Net;
using IPMaster.Core.Queries;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Tools;
using Lextm.SharpSnmpLib;

namespace IPMaster.Tests;

/// <summary>SNMP Interface Monitor (D-091) against the loopback lab agent; no real device is queried.</summary>
public class SnmpInterfaceMonitorTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(2);

    private static Dictionary<string, ISnmpData> Switch() => new()
    {
        ["1.3.6.1.2.1.1.3.0"] = new TimeTicks(100_000),
        // port 1: gigabit with 64-bit counters and ifXTable names
        ["1.3.6.1.2.1.2.2.1.2.1"] = new OctetString("GigabitEthernet1/0/1"),
        ["1.3.6.1.2.1.2.2.1.5.1"] = new Gauge32(1_000_000_000),
        ["1.3.6.1.2.1.2.2.1.6.1"] = new OctetString([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]),
        ["1.3.6.1.2.1.2.2.1.7.1"] = new Integer32(1),
        ["1.3.6.1.2.1.2.2.1.8.1"] = new Integer32(1),
        ["1.3.6.1.2.1.2.2.1.13.1"] = new Counter32(0),
        ["1.3.6.1.2.1.2.2.1.14.1"] = new Counter32(5),
        ["1.3.6.1.2.1.2.2.1.19.1"] = new Counter32(0),
        ["1.3.6.1.2.1.2.2.1.20.1"] = new Counter32(0),
        ["1.3.6.1.2.1.31.1.1.1.1.1"] = new OctetString("Gi1/0/1"),
        ["1.3.6.1.2.1.31.1.1.1.6.1"] = new Counter64(1_000_000),
        ["1.3.6.1.2.1.31.1.1.1.10.1"] = new Counter64(2_000_000),
        ["1.3.6.1.2.1.31.1.1.1.15.1"] = new Gauge32(1000),
        ["1.3.6.1.2.1.31.1.1.1.18.1"] = new OctetString("uplink to core"),
        // port 2: old 10 Mbit/s port, 32-bit counters only
        ["1.3.6.1.2.1.2.2.1.2.2"] = new OctetString("FastEthernet0/2"),
        ["1.3.6.1.2.1.2.2.1.5.2"] = new Gauge32(10_000_000),
        ["1.3.6.1.2.1.2.2.1.7.2"] = new Integer32(1),
        ["1.3.6.1.2.1.2.2.1.8.2"] = new Integer32(2),
        ["1.3.6.1.2.1.2.2.1.10.2"] = new Counter32(100),
        ["1.3.6.1.2.1.2.2.1.16.2"] = new Counter32(200),
    };

    private static SnmpTarget Target(SnmpLabAgent a) =>
        new(new IPEndPoint(IPAddress.Loopback, a.Port), Core.Queries.SnmpVersion.V2c, ["lab-ro"], "", SnmpSecurity.NoAuthNoPriv, SnmpAuth.Sha1, "", SnmpPriv.Aes128, "");

    [Fact]
    public async Task Discovers_interfaces_with_names_aliases_speeds_and_counter_width()
    {
        await using var agent = new SnmpLabAgent("lab-ro", Switch());
        var ifs = await SnmpInterfaceMonitor.DiscoverAsync(Target(agent), Timeout, Ct);
        Assert.Equal(2, ifs.Count);
        var gi = ifs[0];
        Assert.Equal(("Gi1/0/1", "GigabitEthernet1/0/1", "uplink to core", "00-11-22-33-44-01"), (gi.Name, gi.Description, gi.Alias, gi.Mac));
        Assert.Equal((1_000_000_000UL, "up", "up", true), (gi.SpeedBitsPerSecond, gi.AdminStatus, gi.OperStatus, gi.HighCapacity));
        var fa = ifs[1];
        Assert.Equal(("FastEthernet0/2", 10_000_000UL, "down", false), (fa.Label, fa.SpeedBitsPerSecond, fa.OperStatus, fa.HighCapacity));
    }

    [Fact]
    public async Task Two_polls_give_rates_from_the_agent_clock()
    {
        await using var agent = new SnmpLabAgent("lab-ro", Switch());
        var target = Target(agent);
        var ifs = await SnmpInterfaceMonitor.DiscoverAsync(target, Timeout, Ct);
        var first = await SnmpInterfaceMonitor.PollAsync(target, ifs, Timeout, Ct);
        Assert.Equal((1_000_000UL, 100_000u, true), (first[0].InOctets!.Value, first[0].UpTime!.Value, first[0].HighCapacity));
        Assert.Equal(100UL, first[1].InOctets);

        agent.Set("1.3.6.1.2.1.1.3.0", new TimeTicks(101_000)); // 10 s later on the agent
        agent.Set("1.3.6.1.2.1.31.1.1.1.6.1", new Counter64(1_000_000 + 125_000_000)); // 100 Mbit/s in
        agent.Set("1.3.6.1.2.1.2.2.1.14.1", new Counter32(25)); // 2 errors/s
        agent.Set("1.3.6.1.2.1.2.2.1.10.2", new Counter32(50)); // 32-bit counter went backwards on a 10 Mbit/s port: implausible wrap
        var second = await SnmpInterfaceMonitor.PollAsync(target, ifs, Timeout, Ct);

        var gi = InterfaceRates.Compute(first[0], second[0]);
        Assert.Equal(RateStatus.Ok, gi.Status);
        Assert.Equal(100e6, gi.InBitsPerSecond!.Value, 3);
        Assert.Equal(10, gi.InUtilisation!.Value, 3);
        Assert.Equal(0, gi.OutBitsPerSecond!.Value, 3);
        Assert.Equal(2, gi.InErrorsPerSecond!.Value, 3);
        Assert.Equal(RateStatus.Discontinuity, InterfaceRates.Compute(first[1], second[1]).Status);
    }

    [Fact]
    public async Task Agent_without_interfaces_is_reported()
    {
        await using var agent = new SnmpLabAgent("lab-ro", new Dictionary<string, ISnmpData> { ["1.3.6.1.2.1.1.1.0"] = new OctetString("printer") });
        var ex = await Assert.ThrowsAsync<IPMaster.Infrastructure.Queries.SnmpException>(() => SnmpInterfaceMonitor.DiscoverAsync(Target(agent), Timeout, Ct));
        Assert.Contains("no IF-MIB interfaces", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Failures_are_explained_in_words()
    {
        var v2 = new SnmpTarget(new IPEndPoint(IPAddress.Loopback, 161), SnmpVersion.V2c, ["x"], "", SnmpSecurity.NoAuthNoPriv, SnmpAuth.Sha1, "", SnmpPriv.Aes128, "");
        var closed = new IPMaster.Infrastructure.Queries.SnmpException("An existing connection was forcibly closed by the remote host.", Core.Scanning.ObservationState.NoResponse);
        var text = SnmpInterfaceMonitor.Explain(closed, v2, TimeSpan.FromSeconds(1));
        Assert.StartsWith("No answer from 127.0.0.1:161 within 1 s", text, StringComparison.Ordinal);
        Assert.Contains("wrong community", text, StringComparison.Ordinal);
        Assert.DoesNotContain("community", SnmpInterfaceMonitor.Explain(new OperationCanceledException(), v2 with { Version = SnmpVersion.V3 }, TimeSpan.FromSeconds(3)), StringComparison.Ordinal);
        Assert.Equal("authorizationError", SnmpInterfaceMonitor.Explain(new IPMaster.Infrastructure.Queries.SnmpException("authorizationError", Core.Scanning.ObservationState.AccessDenied), v2, TimeSpan.FromSeconds(1)));
    }

    [Fact]
    public async Task Only_get_and_walk_requests_are_sent()
    {
        await using var agent = new SnmpLabAgent("lab-ro", Switch());
        var ifs = await SnmpInterfaceMonitor.DiscoverAsync(Target(agent), Timeout, Ct);
        await SnmpInterfaceMonitor.PollAsync(Target(agent), ifs, Timeout, Ct);
        Assert.All(agent.Pdus, p => Assert.Contains(p, new[] { SnmpType.GetRequestPdu, SnmpType.GetNextRequestPdu, SnmpType.GetBulkRequestPdu }));
    }
}
