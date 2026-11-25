using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Configuration;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Tests;

public class DiscoveryTargetTests
{
    [Fact]
    public void All_nodes_with_scope_is_neighbor_discovery()
    {
        Assert.True(TargetParser.TryParse("ff02::1%12", out var spec, out _));
        Assert.Equal(TargetKind.NeighborDiscovery, spec.Kind);
        Assert.Equal(12, spec.Start.ScopeId);
        Assert.False(TargetParser.TryParse("ff02::1", out _, out var error));
        Assert.Contains("scope", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Planner_discovers_responders_on_the_interface()
    {
        var mac = PhysicalAddress.Parse("00-11-22-33-44-55");
        var neighbors = new FakeNeighbors(
            new NeighborEntry(IPAddress.Parse("fe80::a%12"), mac, 12, false),
            new NeighborEntry(IPAddress.Parse("fe80::b"), mac, 12, false),           // scope filled in from the interface
            new NeighborEntry(IPAddress.Parse("fe80::c%9"), mac, 9, false),          // other interface
            new NeighborEntry(IPAddress.Parse("10.0.0.1"), mac, 12, false));         // IPv4
        var icmp = new FakeIcmp();
        var planner = new ScanPlanner(new FakeAdapters(), new FakeDns(), icmp, neighbors) { DiscoveryWait = TimeSpan.Zero };
        Assert.True(TargetParser.TryParse("ff02::1%12", out var spec, out _));
        var built = await planner.PlanAsync([spec], new AppSettings(), confirmed: true);
        Assert.Equal(["fe80::a%12", "fe80::b%12"], built.Plan.Addresses());
        Assert.True(icmp.Calls >= 1);
    }

    [Fact]
    public async Task Exclude_set_skips_already_discovered_addresses()
    {
        var exclude = new HashSet<AddressKey> { AddressKey.From(IPAddress.Parse("10.0.0.2")) };
        var planner = new ScanPlanner(new FakeAdapters(), new FakeDns());
        Assert.True(TargetParser.TryParse("10.0.0.1-10.0.0.3", out var spec, out _));
        var built = await planner.PlanAsync([spec], new AppSettings(), confirmed: true, exclude);
        Assert.Equal(["10.0.0.1", "10.0.0.3"], built.Plan.Addresses());
    }
}
