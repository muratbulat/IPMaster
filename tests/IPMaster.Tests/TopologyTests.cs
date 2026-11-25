using System.Net;
using System.Text;
using IPMaster.Core.Tools;

namespace IPMaster.Tests;

/// <summary>LLDP/CDP parsing and topology reconciliation (D-092): synthetic MIB values only.</summary>
public class TopologyTests
{
    private static MibValue S(string oid, string text) => new(oid, text, Encoding.ASCII.GetBytes(text));

    private static MibValue N(string oid, ulong n) => new(oid, n.ToString(System.Globalization.CultureInfo.InvariantCulture), null, n);

    private static MibValue B(string oid, params byte[] b) => new(oid, Convert.ToHexString(b), b);

    private const string Rem = NeighborParsers.LldpRemTable;
    private const string Loc = NeighborParsers.LldpLocPortTable;

    /// <summary>Switch A port 1 ("Gi1/0/1") sees switch B (chassis MAC 00:aa:bb:cc:dd:02) on its "Gi1/0/48", mgmt 10.0.0.2.</summary>
    private static List<MibValue> SwitchALldp() =>
    [
        N($"{Loc}.2.1", 7), S($"{Loc}.3.1", "1"), S($"{Loc}.4.1", "Gi1/0/1"),
        N($"{Rem}.4.0.1.1", 4), B($"{Rem}.5.0.1.1", 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0x02),
        N($"{Rem}.6.0.1.1", 5), S($"{Rem}.7.0.1.1", "Gi1/0/48"), S($"{Rem}.8.0.1.1", "uplink"),
        S($"{Rem}.9.0.1.1", "sw-b"), S($"{Rem}.10.0.1.1", "Lab switch B"), B($"{Rem}.12.0.1.1", 0x28), // bridge + router
        N($"{NeighborParsers.LldpRemManAddrTable}.3.0.1.1.1.4.10.0.0.2", 2),
    ];

    [Fact]
    public void Lldp_neighbour_with_mac_chassis_port_name_capabilities_and_management_address()
    {
        var e = Assert.Single(NeighborParsers.Lldp(SwitchALldp()));
        Assert.Equal((NeighborProtocol.Lldp, "Gi1/0/1", "00:aa:bb:cc:dd:02", "sw-b", "Gi1/0/48", "uplink"), (e.Protocol, e.LocalPort, e.RemoteDeviceId, e.RemoteName, e.RemotePort, e.RemotePortDescription));
        Assert.Equal("bridge, router", e.Capabilities);
        Assert.Equal(IPAddress.Parse("10.0.0.2"), Assert.Single(e.ManagementAddresses));
    }

    [Fact]
    public void Malformed_rows_are_skipped()
    {
        List<MibValue> bad =
        [
            S($"{Rem}.9.0.1", "too few index arcs"),
            N($"{NeighborParsers.LldpRemManAddrTable}.3.0.1.1.1.4.10.0", 2), // address shorter than its length
            N($"{Rem}.4.0.2.1", 4), // neither chassis nor name
        ];
        Assert.Empty(NeighborParsers.Lldp(bad));
    }

    [Fact]
    public void Cdp_neighbour_with_ip_address_and_local_port_name()
    {
        var cdp = NeighborParsers.CdpCacheTable;
        List<MibValue> values = [N($"{cdp}.3.10101.1", 1), B($"{cdp}.4.10101.1", 10, 0, 0, 9), S($"{cdp}.6.10101.1", "phone-12.lab"), S($"{cdp}.7.10101.1", "Port 1"), S($"{cdp}.8.10101.1", "Cisco IP Phone 8841")];
        var e = Assert.Single(NeighborParsers.Cdp(values, new Dictionary<string, string> { ["10101"] = "Gi1/0/1" }));
        Assert.Equal((NeighborProtocol.Cdp, "Gi1/0/1", "phone-12.lab", "Port 1", "Cisco IP Phone 8841"), (e.Protocol, e.LocalPort, e.RemoteName, e.RemotePort, e.RemoteDescription));
        Assert.Equal(IPAddress.Parse("10.0.0.9"), Assert.Single(e.ManagementAddresses));
    }

    [Fact]
    public void Link_seen_from_both_ends_is_merged_and_reconciled_by_chassis()
    {
        var a = new DeviceReport("10.0.0.1", "sw-a", "00:aa:bb:cc:dd:01", NeighborParsers.Lldp(SwitchALldp()));
        var b = new DeviceReport("10.0.0.2", "sw-b", "00:aa:bb:cc:dd:02",
        [
            new NeighborEntry(NeighborProtocol.Lldp, "GigabitEthernet1/0/48", "00:aa:bb:cc:dd:01", "sw-a", "GigabitEthernet1/0/1", "", "", [], ""),
            new NeighborEntry(NeighborProtocol.Lldp, "Gi1/0/2", "server-7", "server-7", "eno1", "", "", [], ""),
        ]);
        var g = TopologyBuilder.Build([a, b]);
        Assert.Equal(3, g.Nodes.Count); // sw-a, sw-b (reported by a and queried itself: one node), server-7
        Assert.Equal(2, g.Nodes.Count(n => n.State == NodeState.Queried));
        Assert.Equal(NodeState.Unresolved, g.Nodes.Single(n => n.Name == "server-7").State);
        var ab = Assert.Single(g.Links, l => l.ToPort is "Gi1/0/48" or "GigabitEthernet1/0/48");
        Assert.Equal(LinkEvidence.BothEnds, ab.Evidence); // long and short port names are the same port
        Assert.Equal(LinkEvidence.OneEnd, Assert.Single(g.Links, l => l.ToPort == "eno1").Evidence);
        Assert.Equal(2, g.Links.Count);
    }

    [Fact]
    public void Failed_query_and_name_reconciliation()
    {
        var a = new DeviceReport("10.0.0.1", "core", "", [new NeighborEntry(NeighborProtocol.Cdp, "Te1/1", "EDGE-1", "EDGE-1", "Te0/1", "", "", [IPAddress.Parse("10.0.0.5")], "")]);
        var edge = new DeviceReport("10.0.0.5", "", "", [], "No answer from 10.0.0.5:161 within 3 s.");
        var g = TopologyBuilder.Build([a, edge]);
        Assert.Equal(2, g.Nodes.Count); // same device by management address
        var e = g.Nodes.Single(n => n.Addresses.Contains("10.0.0.5"));
        Assert.Equal((NodeState.QueryFailed, "EDGE-1"), (e.State, e.Name));
        Assert.Equal(LinkEvidence.OneEnd, Assert.Single(g.Links).Evidence);
    }

    private static Dictionary<string, Lextm.SharpSnmpLib.ISnmpData> Agent(string name, byte last, string localPort, string remoteName, byte remoteLast, string remotePort, string? mgmt)
    {
        var d = new Dictionary<string, Lextm.SharpSnmpLib.ISnmpData>
        {
            ["1.3.6.1.2.1.1.5.0"] = new Lextm.SharpSnmpLib.OctetString(name),
            [NeighborParsers.LldpLocChassisSubtype] = new Lextm.SharpSnmpLib.Integer32(4),
            [NeighborParsers.LldpLocChassisId] = new Lextm.SharpSnmpLib.OctetString([0, 0xaa, 0xbb, 0xcc, 0xdd, last]),
            [$"{Loc}.4.1"] = new Lextm.SharpSnmpLib.OctetString(localPort),
            [$"{Rem}.4.0.1.1"] = new Lextm.SharpSnmpLib.Integer32(4),
            [$"{Rem}.5.0.1.1"] = new Lextm.SharpSnmpLib.OctetString([0, 0xaa, 0xbb, 0xcc, 0xdd, remoteLast]),
            [$"{Rem}.6.0.1.1"] = new Lextm.SharpSnmpLib.Integer32(5),
            [$"{Rem}.7.0.1.1"] = new Lextm.SharpSnmpLib.OctetString(remotePort),
            [$"{Rem}.9.0.1.1"] = new Lextm.SharpSnmpLib.OctetString(remoteName),
        };
        if (mgmt is not null) d[$"{NeighborParsers.LldpRemManAddrTable}.3.0.1.1.1.4.{mgmt}"] = new Lextm.SharpSnmpLib.Integer32(2);
        return d;
    }

    [Fact]
    public async Task Explore_follows_management_addresses_and_sees_the_link_from_both_ends()
    {
        await using var a = new SnmpLabAgent("lab", Agent("sw-a", 1, "Gi1/0/1", "sw-b", 2, "Gi1/0/48", "127.0.0.2"));
        await using var b = new SnmpLabAgent("lab", Agent("sw-b", 2, "Gi1/0/48", "sw-a", 1, "Gi1/0/1", null));
        IPMaster.Infrastructure.Queries.SnmpTarget For(IPAddress ip) => new(new IPEndPoint(IPAddress.Loopback, ip.Equals(IPAddress.Parse("127.0.0.2")) ? b.Port : a.Port),
            IPMaster.Core.Queries.SnmpVersion.V2c, ["lab"], "", IPMaster.Core.Queries.SnmpSecurity.NoAuthNoPriv, IPMaster.Core.Queries.SnmpAuth.Sha1, "", IPMaster.Core.Queries.SnmpPriv.Aes128, "");
        var ct = TestContext.Current.CancellationToken;

        var onlySeed = await IPMaster.Infrastructure.Tools.TopologyCollector.ExploreAsync([IPAddress.Loopback], For, follow: false, 10, TimeSpan.FromSeconds(2), null, ct);
        Assert.Single(onlySeed); // not following: B is not queried
        Assert.Equal(NodeState.Unresolved, TopologyBuilder.Build(onlySeed).Nodes.Single(n => n.Name == "sw-b").State);

        var reports = await IPMaster.Infrastructure.Tools.TopologyCollector.ExploreAsync([IPAddress.Loopback], For, follow: true, 10, TimeSpan.FromSeconds(2), null, ct);
        Assert.Equal(["sw-a", "sw-b"], reports.Select(r => r.Name));
        Assert.Equal("00:aa:bb:cc:dd:01", reports[0].ChassisId);
        var g = TopologyBuilder.Build(reports);
        Assert.Equal(2, g.Nodes.Count);
        Assert.All(g.Nodes, n => Assert.Equal(NodeState.Queried, n.State));
        Assert.Equal(LinkEvidence.BothEnds, Assert.Single(g.Links).Evidence);
    }

    [Fact]
    public void Shared_address_does_not_merge_devices_with_different_chassis()
    {
        // two routers answering on the same virtual (VRRP) address
        var r1 = new DeviceReport("10.0.0.254", "rtr-1", "00:aa:bb:cc:dd:01", []);
        var r2 = new DeviceReport("10.0.0.254", "rtr-2", "00:aa:bb:cc:dd:02", []);
        Assert.Equal(2, TopologyBuilder.Build([r1, r2]).Nodes.Count);
    }

    [Fact]
    public void Dot_export_marks_one_sided_links_and_unresolved_nodes()
    {
        var a = new DeviceReport("10.0.0.1", "sw \"a\"", "", [new NeighborEntry(NeighborProtocol.Lldp, "1", "x", "x", "2", "", "", [], "")]);
        var dot = TopologyBuilder.ToDot(TopologyBuilder.Build([a]));
        Assert.Contains("\"sw \\\"a\\\"\\n10.0.0.1\"", dot, StringComparison.Ordinal);
        Assert.Contains("style=dashed];", dot, StringComparison.Ordinal);
        Assert.StartsWith("graph topology {", dot, StringComparison.Ordinal);
    }
}
