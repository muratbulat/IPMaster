using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Discovery;

namespace IPMaster.Tests;

/// <summary>Passive discovery parsing and merging (D-090): synthetic frames only, nothing is captured or sent.</summary>
public class DeviceDiscoveryTests
{
    private static readonly DateTimeOffset T = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly PhysicalAddress Bmc = PhysicalAddress.Parse("94-40-C9-12-34-56");

    private static byte[] Arp(ushort op, IPAddress sender, IPAddress target)
    {
        var f = ArpFrame.Request(Bmc, sender, target);
        BinaryPrimitives.WriteUInt16BigEndian(f.AsSpan(20), op);
        return f;
    }

    private static byte[] Ethernet(ushort type, byte[] payload, bool vlan = false)
    {
        var head = new List<byte>(new byte[6]);
        head.AddRange(Bmc.GetAddressBytes());
        if (vlan) head.AddRange(new byte[] { 0x81, 0x00, 0x00, 0x0A });
        head.Add((byte)(type >> 8));
        head.Add((byte)type);
        head.AddRange(payload);
        return head.ToArray();
    }

    private static byte[] Ipv4(IPAddress source, byte protocol, byte[] payload)
    {
        var ip = new byte[20];
        ip[0] = 0x45;
        ip[9] = protocol;
        source.GetAddressBytes().CopyTo(ip, 12);
        IPAddress.Broadcast.GetAddressBytes().CopyTo(ip, 16);
        return [.. ip, .. payload];
    }

    private static byte[] Udp(ushort sport, ushort dport, byte[] payload)
    {
        var u = new byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(u, sport);
        BinaryPrimitives.WriteUInt16BigEndian(u.AsSpan(2), dport);
        return [.. u, .. payload];
    }

    [Fact]
    public void Arp_reply_and_gratuitous_arp_are_observed_addresses()
    {
        var reply = Assert.Single(FrameObservations.FromFrame(Arp(2, IPAddress.Parse("172.20.30.45"), IPAddress.Parse("172.20.30.1")), T));
        Assert.Equal((Bmc, IPAddress.Parse("172.20.30.45"), IpAssignment.Observed), (reply.Mac, reply.Address, reply.Assignment));
        var announce = Assert.Single(FrameObservations.FromFrame(Arp(1, IPAddress.Parse("172.20.30.45"), IPAddress.Parse("172.20.30.45")), T));
        Assert.Contains("gratuitous", announce.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Arp_probe_is_probing_not_in_use()
    {
        var probe = Assert.Single(FrameObservations.FromFrame(Arp(1, IPAddress.Any, IPAddress.Parse("192.168.0.120")), T));
        Assert.Equal((IPAddress.Parse("192.168.0.120"), IpAssignment.Probing), (probe.Address, probe.Assignment));
    }

    [Fact]
    public void Ipv4_source_and_dhcp_inside_udp_are_recognised_also_with_a_vlan_tag()
    {
        var plain = Assert.Single(FrameObservations.FromFrame(Ethernet(0x0800, Ipv4(IPAddress.Parse("10.5.5.9"), 6, new byte[20]), vlan: true), T));
        Assert.Equal((IPAddress.Parse("10.5.5.9"), DiscoverySource.Ipv4), (plain.Address, plain.Source));

        var dhcp = new DhcpMessage
        {
            Op = 1,
            ClientMac = Bmc,
            Options = new Dictionary<byte, byte[]>
            {
                [53] = [(byte)DhcpMessageType.Discover], [50] = IPAddress.Parse("10.20.0.17").GetAddressBytes(),
                [12] = "ILOCZ1234"u8.ToArray(), [60] = "CPQRIB3"u8.ToArray(),
            },
        }.Serialize();
        var o = Assert.Single(FrameObservations.FromFrame(Ethernet(0x0800, Ipv4(IPAddress.Any, 17, Udp(68, 67, dhcp))), T));
        Assert.Equal((IpAssignment.DhcpRequested, "ILOCZ1234", "CPQRIB3"), (o.Assignment, o.HostName, o.VendorClass));
        Assert.Contains("possibly from another network", o.Evidence, StringComparison.Ordinal);
    }

    [Fact]
    public void Ipv6_neighbour_advertisement_and_dad_probe()
    {
        static byte[] Icmp6(IPAddress source, byte type, IPAddress target)
        {
            var ip = new byte[40 + 24];
            ip[0] = 0x60;
            ip[6] = 58;
            source.GetAddressBytes().CopyTo(ip, 8);
            ip[40] = type;
            target.GetAddressBytes().CopyTo(ip, 48);
            return ip;
        }

        var ll = IPAddress.Parse("fe80::9640:c9ff:fe12:3456");
        var na = FrameObservations.FromFrame(Ethernet(0x86DD, Icmp6(ll, 136, ll)), T);
        Assert.Contains(na, x => x.Assignment == IpAssignment.Observed && x.Address!.Equals(ll));
        var dad = Assert.Single(FrameObservations.FromFrame(Ethernet(0x86DD, Icmp6(IPAddress.IPv6Any, 135, ll)), T));
        Assert.Equal(IpAssignment.Probing, dad.Assignment);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(13)]
    [InlineData(20)]
    [InlineData(30)]
    public void Truncated_frames_give_no_observation(int length)
    {
        var frame = Ethernet(0x0800, Ipv4(IPAddress.Parse("10.5.5.9"), 17, Udp(68, 67, new byte[300])));
        Assert.Empty(FrameObservations.FromFrame(frame.AsSpan(0, Math.Min(length, frame.Length)), T));
        Assert.Empty(FrameObservations.FromFrame(Arp(2, IPAddress.Parse("10.0.0.1"), IPAddress.Any).AsSpan(0, 30), T));
    }

    [Fact]
    public void Book_merges_per_mac_prefers_stronger_evidence_and_ignores_own_and_multicast_macs()
    {
        var own = PhysicalAddress.Parse("00-00-00-AA-BB-CC");
        var book = new DiscoveryBook([own]);
        var ip = IPAddress.Parse("192.168.88.100");
        Assert.True(book.Add(new(T, Bmc, ip, DiscoverySource.Dhcp, IpAssignment.DhcpRequested, "asks", "ILO1")));
        Assert.True(book.Add(new(T.AddSeconds(5), Bmc, ip, DiscoverySource.Arp, IpAssignment.Observed, "arp reply")));
        Assert.False(book.Add(new(T.AddSeconds(6), Bmc, ip, DiscoverySource.Arp, IpAssignment.Probing, "probe"))); // weaker: kept Observed
        Assert.False(book.Add(new(T, own, IPAddress.Parse("192.168.88.1"), DiscoverySource.Arp, IpAssignment.Observed, "me")));
        Assert.False(book.Add(new(T, PhysicalAddress.Parse("01-00-5E-00-00-01"), ip, DiscoverySource.Ipv4, IpAssignment.Observed, "multicast")));

        var d = Assert.Single(book.Devices);
        Assert.Equal(("ILO1", IpAssignment.Observed, T.AddSeconds(6)), (d.HostName, d.Best!.Assignment, d.LastSeen));
        Assert.Equal(new HashSet<DiscoverySource> { DiscoverySource.Dhcp, DiscoverySource.Arp }, d.Sources);
    }

    [Fact]
    public void Book_is_bounded()
    {
        var book = new DiscoveryBook();
        for (var i = 0; i < DiscoveryBook.MaxAddresses + 3; i++)
        {
            book.Add(new(T, Bmc, IPAddress.Parse($"10.0.0.{i + 1}"), DiscoverySource.Ipv4, IpAssignment.Observed, "x"));
        }

        Assert.Equal(DiscoveryBook.MaxAddresses, book.Devices.Single().Addresses.Count);
        Assert.Equal(3, book.Dropped);
    }

    [Fact]
    public void Server_ack_becomes_an_assigned_address()
    {
        var e = new DhcpEvent(T, DhcpEventKind.Acknowledged, Bmc, IPAddress.Parse("192.168.88.100"), "ACK 192.168.88.100");
        Assert.Equal(IpAssignment.DhcpAssigned, FrameObservations.FromServerEvent(e)!.Assignment);
        Assert.Null(FrameObservations.FromServerEvent(e with { Kind = DhcpEventKind.Offered }));
    }
}
