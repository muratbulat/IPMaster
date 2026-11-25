using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Discovery;

namespace IPMaster.Tests;

/// <summary>DHCP diagnostics (D-095): offer comparison and assessment on synthetic offers; nothing is sent.</summary>
public class DhcpDiagnosticsTests
{
    private static DhcpOffer Offer(string server, string gateway, string dns, string mask = "255.255.255.0", double ms = 20) => new()
    {
        ServerAddress = IPAddress.Parse(server), ServerIdentifier = IPAddress.Parse(server), OfferedAddress = IPAddress.Parse("192.0.2.50"),
        ResponseTime = TimeSpan.FromMilliseconds(ms),
        Options = new Dictionary<byte, byte[]>
        {
            [1] = IPAddress.Parse(mask).GetAddressBytes(), [3] = IPAddress.Parse(gateway).GetAddressBytes(), [6] = IPAddress.Parse(dns).GetAddressBytes(),
            [54] = IPAddress.Parse(server).GetAddressBytes(),
        },
    };

    [Fact]
    public void One_expected_server_is_fine()
    {
        var f = DhcpDiagnostics.Assess([Offer("192.0.2.1", "192.0.2.1", "192.0.2.53")], [IPAddress.Parse("192.0.2.1")]);
        Assert.Equal(["One DHCP server answered: 192.0.2.1."], f);
    }

    [Fact]
    public void Unexpected_server_is_a_suspicion_and_differences_are_listed()
    {
        var legit = Offer("192.0.2.1", "192.0.2.1", "192.0.2.53");
        var rogue = Offer("192.0.2.77", "192.0.2.77", "8.8.8.8", ms: 1500);
        var f = DhcpDiagnostics.Assess([legit, rogue], [IPAddress.Parse("192.0.2.1")]);
        Assert.Contains(f, x => x.StartsWith("2 DHCP servers answer", StringComparison.Ordinal));
        Assert.Contains(f, x => x.Contains("192.0.2.77 is not on the expected list: a suspected rogue", StringComparison.Ordinal) && x.Contains("verify", StringComparison.Ordinal));
        Assert.Contains(f, x => x.StartsWith("Servers hand out different router", StringComparison.Ordinal));
        Assert.Contains(f, x => x.StartsWith("Servers hand out different dns servers", StringComparison.Ordinal));
        Assert.Contains(f, x => x.Contains("answered after 1,500 ms", StringComparison.Ordinal) || x.Contains("answered after 1.500 ms", StringComparison.Ordinal));

        var cmp = DhcpDiagnostics.Compare([legit, rogue]);
        Assert.True(cmp.Single(d => d.Code == 3).Differs);
        Assert.False(cmp.Single(d => d.Code == 1).Differs); // same mask
        Assert.DoesNotContain(cmp, d => d.Code is 53 or 54);
    }

    [Fact]
    public void Several_servers_without_an_expected_list_ask_for_one()
    {
        var f = DhcpDiagnostics.Assess([Offer("192.0.2.1", "192.0.2.1", "192.0.2.53"), Offer("192.0.2.2", "192.0.2.1", "192.0.2.53")], []);
        Assert.Contains(f, x => x.StartsWith("Several servers answer: enter the expected", StringComparison.Ordinal));
        Assert.Equal(["No DHCP server answered."], DhcpDiagnostics.Assess([], []));
    }

    [Fact]
    public void Passively_seen_ack_becomes_a_row()
    {
        var ack = new DhcpMessage
        {
            Op = 2, ClientMac = PhysicalAddress.Parse("00-11-22-33-44-55"), YourAddress = IPAddress.Parse("192.0.2.60"),
            Options = new Dictionary<byte, byte[]> { [53] = [(byte)DhcpMessageType.Ack], [54] = IPAddress.Parse("192.0.2.1").GetAddressBytes(), [51] = [0, 0, 0x0E, 0x10], [15] = "lab\0"u8.ToArray() },
        };
        var row = DhcpOffer.FromReply(DhcpMessage.Parse(ack.Serialize())!, IPAddress.Parse("192.0.2.1"));
        Assert.Equal(("ACK", "00-11-22-33-44-55", "192.0.2.60", "192.0.2.1"), (row.MessageType, row.ClientMac, row.OfferedAddress.ToString(), row.ServerDisplay));
        Assert.Equal((TimeSpan.FromHours(1), "lab"), (row.LeaseTime!.Value, row.DomainName));
        Assert.Null(row.ResponseTime);
    }
}
