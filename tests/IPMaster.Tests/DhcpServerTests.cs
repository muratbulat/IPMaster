using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Discovery;

namespace IPMaster.Tests;

/// <summary>Isolated DHCP server lease logic (D-090). Pure: no sockets, no network traffic.</summary>
public class DhcpServerTests
{
    private sealed class ManualClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static readonly IPAddress Server = IPAddress.Parse("192.168.88.1");

    private static DhcpServerConfig Config(string start = "192.168.88.100", string end = "192.168.88.110") => new()
    {
        ServerAddress = Server,
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        PoolStart = IPAddress.Parse(start),
        PoolEnd = IPAddress.Parse(end),
    };

    private static PhysicalAddress Mac(int n) => PhysicalAddress.Parse($"00-11-22-33-44-{n:X2}");

    private static DhcpMessage Client(DhcpMessageType type, int mac, IPAddress? requested = null, IPAddress? server = null, IPAddress? ciaddr = null,
        byte[]? clientId = null, string? host = null, uint xid = 0x1234)
    {
        var o = new Dictionary<byte, byte[]> { [53] = [(byte)type] };
        if (requested is not null) o[50] = requested.GetAddressBytes();
        if (server is not null) o[54] = server.GetAddressBytes();
        if (clientId is not null) o[61] = clientId;
        if (host is not null) o[12] = System.Text.Encoding.ASCII.GetBytes(host);
        return new DhcpMessage { Op = 1, TransactionId = xid, Flags = 0x8000, ClientMac = Mac(mac), ClientAddress = ciaddr ?? IPAddress.Any, Options = o };
    }

    /// <summary>DISCOVER → OFFER → REQUEST → ACK, as a BMC on a direct cable does it.</summary>
    private static IPAddress Bind(DhcpServerEngine e, int mac, string? host = null)
    {
        var offer = e.Handle(Client(DhcpMessageType.Discover, mac, host: host)).Reply!;
        var ack = e.Handle(Client(DhcpMessageType.Request, mac, offer.YourAddress, Server, host: host)).Reply!;
        Assert.Equal(DhcpMessageType.Ack, ack.Type);
        return ack.YourAddress;
    }

    [Fact]
    public void Discover_offer_request_ack_binds_the_first_pool_address()
    {
        var clock = new ManualClock();
        var e = new DhcpServerEngine(Config(), clock);
        var offer = e.Handle(Client(DhcpMessageType.Discover, 1, host: "ILO-CZ123")).Reply!;
        Assert.Equal(DhcpMessageType.Offer, offer.Type);
        Assert.Equal(IPAddress.Parse("192.168.88.100"), offer.YourAddress);
        Assert.Equal(0x1234u, offer.TransactionId);
        Assert.Equal(Server, offer.ServerIdentifier);
        Assert.Equal(IPAddress.Parse("255.255.255.0"), offer.Address(1));
        Assert.False(offer.Options.ContainsKey(3)); // no default gateway unless configured
        Assert.Equal([0, 0, 0x02, 0x58], offer.Options[51]); // 600 s

        var ack = e.Handle(Client(DhcpMessageType.Request, 1, offer.YourAddress, Server)).Reply!;
        Assert.Equal(DhcpMessageType.Ack, ack.Type);
        var lease = Assert.Single(e.Leases);
        Assert.Equal((DhcpLeaseState.Bound, "ILO-CZ123"), (lease.State, lease.HostName));
        Assert.Equal(clock.Now.AddMinutes(10), lease.Expires);
    }

    [Fact]
    public void Message_round_trips_and_malformed_packets_are_rejected()
    {
        var m = Client(DhcpMessageType.Request, 7, IPAddress.Parse("192.168.88.105"), Server, clientId: [1, 0, 0x11, 0x22, 0x33, 0x44, 0x07], host: "idrac");
        var bytes = m.Serialize();
        Assert.True(bytes.Length >= 300);
        var back = DhcpMessage.Parse(bytes)!;
        Assert.Equal((DhcpMessageType.Request, Mac(7), "idrac"), (back.Type!.Value, back.ClientMac, back.HostName));
        Assert.Equal(IPAddress.Parse("192.168.88.105"), back.RequestedAddress);
        Assert.Equal("id:01001122334407", back.ClientKey);

        Assert.Null(DhcpMessage.Parse(bytes.AsSpan(0, 239))); // truncated header
        var badCookie = (byte[])bytes.Clone();
        badCookie[236] = 0;
        Assert.Null(DhcpMessage.Parse(badCookie));
        var overrun = bytes[..243];
        overrun[240] = 53;
        overrun[241] = 40; // option claims 40 bytes, 1 present
        Assert.Null(DhcpMessage.Parse(overrun));
        var noEnd = bytes[..240].Concat(new byte[] { 53, 1, 1 }).ToArray();
        Assert.Null(DhcpMessage.Parse(noEnd)); // no end option
        var tokenRing = (byte[])bytes.Clone();
        tokenRing[1] = 6;
        Assert.Null(DhcpMessage.Parse(tokenRing));
    }

    [Fact]
    public void Same_client_keeps_its_address_and_clients_never_share_one()
    {
        var e = new DhcpServerEngine(Config());
        var a = Bind(e, 1);
        var b = Bind(e, 2);
        Assert.NotEqual(a, b);
        Assert.Equal(a, Bind(e, 1)); // rediscover: same address
        Assert.Equal(2, e.Leases.Count);
    }

    [Fact]
    public void Client_identifier_is_the_lease_key()
    {
        var e = new DhcpServerEngine(Config());
        byte[] id = [0xFF, 1, 2, 3];
        var offer = e.Handle(Client(DhcpMessageType.Discover, 1, clientId: id)).Reply!;
        e.Handle(Client(DhcpMessageType.Request, 1, offer.YourAddress, Server, clientId: id));
        // same client id from another NIC (e.g. a BMC with a shared/dedicated port): same lease
        var again = e.Handle(Client(DhcpMessageType.Discover, 9, clientId: id)).Reply!;
        Assert.Equal(offer.YourAddress, again.YourAddress);
    }

    [Fact]
    public void Requested_address_is_honoured_when_free_and_refused_when_taken()
    {
        var e = new DhcpServerEngine(Config());
        var offer = e.Handle(Client(DhcpMessageType.Discover, 1, requested: IPAddress.Parse("192.168.88.107"))).Reply!;
        Assert.Equal(IPAddress.Parse("192.168.88.107"), offer.YourAddress);
        e.Handle(Client(DhcpMessageType.Request, 1, offer.YourAddress, Server));

        // INIT-REBOOT of another client asking for the same address: NAK
        var nak = e.Handle(Client(DhcpMessageType.Request, 2, IPAddress.Parse("192.168.88.107"))).Reply!;
        Assert.Equal(DhcpMessageType.Nak, nak.Type);
        Assert.Equal(IPAddress.Any, nak.YourAddress);
        // an address from another network (the device remembers its old site): NAK
        Assert.Equal(DhcpMessageType.Nak, e.Handle(Client(DhcpMessageType.Request, 3, IPAddress.Parse("10.1.1.5"))).Reply!.Type);
        // outside the pool but inside the subnet: NAK, never handed out
        Assert.Equal(DhcpMessageType.Nak, e.Handle(Client(DhcpMessageType.Request, 3, IPAddress.Parse("192.168.88.50"))).Reply!.Type);
    }

    [Fact]
    public void Request_for_another_server_is_ignored_and_frees_the_offer()
    {
        var e = new DhcpServerEngine(Config());
        var offer = e.Handle(Client(DhcpMessageType.Discover, 1)).Reply!;
        var r = e.Handle(Client(DhcpMessageType.Request, 1, IPAddress.Parse("192.168.88.200"), IPAddress.Parse("192.168.88.254")));
        Assert.Null(r.Reply); // never answer for another server (it means a second DHCP server is on this link)
        Assert.Equal(DhcpEventKind.Ignored, r.Event.Kind);
        Assert.Contains("another DHCP server", r.Event.Text, StringComparison.Ordinal);
        Assert.Empty(e.Leases);
        Assert.Equal(offer.YourAddress, e.Handle(Client(DhcpMessageType.Discover, 2)).Reply!.YourAddress);
    }

    [Fact]
    public void Pool_exhaustion_sends_nothing_and_expired_leases_are_reused()
    {
        var clock = new ManualClock();
        var e = new DhcpServerEngine(Config(end: "192.168.88.101"), clock);
        Bind(e, 1);
        Bind(e, 2);
        var full = e.Handle(Client(DhcpMessageType.Discover, 3));
        Assert.Null(full.Reply);
        Assert.Equal(DhcpEventKind.PoolExhausted, full.Event.Kind);

        clock.Now += TimeSpan.FromMinutes(11); // both leases expired
        Assert.NotNull(e.Handle(Client(DhcpMessageType.Discover, 3)).Reply);
        Assert.Equal(DhcpLeaseState.Released, e.Leases.First(l => l.Mac.Equals(Mac(2))).State); // shown as expired
    }

    [Fact]
    public void Unanswered_offer_is_released_after_the_hold_time()
    {
        var clock = new ManualClock();
        var e = new DhcpServerEngine(Config(end: "192.168.88.100"), clock);
        e.Handle(Client(DhcpMessageType.Discover, 1)); // never requests
        Assert.Null(e.Handle(Client(DhcpMessageType.Discover, 2)).Reply);
        clock.Now += DhcpServerEngine.OfferHold;
        Assert.NotNull(e.Handle(Client(DhcpMessageType.Discover, 2)).Reply);
    }

    [Fact]
    public void Release_frees_and_decline_quarantines_the_address()
    {
        var clock = new ManualClock();
        var e = new DhcpServerEngine(Config(end: "192.168.88.101"), clock);
        var a = Bind(e, 1);
        Assert.Equal(DhcpEventKind.Ignored, e.Handle(Client(DhcpMessageType.Release, 2, ciaddr: a, server: Server)).Event.Kind); // not its lease
        Assert.Equal(DhcpEventKind.Released, e.Handle(Client(DhcpMessageType.Release, 1, ciaddr: a, server: Server)).Event.Kind);
        Assert.Equal(a, Bind(e, 2)); // free again

        var b = e.Handle(Client(DhcpMessageType.Discover, 3)).Reply!.YourAddress;
        e.Handle(Client(DhcpMessageType.Request, 3, b, Server));
        var declined = e.Handle(Client(DhcpMessageType.Decline, 3, b, Server));
        Assert.Equal(DhcpEventKind.Declined, declined.Event.Kind); // a static device already uses b
        Assert.Null(e.Handle(Client(DhcpMessageType.Discover, 3)).Reply); // b held back, a taken: nothing left
        clock.Now += TimeSpan.FromMinutes(10);
        Assert.Equal(a, Bind(e, 2)); // client 2 renews its (just expired) lease first
        Assert.Equal(b, e.Handle(Client(DhcpMessageType.Discover, 3)).Reply!.YourAddress); // quarantine over
    }

    [Fact]
    public void Reservation_wins_and_is_never_given_to_another_client()
    {
        var c = Config() with { Reservations = new Dictionary<string, IPAddress> { ["00:11:22:33:44:05"] = IPAddress.Parse("192.168.88.100") } };
        var e = new DhcpServerEngine(c);
        Assert.Equal(IPAddress.Parse("192.168.88.101"), Bind(e, 1)); // .100 skipped: reserved
        Assert.Equal(IPAddress.Parse("192.168.88.100"), Bind(e, 5));
        Assert.Equal(DhcpMessageType.Nak, e.Handle(Client(DhcpMessageType.Request, 2, IPAddress.Parse("192.168.88.100"))).Reply!.Type);
    }

    [Fact]
    public void Inform_gets_settings_but_no_address_or_lease()
    {
        var e = new DhcpServerEngine(Config() with { DnsServers = [IPAddress.Parse("192.168.88.1")] });
        var ack = e.Handle(Client(DhcpMessageType.Inform, 1, ciaddr: IPAddress.Parse("192.168.88.40"))).Reply!;
        Assert.Equal(DhcpMessageType.Ack, ack.Type);
        Assert.Equal(IPAddress.Any, ack.YourAddress);
        Assert.False(ack.Options.ContainsKey(51));
        Assert.Equal(IPAddress.Parse("192.168.88.1"), ack.Address(6));
        Assert.Empty(e.Leases);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("192.168.88.40"), 68), DhcpServerEngine.ReplyTarget(Client(DhcpMessageType.Inform, 1, ciaddr: IPAddress.Parse("192.168.88.40")), ack, IPAddress.Broadcast));
    }

    [Fact]
    public void Replies_without_a_client_address_are_broadcast()
    {
        var e = new DhcpServerEngine(Config());
        var discover = Client(DhcpMessageType.Discover, 1);
        var offer = e.Handle(discover).Reply!;
        Assert.Equal(new IPEndPoint(IPAddress.Broadcast, 68), DhcpServerEngine.ReplyTarget(discover, offer, IPAddress.Broadcast));
        var servers = e.Handle(Client(DhcpMessageType.Offer, 1) with { Op = 2 });
        Assert.Null(servers.Reply); // a reply from another server is never answered
    }

    [Theory]
    [InlineData("192.168.88.1", "255.255.255.0", "192.168.88.100", "192.168.88.110", null)]
    [InlineData("192.168.88.1", "255.255.255.0", "192.168.88.0", "192.168.88.10", "network and broadcast")]
    [InlineData("192.168.88.1", "255.255.255.0", "192.168.89.1", "192.168.89.10", "inside the server's subnet")]
    [InlineData("192.168.88.1", "255.255.255.0", "192.168.88.110", "192.168.88.100", "start is after")]
    [InlineData("192.168.88.5", "255.255.255.0", "192.168.88.1", "192.168.88.10", "server address is inside the pool")]
    [InlineData("10.0.0.1", "255.255.0.0", "10.0.1.0", "10.0.9.0", "larger than 1024")]
    [InlineData("192.168.88.1", "255.0.255.0", "192.168.88.100", "192.168.88.110", "contiguous")]
    [InlineData("192.168.88.1", "255.255.255.255", "192.168.88.1", "192.168.88.1", "too small")]
    public void Invalid_configurations_are_rejected(string server, string mask, string start, string end, string? error)
    {
        var c = new DhcpServerConfig { ServerAddress = IPAddress.Parse(server), SubnetMask = IPAddress.Parse(mask), PoolStart = IPAddress.Parse(start), PoolEnd = IPAddress.Parse(end) };
        var errors = c.Validate();
        if (error is null)
        {
            Assert.Empty(errors);
            return;
        }

        Assert.Contains(errors, x => x.Contains(error, StringComparison.Ordinal));
        Assert.Throws<ArgumentException>(() => new DhcpServerEngine(c));
    }

    [Fact]
    public void Gateway_lease_time_and_reservations_are_validated()
    {
        Assert.Contains(Config() with { Router = IPAddress.Parse("10.0.0.1") } is var c1 ? c1.Validate() : [], x => x.Contains("gateway", StringComparison.Ordinal));
        Assert.Contains((Config() with { LeaseTime = TimeSpan.FromSeconds(20) }).Validate(), x => x.Contains("lease time", StringComparison.Ordinal));
        Assert.Contains((Config() with { Reservations = new Dictionary<string, IPAddress> { ["nope"] = IPAddress.Parse("192.168.88.5") } }).Validate(), x => x.Contains("not a MAC", StringComparison.Ordinal));
        Assert.Contains((Config() with { Reservations = new Dictionary<string, IPAddress> { ["00-11-22-33-44-55"] = Server } }).Validate(), x => x.Contains("not a usable", StringComparison.Ordinal));
        Assert.Contains((Config() with { ServerAddress = IPAddress.IPv6Loopback }).Validate(), x => x.Contains("IPv4", StringComparison.Ordinal));
    }
}
