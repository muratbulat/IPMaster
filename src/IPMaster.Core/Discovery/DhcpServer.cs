using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace IPMaster.Core.Discovery;

public enum DhcpMessageType : byte
{
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

/// <summary>A BOOTP/DHCP message (RFC 2131 §2, options RFC 2132), Ethernet clients only.</summary>
public sealed record DhcpMessage
{
    private static readonly byte[] Cookie = [0x63, 0x82, 0x53, 0x63];

    /// <summary>1 = BOOTREQUEST (client), 2 = BOOTREPLY (server).</summary>
    public byte Op { get; init; }

    public uint TransactionId { get; init; }

    public ushort Flags { get; init; }

    public IPAddress ClientAddress { get; init; } = IPAddress.Any;

    public IPAddress YourAddress { get; init; } = IPAddress.Any;

    public IPAddress NextServerAddress { get; init; } = IPAddress.Any;

    public IPAddress RelayAddress { get; init; } = IPAddress.Any;

    public required PhysicalAddress ClientMac { get; init; }

    public IReadOnlyDictionary<byte, byte[]> Options { get; init; } = new Dictionary<byte, byte[]>();

    public DhcpMessageType? Type => Options.TryGetValue(53, out var v) && v.Length == 1 && v[0] is >= 1 and <= 8 ? (DhcpMessageType)v[0] : null;

    /// <summary>The client asked for a broadcast reply (it cannot receive unicast before it has an address).</summary>
    public bool BroadcastFlag => (Flags & 0x8000) != 0;

    public IPAddress? RequestedAddress => Address(50);

    public IPAddress? ServerIdentifier => Address(54);

    /// <summary>Option 12, as the client advertised it (untrusted text).</summary>
    public string? HostName => Options.TryGetValue(12, out var v) && v.Length > 0 ? Encoding.ASCII.GetString(v).TrimEnd('\0') : null;

    /// <summary>Lease key: the client identifier (option 61) when present, else the hardware address (RFC 2131 §4.2).</summary>
    public string ClientKey => Options.TryGetValue(61, out var id) && id.Length > 0 ? "id:" + Convert.ToHexString(id) : "mac:" + ClientMac;

    public IPAddress? Address(byte code) => Options.TryGetValue(code, out var v) && v.Length == 4 ? new IPAddress(v) : null;

    /// <summary>Parses a message; null when it is not a well-formed Ethernet DHCP message (truncated, bad cookie or options).</summary>
    public static DhcpMessage? Parse(ReadOnlySpan<byte> p)
    {
        if (p.Length < 240 || p[0] is not (1 or 2) || p[1] != 1 || p[2] != 6) return null; // Ethernet, 6-byte MAC
        if (!p.Slice(236, 4).SequenceEqual(Cookie)) return null;
        var options = new Dictionary<byte, byte[]>();
        var pos = 240;
        var ended = false;
        while (pos < p.Length)
        {
            var code = p[pos++];
            if (code == 0) continue;
            if (code == 255)
            {
                ended = true;
                break;
            }

            if (pos >= p.Length) return null;
            var len = p[pos++];
            if (pos + len > p.Length) return null; // option runs past the packet
            options[code] = p.Slice(pos, len).ToArray();
            pos += len;
        }

        if (!ended) return null;
        return new DhcpMessage
        {
            Op = p[0],
            TransactionId = BinaryPrimitives.ReadUInt32BigEndian(p[4..]),
            Flags = BinaryPrimitives.ReadUInt16BigEndian(p[10..]),
            ClientAddress = new IPAddress(p.Slice(12, 4)),
            YourAddress = new IPAddress(p.Slice(16, 4)),
            NextServerAddress = new IPAddress(p.Slice(20, 4)),
            RelayAddress = new IPAddress(p.Slice(24, 4)),
            ClientMac = new PhysicalAddress(p.Slice(28, 6).ToArray()),
            Options = options,
        };
    }

    public byte[] Serialize()
    {
        var p = new byte[240];
        p[0] = Op;
        p[1] = 1;
        p[2] = 6;
        BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(4), TransactionId);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(10), Flags);
        ClientAddress.GetAddressBytes().CopyTo(p, 12);
        YourAddress.GetAddressBytes().CopyTo(p, 16);
        NextServerAddress.GetAddressBytes().CopyTo(p, 20);
        RelayAddress.GetAddressBytes().CopyTo(p, 24);
        ClientMac.GetAddressBytes().AsSpan(0, Math.Min(6, ClientMac.GetAddressBytes().Length)).CopyTo(p.AsSpan(28));
        Cookie.CopyTo(p, 236);
        var list = new List<byte>(p);
        foreach (var (code, value) in Options.OrderBy(o => o.Key == 53 ? 0 : 1).ThenBy(o => o.Key))
        {
            list.Add(code);
            list.Add((byte)value.Length);
            list.AddRange(value);
        }

        list.Add(255);
        while (list.Count < 300) list.Add(0); // BOOTP minimum size
        return list.ToArray();
    }
}

/// <summary>Isolated DHCP server settings (D-090). Validate before use; the server never starts on an invalid configuration.</summary>
public sealed record DhcpServerConfig
{
    public const int MaxPoolSize = 1024;

    public required IPAddress ServerAddress { get; init; }

    public required IPAddress SubnetMask { get; init; }

    public required IPAddress PoolStart { get; init; }

    public required IPAddress PoolEnd { get; init; }

    public TimeSpan LeaseTime { get; init; } = TimeSpan.FromMinutes(10);

    /// <summary>Default gateway option; not advertised when null (the default: a direct link needs none).</summary>
    public IPAddress? Router { get; init; }

    public IReadOnlyList<IPAddress> DnsServers { get; init; } = [];

    /// <summary>Fixed addresses by MAC (any common notation).</summary>
    public IReadOnlyDictionary<string, IPAddress> Reservations { get; init; } = new Dictionary<string, IPAddress>();

    public IReadOnlyList<string> Validate()
    {
        var errors = new List<string>();
        IPAddress[] all = [ServerAddress, SubnetMask, PoolStart, PoolEnd, .. Router is null ? Array.Empty<IPAddress>() : [Router], .. DnsServers, .. Reservations.Values];
        if (all.Any(a => a.AddressFamily != AddressFamily.InterNetwork)) return ["DHCP serves IPv4 addresses only."];
        var mask = U(SubnetMask);
        if (mask == 0 || (~mask & (~mask + 1)) != 0) errors.Add("The subnet mask is not a valid contiguous mask.");
        else if (mask > 0xFFFFFFFC) errors.Add("The subnet is too small: use a /30 or larger.");
        if (errors.Count > 0) return errors;
        var net = U(ServerAddress) & mask;
        var broadcast = net | ~mask;
        bool InSubnet(IPAddress a) => (U(a) & mask) == net && U(a) != net && U(a) != broadcast;
        if (!InSubnet(ServerAddress)) errors.Add("The server address is the network or broadcast address of its subnet.");
        if (!InSubnet(PoolStart) || !InSubnet(PoolEnd)) errors.Add("The pool must lie inside the server's subnet (network and broadcast addresses excluded).");
        else if (U(PoolStart) > U(PoolEnd)) errors.Add("The pool start is after the pool end.");
        else
        {
            if (U(PoolEnd) - U(PoolStart) + 1 > MaxPoolSize) errors.Add($"The pool is larger than {MaxPoolSize} addresses.");
            if (U(ServerAddress) >= U(PoolStart) && U(ServerAddress) <= U(PoolEnd)) errors.Add("The server address is inside the pool.");
        }

        if (Router is not null && !InSubnet(Router)) errors.Add("The gateway is outside the subnet.");
        if (LeaseTime < TimeSpan.FromMinutes(1) || LeaseTime > TimeSpan.FromHours(24)) errors.Add("The lease time must be between 1 minute and 24 hours.");
        foreach (var (mac, ip) in Reservations)
        {
            if (Results.Formats.ParseMac(mac) is null) errors.Add($"Reservation '{mac}': not a MAC address.");
            else if (!InSubnet(ip) || ip.Equals(ServerAddress)) errors.Add($"Reservation {mac}: {ip} is not a usable address of the subnet.");
        }

        if (Reservations.Values.GroupBy(U).Any(g => g.Count() > 1)) errors.Add("Two reservations use the same address.");
        return errors;
    }

    internal static uint U(IPAddress a) => BinaryPrimitives.ReadUInt32BigEndian(a.GetAddressBytes());
}

public enum DhcpLeaseState
{
    /// <summary>Offered, waiting for the client's REQUEST.</summary>
    Offered,
    Bound,
    Released,

    /// <summary>The client reported the address as already in use (DHCPDECLINE); it is held back for one lease time.</summary>
    Declined,
}

public sealed record DhcpLease(string ClientKey, PhysicalAddress Mac, IPAddress Address, DhcpLeaseState State, DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen, DateTimeOffset Expires, string? HostName);

public enum DhcpEventKind
{
    Offered,
    Acknowledged,
    Refused,
    Released,
    Declined,
    Informed,
    Ignored,
    PoolExhausted,
}

public sealed record DhcpEvent(DateTimeOffset At, DhcpEventKind Kind, PhysicalAddress Mac, IPAddress? Address, string Text);

public sealed record DhcpResult(DhcpMessage? Reply, DhcpEvent Event);

/// <summary>
/// The lease logic of the isolated DHCP server (D-090): DISCOVER/OFFER, REQUEST/ACK/NAK, RELEASE, DECLINE, INFORM per
/// RFC 2131 §4.3, keyed by client identifier or MAC, with reservations and a bounded pool. Pure (no sockets, clock
/// injected); the caller serialises calls. Leases live only in memory: nothing about clients is persisted.
/// </summary>
public sealed class DhcpServerEngine
{
    /// <summary>How long an offered address is held for the client's REQUEST.</summary>
    public static readonly TimeSpan OfferHold = TimeSpan.FromMinutes(2);

    private readonly DhcpServerConfig _c;
    private readonly TimeProvider _time;
    private readonly Dictionary<uint, Entry> _byAddress = [];
    private readonly Dictionary<string, uint> _byClient = new(StringComparer.Ordinal);
    private readonly Dictionary<string, uint> _reserved = new(StringComparer.Ordinal);
    private readonly uint _mask;
    private readonly uint _net;

    private sealed class Entry
    {
        public required string Key;
        public required PhysicalAddress Mac;
        public required uint Address;
        public DhcpLeaseState State;
        public DateTimeOffset FirstSeen;
        public DateTimeOffset LastSeen;
        public DateTimeOffset Expires;
        public string? HostName;
    }

    public DhcpServerEngine(DhcpServerConfig config, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        var errors = config.Validate();
        if (errors.Count > 0) throw new ArgumentException(string.Join(" ", errors), nameof(config));
        _c = config;
        _time = time ?? TimeProvider.System;
        _mask = DhcpServerConfig.U(config.SubnetMask);
        _net = DhcpServerConfig.U(config.ServerAddress) & _mask;
        foreach (var (mac, ip) in config.Reservations) _reserved["mac:" + Results.Formats.ParseMac(mac)] = DhcpServerConfig.U(ip);
    }

    public DhcpServerConfig Config => _c;

    public IReadOnlyList<DhcpLease> Leases
    {
        get
        {
            var now = _time.GetUtcNow();
            return _byAddress.Values.OrderBy(e => e.Address).Select(e => new DhcpLease(e.Key, e.Mac, Ip(e.Address),
                e.State is DhcpLeaseState.Offered or DhcpLeaseState.Bound && e.Expires <= now ? DhcpLeaseState.Released : e.State,
                e.FirstSeen, e.LastSeen, e.Expires, e.HostName)).ToList();
        }
    }

    public DhcpResult Handle(DhcpMessage m)
    {
        ArgumentNullException.ThrowIfNull(m);
        var now = _time.GetUtcNow();
        if (m.Op != 1) return Ignore(m, now, "Not a client message.");
        return m.Type switch
        {
            DhcpMessageType.Discover => Discover(m, now),
            DhcpMessageType.Request => Request(m, now),
            DhcpMessageType.Release => Release(m, now),
            DhcpMessageType.Decline => Decline(m, now),
            DhcpMessageType.Inform => Inform(m, now),
            _ => Ignore(m, now, "Unsupported DHCP message type."),
        };
    }

    /// <summary>Where a reply goes (RFC 2131 §4.1): the relay agent, else unicast to a configured client, else broadcast.</summary>
    public static IPEndPoint ReplyTarget(DhcpMessage request, DhcpMessage reply, IPAddress broadcast)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(reply);
        if (!request.RelayAddress.Equals(IPAddress.Any)) return new IPEndPoint(request.RelayAddress, 67);
        if (reply.Type != DhcpMessageType.Nak && !request.ClientAddress.Equals(IPAddress.Any)) return new IPEndPoint(request.ClientAddress, 68);
        return new IPEndPoint(broadcast, 68); // a client without an address may not receive unicast (no ARP entry yet)
    }

    private DhcpResult Discover(DhcpMessage m, DateTimeOffset now)
    {
        var address = Allocate(m, now);
        if (address is not { } a)
        {
            return new DhcpResult(null, new DhcpEvent(now, DhcpEventKind.PoolExhausted, m.ClientMac, null,
                $"DISCOVER from {Mac(m)}: no free address (pool exhausted or reservation in use); no offer sent."));
        }

        var e = Hold(m, a, DhcpLeaseState.Offered, now + Min(OfferHold, _c.LeaseTime), now);
        return new DhcpResult(Reply(m, DhcpMessageType.Offer, a, lease: true),
            new DhcpEvent(now, DhcpEventKind.Offered, m.ClientMac, Ip(a), $"OFFER {Ip(a)} to {Mac(m)}{Host(e)}."));
    }

    private DhcpResult Request(DhcpMessage m, DateTimeOffset now)
    {
        var server = m.ServerIdentifier;
        if (server is not null && !server.Equals(_c.ServerAddress))
        {
            // SELECTING state answering another server's offer: it chose that server, so drop ours and stay silent
            if (_byClient.TryGetValue(m.ClientKey, out var held) && _byAddress[held].State == DhcpLeaseState.Offered) Remove(held);
            return Ignore(m, now, $"REQUEST from {Mac(m)} is for another DHCP server ({server}).");
        }

        var requested = m.RequestedAddress ?? (m.ClientAddress.Equals(IPAddress.Any) ? null : m.ClientAddress);
        if (requested is null || requested.AddressFamily != AddressFamily.InterNetwork) return Ignore(m, now, $"REQUEST from {Mac(m)} names no address.");
        var r = DhcpServerConfig.U(requested);
        if ((r & _mask) != _net || !Assignable(m, r, now))
        {
            return new DhcpResult(Reply(m, DhcpMessageType.Nak, null, lease: false),
                new DhcpEvent(now, DhcpEventKind.Refused, m.ClientMac, requested, $"NAK {requested} to {Mac(m)}: not available from this server."));
        }

        var e = Hold(m, r, DhcpLeaseState.Bound, now + _c.LeaseTime, now);
        return new DhcpResult(Reply(m, DhcpMessageType.Ack, r, lease: true),
            new DhcpEvent(now, DhcpEventKind.Acknowledged, m.ClientMac, requested, $"ACK {requested} to {Mac(m)}{Host(e)}, lease {_c.LeaseTime.TotalMinutes:0.#} min."));
    }

    private DhcpResult Release(DhcpMessage m, DateTimeOffset now)
    {
        if (_byClient.TryGetValue(m.ClientKey, out var a) && a == DhcpServerConfig.U(m.ClientAddress) && SameServer(m))
        {
            var e = _byAddress[a];
            e.State = DhcpLeaseState.Released;
            e.Expires = now;
            e.LastSeen = now;
            return new DhcpResult(null, new DhcpEvent(now, DhcpEventKind.Released, m.ClientMac, Ip(a), $"RELEASE {Ip(a)} by {Mac(m)}."));
        }

        return Ignore(m, now, $"RELEASE from {Mac(m)} for an address it does not hold.");
    }

    private DhcpResult Decline(DhcpMessage m, DateTimeOffset now)
    {
        if (m.RequestedAddress is { } d && _byClient.TryGetValue(m.ClientKey, out var a) && a == DhcpServerConfig.U(d) && SameServer(m))
        {
            var e = _byAddress[a];
            _byClient.Remove(m.ClientKey);
            e.State = DhcpLeaseState.Declined;
            e.Expires = now + _c.LeaseTime;
            e.LastSeen = now;
            return new DhcpResult(null, new DhcpEvent(now, DhcpEventKind.Declined, m.ClientMac, d,
                $"DECLINE {d} by {Mac(m)}: another device already uses it; held back for {_c.LeaseTime.TotalMinutes:0.#} min."));
        }

        return Ignore(m, now, $"DECLINE from {Mac(m)} for an address it was not given.");
    }

    private DhcpResult Inform(DhcpMessage m, DateTimeOffset now) =>
        new(Reply(m, DhcpMessageType.Ack, null, lease: false),
            new DhcpEvent(now, DhcpEventKind.Informed, m.ClientMac, m.ClientAddress, $"INFORM from {Mac(m)} at {m.ClientAddress}: settings sent, no address assigned."));

    private uint? Allocate(DhcpMessage m, DateTimeOffset now)
    {
        if (_reserved.TryGetValue("mac:" + m.ClientMac, out var reserved)) return Assignable(m, reserved, now) ? reserved : null;
        if (_byClient.TryGetValue(m.ClientKey, out var current) && Assignable(m, current, now)) return current;
        if (m.RequestedAddress is { } req && Assignable(m, DhcpServerConfig.U(req), now)) return DhcpServerConfig.U(req);
        for (var a = DhcpServerConfig.U(_c.PoolStart); a <= DhcpServerConfig.U(_c.PoolEnd); a++)
        {
            if (Assignable(m, a, now)) return a;
        }

        return null;
    }

    /// <summary>The address may go to this client: in the pool (or reserved for it), not reserved for another MAC, not held by another client.</summary>
    private bool Assignable(DhcpMessage m, uint a, DateTimeOffset now)
    {
        var mine = _reserved.TryGetValue("mac:" + m.ClientMac, out var r) && r == a;
        var inPool = a >= DhcpServerConfig.U(_c.PoolStart) && a <= DhcpServerConfig.U(_c.PoolEnd);
        if (!mine && (!inPool || _reserved.ContainsValue(a))) return false;
        if (!_byAddress.TryGetValue(a, out var e) || e.Key == m.ClientKey && e.State != DhcpLeaseState.Declined) return true;
        return e.State == DhcpLeaseState.Released || e.Expires <= now;
    }

    private Entry Hold(DhcpMessage m, uint a, DhcpLeaseState state, DateTimeOffset expires, DateTimeOffset now)
    {
        if (_byClient.TryGetValue(m.ClientKey, out var old) && old != a) Remove(old);
        if (_byAddress.TryGetValue(a, out var other) && other.Key != m.ClientKey) _byClient.Remove(other.Key); // expired or released
        var first = _byAddress.TryGetValue(a, out var prev) && prev.Key == m.ClientKey ? prev.FirstSeen : now;
        var e = new Entry { Key = m.ClientKey, Mac = m.ClientMac, Address = a, State = state, FirstSeen = first, LastSeen = now, Expires = expires, HostName = m.HostName ?? prev?.HostName };
        _byAddress[a] = e;
        _byClient[m.ClientKey] = a;
        return e;
    }

    private void Remove(uint a)
    {
        if (_byAddress.Remove(a, out var e)) _byClient.Remove(e.Key);
    }

    private bool SameServer(DhcpMessage m) => m.ServerIdentifier is null || m.ServerIdentifier.Equals(_c.ServerAddress);

    private DhcpMessage Reply(DhcpMessage request, DhcpMessageType type, uint? yours, bool lease)
    {
        var o = new Dictionary<byte, byte[]> { [53] = [(byte)type], [54] = _c.ServerAddress.GetAddressBytes() };
        if (type != DhcpMessageType.Nak)
        {
            o[1] = _c.SubnetMask.GetAddressBytes();
            if (_c.Router is not null) o[3] = _c.Router.GetAddressBytes();
            if (_c.DnsServers.Count > 0) o[6] = _c.DnsServers.SelectMany(d => d.GetAddressBytes()).ToArray();
            if (lease)
            {
                var s = (uint)_c.LeaseTime.TotalSeconds;
                o[51] = Be(s);
                o[58] = Be(s / 2);
                o[59] = Be(s / 8 * 7);
            }
        }

        return new DhcpMessage
        {
            Op = 2,
            TransactionId = request.TransactionId,
            Flags = request.Flags,
            ClientAddress = type == DhcpMessageType.Nak ? IPAddress.Any : request.ClientAddress,
            YourAddress = yours is { } y ? Ip(y) : IPAddress.Any,
            NextServerAddress = type == DhcpMessageType.Nak ? IPAddress.Any : _c.ServerAddress,
            RelayAddress = request.RelayAddress,
            ClientMac = request.ClientMac,
            Options = o,
        };
    }

    private static DhcpResult Ignore(DhcpMessage m, DateTimeOffset now, string why) => new(null, new DhcpEvent(now, DhcpEventKind.Ignored, m.ClientMac, null, why));

    private static string Host(Entry e) => e.HostName is { Length: > 0 } h ? $" ({h})" : "";

    private static string Mac(DhcpMessage m) => Results.Formats.Mac(m.ClientMac);

    private static IPAddress Ip(uint a)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, a);
        return new IPAddress(b);
    }

    private static byte[] Be(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return b;
    }

    private static TimeSpan Min(TimeSpan a, TimeSpan b) => a < b ? a : b;
}
