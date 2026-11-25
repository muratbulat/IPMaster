using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace IPMaster.Core.Discovery;

/// <summary>What an observed address says about how the device got it (D-090). Never "static": that cannot be observed.</summary>
public enum IpAssignment
{
    /// <summary>Seen in use: ARP sender, IPv4/IPv6 source address, neighbour advertisement.</summary>
    Observed,

    /// <summary>The device asked for it in a DHCP request (option 50); it may be a lease from another network.</summary>
    DhcpRequested,

    /// <summary>The IPMaster DHCP server acknowledged it to the device.</summary>
    DhcpAssigned,

    /// <summary>The device is checking whether it may use it (ARP probe RFC 5227, IPv6 DAD); not in use yet.</summary>
    Probing,
}

public enum DiscoverySource
{
    Arp,
    Ipv4,
    Ipv6,
    Dhcp,
    ActiveArp,
    Icmp,
}

/// <summary>One piece of evidence about one device. <see cref="Address"/> is null when only the MAC was seen.</summary>
public sealed record DiscoveryObservation(DateTimeOffset At, PhysicalAddress Mac, IPAddress? Address, DiscoverySource Source, IpAssignment Assignment,
    string Evidence, string? HostName = null, string? VendorClass = null);

/// <summary>Turns captured Ethernet frames and DHCP client messages into observations (D-090). Pure; malformed input gives none.</summary>
public static class FrameObservations
{
    public static IReadOnlyList<DiscoveryObservation> FromFrame(ReadOnlySpan<byte> f, DateTimeOffset at)
    {
        if (f.Length < 14) return [];
        var src = new PhysicalAddress(f.Slice(6, 6).ToArray());
        var type = BinaryPrimitives.ReadUInt16BigEndian(f[12..]);
        var offset = 14;
        if (type == 0x8100 && f.Length >= 18) // 802.1Q VLAN tag
        {
            type = BinaryPrimitives.ReadUInt16BigEndian(f[16..]);
            offset = 18;
        }

        var p = f[offset..];
        return type switch
        {
            0x0806 => Arp(p, at),
            0x0800 => Ipv4(p, src, at),
            0x86DD => Ipv6(p, src, at),
            _ => [],
        };
    }

    public static IReadOnlyList<DiscoveryObservation> FromDhcp(DhcpMessage m, DateTimeOffset at)
    {
        ArgumentNullException.ThrowIfNull(m);
        if (m.Op != 1 || m.Type is not { } type) return [];
        var vendor = m.Options.TryGetValue(60, out var v) && v.Length > 0 ? System.Text.Encoding.ASCII.GetString(v).TrimEnd('\0') : null;
        var list = new List<DiscoveryObservation>();
        var label = "DHCP " + type.ToString().ToUpperInvariant();
        if (!m.ClientAddress.Equals(IPAddress.Any))
        {
            list.Add(new(at, m.ClientMac, m.ClientAddress, DiscoverySource.Dhcp, IpAssignment.Observed, $"{label} from configured address {m.ClientAddress}", m.HostName, vendor));
        }

        if (m.RequestedAddress is { } requested && type is DhcpMessageType.Discover or DhcpMessageType.Request)
        {
            list.Add(new(at, m.ClientMac, requested, DiscoverySource.Dhcp, IpAssignment.DhcpRequested,
                $"{label} asks for {requested} (its previous lease, possibly from another network)", m.HostName, vendor));
        }

        if (list.Count == 0) list.Add(new(at, m.ClientMac, null, DiscoverySource.Dhcp, IpAssignment.Observed, $"{label}: DHCP client without an address", m.HostName, vendor));
        return list;
    }

    /// <summary>An ACK of the IPMaster DHCP server: the device was given that address (it may still decline it).</summary>
    public static DiscoveryObservation? FromServerEvent(DhcpEvent e)
    {
        ArgumentNullException.ThrowIfNull(e);
        return e.Kind == DhcpEventKind.Acknowledged && e.Address is { } a
            ? new DiscoveryObservation(e.At, e.Mac, a, DiscoverySource.Dhcp, IpAssignment.DhcpAssigned, $"Assigned by the IPMaster DHCP server: {e.Text}")
            : null;
    }

    private static IReadOnlyList<DiscoveryObservation> Arp(ReadOnlySpan<byte> a, DateTimeOffset at)
    {
        if (a.Length < 28 || BinaryPrimitives.ReadUInt16BigEndian(a) != 1 || BinaryPrimitives.ReadUInt16BigEndian(a[2..]) != 0x0800 || a[4] != 6 || a[5] != 4) return [];
        var op = BinaryPrimitives.ReadUInt16BigEndian(a[6..]);
        var mac = new PhysicalAddress(a.Slice(8, 6).ToArray());
        var sender = new IPAddress(a.Slice(14, 4));
        var target = new IPAddress(a.Slice(24, 4));
        if (sender.Equals(IPAddress.Any))
        {
            // RFC 5227 probe: the device is about to use `target` (often its static address) and checks for conflicts
            return op == 1 ? [new(at, mac, target, DiscoverySource.Arp, IpAssignment.Probing, $"ARP probe for {target} (address conflict check, not in use yet)")] : [];
        }

        if (!Usable(sender)) return [];
        var what = sender.Equals(target) ? "gratuitous ARP announcing" : op == 2 ? "ARP reply from" : "ARP request from";
        return [new(at, mac, sender, DiscoverySource.Arp, IpAssignment.Observed, $"{what} {sender}")];
    }

    private static IReadOnlyList<DiscoveryObservation> Ipv4(ReadOnlySpan<byte> ip, PhysicalAddress src, DateTimeOffset at)
    {
        if (ip.Length < 20 || ip[0] >> 4 != 4) return [];
        var ihl = (ip[0] & 0x0F) * 4;
        if (ihl < 20 || ip.Length < ihl) return [];
        var source = new IPAddress(ip.Slice(12, 4));
        if (ip[9] == 17 && ip.Length >= ihl + 8)
        {
            var udp = ip[ihl..];
            var sport = BinaryPrimitives.ReadUInt16BigEndian(udp);
            var dport = BinaryPrimitives.ReadUInt16BigEndian(udp[2..]);
            if (sport == 68 && dport == 67 && DhcpMessage.Parse(udp[8..]) is { } dhcp) return FromDhcp(dhcp, at);
        }

        return Usable(source) ? [new(at, src, source, DiscoverySource.Ipv4, IpAssignment.Observed, $"IPv4 traffic from {source}")] : [];
    }

    private static IReadOnlyList<DiscoveryObservation> Ipv6(ReadOnlySpan<byte> ip, PhysicalAddress src, DateTimeOffset at)
    {
        if (ip.Length < 40 || ip[0] >> 4 != 6) return [];
        var source = new IPAddress(ip.Slice(8, 16).ToArray());
        if (ip[6] == 58 && ip.Length >= 40 + 24 && ip[40] is 135 or 136) // ICMPv6 neighbour solicitation / advertisement
        {
            var target = new IPAddress(ip.Slice(48, 16).ToArray());
            if (ip[40] == 135 && source.Equals(IPAddress.IPv6Any))
            {
                return [new(at, src, target, DiscoverySource.Ipv6, IpAssignment.Probing, $"IPv6 duplicate address detection for {target} (not in use yet)")];
            }

            if (ip[40] == 136) return [new(at, src, target, DiscoverySource.Ipv6, IpAssignment.Observed, $"IPv6 neighbour advertisement for {target}")];
        }

        return source.Equals(IPAddress.IPv6Any) || source.IsIPv6Multicast ? [] : [new(at, src, source, DiscoverySource.Ipv6, IpAssignment.Observed, $"IPv6 traffic from {source}")];
    }

    private static bool Usable(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.Broadcast) && b[0] is not (0 or 127) && b[0] < 224;
    }
}

/// <summary>A device as the discovery tool shows it: everything observed for one MAC.</summary>
public sealed record CapturedDevice
{
    public required PhysicalAddress Mac { get; init; }

    public IReadOnlyList<DiscoveredAddress> Addresses { get; init; } = [];

    public string? HostName { get; init; }

    public string? VendorClass { get; init; }

    public IReadOnlySet<DiscoverySource> Sources { get; init; } = new HashSet<DiscoverySource>();

    public DateTimeOffset FirstSeen { get; init; }

    public DateTimeOffset LastSeen { get; init; }

    /// <summary>The address to use first: in use (observed or assigned) before requested before probing; IPv4 first.</summary>
    public DiscoveredAddress? Best => Addresses
        .OrderBy(a => a.Assignment switch { IpAssignment.DhcpAssigned => 0, IpAssignment.Observed => 1, IpAssignment.Probing => 2, _ => 3 })
        .ThenBy(a => a.Address.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
        .ThenByDescending(a => a.LastSeen)
        .FirstOrDefault();
}

public sealed record DiscoveredAddress(IPAddress Address, IpAssignment Assignment, string Evidence, DateTimeOffset FirstSeen, DateTimeOffset LastSeen);

/// <summary>
/// Merges observations per MAC (D-090). Bounded: at most <see cref="MaxDevices"/> devices and <see cref="MaxAddresses"/>
/// addresses each (further ones are counted in <see cref="Dropped"/>). The scanning computer's own MACs are ignored.
/// Thread-safe.
/// </summary>
public sealed class DiscoveryBook(IEnumerable<PhysicalAddress>? ownMacs = null)
{
    public const int MaxDevices = 4096;
    public const int MaxAddresses = 16;

    private readonly HashSet<PhysicalAddress> _own = [.. ownMacs ?? []];
    private readonly Dictionary<PhysicalAddress, CapturedDevice> _devices = [];
    private readonly object _lock = new();

    public int Dropped { get; private set; }

    public IReadOnlyList<CapturedDevice> Devices
    {
        get
        {
            lock (_lock) return _devices.Values.OrderBy(d => d.FirstSeen).ToList();
        }
    }

    /// <returns>True when the observation changed what is known.</returns>
    public bool Add(DiscoveryObservation o)
    {
        ArgumentNullException.ThrowIfNull(o);
        if (_own.Contains(o.Mac) || o.Mac.GetAddressBytes() is not { Length: 6 } b || b.All(x => x == 0) || (b[0] & 1) == 1) return false; // own, empty or multicast
        lock (_lock)
        {
            if (!_devices.TryGetValue(o.Mac, out var d))
            {
                if (_devices.Count >= MaxDevices)
                {
                    Dropped++;
                    return false;
                }

                d = new CapturedDevice { Mac = o.Mac, FirstSeen = o.At, LastSeen = o.At };
            }

            var addresses = d.Addresses.ToList();
            var changed = !_devices.ContainsKey(o.Mac);
            if (o.Address is { } ip)
            {
                var i = addresses.FindIndex(a => a.Address.Equals(ip));
                if (i < 0)
                {
                    if (addresses.Count >= MaxAddresses) Dropped++;
                    else
                    {
                        addresses.Add(new DiscoveredAddress(ip, o.Assignment, o.Evidence, o.At, o.At));
                        changed = true;
                    }
                }
                else
                {
                    // stronger evidence replaces weaker: assigned/observed over requested/probing
                    var old = addresses[i];
                    var stronger = Rank(o.Assignment) < Rank(old.Assignment);
                    addresses[i] = old with { Assignment = stronger ? o.Assignment : old.Assignment, Evidence = stronger ? o.Evidence : old.Evidence, LastSeen = o.At };
                    changed |= stronger;
                }
            }

            var sources = new HashSet<DiscoverySource>(d.Sources) { o.Source };
            changed |= sources.Count != d.Sources.Count || (o.HostName is not null && o.HostName != d.HostName);
            _devices[o.Mac] = d with
            {
                Addresses = addresses,
                HostName = o.HostName ?? d.HostName,
                VendorClass = o.VendorClass ?? d.VendorClass,
                Sources = sources,
                LastSeen = o.At > d.LastSeen ? o.At : d.LastSeen,
            };
            return changed;
        }
    }

    public void Clear()
    {
        lock (_lock)
        {
            _devices.Clear();
            Dropped = 0;
        }
    }

    private static int Rank(IpAssignment a) => a switch { IpAssignment.DhcpAssigned => 0, IpAssignment.Observed => 1, IpAssignment.Probing => 2, _ => 3 };
}
