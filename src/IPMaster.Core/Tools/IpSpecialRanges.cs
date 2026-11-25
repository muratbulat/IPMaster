namespace IPMaster.Core.Tools;

/// <summary>What an address is used for, from the special-purpose registry (most specific match wins).</summary>
/// <param name="GloballyReachable">IANA's "Globally Reachable" column: true/false, or null where IANA says N/A or it depends.</param>
public sealed record IpClassification(string Name, string Reference, bool? GloballyReachable, string Description, IpBlock? Block)
{
    public string Display => GloballyReachable switch
    {
        true => $"{Name} · globally reachable",
        false => $"{Name} · not globally reachable",
        null => Name,
    };
}

public sealed record IpSpecialRange(IpBlock Block, string Name, string Reference, bool? GloballyReachable, string Description);

/// <summary>
/// Special-use ranges, transcribed from the IANA IPv4 and IPv6 Special-Purpose Address Registries (RFC 6890) plus the
/// multicast and global-unicast blocks of the IANA address-space registries (checked against the live registries on
/// 2026-11-17). Limits: the table is a snapshot built into
/// the program (it is not downloaded), so ranges IANA adds later are not known; "not special-purpose" means only that no
/// entry matched, not that the address is allocated, announced or reachable on the Internet.
/// </summary>
public static class IpSpecialRanges
{
    public const string Source = "Classification source: IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890) and address-space registries, built-in snapshot; "
                                 + "an address outside them is not necessarily allocated or routed on the Internet.";

    private static readonly (string Cidr, string Name, string Rfc, bool? Global, string Description)[] Data =
    [
        // ---- IPv4 special-purpose registry
        ("0.0.0.0/8", "\"This network\"", "RFC 791", false, "Source address only (this network); not usable as a destination."),
        ("0.0.0.0/32", "\"This host on this network\"", "RFC 1122", false, "Unspecified address; used as a source before an address is configured."),
        ("10.0.0.0/8", "Private-Use", "RFC 1918", false, "Private network address space; not routed on the public Internet."),
        ("100.64.0.0/10", "Shared Address Space", "RFC 6598", false, "Carrier-grade NAT space between a provider and its customers; not private-use, not public."),
        ("127.0.0.0/8", "Loopback", "RFC 1122", false, "Loopback: traffic never leaves the host."),
        ("169.254.0.0/16", "Link-Local", "RFC 3927", false, "Automatic link-local addressing (APIPA); not forwarded by routers. Often means DHCP failed."),
        ("172.16.0.0/12", "Private-Use", "RFC 1918", false, "Private network address space; not routed on the public Internet."),
        ("192.0.0.0/24", "IETF Protocol Assignments", "RFC 6890", false, "Reserved for IETF protocol assignments."),
        ("192.0.0.0/29", "IPv4 Service Continuity Prefix", "RFC 7335", false, "DS-Lite / 464XLAT B4 element addressing."),
        ("192.0.0.8/32", "IPv4 Dummy Address", "RFC 7600", false, "Used as a source when no other IPv4 address is available."),
        ("192.0.0.9/32", "Port Control Protocol Anycast", "RFC 7723", true, "PCP server anycast address."),
        ("192.0.0.10/32", "Traversal Using Relays around NAT Anycast", "RFC 8155", true, "TURN server anycast address."),
        ("192.0.0.170/31", "NAT64/DNS64 Discovery", "RFC 8880", false, "Well-known names ipv4only.arpa resolve to these addresses."),
        ("192.0.2.0/24", "Documentation (TEST-NET-1)", "RFC 5737", false, "Reserved for examples in documentation; never used on real networks."),
        ("192.31.196.0/24", "AS112-v4", "RFC 7535", true, "AS112 DNS sink service."),
        ("192.52.193.0/24", "AMT", "RFC 7450", true, "Automatic Multicast Tunneling."),
        ("192.88.99.0/24", "Deprecated (6to4 Relay Anycast)", "RFC 7526", null, "Formerly 6to4 relay anycast; deprecated."),
        ("192.88.99.2/32", "6a44-relay anycast address", "RFC 6751", false, "6a44 relay anycast address."),
        ("192.168.0.0/16", "Private-Use", "RFC 1918", false, "Private network address space; not routed on the public Internet."),
        ("192.175.48.0/24", "Direct Delegation AS112 Service", "RFC 7534", true, "AS112 DNS sink service."),
        ("198.18.0.0/15", "Benchmarking", "RFC 2544", false, "Reserved for network device benchmarking; do not use on production networks."),
        ("198.51.100.0/24", "Documentation (TEST-NET-2)", "RFC 5737", false, "Reserved for examples in documentation; never used on real networks."),
        ("203.0.113.0/24", "Documentation (TEST-NET-3)", "RFC 5737", false, "Reserved for examples in documentation; never used on real networks."),
        ("240.0.0.0/4", "Reserved", "RFC 1112", false, "Reserved for future use (former Class E); most stacks refuse it."),
        ("255.255.255.255/32", "Limited Broadcast", "RFC 919", false, "Broadcast to the local link only; never forwarded."),
        // ---- IPv4 multicast (address-space registry)
        ("224.0.0.0/4", "Multicast", "RFC 5771", null, "IPv4 multicast; group addresses, not host addresses."),
        ("224.0.0.0/24", "Multicast · Local Network Control Block", "RFC 5771", false, "Link-local multicast (routing protocols, mDNS 224.0.0.251); not forwarded."),
        ("232.0.0.0/8", "Multicast · Source-Specific", "RFC 4607", null, "Source-specific multicast (SSM)."),
        ("239.0.0.0/8", "Multicast · Administratively Scoped", "RFC 2365", false, "Organisation-local multicast."),

        // ---- IPv6 address-space registry (broad blocks; special-purpose entries below are more specific)
        ("::/8", "Reserved by IETF", "RFC 4291", null, "Reserved part of the IPv6 space; contains the special addresses below."),
        ("2000::/3", "Global Unicast", "RFC 4291", null, "Global unicast space. Whether this address is allocated and routed is not known from the address alone."),
        ("fc00::/7", "Unique-Local", "RFC 4193", false, "Unique local addresses (ULA), the IPv6 counterpart of private-use space."),
        ("fe80::/10", "Link-Local Unicast", "RFC 4291", false, "Link-local: valid only on one link; needs a zone ID (%interface) to be used unambiguously."),
        ("fec0::/10", "Site-Local (deprecated)", "RFC 3879", false, "Deprecated site-local space; do not use."),
        ("ff00::/8", "Multicast", "RFC 4291", null, "IPv6 multicast; group addresses, not host addresses."),
        // ---- IPv6 special-purpose registry
        ("::/128", "Unspecified Address", "RFC 4291", false, "The unspecified address; never assigned to an interface."),
        ("::1/128", "Loopback Address", "RFC 4291", false, "Loopback: traffic never leaves the host."),
        ("::ffff:0:0/96", "IPv4-mapped Address", "RFC 4291", false, "Represents an IPv4 address inside IPv6 APIs; not used on the wire."),
        ("64:ff9b::/96", "IPv4-IPv6 Translation (NAT64)", "RFC 6052", true, "Well-known NAT64 prefix; the low 32 bits are the IPv4 address."),
        ("64:ff9b:1::/48", "Local-Use IPv4/IPv6 Translation", "RFC 8215", false, "NAT64 prefix for local use."),
        ("100::/64", "Discard-Only Address Block", "RFC 6666", false, "Remote-triggered black-hole routing."),
        ("100:0:0:1::/64", "Dummy IPv6 Prefix", "RFC 9780", false, "Used as a source when no other IPv6 address is available."),
        ("2001::/23", "IETF Protocol Assignments", "RFC 2928", false, "Reserved for IETF protocol assignments."),
        ("2001::/32", "TEREDO", "RFC 4380", null, "Teredo tunnelling."),
        ("2001:1::1/128", "Port Control Protocol Anycast", "RFC 7723", true, "PCP server anycast address."),
        ("2001:1::2/128", "Traversal Using Relays around NAT Anycast", "RFC 8155", true, "TURN server anycast address."),
        ("2001:1::3/128", "DNS-SD Service Registration Protocol Anycast", "RFC 9665", true, "DNS-SD SRP anycast address."),
        ("2001:2::/48", "Benchmarking", "RFC 5180", false, "Reserved for network device benchmarking."),
        ("2001:3::/32", "AMT", "RFC 7450", true, "Automatic Multicast Tunneling."),
        ("2001:4:112::/48", "AS112-v6", "RFC 7535", true, "AS112 DNS sink service."),
        ("2001:10::/28", "Deprecated (previously ORCHID)", "RFC 4843", null, "Deprecated ORCHID block."),
        ("2001:20::/28", "ORCHIDv2", "RFC 7343", true, "Overlay routable cryptographic hash identifiers."),
        ("2001:30::/28", "Drone Remote ID Protocol Entity Tags", "RFC 9374", true, "DET prefix."),
        ("2001:db8::/32", "Documentation", "RFC 3849", false, "Reserved for examples in documentation; never used on real networks."),
        ("2002::/16", "6to4", "RFC 3056", null, "6to4 tunnelling; bits 16–47 hold the IPv4 address."),
        ("2620:4f:8000::/48", "Direct Delegation AS112 Service", "RFC 7534", true, "AS112 DNS sink service."),
        ("3fff::/20", "Documentation", "RFC 9637", false, "Reserved for examples in documentation; never used on real networks."),
        ("5f00::/16", "Segment Routing (SRv6) SIDs", "RFC 9602", false, "SRv6 segment identifiers."),
        ("ff01::/16", "Multicast · Interface-Local", "RFC 4291", false, "Interface-local multicast scope."),
        ("ff02::/16", "Multicast · Link-Local", "RFC 4291", false, "Link-local multicast scope (e.g. ff02::1 all nodes); not forwarded."),
        ("ff05::/16", "Multicast · Site-Local", "RFC 4291", false, "Site-local multicast scope."),
        ("ff0e::/16", "Multicast · Global", "RFC 4291", null, "Global multicast scope."),
    ];

    public static IReadOnlyList<IpSpecialRange> All { get; } = Data.Select(Build).ToList();

    private static IpSpecialRange Build((string Cidr, string Name, string Rfc, bool? Global, string Description) d)
    {
        if (!IpCalculator.TryParseNetwork(d.Cidr, null, out var block, out var normalized, out var error) || normalized)
        {
            throw new InvalidOperationException($"Bad registry entry {d.Cidr}: {error}");
        }

        return new IpSpecialRange(block, d.Name, d.Rfc, d.Global, d.Description);
    }

    public static IpClassification Classify(UInt128 value, bool isV6)
    {
        IpSpecialRange? best = null;
        foreach (var r in All)
        {
            if (r.Block.IsV6 == isV6 && r.Block.Contains(value) && (best is null || r.Block.Prefix > best.Block.Prefix)) best = r;
        }

        if (best is not null)
        {
            return new IpClassification(best.Name, best.Reference, best.GloballyReachable, $"{best.Name} ({best.Block}, {best.Reference}): {best.Description}", best.Block);
        }

        return isV6
            ? new IpClassification("Reserved by IETF", "RFC 4291", null, "Outside the global unicast, unique-local, link-local and multicast blocks: reserved by the IETF.", null)
            : new IpClassification("Not special-purpose", "", null,
                "Not in the IANA special-purpose registry. That alone does not make it publicly routable: it may be unallocated, unannounced or filtered.", null);
    }

    /// <summary>Registry entries inside <paramref name="block"/> (bounded: the table is small and fixed).</summary>
    public static IEnumerable<IpSpecialRange> Within(IpBlock block) => All.Where(r => block.Contains(r.Block));
}
