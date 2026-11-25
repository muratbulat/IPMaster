namespace IPMaster.Core.Targets;

public enum TargetKind
{
    SingleAddress,
    Range,
    Cidr,
    HostName,

    /// <summary>IPv6 neighbour discovery: <c>ff02::1%scope</c> — multicast echo, then scan the responders.</summary>
    NeighborDiscovery,
}

/// <summary>A single parsed target expression (one address-bar entry or one import line).</summary>
public sealed record TargetSpec
{
    public required TargetKind Kind { get; init; }

    /// <summary>First address (inclusive). Unset for <see cref="TargetKind.HostName"/>.</summary>
    public AddressKey Start { get; init; }

    /// <summary>Last address (inclusive). Unset for <see cref="TargetKind.HostName"/>.</summary>
    public AddressKey End { get; init; }

    /// <summary>Prefix length for CIDR entries.</summary>
    public int? PrefixLength { get; init; }

    public string? HostName { get; init; }

    /// <summary>IPv4 only: enumerate octet-wise instead of sequentially (manual: "Octet range mode").</summary>
    public bool OctetMode { get; init; }

    public string Original { get; init; } = "";

    public bool IsV6 => Start.IsV6;

    /// <summary>Raw (pre-deduplication, pre-exclusion) number of addresses described.</summary>
    public UInt128 RawCount
    {
        get
        {
            return Kind switch
            {
                TargetKind.HostName => 1,
                TargetKind.NeighborDiscovery => 1,
                TargetKind.SingleAddress => 1,
                _ when OctetMode => OctetRangeSource.CountFor(Start.V4, End.V4),
                _ => End.Value - Start.Value + 1,
            };
        }
    }
}
