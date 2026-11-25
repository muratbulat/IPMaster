using System.Net;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Network;

public sealed record AdapterAddress(IPAddress Address, int PrefixLength)
{
    public bool IsV6 => Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;

    public bool IsLinkLocal => IsV6 && Address.IsIPv6LinkLocal;

    /// <summary>Scan range for this address: the whole IPv4 subnet, or for IPv6 the subnet when it is
    /// small enough (prefix ≥ 104); /64 subnets need neighbour discovery instead.</summary>
    public TargetSpec? ToSubnetSpec(int minIPv6Prefix = 104)
    {
        if (IsV6 && PrefixLength < minIPv6Prefix) return null;
        var text = $"{Address}/{PrefixLength}";
        return TargetParser.TryParse(text, out var spec, out _) ? spec : null;
    }

    public override string ToString() => $"{Address}/{PrefixLength}";
}

public sealed record NetworkAdapterInfo(
    string Id,
    string Name,
    string Description,
    string Type,
    string? MacAddress,
    IReadOnlyList<AdapterAddress> Addresses,
    IReadOnlyList<IPAddress> Gateways,
    long SpeedBitsPerSecond)
{
    public IEnumerable<AdapterAddress> IPv4 => Addresses.Where(a => !a.IsV6);

    public IEnumerable<AdapterAddress> IPv6 => Addresses.Where(a => a.IsV6);
}

public interface INetworkAdapterProvider
{
    /// <summary>Operational, non-loopback adapters with at least one unicast address.</summary>
    IReadOnlyList<NetworkAdapterInfo> GetAdapters();
}

public static class LocalNetworks
{
    public static IReadOnlyList<LocalSubnet> Subnets(IEnumerable<NetworkAdapterInfo> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        return adapters.SelectMany(a => a.IPv4)
            .Select(a => new LocalSubnet(AddressKey.From(a.Address), a.PrefixLength))
            .Distinct()
            .ToList();
    }

    /// <summary>Ranges for <c>/range:all|v4|v6</c> and the Detect dialog. IPv6 subnets larger than
    /// /104 are reported in <paramref name="skipped"/> (they require neighbour discovery, Phase 2).</summary>
    public static IReadOnlyList<TargetSpec> AutoDetect(IEnumerable<NetworkAdapterInfo> adapters, bool v4, bool v6, List<string> skipped)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(skipped);
        var result = new List<TargetSpec>();
        foreach (var adapter in adapters)
        {
            foreach (var a in adapter.Addresses)
            {
                if (a.IsV6 ? !v6 : !v4) continue;
                var spec = a.ToSubnetSpec();
                if (spec is null)
                {
                    skipped.Add($"{adapter.Name}: {a} is too large to sweep; IPv6 neighbour discovery is not implemented yet.");
                    continue;
                }

                if (!result.Any(r => r.Start == spec.Start && r.End == spec.End)) result.Add(spec);
            }
        }

        return result;
    }
}
