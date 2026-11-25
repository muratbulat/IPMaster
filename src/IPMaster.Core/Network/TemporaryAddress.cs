using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Network;

/// <summary>A secondary address IPMaster added to a laptop adapter to reach a discovered device (D-090).</summary>
public sealed record TemporaryAddress(string AdapterId, string AdapterName, int InterfaceIndex, IPAddress Address, int PrefixLength, DateTimeOffset AddedAt)
{
    /// <summary>What to do when automatic removal failed or IPMaster ended unexpectedly.</summary>
    public string Recovery =>
        $"Remove {Address}/{PrefixLength} from '{AdapterName}': run 'Remove-NetIPAddress -IPAddress {Address} -Confirm:$false' as administrator, "
        + "or disable and re-enable the adapter, or restart Windows (the address was added to the active configuration only and does not survive either).";
}

/// <summary>Adds and removes temporary secondary addresses. Never adds a gateway, never touches existing addresses.</summary>
public interface ITemporaryAddressManager
{
    CapabilityStatus Capability { get; }

    IReadOnlyList<TemporaryAddress> Active { get; }

    /// <summary>Adds <paramref name="address"/>; throws <see cref="InvalidOperationException"/> with the reason (rights, conflict).</summary>
    Task<TemporaryAddress> AddAsync(NetworkAdapterInfo adapter, IPAddress address, int prefixLength, CancellationToken ct);

    Task RemoveAsync(TemporaryAddress address, CancellationToken ct);

    /// <summary>Removes every address this instance added; returns the ones that could not be removed, with why.</summary>
    Task<IReadOnlyList<(TemporaryAddress Address, string Error)>> RemoveAllAsync(CancellationToken ct);
}

/// <summary>Chooses and checks a laptop address next to a discovered device (D-090). Pure.</summary>
public static class TemporaryAddressPlanner
{
    /// <summary>The nearest free neighbour of <paramref name="device"/> in its subnet (+1, −1, +2, …), or null.</summary>
    public static IPAddress? Suggest(IPAddress device, int prefixLength, IReadOnlySet<IPAddress> inUse)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(inUse);
        if (device.AddressFamily != AddressFamily.InterNetwork || prefixLength is < 8 or > 30) return null;
        var d = U(device);
        var mask = uint.MaxValue << (32 - prefixLength);
        var net = d & mask;
        var broadcast = net | ~mask;
        for (var step = 1; step <= 32; step++)
        {
            foreach (var candidate in new[] { (long)d + step, (long)d - step })
            {
                if (candidate <= net || candidate >= broadcast) continue;
                var ip = Ip((uint)candidate);
                if (!inUse.Contains(ip)) return ip;
            }
        }

        return null;
    }

    /// <summary>Reasons not to add the address: invalid, already on this computer, or a subnet an adapter already uses.</summary>
    public static IReadOnlyList<string> Check(IReadOnlyList<NetworkAdapterInfo> adapters, NetworkAdapterInfo target, IPAddress address, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(address);
        var problems = new List<string>();
        if (address.AddressFamily != AddressFamily.InterNetwork) return ["Only IPv4 addresses can be added."];
        if (prefixLength is < 8 or > 30) return ["The prefix length must be between 8 and 30."];
        var mask = uint.MaxValue << (32 - prefixLength);
        var a = U(address);
        if ((a & ~mask) == 0 || (a & ~mask) == ~mask) problems.Add($"{address} is the network or broadcast address of /{prefixLength}.");
        foreach (var adapter in adapters)
        {
            foreach (var existing in adapter.IPv4)
            {
                if (existing.Address.Equals(address)) problems.Add($"{address} is already an address of '{adapter.Name}'.");
                else if (adapter.Id != target.Id && (U(existing.Address) & mask) == (a & mask))
                {
                    problems.Add($"'{adapter.Name}' is already in this subnet ({existing.Address}/{existing.PrefixLength}): traffic to the device could leave through it.");
                }
            }
        }

        return problems;
    }

    private static uint U(IPAddress a) => BinaryPrimitives.ReadUInt32BigEndian(a.GetAddressBytes());

    private static IPAddress Ip(uint v)
    {
        var b = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return new IPAddress(b);
    }
}
