using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using IPMaster.Core.Network;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Infrastructure.Network;

/// <summary>
/// Windows: adds the address with <c>New-NetIPAddress -PolicyStore ActiveStore</c> (D-090). The active store is never
/// written to the persistent configuration, so the address disappears on an adapter restart or a reboot even when IPMaster
/// cannot remove it (crash, power loss). No gateway is added; existing addresses are not touched. Only validated values
/// (interface index, parsed address, integer prefix) reach the command line. Administrator rights are required.
/// Other platforms: Unsupported.
/// </summary>
public sealed class TemporaryAddressManager : ITemporaryAddressManager
{
    private readonly object _lock = new();
    private readonly List<TemporaryAddress> _active = [];

    public CapabilityStatus Capability { get; } = OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes("Windows active-store address (administrator rights needed; gone after a reboot).")
        : CapabilityStatus.No("Adding a temporary address is implemented for Windows only; add it with 'ip addr add' (Linux) or 'ifconfig alias' (macOS).");

    public IReadOnlyList<TemporaryAddress> Active
    {
        get
        {
            lock (_lock) return _active.ToList();
        }
    }

    /// <summary>The PowerShell arguments for adding (public for tests: no gateway, active store, validated values only).</summary>
    public static IReadOnlyList<string> AddArguments(int interfaceIndex, IPAddress address, int prefixLength) => Arguments(
        $"New-NetIPAddress -InterfaceIndex {interfaceIndex.ToString(CultureInfo.InvariantCulture)} -IPAddress {Validated(address)} " +
        $"-PrefixLength {prefixLength.ToString(CultureInfo.InvariantCulture)} -PolicyStore ActiveStore -ErrorAction Stop | Out-Null");

    public static IReadOnlyList<string> RemoveArguments(int interfaceIndex, IPAddress address) => Arguments(
        $"Remove-NetIPAddress -InterfaceIndex {interfaceIndex.ToString(CultureInfo.InvariantCulture)} -IPAddress {Validated(address)} " +
        "-PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop");

    public async Task<TemporaryAddress> AddAsync(NetworkAdapterInfo adapter, IPAddress address, int prefixLength, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(address);
        if (!Capability.Available) throw new InvalidOperationException(Capability.Description);
        if (prefixLength is < 8 or > 30) throw new ArgumentOutOfRangeException(nameof(prefixLength), "The prefix length must be between 8 and 30.");
        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == adapter.Id)
                  ?? throw new InvalidOperationException($"The adapter '{adapter.Name}' is no longer present.");
        var index = nic.GetIPProperties().GetIPv4Properties()?.Index ?? throw new InvalidOperationException($"'{adapter.Name}' has no IPv4 stack.");
        await RunAsync(AddArguments(index, address, prefixLength), ct).ConfigureAwait(false);
        var added = new TemporaryAddress(adapter.Id, adapter.Name, index, address, prefixLength, DateTimeOffset.Now);
        lock (_lock) _active.Add(added);

        // Windows probes the address (IPv4 duplicate address detection); a device already using it makes it Duplicate.
        for (var i = 0; i < 30 && OperatingSystem.IsWindows(); i++)
        {
            var state = nic.GetIPProperties().UnicastAddresses.FirstOrDefault(u => u.Address.Equals(address)) is { } u ? u.DuplicateAddressDetectionState : (DuplicateAddressDetectionState?)null;
            if (state == DuplicateAddressDetectionState.Preferred) return added;
            if (state == DuplicateAddressDetectionState.Duplicate)
            {
                await RemoveAsync(added, CancellationToken.None).ConfigureAwait(false);
                throw new InvalidOperationException($"{address} is already used by another device on '{adapter.Name}'; it was removed again. Choose another address.");
            }

            await Task.Delay(100, ct).ConfigureAwait(false);
        }

        return added; // still tentative after 3 s: kept, the caller sees it as active and can remove it
    }

    public async Task RemoveAsync(TemporaryAddress address, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(address);
        try
        {
            await RunAsync(RemoveArguments(address.InterfaceIndex, address.Address), ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("No matching", StringComparison.OrdinalIgnoreCase))
        {
            // already gone (adapter restarted or removed): nothing left to restore
        }

        lock (_lock) _active.Remove(address);
    }

    public async Task<IReadOnlyList<(TemporaryAddress Address, string Error)>> RemoveAllAsync(CancellationToken ct)
    {
        var failed = new List<(TemporaryAddress, string)>();
        foreach (var a in Active)
        {
            try
            {
                await RemoveAsync(a, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
            {
                failed.Add((a, ex.Message));
            }
        }

        return failed;
    }

    private static async Task RunAsync(IReadOnlyList<string> arguments, CancellationToken ct)
    {
        var shell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        var r = await ProcessRunner.RunAsync(shell, arguments, ct, maxOutput: 64 * 1024).ConfigureAwait(false);
        if (r.ExitCode == 0) return;
        var error = (r.Error.Length > 0 ? r.Error : r.Output).Trim();
        if (error.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) || error.Contains("PermissionDenied", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Changing adapter addresses needs administrator rights: run IPMaster as administrator.");
        }

        throw new InvalidOperationException(error.Length > 0 ? error.Split('\n')[0].Trim() : $"PowerShell exited with code {r.ExitCode}.");
    }

    private static IReadOnlyList<string> Arguments(string command) => ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command];

    private static string Validated(IPAddress a) => a.AddressFamily == AddressFamily.InterNetwork
        ? a.ToString()
        : throw new ArgumentException("Only IPv4 addresses can be added.", nameof(a));
}
