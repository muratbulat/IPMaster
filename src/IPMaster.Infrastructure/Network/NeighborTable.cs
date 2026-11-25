using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Network;

/// <summary>
/// Reads the OS neighbour cache without sending traffic. Windows: <c>GetIpNetTable2</c> (IPv4 + IPv6).
/// Linux: <c>/proc/net/arp</c> and <c>ip -6 neigh</c>. macOS: <c>arp -an</c> and <c>ndp -an</c>.
/// External tools are run with argument lists, bounded output and a timeout.
/// </summary>
public sealed partial class NeighborTable : INeighborTable
{
    public CapabilityStatus Capability { get; } =
        OperatingSystem.IsWindows() ? CapabilityStatus.Yes("Neighbour cache via GetIpNetTable2.")
        : OperatingSystem.IsLinux() ? CapabilityStatus.Yes("Neighbour cache via /proc/net/arp and 'ip -6 neigh'.")
        : OperatingSystem.IsMacOS() ? CapabilityStatus.Yes("Neighbour cache via 'arp -an' and 'ndp -an' (unverified platform).")
        : CapabilityStatus.No("Neighbour cache is not supported on this platform.");

    public async Task<IReadOnlyList<NeighborEntry>> SnapshotAsync(CancellationToken cancellationToken)
    {
        if (OperatingSystem.IsWindows()) return await Task.Run(ReadWindows, cancellationToken).ConfigureAwait(false);
        var list = new List<NeighborEntry>();
        if (OperatingSystem.IsLinux())
        {
            if (File.Exists("/proc/net/arp")) list.AddRange(ParseProcArp(await File.ReadAllTextAsync("/proc/net/arp", cancellationToken).ConfigureAwait(false)));
            list.AddRange(ParseIpNeigh(await RunToolAsync("ip", ["-6", "neigh", "show"], cancellationToken).ConfigureAwait(false)));
        }
        else if (OperatingSystem.IsMacOS())
        {
            list.AddRange(ParseArpAn(await RunToolAsync("arp", ["-an"], cancellationToken).ConfigureAwait(false)));
            list.AddRange(ParseNdp(await RunToolAsync("ndp", ["-an"], cancellationToken).ConfigureAwait(false)));
        }

        return list;
    }

    internal static IEnumerable<NeighborEntry> ParseProcArp(string text)
    {
        // IP address  HW type  Flags  HW address  Mask  Device
        foreach (var line in text.Split('\n').Skip(1))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 6 || !IPAddress.TryParse(f[0], out var ip)) continue;
            if (f[2] == "0x0") continue; // incomplete
            if (Formats.ParseMac(f[3]) is { } mac && mac.GetAddressBytes().Any(b => b != 0)) yield return new NeighborEntry(ip, mac, 0, false);
        }
    }

    internal static IEnumerable<NeighborEntry> ParseIpNeigh(string text)
    {
        // fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
        foreach (var line in text.Split('\n'))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var ll = Array.IndexOf(f, "lladdr");
            if (f.Length < 3 || ll < 0 || ll + 1 >= f.Length || !IPAddress.TryParse(f[0], out var ip)) continue;
            if (f.Contains("FAILED") || f.Contains("INCOMPLETE")) continue;
            if (Formats.ParseMac(f[ll + 1]) is { } mac) yield return new NeighborEntry(ip, mac, 0, f.Contains("STALE"));
        }
    }

    internal static IEnumerable<NeighborEntry> ParseArpAn(string text)
    {
        // ? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]
        foreach (Match m in ArpLine().Matches(text))
        {
            if (!IPAddress.TryParse(m.Groups[1].Value, out var ip)) continue;
            var mac = NormalizeShortMac(m.Groups[2].Value);
            if (mac is not null) yield return new NeighborEntry(ip, mac, 0, false);
        }
    }

    internal static IEnumerable<NeighborEntry> ParseNdp(string text)
    {
        // Neighbor  Linklayer Address  Netif Expire St Flgs Prbs
        foreach (var line in text.Split('\n').Skip(1))
        {
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 2) continue;
            var addr = f[0].Split('%')[0];
            if (!IPAddress.TryParse(addr, out var ip)) continue;
            if (NormalizeShortMac(f[1]) is { } mac) yield return new NeighborEntry(ip, mac, 0, false);
        }
    }

    private static PhysicalAddress? NormalizeShortMac(string s)
    {
        var parts = s.Split(':');
        if (parts.Length != 6) return null;
        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            if (!byte.TryParse(parts[i], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out bytes[i])) return null;
        }

        return new PhysicalAddress(bytes);
    }

    /// <summary>Runs a neighbour-table tool for at most 3 s (bounded output, process tree killed on timeout). A missing or hanging
    /// tool yields no entries instead of failing the device (review C-11).</summary>
    internal static async Task<string> RunToolAsync(string file, string[] args, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(3));
        try
        {
            var r = await Queries.ProcessRunner.RunAsync(file, args, cts.Token).ConfigureAwait(false);
            return r.Output;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return ""; // timed out
        }
        catch (InvalidOperationException)
        {
            return ""; // tool not installed
        }
    }

    [GeneratedRegex(@"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)")]
    private static partial Regex ArpLine();

    // ---- Windows ----
    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<NeighborEntry> ReadWindows()
    {
        const int AfUnspec = 0;
        var list = new List<NeighborEntry>();
        if (GetIpNetTable2(AfUnspec, out var table) != 0) return list;
        try
        {
            var count = Marshal.ReadInt32(table);
            const int rowSize = 88; // MIB_IPNET_ROW2 (x64 and arm64)
            var first = table + 8;
            for (var i = 0; i < count; i++)
            {
                var row = first + (i * rowSize);
                var family = Marshal.ReadInt16(row);
                IPAddress ip;
                if (family == (short)AddressFamily.InterNetwork)
                {
                    var b = new byte[4];
                    Marshal.Copy(row + 4, b, 0, 4);
                    ip = new IPAddress(b);
                }
                else if (family == (short)AddressFamily.InterNetworkV6)
                {
                    var b = new byte[16];
                    Marshal.Copy(row + 8, b, 0, 16);
                    var scope = Marshal.ReadInt32(row + 24);
                    ip = new IPAddress(b, (uint)scope);
                }
                else
                {
                    continue;
                }

                var ifIndex = Marshal.ReadInt32(row + 28);
                var macLen = Marshal.ReadInt32(row + 72);
                var state = Marshal.ReadInt32(row + 76); // NL_NEIGHBOR_STATE: 0 unreachable,1 incomplete,2 probe,3 delay,4 stale,5 reachable,6 permanent
                if (macLen != 6 || state is 0 or 1) continue;
                var mac = new byte[6];
                Marshal.Copy(row + 40, mac, 0, 6);
                if (mac.All(x => x == 0) || mac.All(x => x == 0xFF) || (mac[0] & 0x01) != 0) continue; // broadcast/multicast
                list.Add(new NeighborEntry(ip, new PhysicalAddress(mac), ifIndex, state == 4));
            }
        }
        finally
        {
            FreeMibTable(table);
        }

        return list;
    }

    [LibraryImport("iphlpapi.dll")]
    [SupportedOSPlatform("windows")]
    private static partial int GetIpNetTable2(int family, out IntPtr table);

    [LibraryImport("iphlpapi.dll")]
    [SupportedOSPlatform("windows")]
    private static partial void FreeMibTable(IntPtr memory);
}
