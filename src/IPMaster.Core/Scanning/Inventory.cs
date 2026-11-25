using System.Net;
using System.Net.NetworkInformation;

namespace IPMaster.Core.Scanning;

public enum PortProtocol
{
    Tcp,
    Udp,
}

/// <summary>
/// Port states. UDP silence is never "open": it is <see cref="OpenOrFiltered"/> (no reply, no ICMP error).
/// </summary>
public enum PortState
{
    Open,

    /// <summary>TCP RST, or ICMP port unreachable for UDP.</summary>
    Closed,

    /// <summary>TCP: no answer within the timeout, or ICMP host/network unreachable.</summary>
    Filtered,

    /// <summary>UDP: no reply and no ICMP error.</summary>
    OpenOrFiltered,

    Unsupported,

    /// <summary>The probe failed locally (no buffer space, address in use, access denied…): says nothing about the device (review C-10).</summary>
    Failed,
}

public sealed record PortResult(PortProtocol Protocol, int Port, PortState State, string? Service = null, string? Detail = null);

/// <summary>Software identification read from a service greeting or protocol response.</summary>
public sealed record ServiceBanner(string Service, PortProtocol Protocol, int Port, string Text);

public sealed record TlsCertificateInfo(
    int Port,
    string Subject,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string SerialNumber,
    string Thumbprint,
    IReadOnlyList<string> SubjectAlternativeNames,
    string Protocol,
    bool ChainValid,
    string? ChainStatus)
{
    public int DaysUntilExpiry(DateTimeOffset now) => (int)Math.Floor((NotAfter - now).TotalDays);
}

public sealed record NetBiosName(string Name, byte Suffix, bool IsGroup);

public sealed record NetBiosInfo(string? ComputerName, string? Domain, string? UserName, PhysicalAddress? Mac, IReadOnlyList<NetBiosName> Names);

public enum ShareKind
{
    Folder,
    Printer,
    Device,
    Ipc,
    Other,
}

public sealed record DiskSpace(long TotalBytes, long FreeBytes);

/// <summary>Share access result. <see cref="Readable"/> = listing the root succeeded.</summary>
public sealed record ShareAccess(bool Readable, bool? Writable);

public sealed record ShareAccessEntry(string Account, string Rights, bool Allow);

public sealed record ShareInfo
{
    public required string Name { get; init; }

    public ShareKind Kind { get; init; }

    /// <summary>Hidden administrative share (C$, ADMIN$, IPC$, PRINT$ ...).</summary>
    public bool IsAdministrative { get; init; }

    public string Remark { get; init; } = "";

    public Observation<ShareAccess> Access { get; init; } = Observation<ShareAccess>.NotRequested;

    public Observation<DiskSpace> Disk { get; init; } = Observation<DiskSpace>.NotRequested;

    public Observation<IReadOnlyList<ShareAccessEntry>> Permissions { get; init; } = Observation<IReadOnlyList<ShareAccessEntry>>.NotRequested;

    /// <summary>Manual /sharetype letters: C common, R restricted, W writable, A administrative, P printer.</summary>
    public string TypeLetters
    {
        get
        {
            if (Kind == ShareKind.Printer) return "P";
            if (IsAdministrative) return "A";
            var s = Access.State == ObservationState.AccessDenied || (Access.HasValue && !Access.Value!.Readable) ? "R" : "C";
            if (Access.HasValue && Access.Value!.Writable == true) s += "W";
            return s;
        }
    }
}

public sealed record InstalledApplication(string Name, string? Version, string? Publisher);

/// <summary>A friendly MAC address source label.</summary>
public enum MacSource
{
    None,
    Arp,
    NeighborCache,
    NetBios,
    Wmi,
    RouterMib,
}

public sealed record NeighborEntry(IPAddress Address, PhysicalAddress Mac, int InterfaceIndex, bool IsStale);

public sealed record GeoLocation(string City, string Region, string Country)
{
    public override string ToString() => string.Join(", ", new[] { City, Region, Country }.Where(s => s.Length > 0));
}

public static class PublicAddress
{
    /// <summary>True for internet-routable unicast addresses (not private, loopback, link-local, CGNAT, ULA, documentation or multicast).</summary>
    public static bool IsPublic(IPAddress a)
    {
        ArgumentNullException.ThrowIfNull(a);
        if (IPAddress.IsLoopback(a)) return false;
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            return !(b[0] == 10 || b[0] == 0 || b[0] >= 224 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168)
                     || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || (b[0] == 192 && b[1] == 0 && b[2] == 2)
                     || (b[0] == 198 && b[1] == 51 && b[2] == 100) || (b[0] == 203 && b[1] == 0 && b[2] == 113));
        }

        var v6 = a.GetAddressBytes();
        return !(a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || (v6[0] & 0xFE) == 0xFC || (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0D && v6[3] == 0xB8));
    }
}

/// <summary>A display attached to a Windows host, decoded from its EDID (BAN-03).</summary>
public sealed record MonitorInfo(string Manufacturer, string Model, string Serial, int? Year)
{
    public override string ToString() => $"{Manufacturer} {Model}".Trim() + (Serial.Length > 0 ? $" (S/N {Serial})" : "");
}

/// <summary>A Remote Desktop / console session on a Windows host (BAN-05).</summary>
public sealed record TerminalSession(int Id, string User, string State, string ClientName, string ClientAddress)
{
    public override string ToString() =>
        (User.Length > 0 ? User : "(no user)") + $" [{State}]" + (ClientName.Length > 0 || ClientAddress.Length > 0
            ? " from " + string.Join(" ", new[] { ClientName, ClientAddress.Length > 0 ? $"({ClientAddress})" : "" }.Where(s => s.Length > 0))
            : "");
}

/// <summary>VESA EDID 1.x base block decoder (128 bytes).</summary>
public static class Edid
{
    private static readonly byte[] Header = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

    public static MonitorInfo? Parse(ReadOnlySpan<byte> edid)
    {
        if (edid.Length < 128 || !edid[..8].SequenceEqual(Header)) return null;
        var m = (edid[8] << 8) | edid[9];
        var manufacturer = new string([(char)('A' - 1 + ((m >> 10) & 0x1F)), (char)('A' - 1 + ((m >> 5) & 0x1F)), (char)('A' - 1 + (m & 0x1F))]);
        var product = edid[10] | (edid[11] << 8);
        var serialNumber = (uint)(edid[12] | (edid[13] << 8) | (edid[14] << 16) | (edid[15] << 24));
        int? year = edid[17] is > 0 and < 0xFF ? 1990 + edid[17] : null;
        string? name = null, serialText = null;
        for (var off = 54; off <= 108; off += 18)
        {
            var d = edid.Slice(off, 18);
            if (d[0] != 0 || d[1] != 0) continue; // detailed timing descriptor
            var text = Text(d[5..]);
            if (d[3] == 0xFC) name ??= text;
            else if (d[3] == 0xFF) serialText ??= text;
        }

        return new MonitorInfo(manufacturer, name is { Length: > 0 } ? name : $"{manufacturer}{product:X4}",
            serialText is { Length: > 0 } ? serialText : serialNumber is 0 or 0x01010101 ? "" : serialNumber.ToString(System.Globalization.CultureInfo.InvariantCulture), year);
    }

    private static string Text(ReadOnlySpan<byte> b)
    {
        var end = b.IndexOf((byte)0x0A);
        var s = System.Text.Encoding.ASCII.GetString(end >= 0 ? b[..end] : b);
        return new string(s.Where(c => c >= 0x20 && c < 0x7F).ToArray()).Trim();
    }
}

/// <summary>Windows extras of Phase 4 (WKS-07, MAC-03, BAN-03/05). Calls may block; the engine bounds them.</summary>
public interface IWindowsExtras
{
    CapabilityStatus Capability { get; }

    /// <summary>Authenticated SMB session to the host for the following NetApi/registry/SCM calls; null when not needed.</summary>
    IDisposable? OpenSession(string host, Security.ResolvedCredential credential);

    Observation<IReadOnlyList<MonitorInfo>> GetMonitors(string host, DateTimeOffset now);

    Observation<IReadOnlyList<TerminalSession>> GetTerminalSessions(string host, DateTimeOffset now);

    /// <summary>MAC of the adapter that owns <paramref name="address"/>, from Win32_NetworkAdapterConfiguration (WMI).</summary>
    Observation<PhysicalAddress> GetMacViaWmi(IPAddress address, Security.ResolvedCredential? credential, TimeSpan timeout, DateTimeOffset now);
}

/// <summary>ARP table of a router via SNMP ipNetToMediaPhysAddress (MAC-04).</summary>
public interface IRouterArpSource
{
    Task<IReadOnlyDictionary<IPAddress, PhysicalAddress>> ArpTableAsync(IPAddress router, string community, CancellationToken cancellationToken);
}
