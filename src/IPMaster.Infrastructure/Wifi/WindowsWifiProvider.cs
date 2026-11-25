using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using IPMaster.Core.Scanning;
using IPMaster.Core.Wifi;

namespace IPMaster.Infrastructure.Wifi;

/// <summary>
/// Windows Native Wifi API (wlanapi.dll, D-097): WlanEnumInterfaces, WlanScan, WlanGetNetworkBssList and
/// WlanQueryInterface. Read-only: nothing connects, disconnects or changes a profile. Windows 11 24H2 and later return
/// ERROR_ACCESS_DENIED for scan results and the connected SSID/BSSID unless desktop apps may use location (Settings →
/// Privacy &amp; security → Location); that is reported as <see cref="ObservationState.AccessDenied"/> with the fix.
/// A handle is opened per call, so there is no long-lived native state to leak.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed partial class WindowsWifiProvider : IWifiProvider
{
    private const int ErrorSuccess = 0;
    private const int ErrorAccessDenied = 5;
    private const int ErrorInvalidState = 5023;
    private const int ErrorServiceNotActive = 1062;
    private const int ErrorNdisDot11PowerStateInvalid = unchecked((int)0x80342002);
    private const int OpcodeCurrentConnection = 7;
    private const int OpcodeRssi = 0x10000102;

    /// <summary>Drivers must finish a scan within 4 seconds (WlanScan documentation).</summary>
    public static readonly TimeSpan ScanWait = TimeSpan.FromSeconds(4);

    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("Windows Native Wifi API (read-only).");

    public Task<Observation<IReadOnlyList<WifiAdapter>>> AdaptersAsync(CancellationToken ct) => Task.Run(() =>
    {
        var now = DateTimeOffset.UtcNow;
        var open = Open(out var handle);
        if (open is { } failed) return Observation<IReadOnlyList<WifiAdapter>>.Of(failed.State, now, failed.Detail);
        try
        {
            var rc = WlanEnumInterfaces(handle, IntPtr.Zero, out var list);
            if (rc != ErrorSuccess) return Observation<IReadOnlyList<WifiAdapter>>.Of(StateOf(rc), now, Describe(rc, "WlanEnumInterfaces"));
            try
            {
                var adapters = ReadInterfaces(list).Select(i => WithIp(i.Id, i.Description, i.State)).ToList();
                return adapters.Count == 0
                    ? Observation<IReadOnlyList<WifiAdapter>>.Of(ObservationState.Empty, now, "No wireless adapter is present or enabled.")
                    : Observation<IReadOnlyList<WifiAdapter>>.Ok(adapters, now);
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }
        finally
        {
            _ = WlanCloseHandle(handle, IntPtr.Zero);
        }
    }, ct);

    public async Task<Observation<IReadOnlyList<WifiBss>>> ScanAsync(Guid adapter, bool fresh, CancellationToken ct)
    {
        if (fresh)
        {
            var requested = await Task.Run(() => RequestScan(adapter), ct).ConfigureAwait(false);
            if (requested is { } failed) return Observation<IReadOnlyList<WifiBss>>.Of(failed.State, DateTimeOffset.UtcNow, failed.Detail);
            await Task.Delay(ScanWait, ct).ConfigureAwait(false);
        }

        return await Task.Run(() => ReadBssList(adapter), ct).ConfigureAwait(false);
    }

    public Task<Observation<WifiConnection>> ConnectionAsync(Guid adapter, CancellationToken ct) => Task.Run(() =>
    {
        var now = DateTimeOffset.UtcNow;
        var open = Open(out var handle);
        if (open is { } failed) return Observation<WifiConnection>.Of(failed.State, now, failed.Detail);
        try
        {
            var id = adapter;
            var rc = WlanQueryInterface(handle, ref id, OpcodeCurrentConnection, IntPtr.Zero, out var size, out var data, IntPtr.Zero);
            if (rc == ErrorInvalidState) return Observation<WifiConnection>.Of(ObservationState.Empty, now, "Not connected.");
            if (rc != ErrorSuccess) return Observation<WifiConnection>.Of(StateOf(rc), now, Describe(rc, "WlanQueryInterface"));
            byte[] raw;
            try
            {
                raw = new byte[size];
                Marshal.Copy(data, raw, 0, size);
            }
            finally
            {
                WlanFreeMemory(data);
            }

            int? rssi = null;
            if (WlanQueryInterface(handle, ref id, OpcodeRssi, IntPtr.Zero, out var rs, out var rd, IntPtr.Zero) == ErrorSuccess)
            {
                if (rs >= 4) rssi = Marshal.ReadInt32(rd);
                WlanFreeMemory(rd);
            }

            var c = WlanLayout.ParseConnection(raw, adapter, rssi);
            if (c is null) return Observation<WifiConnection>.Of(ObservationState.Empty, now, "Not connected.");

            // the connected BSS's frequency comes from the cached BSS list (the channel number alone is ambiguous between bands)
            var bss = ReadBssList(adapter);
            var match = bss.HasValue ? bss.Value!.FirstOrDefault(b => b.Bssid.Equals(c.Bssid)) : null;
            if (match is not null) c = c with { FrequencyMhz = match.FrequencyMhz, RssiDbm = c.RssiDbm ?? match.RssiDbm };
            return Observation<WifiConnection>.Ok(c, now);
        }
        finally
        {
            _ = WlanCloseHandle(handle, IntPtr.Zero);
        }
    }, ct);

    private static (ObservationState State, string Detail)? RequestScan(Guid adapter)
    {
        var open = Open(out var handle);
        if (open is not null) return open;
        try
        {
            var id = adapter;
            var rc = WlanScan(handle, ref id, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            return rc == ErrorSuccess ? null : (StateOf(rc), Describe(rc, "WlanScan"));
        }
        finally
        {
            _ = WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private static Observation<IReadOnlyList<WifiBss>> ReadBssList(Guid adapter)
    {
        var now = DateTimeOffset.UtcNow;
        var open = Open(out var handle);
        if (open is { } failed) return Observation<IReadOnlyList<WifiBss>>.Of(failed.State, now, failed.Detail);
        try
        {
            var id = adapter;
            var rc = WlanGetNetworkBssList(handle, ref id, IntPtr.Zero, 3 /* dot11_BSS_type_any */, false, IntPtr.Zero, out var list);
            if (rc != ErrorSuccess) return Observation<IReadOnlyList<WifiBss>>.Of(StateOf(rc), now, Describe(rc, "WlanGetNetworkBssList"));
            try
            {
                var total = Marshal.ReadInt32(list);
                var raw = new byte[total];
                Marshal.Copy(list, raw, 0, total);
                var entries = WlanLayout.ParseBssList(raw, adapter, now);
                return entries.Count == 0
                    ? Observation<IReadOnlyList<WifiBss>>.Of(ObservationState.Empty, now, "No networks in range (or the adapter is off).")
                    : Observation<IReadOnlyList<WifiBss>>.Ok(entries, now);
            }
            finally
            {
                WlanFreeMemory(list);
            }
        }
        finally
        {
            _ = WlanCloseHandle(handle, IntPtr.Zero);
        }
    }

    private static (ObservationState State, string Detail)? Open(out IntPtr handle)
    {
        handle = IntPtr.Zero;
        try
        {
            var rc = WlanOpenHandle(2, IntPtr.Zero, out _, out handle);
            if (rc == ErrorSuccess) return null;
            return rc == ErrorServiceNotActive
                ? (ObservationState.Empty, "The WLAN AutoConfig service is not running: no wireless adapter is present, or the service is stopped.")
                : (StateOf(rc), Describe(rc, "WlanOpenHandle"));
        }
        catch (DllNotFoundException)
        {
            // Windows Server without the Wireless LAN Service feature has no wlanapi.dll
            return (ObservationState.Unsupported, "wlanapi.dll is not present (on Windows Server, install the Wireless LAN Service feature).");
        }
    }

    private static ObservationState StateOf(int rc) => rc switch
    {
        ErrorAccessDenied => ObservationState.AccessDenied,
        ErrorNdisDot11PowerStateInvalid => ObservationState.Empty,
        _ => ObservationState.Failed,
    };

    private static string Describe(int rc, string call) => rc switch
    {
        ErrorAccessDenied => WlanLayout.LocationHint,
        ErrorNdisDot11PowerStateInvalid => "The wireless radio is turned off.",
        _ => $"{call} failed: {new System.ComponentModel.Win32Exception(rc).Message} ({rc}).",
    };

    private static IEnumerable<(Guid Id, string Description, string State)> ReadInterfaces(IntPtr list)
    {
        var count = Marshal.ReadInt32(list);
        const int itemSize = 16 + 512 + 4;
        for (var i = 0; i < count; i++)
        {
            var item = list + 8 + (i * itemSize);
            var guid = Marshal.PtrToStructure<Guid>(item);
            var description = Marshal.PtrToStringUni(item + 16) ?? "";
            var state = Marshal.ReadInt32(item + 16 + 512);
            yield return (guid, description, WlanLayout.InterfaceState(state));
        }
    }

    private static WifiAdapter WithIp(Guid id, string description, string state)
    {
        IPAddress? gateway = null;
        IReadOnlyList<IPAddress> dns = [];
        var nic = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => Guid.TryParse(n.Id, out var g) && g == id);
        if (nic is not null)
        {
            var ip = nic.GetIPProperties();
            gateway = ip.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork && !a.Equals(IPAddress.Any))
                      ?? ip.GatewayAddresses.Select(g => g.Address).FirstOrDefault(a => !a.Equals(IPAddress.IPv6Any));
            dns = ip.DnsAddresses.ToList();
        }

        return new WifiAdapter(id, description, state, gateway, dns);
    }

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanOpenHandle(uint clientVersion, IntPtr reserved, out uint negotiatedVersion, out IntPtr handle);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanCloseHandle(IntPtr handle, IntPtr reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanEnumInterfaces(IntPtr handle, IntPtr reserved, out IntPtr list);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanScan(IntPtr handle, ref Guid interfaceGuid, IntPtr ssid, IntPtr ieData, IntPtr reserved);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanGetNetworkBssList(IntPtr handle, ref Guid interfaceGuid, IntPtr ssid, int bssType,
        [MarshalAs(UnmanagedType.Bool)] bool securityEnabled, IntPtr reserved, out IntPtr list);

    [LibraryImport("wlanapi.dll")]
    private static partial int WlanQueryInterface(IntPtr handle, ref Guid interfaceGuid, int opCode, IntPtr reserved, out int dataSize, out IntPtr data, IntPtr valueType);

    [LibraryImport("wlanapi.dll")]
    private static partial void WlanFreeMemory(IntPtr memory);
}

/// <summary>Byte layouts of the Native Wifi structures (pure: no native calls, testable on every platform).</summary>
public static class WlanLayout
{
    public const string LocationHint = "Windows blocks Wi-Fi details without location access: turn on Settings → Privacy & security → Location → " +
                                       "\"Location services\" and \"Let desktop apps access your location\", then refresh.";

    public static string InterfaceState(int state) => state switch
    {
        0 => "not ready",
        1 => "connected",
        2 => "ad hoc network formed",
        3 => "disconnecting",
        4 => "disconnected",
        5 => "associating",
        6 => "discovering",
        7 => "authenticating",
        _ => "unknown",
    };

    /// <summary>
    /// WLAN_BSS_LIST: dwTotalSize, dwNumberOfItems, then 360-byte WLAN_BSS_ENTRY items whose information elements sit at
    /// ulIeOffset from the entry start. Entries that do not fit the buffer are skipped, never read past its end.
    /// </summary>
    public static IReadOnlyList<WifiBss> ParseBssList(ReadOnlySpan<byte> raw, Guid adapter, DateTimeOffset seenAt)
    {
        const int entrySize = 360;
        var result = new List<WifiBss>();
        if (raw.Length < 8) return result;
        var count = BinaryPrimitives.ReadInt32LittleEndian(raw[4..]);
        for (var i = 0; i < count; i++)
        {
            var start = 8 + (i * entrySize);
            if (start + entrySize > raw.Length) break;
            var e = raw.Slice(start, entrySize);
            var ssidLength = Math.Min(32, BinaryPrimitives.ReadInt32LittleEndian(e));
            var ssid = Ssid(e.Slice(4, Math.Max(0, ssidLength)));
            var bssid = new PhysicalAddress(e.Slice(40, 6).ToArray());
            var phy = BinaryPrimitives.ReadInt32LittleEndian(e[52..]);
            var rssi = BinaryPrimitives.ReadInt32LittleEndian(e[56..]);
            var quality = BinaryPrimitives.ReadInt32LittleEndian(e[60..]);
            var capability = BinaryPrimitives.ReadUInt16LittleEndian(e[88..]);
            var frequencyKhz = BinaryPrimitives.ReadUInt32LittleEndian(e[92..]);
            var ieOffset = BinaryPrimitives.ReadUInt32LittleEndian(e[352..]);
            var ieSize = BinaryPrimitives.ReadUInt32LittleEndian(e[356..]);
            var ies = InformationElements.None;
            if (ieSize > 0 && (long)start + ieOffset + ieSize <= raw.Length) ies = InformationElements.Parse(raw.Slice(start + (int)ieOffset, (int)ieSize));
            result.Add(new WifiBss(adapter, ssid, bssid, rssi, quality, (int)(frequencyKhz / 1000), capability, phy, ies, seenAt));
        }

        return result;
    }

    /// <summary>
    /// WLAN_CONNECTION_ATTRIBUTES (604 bytes): state, mode, profile name (WCHAR[256]), association attributes
    /// (SSID, BSS type, BSSID, PHY type, PHY index, signal quality, rx/tx rate in kbit/s) and security attributes.
    /// Null when the buffer is too short or the interface is not connected.
    /// </summary>
    public static WifiConnection? ParseConnection(ReadOnlySpan<byte> raw, Guid adapter, int? rssiDbm)
    {
        if (raw.Length < 604) return null;
        var state = BinaryPrimitives.ReadInt32LittleEndian(raw);
        if (state != 1) return null;
        var profile = Encoding.Unicode.GetString(raw.Slice(8, 512)).Split('\0')[0];
        var a = raw[520..];
        var ssid = Ssid(a.Slice(4, Math.Clamp(BinaryPrimitives.ReadInt32LittleEndian(a), 0, 32)));
        var bssid = new PhysicalAddress(a.Slice(40, 6).ToArray());
        var phy = BinaryPrimitives.ReadInt32LittleEndian(a[48..]);
        var quality = BinaryPrimitives.ReadInt32LittleEndian(a[56..]);
        var rx = BinaryPrimitives.ReadUInt32LittleEndian(a[60..]);
        var tx = BinaryPrimitives.ReadUInt32LittleEndian(a[64..]);
        var auth = BinaryPrimitives.ReadInt32LittleEndian(raw[596..]);
        var cipher = BinaryPrimitives.ReadInt32LittleEndian(raw[600..]);
        return new WifiConnection(adapter, profile, ssid, bssid, quality, rssiDbm, null, null, phy, rx, tx, AuthName(auth), CipherName(cipher));
    }

    private static string Ssid(ReadOnlySpan<byte> bytes)
    {
        var s = Encoding.UTF8.GetString(bytes);
        return s.Contains('�', StringComparison.Ordinal) ? Convert.ToHexString(bytes) : s.Replace('\0', ' ').TrimEnd();
    }

    public static string AuthName(int auth) => auth switch
    {
        1 => "Open",
        2 => "Shared key",
        3 => "WPA-Enterprise",
        4 => "WPA-Personal",
        6 => "WPA2-Enterprise",
        7 => "WPA2-Personal",
        8 => "WPA3-Enterprise 192-bit",
        9 => "WPA3-Personal (SAE)",
        10 => "Enhanced Open (OWE)",
        11 => "WPA3-Enterprise",
        _ => $"other ({auth})",
    };

    public static string CipherName(int cipher) => cipher switch
    {
        0 => "none",
        1 => "WEP-40",
        2 => "TKIP",
        4 => "CCMP (AES)",
        5 => "WEP-104",
        8 => "GCMP",
        9 => "GCMP-256",
        10 => "CCMP-256",
        0x101 => "WEP",
        _ => $"other ({cipher})",
    };
}
