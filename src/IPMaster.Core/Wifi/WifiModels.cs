using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Wifi;

public enum WifiBand
{
    Unknown,
    Band24,
    Band5,
    Band6,
}

/// <summary>A wireless adapter. <see cref="Gateway"/> and <see cref="DnsServers"/> come from its IP configuration.</summary>
public sealed record WifiAdapter(Guid Id, string Description, string State, IPAddress? Gateway, IReadOnlyList<IPAddress> DnsServers);

/// <summary>
/// One BSS (an access-point radio advertising one SSID) from a scan. Values are what the OS reported; the derived
/// properties come from the beacon's information elements and are null or "unknown" when the elements do not say.
/// </summary>
public sealed record WifiBss(
    Guid AdapterId,
    string Ssid,
    PhysicalAddress Bssid,
    int RssiDbm,
    int LinkQuality,
    int FrequencyMhz,
    ushort CapabilityInformation,
    int PhyType,
    InformationElements Ies,
    DateTimeOffset SeenAt)
{
    public WifiBand Band => WifiChannels.BandOf(FrequencyMhz);

    public int? Channel => WifiChannels.ChannelOf(FrequencyMhz);

    /// <summary>Null when the scan carried no information elements (width unknown).</summary>
    public int? WidthMhz => Ies.ChannelWidthMhz;

    public string Standard => WifiStandards.Describe(PhyType, Ies, Band);

    public string Security => WifiSecurity.Describe(CapabilityInformation, Ies);

    public bool Hidden => Ssid.Length == 0;

    /// <summary>Occupied spectrum in MHz (20 MHz assumed when the width is unknown).</summary>
    public (double Low, double High) Span => Channel is { } ch
        ? WifiChannels.Span(Band, ch, WidthMhz ?? 20, Ies.CenterChannel, Ies.SecondaryChannelOffset)
        : (FrequencyMhz - 10, FrequencyMhz + 10);
}

/// <summary>The current association as reported by the OS. <see cref="RssiDbm"/> is null when the driver does not report it.</summary>
public sealed record WifiConnection(
    Guid AdapterId,
    string ProfileName,
    string Ssid,
    PhysicalAddress Bssid,
    int SignalQuality,
    int? RssiDbm,
    int? FrequencyMhz,
    int? ChannelNumber,
    int PhyType,
    long RxRateKbps,
    long TxRateKbps,
    string Authentication,
    string Cipher)
{
    public WifiBand Band => FrequencyMhz is { } f ? WifiChannels.BandOf(f) : WifiBand.Unknown;

    public int? Channel => FrequencyMhz is { } f ? WifiChannels.ChannelOf(f) : ChannelNumber;
}

/// <summary>
/// Platform Wi-Fi access (D-097). Every call reports a typed state: <see cref="ObservationState.Unsupported"/> (platform or
/// service missing), <see cref="ObservationState.AccessDenied"/> (for example Windows location privacy),
/// <see cref="ObservationState.Empty"/> (no adapter, not connected) or <see cref="ObservationState.Failed"/>. Nothing is
/// ever changed on the adapter or on any access point.
/// </summary>
public interface IWifiProvider
{
    CapabilityStatus Capability { get; }

    Task<Observation<IReadOnlyList<WifiAdapter>>> AdaptersAsync(CancellationToken ct);

    /// <summary>The adapter's BSS list. <paramref name="fresh"/> asks the driver for a new scan first (a few seconds).</summary>
    Task<Observation<IReadOnlyList<WifiBss>>> ScanAsync(Guid adapter, bool fresh, CancellationToken ct);

    /// <summary>The current connection; Empty when the adapter is not connected.</summary>
    Task<Observation<WifiConnection>> ConnectionAsync(Guid adapter, CancellationToken ct);
}

/// <summary>Used where no Wi-Fi implementation exists (Linux nl80211 and macOS CoreWLAN are not implemented).</summary>
public sealed class UnsupportedWifiProvider(string reason) : IWifiProvider
{
    public CapabilityStatus Capability { get; } = CapabilityStatus.No(reason);

    public Task<Observation<IReadOnlyList<WifiAdapter>>> AdaptersAsync(CancellationToken ct) =>
        Task.FromResult(Observation<IReadOnlyList<WifiAdapter>>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, reason));

    public Task<Observation<IReadOnlyList<WifiBss>>> ScanAsync(Guid adapter, bool fresh, CancellationToken ct) =>
        Task.FromResult(Observation<IReadOnlyList<WifiBss>>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, reason));

    public Task<Observation<WifiConnection>> ConnectionAsync(Guid adapter, CancellationToken ct) =>
        Task.FromResult(Observation<WifiConnection>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, reason));
}

/// <summary>Labels for the 802.11 generation, from the PHY type the OS reports and the capability elements.</summary>
public static class WifiStandards
{
    public static string Describe(int phyType, InformationElements ies, WifiBand band)
    {
        ArgumentNullException.ThrowIfNull(ies);
        if (ies.Eht) return "Wi-Fi 7 (802.11be)";
        if (ies.He) return band == WifiBand.Band6 ? "Wi-Fi 6E (802.11ax)" : "Wi-Fi 6 (802.11ax)";
        if (ies.Vht) return "Wi-Fi 5 (802.11ac)";
        if (ies.Ht) return "Wi-Fi 4 (802.11n)";

        // DOT11_PHY_TYPE when the elements are missing
        return phyType switch
        {
            11 => "Wi-Fi 7 (802.11be)",
            10 => band == WifiBand.Band6 ? "Wi-Fi 6E (802.11ax)" : "Wi-Fi 6 (802.11ax)",
            8 => "Wi-Fi 5 (802.11ac)",
            7 => "Wi-Fi 4 (802.11n)",
            6 => "802.11g",
            5 => "802.11b",
            4 => "802.11a",
            _ => "unknown",
        };
    }

    public static string PhyName(int phyType) => phyType switch
    {
        11 => "EHT (802.11be)",
        10 => "HE (802.11ax)",
        8 => "VHT (802.11ac)",
        7 => "HT (802.11n)",
        6 => "ERP (802.11g)",
        5 => "HR-DSSS (802.11b)",
        4 => "OFDM (802.11a)",
        _ => "unknown",
    };
}

/// <summary>Security from the RSN/WPA elements and the privacy bit of the capability information.</summary>
public static class WifiSecurity
{
    public static string Describe(ushort capabilityInformation, InformationElements ies)
    {
        ArgumentNullException.ThrowIfNull(ies);
        var akm = ies.AkmSuites;
        if (akm.Count > 0)
        {
            var parts = new List<string>();
            if (akm.Contains(12) || akm.Contains(13)) parts.Add("WPA3-Enterprise 192-bit");
            if (akm.Contains(1) || akm.Contains(3) || akm.Contains(5)) parts.Add(akm.Contains(5) && !akm.Contains(1) ? "WPA3-Enterprise" : "WPA2-Enterprise");
            if (akm.Contains(8) || akm.Contains(9) || akm.Contains(24) || akm.Contains(25)) parts.Add("WPA3-Personal");
            if (akm.Contains(2) || akm.Contains(4) || akm.Contains(6)) parts.Add("WPA2-Personal");
            if (akm.Contains(18)) parts.Add("Enhanced Open (OWE)");
            return parts.Count > 0 ? string.Join(" / ", parts.Distinct()) : "RSN (other)";
        }

        if (ies.Wpa1) return "WPA";
        return (capabilityInformation & 0x0010) != 0 ? "WEP" : "Open";
    }
}
