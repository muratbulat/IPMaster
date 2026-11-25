namespace IPMaster.Core.Network;

/// <summary>What kind of link an adapter is. <see cref="Unknown"/> when the OS metadata does not say clearly.</summary>
public enum AdapterKind
{
    Unknown,
    Ethernet,
    WiFi,
    Virtual,
    Vpn,
}

/// <summary>The classification and the evidence it rests on (shown to the user).</summary>
public sealed record AdapterClass(AdapterKind Kind, bool? Physical, string Evidence)
{
    public string Label => Kind switch
    {
        AdapterKind.Ethernet => Physical == true ? "Ethernet" : "Ethernet (unknown origin)",
        AdapterKind.WiFi => "Wi-Fi",
        AdapterKind.Virtual => "Virtual",
        AdapterKind.Vpn => "VPN",
        _ => "Unknown type",
    };
}

/// <summary>
/// Classifies adapters for the range picker (D-101) from the OS interface type, well-known virtual/VPN MAC prefixes
/// and description keywords. Only evidence that is reliable counts: the OS type for Wi-Fi, PPP and tunnels; vendor MAC
/// prefixes of Hyper-V, VMware, VirtualBox, Parallels, QEMU and Fortinet; and product names in the description. An
/// Ethernet adapter with none of these is "likely physical"; anything else is Unknown rather than guessed.
/// </summary>
public static class AdapterClassifier
{
    private static readonly (string Prefix, AdapterKind Kind, string Vendor)[] MacPrefixes =
    [
        ("00-15-5D", AdapterKind.Virtual, "Hyper-V"),
        ("00-50-56", AdapterKind.Virtual, "VMware"),
        ("00-0C-29", AdapterKind.Virtual, "VMware"),
        ("00-05-69", AdapterKind.Virtual, "VMware"),
        ("08-00-27", AdapterKind.Virtual, "VirtualBox"),
        ("0A-00-27", AdapterKind.Virtual, "VirtualBox host-only"),
        ("00-1C-42", AdapterKind.Virtual, "Parallels"),
        ("52-54-00", AdapterKind.Virtual, "QEMU/KVM"),
        ("00-09-0F", AdapterKind.Vpn, "Fortinet"),
    ];

    private static readonly (string Word, AdapterKind Kind)[] Keywords =
    [
        ("vpn", AdapterKind.Vpn), ("wireguard", AdapterKind.Vpn), ("openvpn", AdapterKind.Vpn), ("tap-windows", AdapterKind.Vpn),
        ("anyconnect", AdapterKind.Vpn), ("globalprotect", AdapterKind.Vpn), ("fortinet", AdapterKind.Vpn), ("pangp", AdapterKind.Vpn),
        ("tailscale", AdapterKind.Vpn), ("zerotier", AdapterKind.Vpn), ("nordlynx", AdapterKind.Vpn), ("wintun", AdapterKind.Vpn),
        ("hyper-v", AdapterKind.Virtual), ("vethernet", AdapterKind.Virtual), ("vmware", AdapterKind.Virtual), ("virtualbox", AdapterKind.Virtual),
        ("wsl", AdapterKind.Virtual), ("docker", AdapterKind.Virtual), ("virtual", AdapterKind.Virtual), ("loopback", AdapterKind.Virtual),
        ("wi-fi direct", AdapterKind.Virtual), ("bluetooth", AdapterKind.Unknown),
    ];

    public static AdapterClass Classify(NetworkAdapterInfo adapter)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        var type = adapter.Type;
        if (type.Equals("Ppp", StringComparison.OrdinalIgnoreCase)) return new(AdapterKind.Vpn, false, "OS interface type PPP");
        if (type.Equals("Tunnel", StringComparison.OrdinalIgnoreCase)) return new(AdapterKind.Vpn, false, "OS interface type tunnel");

        var mac = (adapter.MacAddress ?? "").Replace(':', '-').ToUpperInvariant();
        foreach (var (prefix, kind, vendor) in MacPrefixes)
        {
            if (mac.StartsWith(prefix, StringComparison.Ordinal)) return new(kind, false, $"MAC prefix {prefix} ({vendor})");
        }

        var text = (adapter.Name + " " + adapter.Description).ToLowerInvariant();
        foreach (var (word, kind) in Keywords)
        {
            if (!text.Contains(word, StringComparison.Ordinal)) continue;
            return kind == AdapterKind.Unknown
                ? new(AdapterKind.Unknown, null, $"\"{word}\" in the name or description")
                : new(kind, false, $"\"{word}\" in the name or description");
        }

        if (type.Equals("Wireless80211", StringComparison.OrdinalIgnoreCase)) return new(AdapterKind.WiFi, true, "OS interface type 802.11");
        if (type.StartsWith("Ethernet", StringComparison.OrdinalIgnoreCase) || type.StartsWith("GigabitEthernet", StringComparison.OrdinalIgnoreCase) || type.StartsWith("FastEthernet", StringComparison.OrdinalIgnoreCase))
        {
            // locally administered MAC (second hex digit 2, 6, A or E): set by software, so not proof of hardware
            if (mac.Length >= 2 && "26AE".Contains(mac[1], StringComparison.Ordinal)) return new(AdapterKind.Ethernet, null, "OS type Ethernet, locally administered MAC");
            return new(AdapterKind.Ethernet, true, "OS type Ethernet, no virtual or VPN marker (likely physical)");
        }

        return new(AdapterKind.Unknown, null, $"OS interface type {type}");
    }
}
