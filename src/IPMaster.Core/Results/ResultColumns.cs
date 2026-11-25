using System.Globalization;
using System.Net.NetworkInformation;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Results;

public enum ColumnKind
{
    Text,
    IpAddress,
    Number,
    DateTime,
}

public enum MacFormat
{
    /// <summary>AA-BB-CC-DD-EE-FF</summary>
    Dashes,

    /// <summary>AA:BB:CC:DD:EE:FF</summary>
    Colons,

    /// <summary>AABBCCDDEEFF</summary>
    Plain,

    /// <summary>aabb.ccdd.eeff</summary>
    Dotted,

    /// <summary>aa:bb:cc:dd:ee:ff</summary>
    LowerColons,
}

/// <summary>Rendering context shared by the grid and every exporter.</summary>
public sealed record ColumnFormat
{
    public static ColumnFormat Default { get; } = new();

    public MacFormat MacFormat { get; init; } = MacFormat.Dashes;

    /// <summary>Separator between multiple values in one cell (manual: "Cell content separator").</summary>
    public string Separator { get; init; } = ", ";

    public bool ShowServiceNames { get; init; }

    /// <summary>MAC addresses (12 hex digits) seen on more than one IP address; rendered with a "(duplicate)" marker.</summary>
    public IReadOnlySet<string>? DuplicateMacs { get; init; }

    /// <summary>Only shares whose type letters intersect these letters are listed (CLI /sharetype). Null = all.</summary>
    public string? ShareTypeFilter { get; init; }

    public bool ShareMatches(ShareInfo share)
    {
        ArgumentNullException.ThrowIfNull(share);
        return ShareTypeFilter is null || share.TypeLetters.Any(c => ShareTypeFilter.Contains(c, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>A result column shared by the grid, exports, filters and <c>/cols</c>. <see cref="Value"/> returns a
/// typed comparable value (AddressKey, double, DateTimeOffset, string) for sorting and numeric filters.</summary>
public sealed record ResultColumn(string Id, string Header, ColumnKind Kind, Func<DeviceResult, ColumnFormat, string> Render,
    Func<DeviceResult, IComparable?>? Value = null)
{
    public string Text(DeviceResult device) => Render(device, ColumnFormat.Default);

    public string Text(DeviceResult device, ColumnFormat format) => Render(device, format);

    public IComparable? SortValue(DeviceResult device, ColumnFormat format) => Value is not null ? Value(device) : Render(device, format);
}

/// <summary>Text rendering rules for observations (D-013): values as-is; Empty/NotRequested/Pending blank;
/// failure states in square brackets so they cannot be confused with values.</summary>
public static class ObservationText
{
    public static string Render<T>(Observation<T> o, Func<T, string> value) => o.State switch
    {
        ObservationState.Success => value(o.Value!),
        ObservationState.Empty or ObservationState.NotRequested or ObservationState.Pending => "",
        ObservationState.NoResponse => "[no response]",
        ObservationState.Timeout => "[timeout]",
        ObservationState.AccessDenied => "[access denied]",
        ObservationState.Unsupported => "[unsupported]",
        ObservationState.Cancelled => "[cancelled]",
        _ => "[failed]",
    };

    public static string StateName(ObservationState s) => s switch
    {
        ObservationState.NotRequested => "notRequested",
        ObservationState.Pending => "pending",
        ObservationState.Success => "success",
        ObservationState.Empty => "empty",
        ObservationState.NoResponse => "noResponse",
        ObservationState.Timeout => "timeout",
        ObservationState.AccessDenied => "accessDenied",
        ObservationState.Unsupported => "unsupported",
        ObservationState.Cancelled => "cancelled",
        _ => "failed",
    };

    public static ObservationState ParseState(string? s) => s switch
    {
        "notRequested" => ObservationState.NotRequested,
        "pending" => ObservationState.Pending,
        "success" => ObservationState.Success,
        "empty" => ObservationState.Empty,
        "noResponse" => ObservationState.NoResponse,
        "timeout" => ObservationState.Timeout,
        "accessDenied" => ObservationState.AccessDenied,
        "unsupported" => ObservationState.Unsupported,
        "cancelled" => ObservationState.Cancelled,
        "failed" => ObservationState.Failed,
        _ => throw new FormatException($"Unknown observation state '{s}'."),
    };
}

public static class Formats
{
    public static string Mac(PhysicalAddress mac, string separator = "-")
    {
        ArgumentNullException.ThrowIfNull(mac);
        return string.Join(separator, mac.GetAddressBytes().Select(b => b.ToString("X2", CultureInfo.InvariantCulture)));
    }

    public static string Mac(PhysicalAddress mac, MacFormat format)
    {
        ArgumentNullException.ThrowIfNull(mac);
        var hex = Convert.ToHexString(mac.GetAddressBytes());
        return format switch
        {
            MacFormat.Colons => Mac(mac, ":"),
            MacFormat.Plain => hex,
            MacFormat.LowerColons => Mac(mac, ":").ToLowerInvariant(),
            MacFormat.Dotted => string.Join(".", Enumerable.Range(0, (hex.Length + 3) / 4).Select(i => hex.Substring(i * 4, Math.Min(4, hex.Length - (i * 4))))).ToLowerInvariant(),
            _ => Mac(mac, "-"),
        };
    }

    public static PhysicalAddress? ParseMac(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var hex = new string(text.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12 || text.Any(c => !Uri.IsHexDigit(c) && c is not ('-' or ':' or '.' or ' '))) return null;
        return new PhysicalAddress(Convert.FromHexString(hex));
    }

    public static string Milliseconds(TimeSpan t) =>
        t.TotalMilliseconds < 1 ? "<1 ms" : t.TotalMilliseconds.ToString("0", CultureInfo.InvariantCulture) + " ms";

    public static string Timestamp(DateTimeOffset t) => t.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    public static string Bytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB"];
        double v = bytes;
        var i = 0;
        while (v >= 1024 && i < units.Length - 1)
        {
            v /= 1024;
            i++;
        }

        return v.ToString(i == 0 ? "0" : "0.0", CultureInfo.InvariantCulture) + " " + units[i];
    }

    public static string Status(DeviceStatus s) => s switch
    {
        DeviceStatus.Online => "Online",
        DeviceStatus.Offline => "Offline",
        DeviceStatus.Cancelled => "Cancelled",
        DeviceStatus.TimedOut => "Timed out",
        _ => "Unsupported",
    };

    public static string HostName(HostNameInfo h) => h.ForwardConfirmed == false ? h.Name + " (unverified)" : h.Name;

    public static string Port(PortResult p, bool serviceNames)
    {
        var label = serviceNames && (p.Service ?? PortList.ServiceName(p.Port)) is { } n ? n : p.Port.ToString(CultureInfo.InvariantCulture);
        return p.State switch
        {
            PortState.Open => label,
            PortState.Closed => label + " (closed)",
            PortState.Filtered => label + " (filtered)",
            PortState.OpenOrFiltered => label + " (open|filtered)",
            PortState.Failed => label + " (not probed: local error)",
            _ => label + " (unsupported)",
        };
    }

    public static string Banner(ServiceBanner b) => $"{b.Service}/{b.Port}: {b.Text}";

    public static string ShareKind(ShareInfo s) => s.Kind switch
    {
        Scanning.ShareKind.Folder => s.IsAdministrative ? "Administrative" : "Folder",
        Scanning.ShareKind.Printer => "Printer",
        Scanning.ShareKind.Device => "Device",
        Scanning.ShareKind.Ipc => "IPC",
        _ => "Other",
    };

    public static string ShareAccessText(ShareInfo s) => ObservationText.Render(s.Access, a =>
        a.Writable == true ? "Read/Write" : a.Readable ? (a.Writable == false ? "Read-only" : "Readable") : "No access");

    public static string ShareSummary(ShareInfo s)
    {
        var flags = s.TypeLetters;
        return $"{s.Name} [{flags}]";
    }
}

public static class ColumnCatalog
{
    private static string Join<T>(Observation<IReadOnlyList<T>> o, ColumnFormat f, Func<T, string> item)
        => ObservationText.Render(o, list => string.Join(f.Separator, list.Select(item)));

    public static readonly ResultColumn IpAddress = new("ip", "IP Address", ColumnKind.IpAddress, (r, _) => r.Key.ToString(), r => r.Key);
    public static readonly ResultColumn Status = new("status", "Status", ColumnKind.Text, (r, _) => Formats.Status(r.Status));
    public static readonly ResultColumn ResponseTime = new("rtt", "Response Time", ColumnKind.Number,
        (r, _) => r.RoundTrip is { } t ? Formats.Milliseconds(t) : "", r => r.RoundTrip?.TotalMilliseconds);
    public static readonly ResultColumn HostName = new("hostName", "Host Name", ColumnKind.Text, (r, _) => ObservationText.Render(r.HostName, Formats.HostName));
    public static readonly ResultColumn MacAddress = new("mac", "MAC Address", ColumnKind.Text, (r, f) => ObservationText.Render(r.Mac,
        m => Formats.Mac(m, f.MacFormat) + (f.DuplicateMacs?.Contains(m.ToString()) == true ? " (duplicate)" : "")));
    public static readonly ResultColumn Vendor = new("vendor", "NIC Vendor", ColumnKind.Text, (r, _) => ObservationText.Render(r.Vendor, v => v));
    public static readonly ResultColumn DeviceType = new("deviceType", "Device Type", ColumnKind.Text, (r, _) => DeviceTypes.Describe(r).Text);
    public static readonly ResultColumn Ttl = new("ttl", "TTL", ColumnKind.Number,
        (r, _) => ObservationText.Render(r.Ttl, v => v.ToString(CultureInfo.InvariantCulture)), r => r.Ttl.HasValue ? r.Ttl.Value : null);
    public static readonly ResultColumn PingMethodColumn = new("pingMethod", "Ping Method", ColumnKind.Text, (r, _) => r.RespondedTo switch
    {
        Scanning.PingMethod.Icmp => "ICMP",
        Scanning.PingMethod.Arp => "ARP",
        _ => "",
    });

    public static readonly ResultColumn PacketLoss = new("loss", "Packet Loss", ColumnKind.Number, (r, _) => ObservationText.Render(r.PingStats,
        s => s.LossPercent.ToString("0.#", CultureInfo.InvariantCulture) + $" % ({s.Sent - s.Received}/{s.Sent})"), r => r.PingStats.HasValue ? r.PingStats.Value!.LossPercent : null);

    public static readonly ResultColumn Jitter = new("jitter", "Jitter", ColumnKind.Number, (r, _) => ObservationText.Render(r.PingStats,
        s => s.Jitter is { } j ? j.TotalMilliseconds.ToString("0.0", CultureInfo.InvariantCulture) + " ms" : "n/a"), r => r.PingStats.Value?.Jitter?.TotalMilliseconds);

    public static readonly ResultColumn NetBiosName = new("netbios", "NetBIOS Name", ColumnKind.Text,
        (r, _) => ObservationText.Render(r.NetBios, n => n.ComputerName ?? ""));
    public static readonly ResultColumn Workgroup = new("workgroup", "Workgroup/Domain", ColumnKind.Text, (r, _) => ObservationText.Render(r.Workgroup, v => v));
    public static readonly ResultColumn OsVersion = new("os", "Windows Version", ColumnKind.Text, (r, _) => ObservationText.Render(r.OsVersion, v => v));
    public static readonly ResultColumn IPv6 = new("ipv6", "IPv6 Address", ColumnKind.Text, (r, f) => Join(r.IPv6Addresses, f, a => a.ToString()));
    public static readonly ResultColumn TcpPorts = new("tcpPorts", "Open TCP Ports", ColumnKind.Text,
        (r, f) => Join(r.TcpPorts, f, p => Formats.Port(p, f.ShowServiceNames)), r => r.TcpPorts.HasValue ? r.TcpPorts.Value!.Count : null);
    public static readonly ResultColumn UdpPorts = new("udpPorts", "UDP Ports", ColumnKind.Text,
        (r, f) => ObservationText.Render(r.UdpPorts, l => string.Join(f.Separator, l.Where(p => p.State == PortState.Open).Select(p => Formats.Port(p, f.ShowServiceNames)))));
    public static readonly ResultColumn Banners = new("banners", "Services", ColumnKind.Text, (r, f) => Join(r.Banners, f, Formats.Banner));
    public static readonly ResultColumn Rtsp = new("rtsp", "RTSP Streams", ColumnKind.Text, (r, f) => Join(r.RtspStreams, f, s => s));
    public static readonly ResultColumn TlsSubject = new("tlsSubject", "SSL Subject", ColumnKind.Text, (r, _) => ObservationText.Render(r.Tls, t => t.Subject));
    public static readonly ResultColumn TlsIssuer = new("tlsIssuer", "SSL Issuer", ColumnKind.Text, (r, _) => ObservationText.Render(r.Tls, t => t.Issuer));
    public static readonly ResultColumn TlsExpiry = new("tlsExpiry", "SSL Expiry", ColumnKind.DateTime,
        (r, _) => ObservationText.Render(r.Tls, t => Formats.Timestamp(t.NotAfter) + (t.ChainValid ? "" : " (untrusted)")), r => r.Tls.HasValue ? r.Tls.Value!.NotAfter : null);
    public static readonly ResultColumn Accounts = new("accounts", "User Accounts", ColumnKind.Text, (r, f) => Join(r.Accounts, f, a => a));
    public static readonly ResultColumn LoggedOnUsers = new("loggedOn", "Logged-on Users", ColumnKind.Text, (r, f) => Join(r.LoggedOnUsers, f, a => a));
    public static readonly ResultColumn LoggedOnSids = new("sids", "Logged-on SIDs", ColumnKind.Text, (r, f) => Join(r.LoggedOnSids, f, a => a));
    public static readonly ResultColumn RemoteTime = new("remoteTime", "Remote Time", ColumnKind.DateTime,
        (r, _) => ObservationText.Render(r.RemoteTime, t => t.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture)), r => r.RemoteTime.HasValue ? r.RemoteTime.Value : null);
    public static readonly ResultColumn InstalledApps = new("apps", "Installed Applications", ColumnKind.Text,
        (r, f) => Join(r.InstalledApps, f, a => a.Version is { Length: > 0 } v ? $"{a.Name} {v}" : a.Name));
    public static readonly ResultColumn Shares = new("shares", "Shares", ColumnKind.Text,
        (r, f) => ObservationText.Render(r.Shares, l => string.Join(f.Separator, l.Where(f.ShareMatches).Select(Formats.ShareSummary))),
        r => r.Shares.HasValue ? r.Shares.Value!.Count : null);
    public static readonly ResultColumn Monitors = new("monitors", "Monitor", ColumnKind.Text, (r, f) => Join(r.Monitors, f, m => m.ToString()));
    public static readonly ResultColumn TerminalSessions = new("sessions", "Terminal Sessions", ColumnKind.Text, (r, f) => Join(r.TerminalSessions, f, s => s.ToString()));
    public static readonly ResultColumn Location = new("location", "Location", ColumnKind.Text, (r, _) => ObservationText.Render(r.Location, g => g.ToString()));
    public static readonly ResultColumn LastScanned = new("lastScanned", "Last Scanned", ColumnKind.DateTime, (r, _) => Formats.Timestamp(r.LastScanned), r => r.LastScanned);
    public static readonly ResultColumn LastSeen = new("lastSeen", "Last Seen", ColumnKind.DateTime, (r, _) => r.LastSeen is { } t ? Formats.Timestamp(t) : "", r => r.LastSeen);

    public static IReadOnlyList<ResultColumn> All { get; } =
    [
        IpAddress, Status, ResponseTime, HostName, MacAddress, Vendor, DeviceType, PingMethodColumn, Ttl, PacketLoss, Jitter, NetBiosName, Workgroup,
        OsVersion, IPv6, TcpPorts, UdpPorts, Banners, Rtsp, TlsSubject, TlsIssuer, TlsExpiry, Accounts, LoggedOnUsers, LoggedOnSids,
        RemoteTime, InstalledApps, Monitors, TerminalSessions, Shares, Location, LastScanned, LastSeen,
    ];

    public static ResultColumn? Find(string id) => All.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase));

    /// <summary>Columns produced by the enabled scan options (manual: columns depend on enabled options).</summary>
    public static IReadOnlyList<ResultColumn> EnabledFor(ScanSettings s)
    {
        ArgumentNullException.ThrowIfNull(s);
        // Default presentation (D-072): IP, MAC, Response Time, Host Name, Device Type; the rest follow when enabled.
        var list = new List<ResultColumn> { IpAddress };
        if (s.DisplayInactiveDevices || s.AnalyseUnresponsive) list.Add(Status);
        if (s.ResolveMac || s.PingMethod != PingMethodSetting.Icmp) list.Add(MacAddress);
        list.Add(ResponseTime);
        if (s.ResolveHostNames) list.Add(HostName);
        if (s.ShowDeviceType) list.Add(DeviceType);
        if (s.LookupVendor) list.Add(Vendor);
        if (s.ShowPingMethod) list.Add(PingMethodColumn);
        if (s.ShowTtl) list.Add(Ttl);
        if (s.DeterminePacketLossAndJitter)
        {
            list.Add(PacketLoss);
            list.Add(Jitter);
        }

        if (s.ResolveHostNames && s.HostNameMode is HostNameMode.Legacy or HostNameMode.NetBiosOnly) list.Add(NetBiosName);
        if (s.LookupWorkgroup) list.Add(Workgroup);
        if (s.LookupWindowsVersion) list.Add(OsVersion);
        if (s.ResolveIPv6) list.Add(IPv6);
        if (s.ScanTcpPorts) list.Add(TcpPorts);
        if (s.ScanUdpPorts) list.Add(UdpPorts);
        if (s.GrabBanners) list.Add(Banners);
        if (s.FindRtspStreams) list.Add(Rtsp);
        if (s.TlsCertificateInfo)
        {
            list.Add(TlsSubject);
            list.Add(TlsIssuer);
            list.Add(TlsExpiry);
        }

        if (s.EnumerateAccounts) list.Add(Accounts);
        if (s.LookupLoggedOnUsers) list.Add(LoggedOnUsers);
        if (s.LookupLoggedOnSids) list.Add(LoggedOnSids);
        if (s.LookupRemoteTime) list.Add(RemoteTime);
        if (s.ListInstalledApplications) list.Add(InstalledApps);
        if (s.LookupMonitors) list.Add(Monitors);
        if (s.ListTerminalSessions) list.Add(TerminalSessions);
        if (s.ScanShares) list.Add(Shares);
        if (s.Geolocation) list.Add(Location);
        if (s.ShowTimestamps)
        {
            list.Add(LastScanned);
            list.Add(LastSeen);
        }

        return list;
    }

    /// <summary>Phase 1 name kept for callers: same as <see cref="EnabledFor"/>.</summary>
    public static IReadOnlyList<ResultColumn> VisibleFor(ScanSettings s) => EnabledFor(s);

    /// <summary>Applies a saved layout (order + hidden columns) to the enabled columns. Columns missing from the layout
    /// keep their catalogue order after the laid-out ones.</summary>
    public static IReadOnlyList<ResultColumn> Arrange(IReadOnlyList<ResultColumn> enabled, IReadOnlyList<ColumnLayout> layout)
    {
        ArgumentNullException.ThrowIfNull(enabled);
        ArgumentNullException.ThrowIfNull(layout);
        if (layout.Count == 0) return enabled;
        var order = layout.Select((l, i) => (l.Id, i)).ToDictionary(x => x.Id, x => x.i, StringComparer.OrdinalIgnoreCase);
        var hidden = layout.Where(l => !l.Visible).Select(l => l.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return enabled.Where(c => !hidden.Contains(c.Id) || c == IpAddress)
            .Select((c, i) => (c, key: order.TryGetValue(c.Id, out var o) ? o : layout.Count + i))
            .OrderBy(x => x.key)
            .Select(x => x.c)
            .ToList();
    }

    /// <summary>Resolves <c>/cols</c> names (header or id, case-insensitive). Unknown names are returned separately.</summary>
    public static (IReadOnlyList<ResultColumn> Columns, IReadOnlyList<string> Unknown) Select(IEnumerable<string> names, IReadOnlyList<ResultColumn>? available = null)
    {
        ArgumentNullException.ThrowIfNull(names);
        available ??= All;
        var cols = new List<ResultColumn>();
        var unknown = new List<string>();
        foreach (var raw in names)
        {
            var n = raw.Trim();
            if (n.Length == 0) continue;
            var c = available.FirstOrDefault(c => string.Equals(c.Header, n, StringComparison.OrdinalIgnoreCase)
                                            || string.Equals(c.Id, n, StringComparison.OrdinalIgnoreCase));
            if (c is null) unknown.Add(n);
            else if (!cols.Contains(c)) cols.Add(c);
        }

        return (cols, unknown);
    }
}

/// <summary>Persisted per-column layout (order = list order).</summary>
public sealed record ColumnLayout
{
    public string Id { get; set; } = "";

    public bool Visible { get; set; } = true;

    public double Width { get; set; }
}

/// <summary>Columns describing one share (tree child rows, HTML/XML/SQLite share tables).</summary>
public static class ShareColumns
{
    public static readonly (string Id, string Header, Func<ShareInfo, string> Text)[] All =
    [
        ("name", "Share", s => s.Name),
        ("type", "Type", Formats.ShareKind),
        ("access", "Access", Formats.ShareAccessText),
        ("disk", "Disk Space", s => ObservationText.Render(s.Disk, d => $"{Formats.Bytes(d.FreeBytes)} free of {Formats.Bytes(d.TotalBytes)}")),
        ("permissions", "Permissions", s => ObservationText.Render(s.Permissions, l => string.Join("; ", l.Select(p => $"{p.Account}: {(p.Allow ? "" : "deny ")}{p.Rights}")))),
        ("remark", "Remark", s => s.Remark),
        ("flags", "Flags", s => s.TypeLetters),
    ];
}

/// <summary>Duplicate MAC detection (manual General tab: "Detect duplicate MAC addresses").</summary>
public static class DuplicateMacs
{
    /// <summary>MACs (PhysicalAddress.ToString form) reported by more than one distinct IP address.</summary>
    public static IReadOnlySet<string> Find(IEnumerable<DeviceResult> devices)
    {
        ArgumentNullException.ThrowIfNull(devices);
        return devices.Where(d => d.Mac.HasValue)
            .GroupBy(d => d.Mac.Value!.ToString(), StringComparer.Ordinal)
            .Where(g => g.Select(d => d.Key).Distinct().Count() > 1)
            .Select(g => g.Key)
            .ToHashSet(StringComparer.Ordinal);
    }
}
