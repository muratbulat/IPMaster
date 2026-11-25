namespace IPMaster.Core.Scanning;

public enum HostNameMode
{
    /// <summary>Fully qualified domain name.</summary>
    Fqdn,

    /// <summary>Relative distinguished name: the first label only.</summary>
    ShortName,

    /// <summary>OS resolver, then NetBIOS node status (Phase 2; currently behaves like Fqdn and reports it).</summary>
    Legacy,

    /// <summary>NetBIOS node status only (Phase 2; currently Unsupported).</summary>
    NetBiosOnly,
}

/// <summary>Scan options (manual "Scan options" General/Additional tabs). Units are explicit in names.</summary>
public sealed record ScanSettings
{
    // General
    public int MaxConcurrency { get; set; } = 256; // D-083: a /24 in ~2 s instead of ~8 s; 1024 measured no faster

    /// <summary>Per-device deadline in seconds (manual "Max. thread run time"); 0 = no limit.</summary>
    public int DeviceDeadlineSeconds { get; set; } = 30;

    public int PingTimeoutMs { get; set; } = 1000;

    public PingMethodSetting PingMethod { get; set; } = PingMethodSetting.Icmp;

    public int PingAttempts { get; set; } = 2;

    public bool AnalyseUnresponsive { get; set; }

    public bool PingNetworkAndBroadcast { get; set; }

    public bool AllowArpOutsideSubnet { get; set; }

    public bool DeterminePacketLossAndJitter { get; set; }

    /// <summary>Echo requests used for loss/jitter (see D-007).</summary>
    public int LossProbeCount { get; set; } = 10;

    public int LossProbeIntervalMs { get; set; } = 100;

    public bool DetectDuplicateMacs { get; set; } = true;

    public bool DisplayInactiveDevices { get; set; }

    /// <summary>Device Type column, built from observed data only (D-072). On by default.</summary>
    public bool ShowDeviceType { get; set; } = true;

    /// <summary>Last Scanned / Last Seen columns. Presentation only: the values are always recorded. Off by default (D-072).</summary>
    public bool ShowTimestamps { get; set; }

    public bool ShowPingMethod { get; set; }

    public bool ShowTtl { get; set; }

    public bool RandomOrder { get; set; }

    /// <summary>Geolocate public addresses through <see cref="GeoUrlTemplate"/> (off by default; no built-in service, D-044).</summary>
    public bool Geolocation { get; set; }

    /// <summary>HTTPS URL with {ip}, returning JSON; e.g. a self-hosted or subscribed geolocation API.</summary>
    public string GeoUrlTemplate { get; set; } = "";

    public string GeoCityField { get; set; } = "city";

    public string GeoRegionField { get; set; } = "region";

    public string GeoCountryField { get; set; } = "country";

    // Additional
    public bool ResolveHostNames { get; set; } = true;

    public HostNameMode HostNameMode { get; set; } = HostNameMode.Fqdn;

    public bool DoubleReverseLookup { get; set; }

    public int DnsTimeoutMs { get; set; } = 6000;

    /// <summary>Separate budget for concurrent DNS lookups.</summary>
    public int DnsConcurrency { get; set; } = 32;

    /// <summary>Lookups that exceeded their timeout but whose OS call is still running. When this many
    /// are outstanding, further lookups report Timeout immediately instead of piling up.</summary>
    public int MaxAbandonedDnsLookups { get; set; } = 64;

    /// <summary>Workers for post-liveness enrichment (DNS, loss/jitter).</summary>
    public int EnrichmentConcurrency { get; set; } = 64;

    // Additional: MAC, vendor, IPv6, banners
    /// <summary>On by default (D-072): neighbour cache, then ARP on local subnets: cheap, and the MAC is a default column.</summary>
    public bool ResolveMac { get; set; } = true;

    /// <summary>MAC providers in priority order (manual: drag to reorder).</summary>
    public IReadOnlyList<MacMethod> MacMethods { get; set; } = [MacMethod.Arp, MacMethod.NetBios];

    public bool LookupVendor { get; set; }

    public bool ResolveIPv6 { get; set; }

    public bool GrabBanners { get; set; }

    /// <summary>Banner services to probe (ids from <see cref="BannerServices.All"/>).</summary>
    public IReadOnlyList<string> BannerServiceIds { get; set; } = BannerServices.DefaultIds;

    public bool FindRtspStreams { get; set; }

    public bool TlsCertificateInfo { get; set; }

    public int ServiceTimeoutMs { get; set; } = 2000;

    /// <summary>NetBIOS node-status timeout (also used by the NetBIOS host-name modes).</summary>
    public int NetBiosTimeoutMs { get; set; } = 1000;

    // Ports
    public bool ScanTcpPorts { get; set; }

    public string TcpPorts { get; set; } = "21-23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080";

    public bool ShowServiceNames { get; set; }

    public bool ScanUdpPorts { get; set; }

    public IReadOnlyList<string> UdpServiceIds { get; set; } = UdpServices.DefaultIds;

    /// <summary>Community sent by the SNMP UDP/banner probe (sysDescr). Configurable; never iterated (no guessing).</summary>
    public string SnmpProbeCommunity { get; set; } = "public";

    public int PortTimeoutMs { get; set; } = 1000;

    /// <summary>Concurrent TCP connections across all devices (separate budget).</summary>
    public int PortConcurrency { get; set; } = 256;

    public bool RandomPortOrder { get; set; }

    // Workstation (remote Windows targets)
    public bool LookupWorkgroup { get; set; }

    public bool LookupWindowsVersion { get; set; }

    public bool EnumerateAccounts { get; set; }

    public bool LookupLoggedOnUsers { get; set; }

    public bool LookupLoggedOnSids { get; set; }

    public bool LookupRemoteTime { get; set; }

    public bool ListInstalledApplications { get; set; }

    /// <summary>Additional › Look up monitor information (EDID via Remote Registry).</summary>
    public bool LookupMonitors { get; set; }

    /// <summary>Additional › Enumerate terminal sessions (WTS).</summary>
    public bool ListTerminalSessions { get; set; }

    /// <summary>Workstation tab authentication: null = current account, else a Credential Manager entry (WKS-07).</summary>
    public Guid? WorkstationCredentialId { get; set; }

    /// <summary>Shares tab authentication: null = current account.</summary>
    public Guid? SharesCredentialId { get; set; }

    /// <summary>Router MIB MAC method: routers besides the default gateways (comma-separated addresses).</summary>
    public string RouterMibRouters { get; set; } = "";

    /// <summary>Router MIB MAC method: SNMP v2c community (configured, never guessed).</summary>
    public string RouterMibCommunity { get; set; } = "public";

    public bool OmitDuplicateAccounts { get; set; } = true;

    /// <summary>Wildcard patterns of account names to disregard (one per entry).</summary>
    public IReadOnlyList<string> ExcludedAccounts { get; set; } = [];

    // Shares
    public bool ScanShares { get; set; }

    public ShareTypeSelection ShareTypes { get; set; } = ShareTypeSelection.FoldersAndPrinters;

    public bool ShareDiskSpace { get; set; }

    public bool ShareSecurity { get; set; }

    /// <summary>Creates and deletes a temporary file on each share. Off unless explicitly enabled (SHR-05).</summary>
    public bool ShareWriteCheck { get; set; }

    /// <summary>Concurrent Windows management calls (NetApi/remote registry), separate budget.</summary>
    public int WindowsConcurrency { get; set; } = 16;

    public int WindowsTimeoutMs { get; set; } = 10_000;

    public bool AnyWorkstationLookup => LookupWorkgroup || LookupWindowsVersion || EnumerateAccounts || LookupLoggedOnUsers
                                        || LookupLoggedOnSids || LookupRemoteTime || ListInstalledApplications
                                        || LookupMonitors || ListTerminalSessions;

    public ScanSettings Normalize() => this with
    {
        ServiceTimeoutMs = Math.Clamp(ServiceTimeoutMs, 100, 60_000),
        NetBiosTimeoutMs = Math.Clamp(NetBiosTimeoutMs, 100, 60_000),
        PortTimeoutMs = Math.Clamp(PortTimeoutMs, 50, 60_000),
        PortConcurrency = Math.Clamp(PortConcurrency, 1, 4096),
        WindowsConcurrency = Math.Clamp(WindowsConcurrency, 1, 256),
        WindowsTimeoutMs = Math.Clamp(WindowsTimeoutMs, 500, 120_000),
        MacMethods = MacMethods is { Count: > 0 } ? MacMethods.Distinct().ToList() : [MacMethod.Arp, MacMethod.NetBios],
        BannerServiceIds = BannerServiceIds ?? BannerServices.DefaultIds,
        UdpServiceIds = UdpServiceIds ?? UdpServices.DefaultIds,
        ExcludedAccounts = ExcludedAccounts ?? [],
        TcpPorts = TcpPorts ?? "",
        SnmpProbeCommunity = SnmpProbeCommunity ?? "public",
        MaxConcurrency = Math.Clamp(MaxConcurrency, 1, 1024),
        DeviceDeadlineSeconds = Math.Clamp(DeviceDeadlineSeconds, 0, 3600),
        PingTimeoutMs = Math.Clamp(PingTimeoutMs, 50, 60_000),
        PingAttempts = Math.Clamp(PingAttempts, 1, 10),
        LossProbeCount = Math.Clamp(LossProbeCount, 2, 100),
        LossProbeIntervalMs = Math.Clamp(LossProbeIntervalMs, 0, 5000),
        DnsTimeoutMs = Math.Clamp(DnsTimeoutMs, 100, 60_000),
        DnsConcurrency = Math.Clamp(DnsConcurrency, 1, 512),
        MaxAbandonedDnsLookups = Math.Clamp(MaxAbandonedDnsLookups, 1, 4096),
        EnrichmentConcurrency = Math.Clamp(EnrichmentConcurrency, 1, 1024),
    };
}
