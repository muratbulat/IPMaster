using System.Collections.ObjectModel;
using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;

namespace IPMaster.Desktop.ViewModels;

public sealed partial class CheckItem : ObservableObject
{
    public CheckItem(string id, string name, bool isChecked)
    {
        Id = id;
        Name = name;
        IsChecked = isChecked;
    }

    public string Id { get; }

    public string Name { get; }

    [ObservableProperty] public partial bool IsChecked { get; set; }
}

/// <summary>Editable copy of the scan options. Only implemented options are exposed.</summary>
public sealed partial class OptionsViewModel : ObservableObject
{
    private static readonly ShareTypeSelection[] SharePresets =
    [
        ShareTypeSelection.All, ShareTypeSelection.Folders, ShareTypeSelection.Printers, ShareTypeSelection.Devices,
        ShareTypeSelection.Administrative, ShareTypeSelection.Ipc, ShareTypeSelection.FoldersAndPrinters,
    ];

    private readonly AppSettings _original;

    public OptionsViewModel(AppSettings settings, ScanProbes probes, Func<Task<string>>? downloadOui = null)
    {
        _original = settings;
        _downloadOui = downloadOui;
        ArpAvailable = probes.Arp.Capability.Available;
        ArpDescription = probes.Arp.Capability.Description;
        WindowsAvailable = probes.Windows.Capability.Available;
        WindowsDescription = probes.Windows.Capability.Description;
        VendorDescription = probes.Vendors.Capability.Description;
        var s = settings.Scan;
        var v = settings.View;
        MinimizeToTray = v.MinimizeToTray;
        Shortcuts = v.Shortcuts;
        MaxConcurrency = s.MaxConcurrency;
        DeviceDeadlineSeconds = s.DeviceDeadlineSeconds;
        PingTimeoutMs = s.PingTimeoutMs;
        PingMethodIndex = (int)s.PingMethod;
        PingAttempts = s.PingAttempts;
        AnalyseUnresponsive = s.AnalyseUnresponsive;
        PingNetworkAndBroadcast = s.PingNetworkAndBroadcast;
        AllowArpOutsideSubnet = s.AllowArpOutsideSubnet;
        DeterminePacketLossAndJitter = s.DeterminePacketLossAndJitter;
        LossProbeCount = s.LossProbeCount;
        DetectDuplicateMacs = s.DetectDuplicateMacs;
        DisplayInactiveDevices = s.DisplayInactiveDevices;
        ShowTimestamps = s.ShowTimestamps;
        ShowDeviceType = s.ShowDeviceType;
        ShowPingMethod = s.ShowPingMethod;
        ShowTtl = s.ShowTtl;
        RandomOrder = s.RandomOrder;
        ConfirmationThreshold = settings.ConfirmationThreshold;

        ResolveHostNames = s.ResolveHostNames;
        HostNameModeIndex = (int)s.HostNameMode;
        DoubleReverseLookup = s.DoubleReverseLookup;
        DnsTimeoutMs = s.DnsTimeoutMs;
        DnsConcurrency = s.DnsConcurrency;
        ResolveMac = s.ResolveMac;
        foreach (var m in s.MacMethods) MacMethods.Add(new CheckItem(m.ToString(), MacLabel(m), true));
        foreach (var m in Enum.GetValues<MacMethod>().Where(m => !s.MacMethods.Contains(m))) MacMethods.Add(new CheckItem(m.ToString(), MacLabel(m), false));
        RouterMibRouters = s.RouterMibRouters;
        RouterMibCommunity = s.RouterMibCommunity;
        LookupMonitors = s.LookupMonitors;
        ListTerminalSessions = s.ListTerminalSessions;
        _credentialIds = [null, .. settings.Credentials.Select(c => (Guid?)c.Id)];
        CredentialChoices = [(settings.Credentials.Count == 0 ? "Current account (add credentials in Options → Credential Manager)" : "Current account"), .. settings.Credentials.Select(c => c.Display)];
        WorkstationCredentialIndex = Math.Max(0, _credentialIds.IndexOf(s.WorkstationCredentialId));
        SharesCredentialIndex = Math.Max(0, _credentialIds.IndexOf(s.SharesCredentialId));

        LookupVendor = s.LookupVendor;
        ResolveIPv6 = s.ResolveIPv6;
        GrabBanners = s.GrabBanners;
        foreach (var b in BannerServices.All) BannerItems.Add(new CheckItem(b.Id, $"{b.Name} ({(b.Protocol == PortProtocol.Tcp ? "TCP" : "UDP")} {string.Join(", ", b.Ports)})", s.BannerServiceIds.Contains(b.Id)));
        FindRtspStreams = s.FindRtspStreams;
        TlsCertificateInfo = s.TlsCertificateInfo;
        ServiceTimeoutMs = s.ServiceTimeoutMs;

        ScanTcpPorts = s.ScanTcpPorts;
        TcpPorts = s.TcpPorts;
        ShowServiceNames = s.ShowServiceNames;
        ScanUdpPorts = s.ScanUdpPorts;
        foreach (var u in UdpServices.All) UdpItems.Add(new CheckItem(u.Id, $"{u.Name} (UDP {u.Port})", s.UdpServiceIds.Contains(u.Id)));
        SnmpProbeCommunity = s.SnmpProbeCommunity;
        PortTimeoutMs = s.PortTimeoutMs;
        PortConcurrency = s.PortConcurrency;
        RandomPortOrder = s.RandomPortOrder;

        LookupWorkgroup = s.LookupWorkgroup;
        LookupWindowsVersion = s.LookupWindowsVersion;
        EnumerateAccounts = s.EnumerateAccounts;
        LookupLoggedOnUsers = s.LookupLoggedOnUsers;
        LookupLoggedOnSids = s.LookupLoggedOnSids;
        LookupRemoteTime = s.LookupRemoteTime;
        ListInstalledApplications = s.ListInstalledApplications;
        OmitDuplicateAccounts = s.OmitDuplicateAccounts;
        ExcludedAccounts = string.Join(Environment.NewLine, s.ExcludedAccounts);
        WindowsTimeoutMs = s.WindowsTimeoutMs;

        ScanShares = s.ScanShares;
        ShareTypeIndex = Math.Max(0, Array.IndexOf(SharePresets, s.ShareTypes));
        ShareDiskSpace = s.ShareDiskSpace;
        ShareSecurity = s.ShareSecurity;
        ShareWriteCheck = s.ShareWriteCheck;

        CellSeparator = v.CellSeparator;
        GridLines = v.GridLines;
        MultiLineCells = v.MultiLineCells;
        RepeatedValuesIndex = (int)v.RepeatedValues;
        MacFormatIndex = (int)v.MacFormat;
        RowSpacingIndex = (int)v.RowSpacing;
        OddRowColor = v.OddRowColor;
        EvenRowColor = v.EvenRowColor;
        HighlightColor = v.HighlightColor;
        FontFamily = v.FontFamily;
        FontSize = v.FontSize <= 0 ? null : (decimal)v.FontSize;
        CaseInsensitiveSort = v.CaseInsensitiveSort;
        AutoExpand = v.AutoExpand;
        CsvDelimiterIndex = v.CsvDelimiter switch
        {
            null => 0,
            ',' => 1,
            ';' => 2,
            '\t' => 3,
            _ => 4,
        };
        CsvCustomDelimiter = v.CsvDelimiter is { } c and not (',' or ';' or '\t') ? c.ToString() : "|";
        CsvEncodingIndex = (int)v.CsvEncoding;
        CsvProtectFormulas = v.CsvProtectFormulas;
        CheckIcmp = settings.Browsing.CheckIcmp;
        var mon = settings.Monitoring;
        MonitorAll = mon.MonitorAll;
        GoodLatencyMs = mon.GoodLatencyMs;
        CriticalLatencyMs = mon.CriticalLatencyMs;
        GoodLossPercent = (decimal)mon.GoodLossPercent;
        CriticalLossPercent = (decimal)mon.CriticalLossPercent;
        WindowSamples = mon.WindowSamples;
        MaxMonitored = mon.MaxDevices;
        ShowLatency = mon.ShowLatency;
        ShowHistoryColumn = mon.ShowHistory;
        ShowLoss = mon.ShowLoss;
        ShowJitter = mon.ShowJitter;
        ShowQuality = mon.ShowQuality;
        HistoryEnabled = settings.History.Enabled;
        RetentionDays = settings.History.RetentionDays;
        ShowFirstSeen = settings.History.ShowFirstSeen;
        ShowLastSeenHistory = settings.History.ShowLastSeen;
        ShowAvailability = settings.History.ShowAvailability;
        var bg = settings.Background;
        BackgroundModeIndex = (int)bg.Mode;
        BackgroundConcurrency = bg.Concurrency;
        RoundDelayMinutes = (decimal)bg.RoundDelayMinutes;
        LeaveAfterMisses = bg.LeaveAfterMisses;
        ClearOffline = bg.ClearOffline;
        KeepOnOffline = string.Join(", ", bg.KeepOnOffline);
        CheckArp = settings.Browsing.CheckArp;
        CheckNetBios = settings.Browsing.CheckNetBios;
        Geolocation = s.Geolocation;
        GeoUrlTemplate = s.GeoUrlTemplate;
        GeoCityField = s.GeoCityField;
        GeoRegionField = s.GeoRegionField;
        GeoCountryField = s.GeoCountryField;
        Applications = settings.Applications.Applications.ToList();
        Variables = settings.Applications.Variables.ToList();
        RefreshApplicationsSummary();
    }

    public List<Core.Management.ExternalApplication> Applications { get; set; }

    public List<Core.Management.GlobalVariable> Variables { get; set; }

    [ObservableProperty] public partial string ApplicationsSummary { get; set; } = "";
    [ObservableProperty] public partial bool CheckIcmp { get; set; }
    [ObservableProperty] public partial bool MonitorAll { get; set; }
    [ObservableProperty] public partial int GoodLatencyMs { get; set; }
    [ObservableProperty] public partial int CriticalLatencyMs { get; set; }
    [ObservableProperty] public partial decimal GoodLossPercent { get; set; }
    [ObservableProperty] public partial decimal CriticalLossPercent { get; set; }
    [ObservableProperty] public partial int WindowSamples { get; set; }
    [ObservableProperty] public partial int MaxMonitored { get; set; }
    [ObservableProperty] public partial bool ShowLatency { get; set; }
    [ObservableProperty] public partial bool ShowHistoryColumn { get; set; }
    [ObservableProperty] public partial bool ShowLoss { get; set; }
    [ObservableProperty] public partial bool ShowJitter { get; set; }
    [ObservableProperty] public partial bool ShowQuality { get; set; }
    [ObservableProperty] public partial bool HistoryEnabled { get; set; }
    [ObservableProperty] public partial int RetentionDays { get; set; }
    [ObservableProperty] public partial bool ShowFirstSeen { get; set; }
    [ObservableProperty] public partial bool ShowLastSeenHistory { get; set; }
    [ObservableProperty] public partial bool ShowAvailability { get; set; }
    [ObservableProperty] public partial int BackgroundModeIndex { get; set; }
    [ObservableProperty] public partial int BackgroundConcurrency { get; set; }
    [ObservableProperty] public partial decimal RoundDelayMinutes { get; set; }
    [ObservableProperty] public partial int LeaveAfterMisses { get; set; }
    [ObservableProperty] public partial bool ClearOffline { get; set; }
    [ObservableProperty] public partial string KeepOnOffline { get; set; } = "";
    [ObservableProperty] public partial bool CheckArp { get; set; }
    [ObservableProperty] public partial bool CheckNetBios { get; set; }
    [ObservableProperty] public partial bool Geolocation { get; set; }
    [ObservableProperty] public partial string GeoUrlTemplate { get; set; } = "";
    [ObservableProperty] public partial string GeoCityField { get; set; } = "";
    [ObservableProperty] public partial string GeoRegionField { get; set; } = "";
    [ObservableProperty] public partial string GeoCountryField { get; set; } = "";

    public void RefreshApplicationsSummary() => ApplicationsSummary = Applications.Count == 0
        ? "No applications defined."
        : string.Join(Environment.NewLine, Applications.Select(a => $"{a.Name}   —   {a.CommandLine}" + (a.Hotkey.Length > 0 ? $"   [{a.Hotkey}]" : "")))
          + (Variables.Count > 0 ? Environment.NewLine + "Variables: " + string.Join(", ", Variables.Select(v => "{$" + v.Name + "}")) : "");

    private readonly Func<Task<string>>? _downloadOui;

    public bool ArpAvailable { get; }

    public string ArpDescription { get; }

    public bool WindowsAvailable { get; }

    public string WindowsDescription { get; }

    [ObservableProperty] public partial string VendorDescription { get; set; }

    public ObservableCollection<CheckItem> MacMethods { get; } = [];

    private readonly List<Guid?> _credentialIds = [];

    public IReadOnlyList<string> CredentialChoices { get; } = [];

    [ObservableProperty] public partial int WorkstationCredentialIndex { get; set; }
    [ObservableProperty] public partial int SharesCredentialIndex { get; set; }
    [ObservableProperty] public partial bool LookupMonitors { get; set; }
    [ObservableProperty] public partial bool ListTerminalSessions { get; set; }
    [ObservableProperty] public partial string RouterMibRouters { get; set; } = "";
    [ObservableProperty] public partial string RouterMibCommunity { get; set; } = "public";

    private static string MacLabel(MacMethod m) => m switch
    {
        MacMethod.Arp => "ARP query / neighbour cache (local subnets)",
        MacMethod.NetBios => "NetBIOS query (works across routers)",
        MacMethod.Wmi => "WMI query (Windows targets; uses the Workstation credential)",
        _ => "Router MIB query (SNMP ARP tables of the gateways and listed routers)",
    };

    public ObservableCollection<CheckItem> BannerItems { get; } = [];

    public ObservableCollection<CheckItem> UdpItems { get; } = [];

    // General
    [ObservableProperty] public partial decimal? MaxConcurrency { get; set; }
    [ObservableProperty] public partial decimal? DeviceDeadlineSeconds { get; set; }
    [ObservableProperty] public partial decimal? PingTimeoutMs { get; set; }
    [ObservableProperty] public partial int PingMethodIndex { get; set; }
    [ObservableProperty] public partial decimal? PingAttempts { get; set; }
    [ObservableProperty] public partial bool AnalyseUnresponsive { get; set; }
    [ObservableProperty] public partial bool PingNetworkAndBroadcast { get; set; }
    [ObservableProperty] public partial bool AllowArpOutsideSubnet { get; set; }
    [ObservableProperty] public partial bool DeterminePacketLossAndJitter { get; set; }
    [ObservableProperty] public partial decimal? LossProbeCount { get; set; }
    [ObservableProperty] public partial bool DetectDuplicateMacs { get; set; }
    [ObservableProperty] public partial bool DisplayInactiveDevices { get; set; }
    [ObservableProperty] public partial bool ShowTimestamps { get; set; }
    [ObservableProperty] public partial bool ShowDeviceType { get; set; }
    [ObservableProperty] public partial bool ShowPingMethod { get; set; }
    [ObservableProperty] public partial bool ShowTtl { get; set; }
    [ObservableProperty] public partial bool RandomOrder { get; set; }
    [ObservableProperty] public partial decimal? ConfirmationThreshold { get; set; }

    // Additional
    [ObservableProperty] public partial bool ResolveHostNames { get; set; }
    [ObservableProperty] public partial int HostNameModeIndex { get; set; }
    [ObservableProperty] public partial bool DoubleReverseLookup { get; set; }
    [ObservableProperty] public partial decimal? DnsTimeoutMs { get; set; }
    [ObservableProperty] public partial decimal? DnsConcurrency { get; set; }
    [ObservableProperty] public partial bool ResolveMac { get; set; }
    [ObservableProperty] public partial bool LookupVendor { get; set; }
    [ObservableProperty] public partial bool ResolveIPv6 { get; set; }
    [ObservableProperty] public partial bool GrabBanners { get; set; }
    [ObservableProperty] public partial bool FindRtspStreams { get; set; }
    [ObservableProperty] public partial bool TlsCertificateInfo { get; set; }
    [ObservableProperty] public partial decimal? ServiceTimeoutMs { get; set; }
    [ObservableProperty] public partial bool DownloadingOui { get; set; }

    // Ports
    [ObservableProperty] public partial bool ScanTcpPorts { get; set; }
    [ObservableProperty] public partial string TcpPorts { get; set; } = "";
    [ObservableProperty] public partial string TcpPortsError { get; set; } = "";
    [ObservableProperty] public partial bool ShowServiceNames { get; set; }
    [ObservableProperty] public partial bool ScanUdpPorts { get; set; }
    [ObservableProperty] public partial string SnmpProbeCommunity { get; set; } = "public";
    [ObservableProperty] public partial decimal? PortTimeoutMs { get; set; }
    [ObservableProperty] public partial decimal? PortConcurrency { get; set; }
    [ObservableProperty] public partial bool RandomPortOrder { get; set; }

    // Workstation
    [ObservableProperty] public partial bool LookupWorkgroup { get; set; }
    [ObservableProperty] public partial bool LookupWindowsVersion { get; set; }
    [ObservableProperty] public partial bool EnumerateAccounts { get; set; }
    [ObservableProperty] public partial bool LookupLoggedOnUsers { get; set; }
    [ObservableProperty] public partial bool LookupLoggedOnSids { get; set; }
    [ObservableProperty] public partial bool LookupRemoteTime { get; set; }
    [ObservableProperty] public partial bool ListInstalledApplications { get; set; }
    [ObservableProperty] public partial bool OmitDuplicateAccounts { get; set; }
    [ObservableProperty] public partial string ExcludedAccounts { get; set; } = "";
    [ObservableProperty] public partial decimal? WindowsTimeoutMs { get; set; }

    // Shares
    [ObservableProperty] public partial bool ScanShares { get; set; }
    [ObservableProperty] public partial int ShareTypeIndex { get; set; }
    [ObservableProperty] public partial bool ShareDiskSpace { get; set; }
    [ObservableProperty] public partial bool ShareSecurity { get; set; }
    [ObservableProperty] public partial bool ShareWriteCheck { get; set; }

    // View
    [ObservableProperty] public partial bool MinimizeToTray { get; set; }

    /// <summary>Shortcut overrides edited on the Shortcuts tab (UI-18).</summary>
    public IReadOnlyList<ShortcutBinding> Shortcuts { get; set; } = [];

    [ObservableProperty] public partial string CellSeparator { get; set; } = ", ";
    [ObservableProperty] public partial bool GridLines { get; set; }
    [ObservableProperty] public partial bool MultiLineCells { get; set; }
    [ObservableProperty] public partial int RepeatedValuesIndex { get; set; }
    [ObservableProperty] public partial int MacFormatIndex { get; set; }
    [ObservableProperty] public partial int RowSpacingIndex { get; set; }
    [ObservableProperty] public partial string OddRowColor { get; set; } = "";
    [ObservableProperty] public partial string EvenRowColor { get; set; } = "";
    [ObservableProperty] public partial string HighlightColor { get; set; } = "";
    [ObservableProperty] public partial string FontFamily { get; set; } = "";
    [ObservableProperty] public partial decimal? FontSize { get; set; }
    [ObservableProperty] public partial bool CaseInsensitiveSort { get; set; }
    [ObservableProperty] public partial bool AutoExpand { get; set; }
    [ObservableProperty] public partial int CsvDelimiterIndex { get; set; }
    [ObservableProperty] public partial string CsvCustomDelimiter { get; set; } = "|";
    [ObservableProperty] public partial int CsvEncodingIndex { get; set; }
    [ObservableProperty] public partial bool CsvProtectFormulas { get; set; }

    partial void OnTcpPortsChanged(string value) => TcpPortsError = PortList.TryParse(value, out _, out var e) ? "" : e;

    [RelayCommand]
    private void MoveMacMethodUp(CheckItem item)
    {
        var i = MacMethods.IndexOf(item);
        if (i > 0) MacMethods.Move(i, i - 1);
    }

    [RelayCommand]
    private void SelectWellKnownPorts() => TcpPorts = string.Join(", ", PortList.WellKnown.Keys.Order());

    [RelayCommand]
    private async Task DownloadOuiAsync()
    {
        if (_downloadOui is null) return;
        DownloadingOui = true;
        try
        {
            VendorDescription = await _downloadOui();
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidOperationException or TaskCanceledException)
        {
            VendorDescription = "Download failed: " + ex.Message;
        }
        finally
        {
            DownloadingOui = false;
        }
    }

    public string? Validate() => TcpPortsError.Length > 0 && ScanTcpPorts ? "TCP ports: " + TcpPortsError : null;

    private static int I(decimal? v, int fallback) => v is { } d ? (int)d : fallback;

    private static string Color(string s)
    {
        s = s.Trim();
        return s.Length == 0 || (s.StartsWith('#') && s.Length is 7 or 9 && s[1..].All(Uri.IsHexDigit)) ? s : "";
    }

    public AppSettings ToSettings()
    {
        var s = _original.Scan with
        {
            MaxConcurrency = I(MaxConcurrency, 64),
            DeviceDeadlineSeconds = I(DeviceDeadlineSeconds, 30),
            PingTimeoutMs = I(PingTimeoutMs, 1000),
            PingMethod = (PingMethodSetting)Math.Clamp(PingMethodIndex, 0, 2),
            PingAttempts = I(PingAttempts, 2),
            AnalyseUnresponsive = AnalyseUnresponsive,
            PingNetworkAndBroadcast = PingNetworkAndBroadcast,
            AllowArpOutsideSubnet = AllowArpOutsideSubnet,
            DeterminePacketLossAndJitter = DeterminePacketLossAndJitter,
            LossProbeCount = I(LossProbeCount, 10),
            DetectDuplicateMacs = DetectDuplicateMacs,
            DisplayInactiveDevices = DisplayInactiveDevices,
            ShowTimestamps = ShowTimestamps,
            ShowDeviceType = ShowDeviceType,
            ShowPingMethod = ShowPingMethod,
            ShowTtl = ShowTtl,
            RandomOrder = RandomOrder,
            ResolveHostNames = ResolveHostNames,
            HostNameMode = (HostNameMode)Math.Clamp(HostNameModeIndex, 0, 3),
            DoubleReverseLookup = DoubleReverseLookup,
            DnsTimeoutMs = I(DnsTimeoutMs, 6000),
            DnsConcurrency = I(DnsConcurrency, 32),
            ResolveMac = ResolveMac,
            MacMethods = MacMethods.Where(m => m.IsChecked).Select(m => Enum.Parse<MacMethod>(m.Id)).ToList(),
            LookupVendor = LookupVendor,
            ResolveIPv6 = ResolveIPv6,
            GrabBanners = GrabBanners,
            BannerServiceIds = BannerItems.Where(b => b.IsChecked).Select(b => b.Id).ToList(),
            FindRtspStreams = FindRtspStreams,
            TlsCertificateInfo = TlsCertificateInfo,
            ServiceTimeoutMs = I(ServiceTimeoutMs, 2000),
            ScanTcpPorts = ScanTcpPorts,
            TcpPorts = TcpPorts,
            ShowServiceNames = ShowServiceNames,
            ScanUdpPorts = ScanUdpPorts,
            UdpServiceIds = UdpItems.Where(u => u.IsChecked).Select(u => u.Id).ToList(),
            SnmpProbeCommunity = string.IsNullOrEmpty(SnmpProbeCommunity) ? "public" : SnmpProbeCommunity,
            PortTimeoutMs = I(PortTimeoutMs, 1000),
            PortConcurrency = I(PortConcurrency, 256),
            RandomPortOrder = RandomPortOrder,
            LookupWorkgroup = LookupWorkgroup,
            LookupWindowsVersion = LookupWindowsVersion,
            EnumerateAccounts = EnumerateAccounts,
            LookupLoggedOnUsers = LookupLoggedOnUsers,
            LookupLoggedOnSids = LookupLoggedOnSids,
            LookupRemoteTime = LookupRemoteTime,
            ListInstalledApplications = ListInstalledApplications,
            LookupMonitors = LookupMonitors,
            ListTerminalSessions = ListTerminalSessions,
            RouterMibRouters = (RouterMibRouters ?? "").Trim(),
            RouterMibCommunity = string.IsNullOrEmpty(RouterMibCommunity) ? "public" : RouterMibCommunity,
            WorkstationCredentialId = _credentialIds.ElementAtOrDefault(WorkstationCredentialIndex),
            SharesCredentialId = _credentialIds.ElementAtOrDefault(SharesCredentialIndex),
            OmitDuplicateAccounts = OmitDuplicateAccounts,
            ExcludedAccounts = ExcludedAccounts.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList(),
            WindowsTimeoutMs = I(WindowsTimeoutMs, 10_000),
            ScanShares = ScanShares,
            ShareTypes = SharePresets[Math.Clamp(ShareTypeIndex, 0, SharePresets.Length - 1)],
            ShareDiskSpace = ShareDiskSpace,
            ShareSecurity = ShareSecurity,
            ShareWriteCheck = ShareWriteCheck,
            Geolocation = Geolocation,
            GeoUrlTemplate = GeoUrlTemplate.Trim(),
            GeoCityField = GeoCityField.Trim(),
            GeoRegionField = GeoRegionField.Trim(),
            GeoCountryField = GeoCountryField.Trim(),
        };
        char? delimiter = CsvDelimiterIndex switch
        {
            0 => null,
            1 => ',',
            2 => ';',
            3 => '\t',
            _ => string.IsNullOrEmpty(CsvCustomDelimiter) ? ',' : CsvCustomDelimiter[0],
        };
        return _original with
        {
            Scan = s.Normalize(),
            View = _original.View with
            {
                CsvDelimiter = delimiter,
                CsvEncoding = (CsvEncoding)Math.Clamp(CsvEncodingIndex, 0, 2),
                CsvProtectFormulas = CsvProtectFormulas,
                CellSeparator = string.IsNullOrEmpty(CellSeparator) ? ", " : CellSeparator,
                MinimizeToTray = MinimizeToTray,
                Shortcuts = Shortcuts,
                GridLines = GridLines,
                MultiLineCells = MultiLineCells,
                RepeatedValues = (RepeatedValueMode)Math.Clamp(RepeatedValuesIndex, 0, 2),
                MacFormat = (MacFormat)Math.Clamp(MacFormatIndex, 0, 4),
                RowSpacing = (RowSpacing)Math.Clamp(RowSpacingIndex, 0, 2),
                OddRowColor = Color(OddRowColor),
                EvenRowColor = Color(EvenRowColor),
                HighlightColor = Color(HighlightColor),
                FontFamily = FontFamily.Trim(),
                FontSize = FontSize is { } fs ? Math.Clamp((double)fs, 6, 40) : 0,
                CaseInsensitiveSort = CaseInsensitiveSort,
                AutoExpand = AutoExpand,
            },
            Browsing = new Core.Management.BrowsingSettings { CheckIcmp = CheckIcmp, CheckArp = CheckArp, CheckNetBios = CheckNetBios },
            Monitoring = _original.Monitoring with
            {
                MonitorAll = MonitorAll,
                GoodLatencyMs = Math.Max(1, GoodLatencyMs),
                CriticalLatencyMs = Math.Max(GoodLatencyMs + 1, CriticalLatencyMs),
                GoodLossPercent = (double)GoodLossPercent,
                CriticalLossPercent = (double)Math.Max(GoodLossPercent, CriticalLossPercent),
                WindowSamples = Math.Clamp(WindowSamples, 5, 3600),
                MaxDevices = Math.Clamp(MaxMonitored, 1, 5000),
                ShowLatency = ShowLatency,
                ShowHistory = ShowHistoryColumn,
                ShowLoss = ShowLoss,
                ShowJitter = ShowJitter,
                ShowQuality = ShowQuality,
            },
            History = new Core.Monitoring.HistorySettings
            {
                Enabled = HistoryEnabled, RetentionDays = Math.Clamp(RetentionDays, 1, 3650), ShowFirstSeen = ShowFirstSeen, ShowLastSeen = ShowLastSeenHistory, ShowAvailability = ShowAvailability,
            },
            Background = _original.Background with
            {
                Mode = (Core.Monitoring.BackgroundMode)Math.Clamp(BackgroundModeIndex, 0, 2),
                Concurrency = Math.Clamp(BackgroundConcurrency, 1, 1024),
                RoundDelayMinutes = (double)Math.Clamp(RoundDelayMinutes, 0, 1440),
                LeaveAfterMisses = Math.Clamp(LeaveAfterMisses, 1, 100),
                ClearOffline = ClearOffline,
                KeepOnOffline = (KeepOnOffline ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries),
            },
            Applications = new Core.Management.ApplicationSettings { Applications = Applications, Variables = Variables },
            ConfirmationThreshold = (ulong)Math.Clamp(I(ConfirmationThreshold, 65_536), 256, int.MaxValue),
        };
    }

    public static string Describe(decimal? v) => v?.ToString(CultureInfo.CurrentCulture) ?? "";
}
