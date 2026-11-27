using Avalonia.Controls;
using IPMaster.Core.Navigation;
using IPMaster.Core.Queries;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Management;
using IPMaster.Infrastructure.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools menu (D-111). Each utility is one entry here: a category, a header and a factory for its window. Entries become commands
/// automatically (shortcuts, Navigator), because the command registry walks the menu; <see cref="ToolEntry.Id"/> keeps the
/// command id independent of the category, so moving a tool to another category keeps its shortcut.
/// </summary>
public partial class MainWindow
{
    internal sealed record ToolEntry(string Category, string Header, Func<MainWindow, MainWindowViewModel, Window> Open, bool Modal = false, string Gesture = "")
    {
        /// <summary>Stable command id: "Tools/" + the caption (no category).</summary>
        public string Id => "Tools/" + Navigator.Clean(Header);
    }

    /// <summary>A command without a menu item: opens a tool on one tab or query type (shortcuts, Navigator, old command ids).</summary>
    internal sealed record ToolCommand(string Id, string Name, string Category, Func<MainWindow, MainWindowViewModel, Window> Open);

    private const string Calculators = "_Calculators";
    private const string Discovery = "_Discovery";
    private const string Diagnostics = "_Network Diagnostics";
    private const string Services = "Network _Services";
    private const string Remote = "_Remote Management";
    private const string Administration = "S_ystem Administration";

    /// <summary>Categories, then entries, alphabetical by caption (accelerator markers and the trailing ellipsis ignored), whatever the order below.</summary>
    internal static readonly ToolEntry[] ToolEntries = Sorted(
    [
        new(Calculators, "_Download Calculator…", (_, _) => new TransferCalculatorWindow(new TransferCalculatorViewModel())),
        new(Calculators, "_IP Calculator…", (_, _) => new IpCalculatorWindow(new IpCalculatorViewModel())),
        new(Discovery, "Device IP _Discovery & DHCP Server…", (_, vm) => new DeviceDiscoveryWindow(vm)),
        new(Discovery, "IP _Address Tools…", (_, vm) => new IpAddressToolsWindow(vm)),
        new(Discovery, "LLDP / CDP _Topology Explorer…", (_, _) => new TopologyExplorerWindow()),
        new(Discovery, "_Wi-Fi Analyzer & Optimizer…", (_, vm) => new WifiAnalyzerWindow(vm.Services.GetRequiredService<IPMaster.Core.Wifi.IWifiProvider>(),
            vm.Services.GetRequiredService<IPMaster.Core.Scanning.IIcmpProbe>())),
        new(Diagnostics, "_DNS Tools…", (_, _) => new DnsToolsWindow()),
        new(Diagnostics, "_HTTP / API Tester…", (_, _) => new HttpTesterWindow()),
        new(Diagnostics, "_iPerf Network Performance…", (_, vm) => new IperfWindow(vm, vm.Services.GetRequiredService<IIperfService>(), vm.Services.GetRequiredService<IPMaster.Core.Network.INetworkAdapterProvider>())),
        new(Diagnostics, "Network _Path & MTU Analyzer…", (_, vm) => new PathAnalyzerWindow(vm.Services.GetRequiredService<IPMaster.Core.Monitoring.IRouteTracer>())),
        new(Diagnostics, "_NTP Time Checker…", (_, _) => new NtpCheckerWindow()),
        new(Diagnostics, "_TCP Connection Tester…", (_, _) => new TcpTesterWindow()),
        new(Diagnostics, "TLS _Certificate Inspector…", (_, _) => new TlsInspectorWindow()),
        new(Services, "_LDAP / Active Directory Tester…", (_, _) => new LdapTesterWindow()),
        new(Services, "_SMTP Client Tester…", (_, vm) => new SmtpTesterWindow(new SmtpTesterViewModel(vm, vm.Services.GetRequiredService<ISmtpTester>()))),
        new(Services, "SN_MP Tools…", (_, vm) => new SnmpToolsWindow(vm)),
        new(Services, "S_yslog Receiver…", (_, _) => new SyslogReceiverWindow()),
        new(Remote, "_Credential Manager…", (_, vm) => CredentialManagerWindow.Create(vm), Modal: true),
        new(Remote, "_Remote Query Manager…", (_, vm) => new QueryManagerWindow(vm, QueryKind.Wmi), Gesture: "Ctrl+W"), // Ctrl+W: Remote WMI before D-111
        new(Remote, "_Wake-on-LAN Manager…", (_, vm) => WolWindow(vm)),
        new(Administration, "_Group Policy Viewer…", (_, vm) => new GroupPolicyViewerWindow(vm.Services.GetRequiredService<IGroupPolicyService>())),
        new(Administration, "_KMS Activation Manager…", (_, vm) => new KmsManagerWindow(vm, vm.Services.GetRequiredService<IKmsService>())),
        new(Administration, "_WinGet Manager…", (_, vm) => new WinGetManagerWindow(vm.Services.GetRequiredService<IWinGetService>())),
    ]);

    /// <summary>Tabs and query types that had menu items of their own before D-111: still commands (shortcuts, Navigator).</summary>
    internal static readonly ToolCommand[] ToolShortcuts =
    [
        new("Tools/DNS Tools/Bulk Audit", "DNS Tools: Bulk Audit", "Tools › Network Diagnostics", (_, _) => new DnsToolsWindow(tab: DnsToolsWindow.BulkAuditTab)),
        new("Tools/SNMP Tools/Interface Monitor", "SNMP Tools: Interface Monitor", "Tools › Network Services", (_, vm) => new SnmpToolsWindow(vm, tab: SnmpToolsWindow.InterfaceMonitorTab)),
        new("Tools/IP Address Tools/From Host Name", "IP Address Tools: From Host Name", "Tools › Discovery", (_, vm) => new IpAddressToolsWindow(vm, IpAddressToolsWindow.FromHostNameTab)),
        new("Tools/IP Address Tools/External IP", "IP Address Tools: External IP", "Tools › Discovery", (_, vm) => new IpAddressToolsWindow(vm, IpAddressToolsWindow.ExternalIpTab)),
        .. Enum.GetValues<QueryKind>().Select(k => new ToolCommand("Tools/Remote Query Manager/" + k, "Remote Query Manager: " + QueryColumns.DisplayName(k), "Tools › Remote Management",
            (_, vm) => new QueryManagerWindow(vm, k))),
    ];

    /// <summary>The caption as it is sorted: no "_" accelerator markers, no trailing "…" or "...".</summary>
    internal static string SortKey(string header) => header.Replace("_", "", StringComparison.Ordinal).TrimEnd('…', '.').Trim();

    internal static ToolEntry[] Sorted(IEnumerable<ToolEntry> entries) =>
        [.. entries.OrderBy(e => SortKey(e.Category), StringComparer.OrdinalIgnoreCase).ThenBy(e => SortKey(e.Header), StringComparer.OrdinalIgnoreCase)];

    private static WolManagerWindow WolWindow(MainWindowViewModel vm) =>
        new(vm.Settings.Wol, vm.Services.GetRequiredService<WakeOnLanSender>(), wol => vm.UpdateSettingsAsync(s => s with { Wol = wol }));

    private void ShowTool(Window window, bool modal = false)
    {
        if (modal) _ = window.ShowDialog(this);
        else window.Show(this);
    }

    /// <summary>
    /// Device context menu → Tools: the utilities that take a target, prefilled with the selected device (the Syslog Receiver only
    /// listens and the IP Calculator and SMTP tester have no device target). Name-validating tools get the host name when known,
    /// because certificate checks need the name; the others get the address. Nothing is sent until the user starts the tool.
    /// </summary>
    private void AddToolItems(ContextMenu menu, DeviceNode node, Func<string, Action, MenuItem> item)
    {
        var ip = node.Result.Address.ToString();
        var name = node.Result.HostName.Value?.Name is { Length: > 0 } n ? n.TrimEnd('.') : ip;
        var root = new MenuItem { Header = "Tools" };
        root.Items.Add(item("DNS Diagnostics", () => new DnsToolsWindow(ip).Show(this)));
        root.Items.Add(item("TCP Connection Tester", () => new TcpTesterWindow(ip).Show(this)));
        root.Items.Add(item("TLS Certificate Inspector", () => new TlsInspectorWindow(name).Show(this)));
        root.Items.Add(item("HTTP / API Tester", () => new HttpTesterWindow(name).Show(this)));
        root.Items.Add(item("LDAP / Active Directory Tester", () => new LdapTesterWindow(name).Show(this)));
        root.Items.Add(item("NTP Time Checker", () => new NtpCheckerWindow(ip).Show(this)));
        root.Items.Add(item("SNMP Tester", () => new SnmpToolsWindow(Vm, ip).Show(this)));
        root.Items.Add(item("SNMP Interface Monitor", () => new SnmpToolsWindow(Vm, ip, SnmpToolsWindow.InterfaceMonitorTab).Show(this)));
        root.Items.Add(item("LLDP / CDP Topology Explorer", () => new TopologyExplorerWindow(ip).Show(this)));
        root.Items.Add(item("Network Path & MTU Analyzer", () => new PathAnalyzerWindow(Vm!.Services.GetRequiredService<IPMaster.Core.Monitoring.IRouteTracer>(), ip).Show(this)));
        menu.Items.Add(root);
    }

    /// <summary>Menu item → stable command id, for items whose id is not their menu path (the Tools entries).</summary>
    private readonly Dictionary<MenuItem, string> _commandIds = [];

    private void BuildToolsMenu()
    {
        ToolsMenu.Items.Clear();
        foreach (var group in ToolEntries.GroupBy(t => t.Category))
        {
            var category = new MenuItem { Header = group.Key };
            foreach (var tool in group)
            {
                var item = new MenuItem { Header = tool.Header, InputGesture = tool.Gesture.Length > 0 ? Avalonia.Input.KeyGesture.Parse(tool.Gesture) : null };
                item.Click += (_, _) =>
                {
                    if (Vm is { } vm) ShowTool(tool.Open(this, vm), tool.Modal);
                };
                _commandIds[item] = tool.Id;
                category.Items.Add(item);
            }

            ToolsMenu.Items.Add(category);
        }
    }
}
