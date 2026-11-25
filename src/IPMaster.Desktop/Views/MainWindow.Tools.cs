using Avalonia.Controls;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Tools;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools menu. Each utility is one entry here: a header and a factory for its non-modal window. Entries become
/// commands automatically (shortcuts, Navigator), because the command registry walks the menu.
/// </summary>
public partial class MainWindow
{
    internal sealed record ToolEntry(string Header, Func<MainWindow, MainWindowViewModel, Window> Open);

    /// <summary>Alphabetical by caption (accelerator markers and the trailing ellipsis ignored), whatever the order below.</summary>
    internal static readonly ToolEntry[] ToolEntries = Sorted(
    [
        new("_DNS Diagnostics…", (_, _) => new DnsDiagnosticsWindow()),
        new("_Bulk DNS Audit…", (_, _) => new BulkDnsAuditWindow()),
        new("_TCP Connection Tester…", (_, _) => new TcpTesterWindow()),
        new("TLS _Certificate Inspector…", (_, _) => new TlsInspectorWindow()),
        new("_HTTP / API Tester…", (_, _) => new HttpTesterWindow()),
        new("_LDAP / Active Directory Tester…", (_, _) => new LdapTesterWindow()),
        new("_NTP Time Checker…", (_, _) => new NtpCheckerWindow()),
        new("S_yslog Receiver…", (_, _) => new SyslogReceiverWindow()),
        new("SN_MP Tester…", (_, _) => new SnmpTesterWindow()),
        new("SNMP Interface _Monitor…", (_, _) => new SnmpInterfaceMonitorWindow()),
        new("LLDP / CDP _Topology Explorer…", (_, _) => new TopologyExplorerWindow()),
        new("Network _Path & MTU Analyzer…", (_, vm) => new PathAnalyzerWindow(vm.Services.GetRequiredService<IPMaster.Core.Monitoring.IRouteTracer>())),
        new("_IP Calculator…", (_, _) => new IpCalculatorWindow(new IpCalculatorViewModel())),
        new("D_ownload Calculator…", (_, _) => new TransferCalculatorWindow(new TransferCalculatorViewModel())),
        new("_SMTP Client Tester…", (_, vm) => new SmtpTesterWindow(new SmtpTesterViewModel(vm, vm.Services.GetRequiredService<ISmtpTester>()))),
        new("Device IP _Discovery & DHCP Server…", (_, vm) => new DeviceDiscoveryWindow(vm)),
        new("_Wi-Fi Analyzer & Optimizer…", (_, vm) => new WifiAnalyzerWindow(vm.Services.GetRequiredService<IPMaster.Core.Wifi.IWifiProvider>(),
            vm.Services.GetRequiredService<IPMaster.Core.Scanning.IIcmpProbe>())),
        new("Win_Get Manager…", (_, vm) => new WinGetManagerWindow(vm.Services.GetRequiredService<IWinGetService>())),
        new("_Group Policy Viewer…", (_, vm) => new GroupPolicyViewerWindow(vm.Services.GetRequiredService<IGroupPolicyService>())),
        new("i_Perf Network Performance…", (_, vm) => new IperfWindow(vm, vm.Services.GetRequiredService<IIperfService>(), vm.Services.GetRequiredService<IPMaster.Core.Network.INetworkAdapterProvider>())),
        new("_KMS Activation Manager…", (_, vm) => new KmsManagerWindow(vm, vm.Services.GetRequiredService<IKmsService>())),
    ]);

    /// <summary>The caption as it is sorted: no "_" accelerator markers, no trailing "…" or "...".</summary>
    internal static string SortKey(string header) => header.Replace("_", "", StringComparison.Ordinal).TrimEnd('…', '.').Trim();

    internal static ToolEntry[] Sorted(IEnumerable<ToolEntry> entries) =>
        [.. entries.OrderBy(e => SortKey(e.Header), StringComparer.OrdinalIgnoreCase)];

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
        root.Items.Add(item("DNS Diagnostics", () => new DnsDiagnosticsWindow(ip).Show(this)));
        root.Items.Add(item("TCP Connection Tester", () => new TcpTesterWindow(ip).Show(this)));
        root.Items.Add(item("TLS Certificate Inspector", () => new TlsInspectorWindow(name).Show(this)));
        root.Items.Add(item("HTTP / API Tester", () => new HttpTesterWindow(name).Show(this)));
        root.Items.Add(item("LDAP / Active Directory Tester", () => new LdapTesterWindow(name).Show(this)));
        root.Items.Add(item("NTP Time Checker", () => new NtpCheckerWindow(ip).Show(this)));
        root.Items.Add(item("SNMP Tester", () => new SnmpTesterWindow(ip).Show(this)));
        root.Items.Add(item("SNMP Interface Monitor", () => new SnmpInterfaceMonitorWindow(ip).Show(this)));
        root.Items.Add(item("LLDP / CDP Topology Explorer", () => new TopologyExplorerWindow(ip).Show(this)));
        root.Items.Add(item("Network Path & MTU Analyzer", () => new PathAnalyzerWindow(Vm!.Services.GetRequiredService<IPMaster.Core.Monitoring.IRouteTracer>(), ip).Show(this)));
        menu.Items.Add(root);
    }

    private void BuildToolsMenu()
    {
        ToolsMenu.Items.Clear();
        foreach (var tool in ToolEntries)
        {
            var item = new MenuItem { Header = tool.Header };
            item.Click += (_, _) =>
            {
                if (Vm is { } vm) tool.Open(this, vm).Show(this);
            };
            ToolsMenu.Items.Add(item);
        }
    }
}
