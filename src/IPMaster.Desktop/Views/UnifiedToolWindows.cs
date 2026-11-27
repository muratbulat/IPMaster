using System.Net;
using System.Net.Sockets;
using Avalonia.Controls;
using IPMaster.Core.Queries;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Management;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → Network Diagnostics → DNS Tools (D-111): DNS Diagnostics and Bulk DNS Audit, each with its own runner and results.</summary>
internal sealed class DnsToolsWindow : ToolTabsWindow
{
    public const int DiagnosticsTab = 0;
    public const int BulkAuditTab = 1;

    public DnsToolsWindow(string? target = null, int tab = DiagnosticsTab)
        : base("DNS Tools", 1150, 800, 680, 460) => AddTabs(tab, ("Diagnostics", new DnsDiagnosticsView(target)), ("Bulk Audit", new BulkDnsAuditView()));
}

/// <summary>
/// Tools → Network Services → SNMP Tools (D-111): Tester, Interface Monitor (its own polling loop, apart from device monitoring) and
/// the SNMP queries of the Remote Query Manager (the same <see cref="QuerySettings.Items"/> list; edited only there).
/// </summary>
internal sealed class SnmpToolsWindow : ToolTabsWindow
{
    public const int TesterTab = 0;
    public const int InterfaceMonitorTab = 1;
    public const int QueriesTab = 2;

    public SnmpToolsWindow(MainWindowViewModel? vm, string? target = null, int tab = TesterTab)
        : base("SNMP Tools", 1200, 820, 700, 480) =>
        AddTabs(tab, ("Tester", new SnmpTesterView(target)), ("Interface Monitor", new SnmpInterfaceMonitorView(target)), ("Queries", new SnmpQueriesView(vm)));
}

/// <summary>SNMP Tools → Queries: the SNMP query columns, read-only; Manage SNMP Queries… opens the Remote Query Manager on SNMP.</summary>
internal sealed class SnmpQueriesView : UserControl
{
    private sealed record Row(string On, string Name, string Summary);

    public SnmpQueriesView(MainWindowViewModel? vm)
    {
        var grid = Ui.Grid(("On", nameof(Row.On), 44), ("Item Name", nameof(Row.Name), 220), ("Version and MIB OID", nameof(Row.Summary), 0));
        Avalonia.Automation.AutomationProperties.SetName(grid, "SNMP queries");
        var status = ToolKit.StatusLine();
        void Refresh()
        {
            var items = vm?.Settings.Queries.Items.Where(q => q.Kind == QueryKind.Snmp).ToList() ?? [];
            grid.ItemsSource = items.Select(q => new Row(q.Enabled ? "✓" : "", q.Name, q.Summary)).ToList();
            status.Text = vm is null ? "Not available: no configuration is loaded." : $"{items.Count} SNMP quer{(items.Count == 1 ? "y" : "ies")}, {items.Count(q => q.Enabled)} enabled.";
        }

        var manage = Ui.Button("Manage SNMP Queries…", () =>
        {
            if (vm is not null && TopLevel.GetTopLevel(this) is Window owner) new QueryManagerWindow(vm, QueryKind.Snmp).Show(owner);
            return Task.CompletedTask;
        }, accent: true);
        manage.IsEnabled = vm is not null;
        var hint = Form.Hint("SNMP queries add result columns to scans. They use the same list as Tools → Remote Management → Remote Query Manager, where you create, test and edit them.");
        Content = Ui.Layout(hint, grid, new StackPanel { Spacing = Styling.Theme.FormRowGap, Children = { Ui.Row(manage), status } });
        AttachedToVisualTree += (_, _) => Refresh(); // every time the tab is shown: the manager may have saved
    }
}

/// <summary>
/// Tools → Discovery → IP Address Tools (D-111): the former Options → IP Address commands. Local Range (adapter ranges, append or
/// replace, large-scan confirmation), From Host Name (address or class C range) and External IP (asked only on request).
/// </summary>
internal sealed class IpAddressToolsWindow : ToolTabsWindow
{
    public const int LocalRangeTab = 0;
    public const int FromHostNameTab = 1;
    public const int ExternalIpTab = 2;

    public IpAddressToolsWindow(MainWindowViewModel vm, int tab = LocalRangeTab)
        : base("IP Address Tools", 800, 620, 560, 400)
    {
        var local = Dialogs.AdapterPicker(vm.Adapters.GetAdapters, vm.Settings.ConfirmationThreshold, (chosen, append) =>
        {
            if (chosen.Count == 0) return "No range selected.";
            vm.SetRanges(chosen.Select(c => new RangeEntryViewModel { Target = c.Range, Comment = c.Adapter }), append);
            return $"{(append ? "Added" : "Set")} {chosen.Count} range(s) in the main window.";
        });
        AddTabs(tab, ("Local Range", local), ("From Host Name", new HostRangeView(vm)), ("External IP", new ExternalIpView(vm, lookUpAtOnce: tab == ExternalIpTab)));
    }
}

/// <summary>IP Address Tools → From Host Name: resolves a name, then sets the address or its class C range as the only range (as before).</summary>
internal sealed class HostRangeView : UserControl, IDisposable
{
    private readonly ToolRunner _runner;

    public HostRangeView(MainWindowViewModel vm)
    {
        var status = ToolKit.StatusLine();
        _runner = new ToolRunner(status);
        var host = ToolKit.Text("Host name", "server.example.test", 320);
        var answer = new SelectableTextBlock { TextWrapping = Avalonia.Media.TextWrapping.Wrap };
        IReadOnlyList<IPAddress> addrs = [];
        string name = "";
        var useAddress = Ui.Button("Use Address", () => Use(false));
        var useRange = Ui.Button("Use Class C Range", () => Use(true));
        void Buttons() => (useAddress.IsEnabled, useRange.IsEnabled) = (addrs.Count > 0 && !_runner.IsBusy, addrs.Count > 0 && addrs[0].AddressFamily == AddressFamily.InterNetwork && !_runner.IsBusy);

        Task Use(bool range)
        {
            if (addrs.Count == 0) return Task.CompletedTask;
            var first = addrs[0].ToString();
            var target = range ? MainWindowViewModel.ExpandPasted(first, 24)! : first;
            vm.SetRanges([new RangeEntryViewModel { Target = target, Comment = name }], append: false);
            status.Text = $"The range is now {target}.";
            return Task.CompletedTask;
        }

        var resolve = Ui.Button("Resolve", async () =>
        {
            name = host.Text?.Trim() ?? "";
            addrs = [];
            answer.Text = "";
            Buttons();
            if (name.Length == 0)
            {
                status.Text = "Enter a host name.";
                return;
            }

            var n = name;
            await _runner.RunAsync("Resolving " + n, async ct =>
            {
                try
                {
                    var found = await vm.Planner.ResolveHostAsync(n, ct);
                    Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                    {
                        addrs = found;
                        answer.Text = found.Count == 0 ? "" : $"{n} resolves to {string.Join(", ", found)}."
                            + (found[0].AddressFamily == AddressFamily.InterNetwork ? $"\nClass C range: {MainWindowViewModel.ExpandPasted(found[0].ToString(), 24)}" : "");
                        Buttons();
                    });
                    return found.Count == 0 ? $"{n} has no addresses." : "Choose what to scan. It replaces the current ranges.";
                }
                catch (SocketException ex)
                {
                    return $"{n} could not be resolved: {ex.Message}";
                }
            });
        }, accent: true);
        _runner.BusyChanged += (_, _) =>
        {
            resolve.IsEnabled = !_runner.IsBusy;
            Buttons();
        };
        Buttons();
        var f = new Form();
        f.Add("Host Name", Ui.Row(host, resolve));
        f.Full(answer);
        Content = ToolKit.Layout(f.Grid, Ui.Row(useAddress, useRange), new Panel(), status);
    }

    public void Dispose() => _runner.Dispose();
}

/// <summary>
/// IP Address Tools → External IP: public IPv4/IPv6 from <see cref="ExternalIp.TraceUrl"/>. Nothing is sent until Look Up is chosen,
/// or the window was opened on this tab (the former menu command, which asked at once).
/// </summary>
internal sealed class ExternalIpView : UserControl, IDisposable
{
    private readonly ToolRunner _runner;

    public ExternalIpView(MainWindowViewModel vm, bool lookUpAtOnce)
    {
        var status = ToolKit.StatusLine();
        _runner = new ToolRunner(status);
        var text = new SelectableTextBlock { TextWrapping = Avalonia.Media.TextWrapping.Wrap, Text = "Look Up asks " + ExternalIp.TraceUrl.Host + " for this network's public addresses." };
        var addresses = new List<string>();
        var use = Ui.Button("Use as Target", () =>
        {
            if (addresses.FirstOrDefault() is { } ip)
            {
                vm.SetRanges([new RangeEntryViewModel { Target = ip, Comment = "External address" }], append: true);
                status.Text = $"Added {ip} to the ranges.";
            }

            return Task.CompletedTask;
        });
        var copy = ToolKit.CopyButton(this, () => string.Join(Environment.NewLine, addresses));
        use.IsEnabled = copy.IsEnabled = false;
        var lookUp = Ui.Button("Look Up", () => _runner.RunAsync("Asking " + ExternalIp.TraceUrl.Host, async ct =>
        {
            var lines = new List<string>();
            var found = new List<string>();
            foreach (var family in new[] { AddressFamily.InterNetwork, AddressFamily.InterNetworkV6 })
            {
                var label = family == AddressFamily.InterNetwork ? "IPv4" : "IPv6";
                try
                {
                    var r = await ExternalIp.LookupAsync(family, ct);
                    if (r is null) lines.Add($"{label}: no answer");
                    else
                    {
                        found.Add(r.Address.ToString());
                        lines.Add($"{label}: {r.Address}" + (r.Country.Length > 0 ? $"  (country: {r.Country})" : ""));
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or SocketException or InvalidOperationException
                                               || (ex is TaskCanceledException && !ct.IsCancellationRequested))
                {
                    lines.Add($"{label}: not available ({ex.Message})");
                }
            }

            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
            {
                addresses.Clear();
                addresses.AddRange(found);
                use.IsEnabled = copy.IsEnabled = addresses.Count > 0;
                text.Text = string.Join("\n", lines) + "\n\nSource: " + ExternalIp.TraceUrl + " (city/region need a geolocation provider, Options → Scan Options → General).";
            });
            return found.Count > 0 ? "Done." : "No public address found.";
        }), accent: true);
        _runner.BusyChanged += (_, _) => lookUp.IsEnabled = !_runner.IsBusy;
        Content = ToolKit.Layout(text, Ui.Row(lookUp, use, copy), new Panel(), status);
        if (lookUpAtOnce)
        {
            var once = true;
            AttachedToVisualTree += (_, _) =>
            {
                if (!once) return;
                once = false;
                lookUp.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            };
        }
    }

    public void Dispose() => _runner.Dispose();
}
