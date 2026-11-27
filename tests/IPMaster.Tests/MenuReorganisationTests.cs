using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using IPMaster.Core.Configuration;
using IPMaster.Core.Queries;
using IPMaster.Desktop.Views;

namespace IPMaster.Tests;

/// <summary>D-111: categorized Tools menu, configuration-only Options menu, stable command ids and renamed-id shortcuts.</summary>
public class ToolsMenuOrderTests
{
    private static readonly Dictionary<string, string[]> Reference = new()
    {
        ["Calculators"] = ["Download Calculator", "IP Calculator"],
        ["Discovery"] = ["Device IP Discovery & DHCP Server", "IP Address Tools", "LLDP / CDP Topology Explorer", "Wi-Fi Analyzer & Optimizer"],
        ["Network Diagnostics"] = ["DNS Tools", "HTTP / API Tester", "iPerf Network Performance", "Network Path & MTU Analyzer", "NTP Time Checker", "TCP Connection Tester", "TLS Certificate Inspector"],
        ["Network Services"] = ["LDAP / Active Directory Tester", "SMTP Client Tester", "SNMP Tools", "Syslog Receiver"],
        ["Remote Management"] = ["Credential Manager", "Remote Query Manager", "Wake-on-LAN Manager"],
        ["System Administration"] = ["Group Policy Viewer", "KMS Activation Manager", "WinGet Manager"],
    };

    [Fact]
    public void Every_tool_is_in_its_category_and_both_are_alphabetical()
    {
        var actual = MainWindow.ToolEntries.GroupBy(t => MainWindow.SortKey(t.Category)).ToDictionary(g => g.Key, g => g.Select(t => MainWindow.SortKey(t.Header)).ToArray());
        Assert.Equal(Reference.Keys, actual.Keys); // categories alphabetical, as Reference is
        foreach (var (category, tools) in Reference) Assert.Equal(tools, actual[category]);
        foreach (var tools in actual.Values) Assert.Equal(tools.OrderBy(k => k, StringComparer.OrdinalIgnoreCase), tools);
        Assert.Equal("SNMP Tools", MainWindow.SortKey("SN_MP Tools…"));
    }

    [Fact]
    public void Ids_headers_and_accelerators_are_unique()
    {
        Assert.Equal(MainWindow.ToolEntries.Length, MainWindow.ToolEntries.Select(t => t.Id).Distinct().Count());
        Assert.Equal(MainWindow.ToolShortcuts.Length, MainWindow.ToolShortcuts.Select(t => t.Id).Distinct().Count());
        Assert.Empty(MainWindow.ToolEntries.Select(t => t.Id).Intersect(MainWindow.ToolShortcuts.Select(t => t.Id)));
        static char Key(string h) => char.ToUpperInvariant(h[h.IndexOf('_', StringComparison.Ordinal) + 1]);
        foreach (var g in MainWindow.ToolEntries.GroupBy(t => t.Category)) Assert.Equal(g.Count(), g.Select(t => Key(t.Header)).Distinct().Count());
        var categories = MainWindow.ToolEntries.Select(t => t.Category).Distinct().ToList();
        Assert.Equal(categories.Count, categories.Select(Key).Distinct().Count());
    }

    [Fact]
    public void A_new_tool_lands_in_its_alphabetical_place()
    {
        var sorted = MainWindow.Sorted(MainWindow.ToolEntries.Append(new MainWindow.ToolEntry("_Calculators", "_Aardvark Tool…", (_, _) => null!))
            .Append(new MainWindow.ToolEntry("S_ystem Administration", "Zebra _Tool...", (_, _) => null!)));
        Assert.Equal("_Aardvark Tool…", sorted[0].Header);
        Assert.Equal("Zebra _Tool...", sorted[^1].Header);
    }

    [Fact]
    public void Every_query_type_is_in_exactly_one_manager_category() =>
        Assert.Equal(Enum.GetValues<QueryKind>().Order(), QueryManagerWindow.Categories.SelectMany(c => c.Kinds).Order());
}

public class RenamedShortcutTests
{
    private static readonly ShortcutCommand Manager = new("Tools/Remote Query Manager", "Remote Query Manager", "Tools", "Ctrl+W");
    private static readonly ShortcutCommand Registry = new("Tools/Remote Query Manager/Registry", "Remote Query Manager: Registry", "Tools", "");
    private static readonly ShortcutCommand Bulk = new("Tools/DNS Tools/Bulk Audit", "DNS Tools: Bulk Audit", "Tools", "");
    private static readonly ShortcutCommand[] Commands = [Manager, Registry, Bulk];

    private static ShortcutBinding B(string id, string g) => new() { CommandId = id, Gesture = g };

    [Fact]
    public void An_old_id_keeps_the_users_key_on_the_new_command()
    {
        var e = Shortcuts.Effective(Commands, [B("Options/Remote Registry", "Ctrl+Shift+R"), B("Tools/Bulk DNS Audit", "F7"), B("Options/Remote WMI", "Ctrl+Shift+W")]);
        Assert.Equal("Ctrl+Shift+R", e[Registry.Id]);
        Assert.Equal("F7", e[Bulk.Id]);
        Assert.Equal("Ctrl+Shift+W", e[Manager.Id]);
    }

    [Fact]
    public void Defaults_stay_when_nothing_was_customised() => Assert.Equal("Ctrl+W", Shortcuts.Effective(Commands, [])[Manager.Id]);

    [Fact]
    public void A_key_set_on_the_new_id_wins_over_the_old_id_whatever_the_order()
    {
        Assert.Equal("F9", Shortcuts.Effective(Commands, [B(Registry.Id, "F9"), B("Options/Remote Registry", "F8")])[Registry.Id]);
        Assert.Equal("F9", Shortcuts.Effective(Commands, [B("Options/Remote Registry", "F8"), B(Registry.Id, "F9")])[Registry.Id]);
    }

    [Fact]
    public void A_removed_shortcut_stays_removed() => Assert.Equal("", Shortcuts.Effective(Commands, [B("Options/Remote WMI", "")])[Manager.Id]);

    [Fact]
    public void Assigning_the_new_command_replaces_the_old_entry_so_it_cannot_come_back()
    {
        IReadOnlyList<ShortcutBinding> o = [B("Options/Remote Registry", "F8"), B("Options/Remote WMI", "F6")];
        o = Shortcuts.Assign(o, Registry, ""); // back to the default (none)
        Assert.DoesNotContain(o, b => b.CommandId == "Options/Remote Registry");
        Assert.Equal("", Shortcuts.Effective(Commands, o)[Registry.Id]);
        Assert.Equal("F6", Shortcuts.Effective(Commands, o)[Manager.Id]); // other renamed entries are kept
    }

    [Fact]
    public void A_renamed_key_that_collides_is_reported_as_a_conflict_not_dropped()
    {
        var e = Shortcuts.Effective(Commands, [B("Options/Remote Registry", "Ctrl+W")]);
        Assert.Equal(["Tools/Remote Query Manager", "Tools/Remote Query Manager/Registry"], Shortcuts.Conflicts(e).Single().CommandIds);
    }

    [Fact]
    public void Every_old_id_maps_to_a_different_new_command() =>
        Assert.Equal(Shortcuts.LegacyIds.Count, Shortcuts.LegacyIds.Values.Distinct().Count());
}

[Collection("Headless UI")]
public class MenuRegistryTests
{
    private static IReadOnlyList<ShortcutCommand> Catalog(out MainWindow w)
    {
        w = new MainWindow();
        w.BuildCommands();
        return w.CommandCatalog;
    }

    [Fact]
    public Task Command_ids_are_unique_and_every_old_id_has_its_command() => HeadlessUi.Run(() =>
    {
        var ids = Catalog(out _).Select(c => c.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        foreach (var (old, now) in Shortcuts.LegacyIds)
        {
            Assert.Contains(now, ids);
            Assert.DoesNotContain(old, ids);
        }

        foreach (var t in MainWindow.ToolEntries) Assert.Contains(t.Id, ids);
        foreach (var t in MainWindow.ToolShortcuts) Assert.Contains(t.Id, ids);
        foreach (var k in Enum.GetValues<QueryKind>()) Assert.Contains("Tools/Remote Query Manager/" + k, ids);
    });

    [Fact]
    public Task Options_holds_configuration_only_and_Actions_is_unchanged() => HeadlessUi.Run(() =>
    {
        var c = Catalog(out _);
        Assert.Equal(["Options/Scan Options", "Options/Ignored IP Addresses", "Options/Friendly Names / Comments", "Options/Virtual Columns"],
            c.Where(x => x.Id.StartsWith("Options/", StringComparison.Ordinal)).Select(x => x.Id));
        foreach (var id in new[] { "Actions/DHCP Server Discovery", "Actions/UPnP Device Discovery", "Actions/mDNS Device Discovery", "Actions/WSD Device Discovery",
                     "Actions/ONVIF Device Discovery", "Actions/Find Duplicate IP Addresses", "Actions/Remote Shutdown", "Actions/Send Message" })
            Assert.Contains(id, c.Select(x => x.Id));
    });

    [Fact]
    public Task Default_shortcuts_are_kept_and_never_shared() => HeadlessUi.Run(() =>
    {
        var c = Catalog(out _);
        Assert.Equal("Ctrl+O", c.Single(x => x.Id == "Options/Scan Options").DefaultGesture);
        Assert.Equal("Ctrl+W", c.Single(x => x.Id == "Tools/Remote Query Manager").DefaultGesture);
        var used = c.Select(x => Shortcuts.Normalize(x.DefaultGesture)).Where(g => g is { Length: > 0 }).ToList();
        Assert.Equal(used.Count, used.Distinct().Count());
        Assert.Empty(Shortcuts.Conflicts(Shortcuts.Effective(c, [])));
    });

    [Fact]
    public Task Every_tool_is_reachable_from_the_Tools_menu_under_its_category() => HeadlessUi.Run(() =>
    {
        _ = Catalog(out var w);
        var tools = w.FindControl<MenuItem>("ToolsMenu")!;
        var categories = tools.Items.OfType<MenuItem>().ToList();
        Assert.Equal(MainWindow.ToolEntries.Select(t => t.Category).Distinct(), categories.Select(m => (string)m.Header!));
        var leaves = categories.SelectMany(m => m.Items.OfType<MenuItem>()).Select(m => (string)m.Header!).ToList();
        Assert.Equal(MainWindow.ToolEntries.Select(t => t.Header), leaves);
        var gesture = categories.SelectMany(m => m.Items.OfType<MenuItem>()).Single(m => (string)m.Header! == "_Remote Query Manager…").InputGesture;
        Assert.Equal("Ctrl+W", gesture?.ToString());
    });
}

[Collection("Headless UI")]
public class UnifiedToolWindowTests
{
    private sealed class Probe : UserControl, IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }

    private sealed class TwoTabs : ToolTabsWindow
    {
        public TwoTabs(Probe a, Probe b)
            : base("Two", 600, 400, 560, 380) => AddTabs(1, ("A", a), ("B", b));
    }

    [Fact]
    public Task Switching_tabs_cancels_nothing_and_closing_one_window_leaves_the_other_running() => HeadlessUi.Run(() =>
    {
        Probe a = new(), b = new(), c = new(), d = new();
        var first = new TwoTabs(a, b);
        var second = new TwoTabs(c, d);
        first.Show();
        second.Show();
        Assert.Equal(1, first.Tabs.SelectedIndex);
        first.Tabs.SelectedIndex = 0;
        UiDesignSystemTests.Dispatch();
        Assert.False(a.Disposed || b.Disposed);
        first.Close();
        Assert.True(a.Disposed && b.Disposed);
        Assert.False(c.Disposed || d.Disposed);
        second.Close();
        Assert.True(c.Disposed && d.Disposed);
    });

    private static List<string> Headers(ToolTabsWindow w) => w.Tabs.Items.OfType<TabItem>().Select(t => (string)t.Header!).ToList();

    [Fact]
    public Task Dns_tools_has_both_tools_as_separate_disposable_views_and_prefills_the_target() => HeadlessUi.Run(() =>
    {
        var w = new DnsToolsWindow("192.0.2.7", DnsToolsWindow.BulkAuditTab);
        w.Show();
        try
        {
            Assert.Equal(["Diagnostics", "Bulk Audit"], Headers(w));
            Assert.Equal(1, w.Tabs.SelectedIndex);
            var tabs = w.Tabs.Items.OfType<TabItem>().ToList();
            Assert.IsType<DnsDiagnosticsView>(tabs[0].Content);
            Assert.IsType<BulkDnsAuditView>(tabs[1].Content);
            Assert.All(tabs, t => Assert.IsNotType<Window>(t.Content));
            w.Tabs.SelectedIndex = 0;
            UiDesignSystemTests.Dispatch();
            Assert.Contains(((Control)tabs[0].Content!).GetVisualDescendants().OfType<TextBox>(), t => t.Text == "192.0.2.7");
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public Task Snmp_tools_shows_the_shared_query_list_and_opens_the_manager_on_snmp() => HeadlessUi.RunAsync(async () =>
    {
        var vm = HeadlessUi.Vm;
        var before = vm.Settings.Queries;
        var snmp = QueryDefinition.New(QueryKind.Snmp, "Uptime test") with { Enabled = false };
        await vm.SaveQueriesAsync(before with { Items = [.. before.Items, snmp] });
        var w = new SnmpToolsWindow(vm, "192.0.2.8", SnmpToolsWindow.QueriesTab);
        w.Show();
        try
        {
            Assert.Equal(["Tester", "Interface Monitor", "Queries"], Headers(w));
            UiDesignSystemTests.Dispatch();
            var grid = w.GetVisualDescendants().OfType<DataGrid>().Single(g => Avalonia.Automation.AutomationProperties.GetName(g) == "SNMP queries");
            Assert.Contains(grid.ItemsSource!.Cast<object>(), r => r.ToString()!.Contains("Uptime test", StringComparison.Ordinal));
            w.GetVisualDescendants().OfType<Button>().Single(b => b.Content as string == "Manage SNMP Queries…").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            UiDesignSystemTests.Dispatch();
            var manager = Assert.IsType<QueryManagerWindow>(Assert.Single(w.OwnedWindows));
            Assert.Equal(QueryKind.Snmp, manager.Kind);
            Assert.Contains(manager.Current!.Rows, r => r.Query.Id == snmp.Id && !r.Enabled);
            manager.Close();
            foreach (var t in w.Tabs.Items.OfType<TabItem>().Take(2))
            {
                w.Tabs.SelectedItem = t;
                UiDesignSystemTests.Dispatch();
                Assert.Contains(((Control)t.Content!).GetVisualDescendants().OfType<TextBox>(), b => b.Text == "192.0.2.8"); // context menu prefill on both tools
            }
        }
        finally
        {
            w.Close();
            await vm.SaveQueriesAsync(before);
        }
    });

    [Fact]
    public Task Ip_address_tools_has_three_tabs_and_sends_nothing_until_asked() => HeadlessUi.Run(() =>
    {
        var w = new IpAddressToolsWindow(HeadlessUi.Vm);
        w.Show();
        try
        {
            Assert.Equal(["Local Range", "From Host Name", "External IP"], Headers(w));
            w.Tabs.SelectedIndex = IpAddressToolsWindow.ExternalIpTab;
            UiDesignSystemTests.Dispatch();
            var view = w.GetVisualDescendants().OfType<ExternalIpView>().Single();
            Assert.Contains(view.GetVisualDescendants().OfType<TextBlock>(), t => t.Classes.Contains("status") && string.IsNullOrEmpty(t.Text)); // no lookup started
        }
        finally
        {
            w.Close();
        }
    });
}

[Collection("Headless UI")]
public class RemoteQueryManagerTests
{
    [Fact]
    public Task Opens_on_the_given_type_and_selects_the_given_query_without_changing_any() => HeadlessUi.RunAsync(async () =>
    {
        var vm = HeadlessUi.Vm;
        var before = vm.Settings.Queries;
        var reg = QueryDefinition.New(QueryKind.Registry, "Reg A") with { Enabled = true };
        var ssh = QueryDefinition.New(QueryKind.Ssh, "Ssh B") with { Enabled = false };
        await vm.SaveQueriesAsync(before with { Items = [.. before.Items, reg, ssh] });
        var items = vm.Settings.Queries.Items.ToList();
        var w = new QueryManagerWindow(vm, QueryKind.Ssh, ssh.Id);
        w.Show();
        try
        {
            UiDesignSystemTests.Dispatch();
            Assert.Equal(QueryKind.Ssh, w.Kind);
            Assert.Equal(ssh.Id, w.Current!.SelectedRow!.Query.Id);
            Assert.True(w.ShowQueries(QueryKind.Registry, reg.Id));
            Assert.Equal(reg.Id, w.Current!.SelectedRow!.Query.Id);
            Assert.False(w.ShowQueries(QueryKind.Wmi, reg.Id)); // not of that type: nothing selected, nothing changed
            var combos = w.GetVisualDescendants().OfType<ComboBox>().Take(2).ToList();
            Assert.Equal("Windows", combos[0].SelectedItem);
            Assert.Equal("WMI", combos[1].SelectedItem);
            combos[0].SelectedIndex = 2; // Network & Data → its first type
            UiDesignSystemTests.Dispatch();
            Assert.Equal(QueryKind.Snmp, w.Kind);
            Assert.Equal(items, vm.Settings.Queries.Items); // browsing saves nothing
        }
        finally
        {
            w.Close();
            await vm.SaveQueriesAsync(before);
        }
    });

    [Fact]
    public Task Duplicate_adds_a_disabled_copy_and_keeps_the_original_id_column_and_state() => HeadlessUi.RunAsync(async () =>
    {
        var vm = HeadlessUi.Vm;
        var before = vm.Settings.Queries;
        var cred = Guid.NewGuid();
        var wmi = QueryDefinition.New(QueryKind.Wmi, "Wmi C") with { Enabled = true, CredentialId = cred };
        await vm.SaveQueriesAsync(before with { Items = [.. before.Items, wmi] });
        var w = new QueryManagerWindow(vm, QueryKind.Wmi, wmi.Id);
        w.Show();
        try
        {
            UiDesignSystemTests.Dispatch();
            w.GetVisualDescendants().OfType<Button>().Single(b => b.Content as string == "Duplicate").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            for (var i = 0; i < 50 && vm.Settings.Queries.Items.Count(q => q.Kind == QueryKind.Wmi && q.Name.StartsWith("Wmi C", StringComparison.Ordinal)) < 2; i++)
            {
                await Task.Delay(20, TestContext.Current.CancellationToken);
                UiDesignSystemTests.Dispatch();
            }

            var original = vm.Settings.Queries.Items.Single(q => q.Id == wmi.Id);
            Assert.True(original.Enabled);
            Assert.Equal(wmi.ColumnId, original.ColumnId);
            Assert.Equal(cred, original.CredentialId);
            var copy = vm.Settings.Queries.Items.Single(q => q.Name == "Wmi C (copy)");
            Assert.False(copy.Enabled);
            Assert.NotEqual(wmi.Id, copy.Id);
            Assert.Equal(cred, copy.CredentialId);
        }
        finally
        {
            w.Close();
            await vm.SaveQueriesAsync(before);
        }
    });
}
