using Avalonia.Platform.Storage;
using System.Globalization;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Layout;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

public sealed record PropertyItem(string Category, string Property, string Value, string State);

/// <summary>
/// Non-modal device properties (manual: two-column view with a search field). The window keeps its own snapshot, so
/// it stays valid when the results list is cleared or rescanned, and follows later updates of the same device.
/// </summary>
public sealed class PropertiesWindow : Window
{
    private readonly MainWindowViewModel _vm;
    private readonly DataGrid _grid;
    private readonly TextBox _search;
    private DeviceResult _device;
    private List<PropertyItem> _items = [];

    public PropertiesWindow(MainWindowViewModel vm, DeviceResult device)
    {
        _vm = vm;
        _device = device;
        Title = $"Properties — {device.Key}";
        Width = 760;
        Height = 560;
        MinWidth = 420;
        MinHeight = 300;
        _search = new TextBox { PlaceholderText = "Search properties and values", Margin = new Thickness(0, 8, 0, 0) };
        _search.TextChanged += (_, _) => ApplyFilter();
        _grid = new DataGrid
        {
            IsReadOnly = true,
            CanUserSortColumns = true,
            HeadersVisibility = DataGridHeadersVisibility.Column,
            GridLinesVisibility = DataGridGridLinesVisibility.Horizontal,
        };
        _grid.Columns.Add(new DataGridTextColumn { Header = "Category", Binding = new ReflectionBinding(nameof(PropertyItem.Category)), Width = new DataGridLength(130) });
        _grid.Columns.Add(new DataGridTextColumn { Header = "Property", Binding = new ReflectionBinding(nameof(PropertyItem.Property)), Width = new DataGridLength(170) });
        _grid.Columns.Add(new DataGridTextColumn { Header = "Value", Binding = new ReflectionBinding(nameof(PropertyItem.Value)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        _grid.Columns.Add(new DataGridTextColumn { Header = "Status", Binding = new ReflectionBinding(nameof(PropertyItem.State)), Width = new DataGridLength(160) });
        var panel = new DockPanel { Margin = new Thickness(12) };
        DockPanel.SetDock(_search, Dock.Bottom);
        panel.Children.Add(_search);
        panel.Children.Add(_grid);
        // MON-04/05: a monitored device gains Charts and Route tabs; the window keeps its device after clear/rescan.
        if (vm.Monitor.Series(device.Key) is not null)
        {
            var tabs = new MonitoringTabs(vm, device);
            Closed += (_, _) => tabs.Dispose();
            Content = new TabControl { Margin = new Thickness(8), Items = { new TabItem { Header = "Properties", Content = panel }, tabs.ChartsTab(), tabs.RouteTab() } };
            Width = 900;
            Height = 620;
        }
        else
        {
            Content = panel;
        }
        Rebuild();
        vm.DeviceUpdated += OnDeviceUpdated;
        Closed += (_, _) => vm.DeviceUpdated -= OnDeviceUpdated;
    }

    private void OnDeviceUpdated(object? sender, DeviceResult d)
    {
        if (d.Key != _device.Key || d.Revision < _device.Revision) return;
        _device = d;
        Rebuild();
    }

    private void Rebuild()
    {
        _items = Build(_device, _vm.Format, _vm.Settings.Queries.Items).ToList();
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        var q = _search.Text?.Trim() ?? "";
        _grid.ItemsSource = q.Length == 0
            ? _items
            : _items.Where(i => i.Property.Contains(q, StringComparison.CurrentCultureIgnoreCase) || i.Value.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                                || i.Category.Contains(q, StringComparison.CurrentCultureIgnoreCase)).ToList();
    }

    private static string State<T>(Observation<T> o)
    {
        var s = o.State switch
        {
            ObservationState.Success => "",
            ObservationState.NotRequested => "not requested",
            _ => ObservationText.StateName(o.State),
        };
        if (o.Detail is { Length: > 0 } d) s = s.Length == 0 ? d : $"{s}: {d}";
        if (o.ObservedAt is { } at && o.State == ObservationState.Success) s = (s.Length > 0 ? s + " · " : "") + Formats.Timestamp(at);
        return s;
    }

    internal static IEnumerable<PropertyItem> Build(DeviceResult d, ColumnFormat f, IReadOnlyList<Core.Queries.QueryDefinition>? queries = null)
    {
        const string general = "General";
        yield return new PropertyItem(general, "IP Address", d.Key.ToString(), "");
        yield return new PropertyItem(general, "Status", Formats.Status(d.Status), "");
        yield return new PropertyItem(general, "Responded to", ColumnCatalog.PingMethodColumn.Text(d, f), "");
        yield return new PropertyItem(general, "Response Time", ColumnCatalog.ResponseTime.Text(d, f), "");
        yield return new PropertyItem(general, "TTL", ColumnCatalog.Ttl.Text(d, f), State(d.Ttl));
        yield return new PropertyItem(general, "Last Scanned", ColumnCatalog.LastScanned.Text(d, f), "");
        yield return new PropertyItem(general, "Last Seen", ColumnCatalog.LastSeen.Text(d, f), "");
        if (d.PingStats.State != ObservationState.NotRequested)
        {
            yield return new PropertyItem(general, "Packet Loss", ColumnCatalog.PacketLoss.Text(d, f), State(d.PingStats));
            yield return new PropertyItem(general, "Jitter", ColumnCatalog.Jitter.Text(d, f), "");
        }

        const string names = "Names";
        yield return new PropertyItem(names, "Host Name", ColumnCatalog.HostName.Text(d, f), State(d.HostName));
        if (d.NetBios.State != ObservationState.NotRequested)
        {
            yield return new PropertyItem(names, "NetBIOS Name", d.NetBios.Value?.ComputerName ?? "", State(d.NetBios));
            if (d.NetBios.Value is { } nb)
            {
                yield return new PropertyItem(names, "NetBIOS Group", nb.Domain ?? "", "");
                foreach (var n in nb.Names) yield return new PropertyItem(names, $"NetBIOS <{n.Suffix:X2}>{(n.IsGroup ? " group" : "")}", n.Name, "");
            }
        }

        const string hw = "Hardware";
        yield return new PropertyItem(hw, "MAC Address", ColumnCatalog.MacAddress.Text(d, f), State(d.Mac) + (d.MacSource != MacSource.None ? $" · via {d.MacSource}" : ""));
        if (d.Vendor.State != ObservationState.NotRequested) yield return new PropertyItem(hw, "NIC Vendor", ColumnCatalog.Vendor.Text(d, f), State(d.Vendor));
        if (d.IPv6Addresses.State != ObservationState.NotRequested) yield return new PropertyItem(hw, "IPv6 Addresses", ColumnCatalog.IPv6.Text(d, f), State(d.IPv6Addresses));

        const string svc = "Services";
        if (d.TcpPorts.State != ObservationState.NotRequested)
        {
            yield return new PropertyItem(svc, "TCP scan", d.TcpPorts.Detail ?? "", ObservationText.StateName(d.TcpPorts.State));
            foreach (var p in d.TcpPorts.Value ?? []) yield return new PropertyItem(svc, $"TCP {p.Port}", p.Service ?? "", p.State.ToString());
        }

        if (d.UdpPorts.State != ObservationState.NotRequested)
        {
            foreach (var p in d.UdpPorts.Value ?? []) yield return new PropertyItem(svc, $"UDP {p.Port} {p.Service}", p.State.ToString(), p.Detail ?? "");
            if (!d.UdpPorts.HasValue) yield return new PropertyItem(svc, "UDP", "", State(d.UdpPorts));
        }

        if (d.Banners.State != ObservationState.NotRequested)
        {
            foreach (var b in d.Banners.Value ?? []) yield return new PropertyItem(svc, $"{b.Service} ({b.Protocol.ToString().ToUpperInvariant()} {b.Port})", b.Text, "");
            if (!d.Banners.HasValue) yield return new PropertyItem(svc, "Banners", "", State(d.Banners));
        }

        if (d.RtspStreams.State != ObservationState.NotRequested) yield return new PropertyItem(svc, "RTSP Streams", ColumnCatalog.Rtsp.Text(d, f), State(d.RtspStreams));

        if (d.Tls.State != ObservationState.NotRequested)
        {
            const string tls = "TLS certificate";
            if (d.Tls.Value is { } t)
            {
                yield return new PropertyItem(tls, "Subject", t.Subject, "");
                yield return new PropertyItem(tls, "Issuer", t.Issuer, "");
                yield return new PropertyItem(tls, "Valid from", Formats.Timestamp(t.NotBefore), "");
                yield return new PropertyItem(tls, "Valid until", Formats.Timestamp(t.NotAfter),
                    string.Create(CultureInfo.CurrentCulture, $"{t.DaysUntilExpiry(DateTimeOffset.Now)} days left"));
                yield return new PropertyItem(tls, "Serial number", t.SerialNumber, "");
                yield return new PropertyItem(tls, "Thumbprint", t.Thumbprint, "");
                yield return new PropertyItem(tls, "Alternative names", string.Join(", ", t.SubjectAlternativeNames), "");
                yield return new PropertyItem(tls, "Protocol", t.Protocol, "");
                yield return new PropertyItem(tls, "Chain", t.ChainValid ? "trusted" : "not trusted", t.ChainStatus ?? "");
            }
            else
            {
                yield return new PropertyItem(tls, "Certificate", "", State(d.Tls));
            }
        }

        const string win = "Windows";
        if (d.Workgroup.State != ObservationState.NotRequested) yield return new PropertyItem(win, "Workgroup/Domain", ColumnCatalog.Workgroup.Text(d, f), State(d.Workgroup));
        if (d.OsVersion.State != ObservationState.NotRequested) yield return new PropertyItem(win, "Windows Version", ColumnCatalog.OsVersion.Text(d, f), State(d.OsVersion));
        if (d.RemoteTime.State != ObservationState.NotRequested) yield return new PropertyItem(win, "Remote Time", ColumnCatalog.RemoteTime.Text(d, f), State(d.RemoteTime));
        if (d.LoggedOnUsers.State != ObservationState.NotRequested) yield return new PropertyItem(win, "Logged-on Users", ColumnCatalog.LoggedOnUsers.Text(d, f), State(d.LoggedOnUsers));
        if (d.LoggedOnSids.State != ObservationState.NotRequested) yield return new PropertyItem(win, "Logged-on SIDs", ColumnCatalog.LoggedOnSids.Text(d, f), State(d.LoggedOnSids));
        if (d.Accounts.State != ObservationState.NotRequested)
        {
            if (d.Accounts.Value is { } accounts) foreach (var a in accounts) yield return new PropertyItem(win, "User Account", a, "");
            else yield return new PropertyItem(win, "User Accounts", "", State(d.Accounts));
        }

        if (d.InstalledApps.State != ObservationState.NotRequested)
        {
            if (d.InstalledApps.Value is { } apps) foreach (var a in apps) yield return new PropertyItem("Applications", a.Name, a.Version ?? "", a.Publisher ?? "");
            else yield return new PropertyItem("Applications", "Installed Applications", "", State(d.InstalledApps));
        }

        if (d.Shares.State != ObservationState.NotRequested)
        {
            if (d.Shares.Value is { } shares)
            {
                foreach (var s in shares)
                {
                    var cat = $@"Share \\{d.Key}\{s.Name}";
                    foreach (var (_, header, text) in ShareColumns.All.Skip(1))
                    {
                        var v = text(s);
                        if (v.Length > 0) yield return new PropertyItem(cat, header, v, "");
                    }
                }
            }
            else
            {
                yield return new PropertyItem("Shares", "Shares", "", State(d.Shares));
            }
        }

        if (d.Monitors.State != ObservationState.NotRequested)
        {
            if (d.Monitors.HasValue) foreach (var m in d.Monitors.Value!) yield return new PropertyItem("Windows", "Monitor", m.ToString(), m.Year is { } y ? $"made {y}" : "");
            else yield return new PropertyItem("Windows", "Monitor", ObservationText.Render(d.Monitors, _ => ""), State(d.Monitors));
        }

        if (d.TerminalSessions.State != ObservationState.NotRequested)
        {
            if (d.TerminalSessions.HasValue) foreach (var s in d.TerminalSessions.Value!) yield return new PropertyItem("Windows", $"Session {s.Id}", s.ToString(), "");
            else yield return new PropertyItem("Windows", "Terminal Sessions", ObservationText.Render(d.TerminalSessions, _ => ""), State(d.TerminalSessions));
        }

        // Remote queries (Phase 4): one row per value line; deleted items still show their stored result by id.
        foreach (var (id, o) in d.Queries)
        {
            var q = queries?.FirstOrDefault(x => x.ColumnId == id);
            var name = q is null ? id : $"{Core.Queries.QueryColumns.DisplayName(q.Kind)}: {q.Name}";
            var lines = o.HasValue ? o.Value!.Split('\n') : [ObservationText.Render(o, v => v)];
            for (var i = 0; i < lines.Length; i++) yield return new PropertyItem("Remote queries", i == 0 ? name : "", lines[i], i == 0 ? State(o) : "");
        }
    }
}

/// <summary>Reports → Compare Scans: two saved XML files, compared by IP or MAC on selected columns.</summary>
public sealed class CompareWindow : Window
{
    public CompareWindow(IReadOnlyList<ResultColumn> columns, ColumnFormat format)
    {
        Title = "Compare Scans";
        Width = 900;
        Height = 600;
        MinWidth = Styling.Theme.ToolMinWidth;
        MinHeight = Styling.Theme.ToolMinHeight;
        var before = new TextBox { PlaceholderText = "Earlier scan (.xml)", Width = 520 };
        var after = new TextBox { PlaceholderText = "Later scan (.xml)", Width = 520 };
        var key = new ComboBox { ItemsSource = new[] { "Identify devices by IP address", "Identify devices by MAC address" }, SelectedIndex = 0, Width = 260 };
        var columnItems = columns.Where(c => c.Id is not ("lastScanned" or "lastSeen" or "rtt"))
            .Select(c => new CheckItem(c.Id, c.Header, c.Id is "hostName" or "mac" or "status" or "tcpPorts" or "os" or "vendor")).ToList();
        var colsList = new ItemsControl
        {
            ItemsSource = columnItems,
            ItemsPanel = new Avalonia.Controls.Templates.FuncTemplate<Panel?>(() => new WrapPanel()),
            ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<CheckItem>((_, _) => new CheckBox
            {
                Width = 200,
                [!ContentControl.ContentProperty] = new ReflectionBinding("Name"),
                [!CheckBox.IsCheckedProperty] = new ReflectionBinding("IsChecked") { Mode = BindingMode.TwoWay },
            }),
        };
        var summary = new TextBlock { Margin = new Thickness(0, 6) };
        var grid = new DataGrid { IsReadOnly = true, HeadersVisibility = DataGridHeadersVisibility.Column };
        grid.Columns.Add(new DataGridTextColumn { Header = "Change", Binding = new ReflectionBinding("Change"), Width = new DataGridLength(90) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Device", Binding = new ReflectionBinding("Key"), Width = new DataGridLength(170) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Details", Binding = new ReflectionBinding("Details"), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });

        Button Browse(TextBox target)
        {
            var b = new Button { Content = "Browse…" };
            b.Click += async (_, _) =>
            {
                var files = await StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions
                {
                    Title = "Choose scan",
                    FileTypeFilter = [new Avalonia.Platform.Storage.FilePickerFileType("IPMaster results (XML)") { Patterns = ["*.xml"] }],
                });
                if (files.Count > 0 && files[0].TryGetLocalPath() is { } p) target.Text = p;
            };
            return b;
        }

        var compare = new Button { Content = "Compare", Classes = { "accent" } };
        compare.Click += async (_, _) =>
        {
            try
            {
                var a = await ResultsXml.LoadAsync(before.Text ?? "");
                var b = await ResultsXml.LoadAsync(after.Text ?? "");
                var cols = columns.Where(c => columnItems.Any(i => i.Id == c.Id && i.IsChecked)).ToList();
                var r = ScanComparer.Compare(a.Devices, b.Devices, key.SelectedIndex == 1 ? CompareKey.MacAddress : CompareKey.IpAddress, cols, format);
                summary.Text = string.Create(CultureInfo.CurrentCulture,
                    $"{r.Count(ChangeKind.Added)} added · {r.Count(ChangeKind.Removed)} removed · {r.Count(ChangeKind.Changed)} changed · {r.Count(ChangeKind.Unchanged)} unchanged")
                    + (r.SkippedWithoutKey > 0 ? $" · {r.SkippedWithoutKey} device(s) without a MAC address skipped" : "");
                grid.ItemsSource = r.Rows.Where(x => x.Change != ChangeKind.Unchanged).Select(x => new
                {
                    Change = x.Change.ToString(),
                    Key = x.Key + (key.SelectedIndex == 1 ? $" ({(x.After ?? x.Before)!.Key})" : ""),
                    Details = x.Change == ChangeKind.Changed
                        ? string.Join("; ", x.Changes.Select(c => $"{c.Column}: '{c.Before}' → '{c.After}'"))
                        : ColumnCatalog.HostName.Text((x.After ?? x.Before)!, format),
                }).ToList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or System.Xml.XmlException or ArgumentException)
            {
                summary.Text = "Comparison failed: " + ex.Message;
            }
        };

        var top = new StackPanel { Spacing = 6 };
        static WrapPanel Row(params Control[] cs) => Ui.Row(cs);

        top.Children.Add(Row(before, Browse(before)));
        top.Children.Add(Row(after, Browse(after)));
        top.Children.Add(Row(key, compare));
        top.Children.Add(new Expander { Header = "Columns", Content = colsList });
        top.Children.Add(summary);
        var panel = new DockPanel { Margin = new Thickness(12) };
        DockPanel.SetDock(top, Dock.Top);
        panel.Children.Add(top);
        panel.Children.Add(grid);
        Content = panel;
    }
}
