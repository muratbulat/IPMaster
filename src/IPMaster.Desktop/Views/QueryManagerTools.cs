using System.Globalization;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Queries;
using IPMaster.Infrastructure.Management;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Layout for the external-tool managers (Nmap, Python; D-072): description and detected dependency at the top, location and
/// download actions, a checkbox table, and search + New/Edit/Delete/Mark All at the bottom. The list, editor, validation,
/// save and test logic are the common <see cref="QueryManagerWindow"/> ones; only what differs per tool is in the switches.
/// </summary>
internal sealed partial class QueryManagerWindow
{
    private TextBox? _search;
    private Button? _test;

    private static bool IsToolManager(QueryKind kind) => kind is QueryKind.Nmap or QueryKind.Python;

    private static string ToolDescription(QueryKind kind) => kind == QueryKind.Nmap
        ? "Run Nmap against each device and show values from its XML output (XPath) as result columns. Nmap is not bundled: install it separately."
        : "Run Python scripts for each device; what a script writes with Output.Write becomes a result column. Python is not bundled: install it separately.";

    private static (string Url, string Label) ToolDownload(QueryKind kind) => kind == QueryKind.Nmap
        ? ("https://nmap.org/download", "Download Nmap")
        : ("https://www.python.org/downloads/", "Download Python");

    private DataGrid ToolGrid()
    {
        var g = new DataGrid
        {
            IsReadOnly = true, HeadersVisibility = DataGridHeadersVisibility.Column, SelectionMode = DataGridSelectionMode.Extended,
            CanUserSortColumns = true, CanUserResizeColumns = true,
        };
        AutomationProperties.SetName(g, _kind == QueryKind.Nmap ? "Nmap queries" : "Python scripts");
        g.Columns.Add(new DataGridTemplateColumn
        {
            Header = "", Width = new DataGridLength(34), CanUserSort = false,
            CellTemplate = new FuncDataTemplate<Row>((row, _) =>
            {
                var box = new CheckBox { HorizontalAlignment = HorizontalAlignment.Center, MinWidth = 0, Padding = new Thickness(0) };
                box.Bind(Avalonia.Controls.Primitives.ToggleButton.IsCheckedProperty, new Binding(nameof(Row.Enabled)) { Mode = BindingMode.OneWay });
                AutomationProperties.SetName(box, "Enabled");
                box.IsCheckedChanged += async (_, _) =>
                {
                    if (box.DataContext is not Row r || box.IsChecked == r.Enabled) return;
                    await SaveAsync(items => items.Select(i => i.Id == r.Query.Id ? i with { Enabled = box.IsChecked == true } : i).ToList());
                };
                return box;
            }),
        });
        DataGridColumn TextColumn(string header, string path, double width)
        {
            return new DataGridTemplateColumn
            {
                Header = header, SortMemberPath = path, Width = width > 0 ? new DataGridLength(width) : new DataGridLength(1, DataGridLengthUnitType.Star),
                CellTemplate = new FuncDataTemplate<Row>((_, _) =>
                {
                    var t = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Padding = new Thickness(8, 0), TextTrimming = TextTrimming.CharacterEllipsis };
                    t.Bind(TextBlock.TextProperty, new Binding(path));
                    t.Bind(ToolTip.TipProperty, new Binding(path)); // long expressions: full text on hover (and in Edit…)
                    return t;
                }),
            };
        }

        g.Columns.Add(TextColumn("Item Name", nameof(Row.Name), 200));
        if (_kind == QueryKind.Nmap)
        {
            g.Columns.Add(TextColumn("Scan Type", nameof(Row.Detail1), 150));
            g.Columns.Add(TextColumn("Response XPath Query", nameof(Row.Detail2), 0));
        }
        else
        {
            g.Columns.Add(TextColumn("Script", nameof(Row.Detail1), 0));
        }

        return g;
    }

    /// <summary>Per-tool columns: Nmap scan type and XPath; Python the script's real size and first line.</summary>
    private static (string, string) ToolDetails(QueryDefinition q)
    {
        if (q.Kind == QueryKind.Nmap && q.Nmap is { } n)
        {
            var type = n.ScanType switch
            {
                NmapScanType.OsDetection => "OS detection",
                NmapScanType.VersionDetection => "Version detection",
                _ => string.IsNullOrWhiteSpace(n.ScriptName) ? "NSE script" : "NSE script: " + n.ScriptName,
            };
            return (type, n.XPath);
        }

        if (q.Kind == QueryKind.Python)
        {
            var script = q.Python?.Script ?? "";
            var body = script.TrimEnd('\r', '\n');
            var lines = body.Length == 0 ? 0 : body.Split('\n').Length; // a final line break does not start another line
            var first = script.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "";
            return (string.Create(CultureInfo.CurrentCulture, $"{lines} line{(lines == 1 ? "" : "s")}{(first.Length > 0 ? " — " + first : "")}"), "");
        }

        return (q.Summary, "");
    }

    private Control ToolLayout()
    {
        var icon = new PathIcon { Width = 32, Height = 32, VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(0, 2, 12, 0) };
        icon.Bind(PathIcon.DataProperty, icon.GetResourceObservable(_kind == QueryKind.Nmap ? "IconRadar" : "IconCode"));
        var status = new TextBlock { Text = "Checking for " + (_kind == QueryKind.Nmap ? "Nmap" : "Python") + "…", TextWrapping = TextWrapping.Wrap, FontWeight = FontWeight.SemiBold };
        AutomationProperties.SetLiveSetting(status, AutomationLiveSetting.Polite);
        var provider = _vm.Queries.Providers(_vm.Settings).First(p => p.Kind == _kind);

        async Task DetectAsync()
        {
            status.Text = "Checking for " + (_kind == QueryKind.Nmap ? "Nmap" : "Python") + "…";
            Styling.Theme.SetState(status, null);
            var capability = await Task.Run(() => provider.Capability); // bounded version check, never on the UI thread
            status.Text = (capability.Available ? "✓ " : "⚠ ") + capability.Description;
            if (!capability.Available) Styling.Theme.SetState(status, "warning");
            if (_test is not null) _test.IsEnabled = capability.Available; // only execution needs the tool
        }

        var description = new StackPanel
        {
            Spacing = 4,
            Children = { new TextBlock { Text = ToolDescription(_kind), TextWrapping = TextWrapping.Wrap }, status },
        };
        var header = new DockPanel { Children = { icon, description } };
        DockPanel.SetDock(icon, Dock.Left);

        var choose = Ui.Button("Choose Location…", async () =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions
            {
                Title = _kind == QueryKind.Nmap ? "Nmap executable" : "Python interpreter",
            });
            if (files.Count == 0 || files[0].TryGetLocalPath() is not { } p) return;
            var queries = _vm.Settings.Queries;
            await _vm.SaveQueriesAsync(_kind == QueryKind.Nmap ? queries with { Nmap = queries.Nmap with { ExecutablePath = p } } : queries with { PythonPath = p });
            await DetectAsync();
        });
        var detected = Ui.Button("Use Detected", async () =>
        {
            var queries = _vm.Settings.Queries;
            await _vm.SaveQueriesAsync(_kind == QueryKind.Nmap ? queries with { Nmap = queries.Nmap with { ExecutablePath = "" } } : queries with { PythonPath = "" });
            await DetectAsync();
        });
        ToolTip.SetTip(detected, "Forget the chosen location and search the PATH and the usual install folders.");
        var (url, label) = ToolDownload(_kind);
        var download = Ui.Button(label, () =>
        {
            _status.Text = Shell.OpenUrl(url).Message; // opens the official page in the browser; nothing is installed
            return Task.CompletedTask;
        });
        ToolTip.SetTip(download, "Opens " + url + " in your browser. IPMaster does not download or install anything.");
        var actions = new DockPanel { LastChildFill = false };
        var left = Ui.Row(choose, detected, download);
        DockPanel.SetDock(left, Dock.Left);
        actions.Children.Add(left);
        if (_kind == QueryKind.Nmap)
        {
            var settings = Ui.Button("Settings…", NmapSettingsAsync);
            DockPanel.SetDock(settings, Dock.Right);
            actions.Children.Add(settings);
        }

        _search = new TextBox { PlaceholderText = "Search", Width = 220 };
        AutomationProperties.SetName(_search, "Search " + (_kind == QueryKind.Nmap ? "Nmap queries" : "Python scripts"));
        _search.TextChanged += (_, _) => Refresh();
        _test = Ui.Button("Test…", TestSelected);
        ToolTip.SetTip(_test, "Run the selected item against one address (needs the tool to be installed).");
        var bottom = new DockPanel { LastChildFill = false };
        DockPanel.SetDock(_search, Dock.Left);
        bottom.Children.Add(_search);
        var buttons = Ui.Row(
            Ui.Button("New…", async () =>
            {
                if (await QueryEditor.EditAsync(this, _vm, QueryDefinition.New(_kind, "")) is { } q) await SaveAsync(items => [.. items, q]);
            }),
            Ui.Button("Edit…", EditSelected),
            Ui.Button("Delete", async () =>
            {
                var sel = _grid.SelectedItems.OfType<Row>().Select(r => r.Query.Id).ToHashSet();
                if (sel.Count == 0 || !await Dialogs.MessageAsync(this, "Delete", $"Delete {sel.Count} item(s)?", confirm: true)) return;
                await SaveAsync(items => items.Where(i => !sel.Contains(i.Id)).ToList());
            }),
            Ui.Button("Mark All/None", async () =>
            {
                // the visible (searched) items: enable all unless all are enabled already, then disable them
                var visible = (_grid.ItemsSource as IEnumerable<Row> ?? []).Select(r => r.Query.Id).ToHashSet();
                var enable = (_grid.ItemsSource as IEnumerable<Row> ?? []).Any(r => !r.Enabled);
                await SaveAsync(items => items.Select(i => visible.Contains(i.Id) ? i with { Enabled = enable } : i).ToList());
            }),
            _test);
        DockPanel.SetDock(buttons, Dock.Right);
        bottom.Children.Add(buttons);

        _ = DetectAsync();
        var top = new StackPanel { Spacing = 10, Children = { header, actions } };
        return Ui.Layout(top, _grid, new StackPanel { Spacing = 6, Children = { bottom, _status } });
    }

    /// <summary>Search filter of the tool managers (name or detail columns).</summary>
    private bool Matches(Row r)
    {
        var q = _search?.Text?.Trim() ?? "";
        return q.Length == 0 || r.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || r.Detail1.Contains(q, StringComparison.OrdinalIgnoreCase)
               || r.Detail2.Contains(q, StringComparison.OrdinalIgnoreCase);
    }
}
