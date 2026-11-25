using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Group Policy Viewer (D-107): applied and filtered GPOs of this computer and the signed-in user from the local
/// RSoP report. Read-only: no gpupdate, no policy or registry change; exports only on an explicit action.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The runner is disposed when the window closes.")]
internal sealed class GroupPolicyViewerWindow : Window
{
    private static readonly string[] ScopeNames = ["All", "Computer", "User"];

    private readonly IGroupPolicyService _service;
    private readonly ObservableCollection<GpoEntry> _rows = [];
    private readonly DataGrid _grid;
    private readonly TextBox _search = ToolKit.Text("Search GPOs", "GPO name", 300);
    private readonly RadioButton[] _scopes;
    private readonly SelectableTextBlock _info = new() { Classes = { Styling.Theme.Classes.Mono }, TextWrapping = TextWrapping.NoWrap };
    private readonly TextBlock _counts = new();
    private readonly SelectableTextBlock _details = new() { Classes = { Styling.Theme.Classes.Mono }, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _status = ToolKit.StatusLine();
    private readonly ToolRunner _runner;
    private readonly Control[] _needsReport;
    private GpoReport? _report;

    public GroupPolicyViewerWindow(IGroupPolicyService service)
    {
        _service = service;
        Title = "Group Policy Viewer";
        Width = 960;
        Height = 700;
        MinWidth = 680;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _runner = new ToolRunner(_status);

        _scopes = ScopeNames.Select((t, i) => new RadioButton { Content = t, GroupName = "gpoScope", IsChecked = i == 0 }).ToArray();
        foreach (var r in _scopes) r.IsCheckedChanged += (_, _) => ApplyFilter();
        _search.TextChanged += (_, _) => ApplyFilter();
        var refresh = Ui.Button("Refresh", RefreshAsync);
        ToolTip.SetTip(refresh, "Reads the local RSoP report again (gpresult). Does not refresh policy.");
        var cancel = Ui.Button("Cancel", () =>
        {
            _runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        var inputs = new StackPanel { Spacing = Styling.Theme.SectionGap, Children = { _info, _counts, Ui.Row(_scopes), Ui.Row(_search, refresh, cancel) } };
        if (!service.IsSupported) inputs.Children.Insert(0, Ui.Banner("Windows only. Group Policy Viewer is unavailable on this system.", Styling.Theme.Classes.Warning));

        _grid = new DataGrid
        {
            ItemsSource = _rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true,
            SelectionMode = DataGridSelectionMode.Single, MinHeight = 100,
        };
        AutomationProperties.SetName(_grid, "Group Policy Objects");
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "GPO Name", Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 180, SortMemberPath = nameof(GpoEntry.Name),
            CellTemplate = new FuncDataTemplate<GpoEntry>((g, _) =>
            {
                var t = new TextBlock { Text = g?.Name, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0), TextTrimming = TextTrimming.CharacterEllipsis };
                ToolTip.SetTip(t, g?.Name);
                return t;
            }),
        });
        _grid.Columns.Add(new DataGridTextColumn { Header = "Scope", Binding = new Binding(nameof(GpoEntry.Scope)), Width = new DataGridLength(105), MinWidth = 100 });
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Status", Width = new DataGridLength(100), MinWidth = 80, SortMemberPath = nameof(GpoEntry.StateText),
            CellTemplate = new FuncDataTemplate<GpoEntry>((g, _) =>
            {
                var t = new TextBlock { Text = g is null ? "" : (g.State == GpoState.Applied ? "✔ " : g.State == GpoState.Filtered ? "⚠ " : "? ") + g.StateText, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0) };
                if (g is not null && GroupPolicy.StateClass(g.State) is { } c) Styling.Theme.SetState(t, c);
                return t;
            }),
        });
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Reason", Width = new DataGridLength(190), MinWidth = 90, SortMemberPath = nameof(GpoEntry.Reason),
            CellTemplate = new FuncDataTemplate<GpoEntry>((g, _) =>
            {
                var t = new TextBlock { Text = g?.Reason, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0), TextTrimming = TextTrimming.CharacterEllipsis };
                ToolTip.SetTip(t, g?.Reason);
                return t;
            }),
        });
        _grid.Columns.Add(new DataGridTextColumn { Header = "GUID", Binding = new Binding(nameof(GpoEntry.Id)), Width = new DataGridLength(140), MinWidth = 70 });
        _grid.SelectionChanged += (_, _) => _details.Text = _grid.SelectedItem is GpoEntry g ? Details(g) : "";

        var settings = Ui.Button("Settings…", () => _report is null ? Task.CompletedTask : new GpoSettingsWindow(_report.Settings).ShowDialog(this));
        ToolTip.SetTip(settings, "Effective settings that the report lists, with the winning GPO.");
        var copy = ToolKit.CopyButton(this, () => _report is null ? "" : GroupPolicy.Summary(_report), "Copy Summary");
        var txt = Ui.Button("Export TXT…", () => _report is null ? Task.CompletedTask : ToolKit.SaveTextAsync(this, GroupPolicy.Summary(_report), $"gpo-summary-{DateTime.Now:yyyyMMdd-HHmmss}.txt"));
        var html = Ui.Button("Export HTML…", () => ExportNativeAsync(true));
        var xml = Ui.Button("Export XML…", () => ExportNativeAsync(false));
        ToolTip.SetTip(html, "gpresult's own report. It can contain domain, user, group and configuration details.");
        ToolTip.SetTip(xml, "gpresult's own XML report. It can contain domain, user, group and configuration details.");
        _needsReport = [settings, copy, txt];
        foreach (var b in new Control[] { settings, copy, txt, html, xml }) b.IsEnabled = false;
        html.IsEnabled = xml.IsEnabled = service.IsSupported;
        var actions = Ui.Row(settings, copy, txt, html, xml);

        var main = new Grid { RowDefinitions = new RowDefinitions("3*,Auto,2*,Auto") };
        void Put(Control c, int row)
        {
            Grid.SetRow(c, row);
            main.Children.Add(c);
        }

        Put(_grid, 0);
        Put(new TextBlock { Text = "Details", Classes = { Styling.Theme.Classes.Section }, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, Styling.Theme.TightGap) }, 1);
        Put(new ScrollViewer { Content = _details, MinHeight = 60 }, 2);
        Put(new Border { Padding = new Thickness(0, Styling.Theme.TightGap, 0, 0), Child = actions }, 3);
        Content = ToolKit.Layout(inputs, new Control(), main, _status);
        _runner.BusyChanged += (_, _) =>
        {
            refresh.IsEnabled = !_runner.IsBusy;
            cancel.IsEnabled = _runner.IsBusy;
        };
        Opened += async (_, _) => await RefreshAsync();
        Closed += (_, _) => _runner.Dispose();
        _info.Text = "Computer: —\nUser:     —";
        _status.Text = "Ready";
    }

    internal IReadOnlyList<GpoEntry> Rows => _rows;

    internal GpoReport? Report => _report;

    private Task RefreshAsync()
    {
        if (!_service.IsSupported)
        {
            _status.Text = "Windows only.";
            return Task.CompletedTask;
        }

        return _runner.RunAsync("Reading the RSoP report", async ct =>
        {
            var c = await _service.CollectAsync(ct);
            await Avalonia.Threading.Dispatcher.UIThread.InvokeAsync(() => Show(c));
            if (c.Report is null || c.Error.Length > 0) return c.Error.Length > 0 ? c.Error : "Report failed.";
            var partial = c.Report.Scopes.FirstOrDefault(s => !s.Available);
            if (partial is not null) return $"Partial data. {partial.Scope}: {partial.Message}";
            return c.Report.Gpos.Count == 0 ? "No GPOs reported." : "Refresh completed.";
        });
    }

    private void Show(GpoResult c)
    {
        _report = c.Report;
        foreach (var b in _needsReport) b.IsEnabled = _report is not null;
        if (_report is null)
        {
            _rows.Clear();
            _info.Text = "Computer: Unavailable\nUser:     Unavailable";
            _counts.Text = "";
            Styling.Theme.SetState(_status, Styling.Theme.Classes.Error);
            return;
        }

        Styling.Theme.SetState(_status, _report.Scopes.Any(s => !s.Available) ? Styling.Theme.Classes.Warning : null);
        string Line(GpoScope scope)
        {
            var s = _report.Scopes.FirstOrDefault(x => x.Scope == scope);
            if (s is null || !s.Available) return $"{scope,-9} {s?.Message ?? "Unavailable"}";
            var domain = s.Domain.Length > 0 ? s.Domain : "Unavailable";
            return $"{scope,-9} {Or(s.Account)}   Domain: {domain}   Last processing: {GroupPolicy.Time(s.LastProcessing)}{(s.ProcessingError is { } e and not 0 ? $" (error {e})" : "")}";
        }

        _info.Text = $"{Line(GpoScope.Computer)}\n{Line(GpoScope.User)}\nReport refreshed: {GroupPolicy.Time(_report.Collected)}";
        _counts.Text = $"Applied: {_report.Gpos.Count(g => g.State == GpoState.Applied)}     Filtered: {_report.Gpos.Count(g => g.State == GpoState.Filtered)}     Unknown: {_report.Gpos.Count(g => g.State == GpoState.Unknown)}     Settings: {_report.Settings.Count}";
        ApplyFilter();
    }

    private static string Or(string s) => s.Length > 0 ? s : "Unavailable";

    private void ApplyFilter()
    {
        var keep = _grid.SelectedItem as GpoEntry;
        _rows.Clear();
        if (_report is null) return;
        GpoScope? scope = Array.FindIndex(_scopes, r => r.IsChecked == true) switch
        {
            1 => GpoScope.Computer,
            2 => GpoScope.User,
            _ => null,
        };
        foreach (var g in _report.Gpos.Where(g => GroupPolicy.Matches(g, scope, _search.Text ?? ""))) _rows.Add(g);
        _grid.SelectedItem = keep is not null && _rows.Contains(keep) ? keep : _rows.FirstOrDefault();
    }

    private string Details(GpoEntry g)
    {
        var settings = _report?.Settings.Count(s => s.Scope == g.Scope && (s.WinningGpo == g.Name || s.WinningGpo == g.Id)) ?? 0;
        string L(string k, string v) => $"{k,-14}{(v.Length > 0 ? v : "Not reported")}";
        return string.Join('\n',
            L("Name:", g.Name), L("GUID:", g.Id), L("Scope:", g.Scope.ToString()), L("Status:", g.StateText), L("Reason:", g.Reason.Length > 0 ? g.Reason : g.State == GpoState.Applied ? "—" : ""),
            L("Domain:", g.Domain), L("Links:", string.Join("; ", g.Links)), L("Version:", g.Version), L("Extensions:", string.Join(", ", g.Extensions)),
            L("Winning:", $"{settings} setting(s) in this report"),
            "Applied GPOs do not win every setting; see Settings for the winning GPO of each reported setting.");
    }

    private async Task ExportNativeAsync(bool html)
    {
        var ext = html ? "html" : "xml";
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export", SuggestedFileName = $"gpresult-{DateTime.Now:yyyyMMdd-HHmmss}.{ext}", DefaultExtension = ext,
            FileTypeChoices = [new FilePickerFileType(ext.ToUpperInvariant()) { Patterns = ["*." + ext] }],
        });
        if (file?.TryGetLocalPath() is not { } path) return;
        await _runner.RunAsync("Writing the gpresult report", async ct => await _service.ExportNativeAsync(html, path, ct) is { } error ? error : $"Exported to {path}.");
    }
}

/// <summary>Searchable list of the effective settings the RSoP report gives (separate view).</summary>
internal sealed class GpoSettingsWindow : Window
{
    public GpoSettingsWindow(IReadOnlyList<GpoSetting> settings)
    {
        Title = "Effective Policy Settings";
        Width = 900;
        Height = 560;
        MinWidth = Styling.Theme.ToolMinWidth;
        MinHeight = Styling.Theme.ToolMinHeight;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var rows = new ObservableCollection<GpoSetting>(settings);
        var search = ToolKit.Text("Search settings", "name, value, category or GPO", 320);
        var grid = new DataGrid { ItemsSource = rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true };
        AutomationProperties.SetName(grid, "Effective settings");
        void Col(string h, string p, DataGridLength w) => grid.Columns.Add(new DataGridTextColumn { Header = h, Binding = new Binding(p), Width = w, MinWidth = 60 });
        Col("Setting", nameof(GpoSetting.Name), new DataGridLength(2, DataGridLengthUnitType.Star));
        Col("Value", nameof(GpoSetting.Value), new DataGridLength(1, DataGridLengthUnitType.Star));
        Col("Category", nameof(GpoSetting.Category), new DataGridLength(1, DataGridLengthUnitType.Star));
        Col("Winning GPO", nameof(GpoSetting.WinningGpo), new DataGridLength(160));
        Col("Scope", nameof(GpoSetting.Scope), new DataGridLength(80));
        var status = ToolKit.StatusLine();
        void Apply()
        {
            rows.Clear();
            foreach (var s in settings.Where(s => GroupPolicy.Matches(s, search.Text ?? ""))) rows.Add(s);
            status.Text = settings.Count == 0 ? "No settings in the report. Only settings the report lists are shown."
                : $"{rows.Count} of {settings.Count} reported settings. Not every Windows setting is in an RSoP report.";
        }

        search.TextChanged += (_, _) => Apply();
        Apply();
        var close = Ui.Button("Close", () =>
        {
            Close();
            return Task.CompletedTask;
        });
        close.IsCancel = true;
        Content = ToolKit.Layout(search, Ui.Row(close), grid, status);
    }
}
