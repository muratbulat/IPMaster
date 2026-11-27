using System.Collections;
using System.Collections.ObjectModel;
using System.Text;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → WinGet Manager (D-106): installed packages from <c>winget list</c>, updates on request only, one package at a time,
/// each verified by reading the package back. Nothing runs in the background and nothing is updated without a confirmation.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The token source is disposed when the window closes.")]
internal sealed class WinGetManagerWindow : Window
{
    /// <summary>One table row; <see cref="Override"/> holds the state of an update run (Updating, Updated, Failed…).</summary>
    internal sealed record Row(WinGetPackage P, WinGetStatus? Override = null, string Note = "")
    {
        public string Name => P.Name;

        public string Id => P.Id;

        public string Installed => P.InstalledVersion.Length > 0 ? P.InstalledVersion : "Unknown";

        public string Available => P.AvailableVersion.Length > 0 ? P.AvailableVersion : "—";

        public string Source => P.Source.Length > 0 ? P.Source : "—";

        public WinGetStatus State => Override ?? P.Status;

        public string Status => State switch
        {
            WinGetStatus.Current or WinGetStatus.Updated or WinGetStatus.Installed => "✔ ",
            WinGetStatus.Unverified => "? ",
            WinGetStatus.UpdateAvailable => "⬆ ",
            WinGetStatus.Failed => "✖ ",
            WinGetStatus.Updating => "… ",
            WinGetStatus.Pinned => "📌 ",
            _ => "– ",
        } + WinGet.StatusText(State);

        public string Tip => $"{P.Name}\nId: {P.Id}\nSource: {Source}\nInstalled: {Installed}  Available: {Available}" + (Note.Length > 0 ? "\n" + Note : "");
    }

    private sealed class VersionOrder(Func<Row, string> pick) : IComparer
    {
        public int Compare(object? x, object? y) => x is Row a && y is Row b ? WinGet.CompareVersions(pick(a), pick(b)) : 0;
    }

    private static readonly string[] FilterNames = ["All", "Updates", "Up to Date"];
    private readonly IWinGetService _service;
    private readonly List<Row> _all = [];
    private readonly ObservableCollection<Row> _rows = [];
    private readonly DataGrid _grid;
    private readonly TextBox _search = ToolKit.Text("Search packages", "name or id", 300);
    private readonly RadioButton[] _filters;
    private readonly TextBlock _summary = new() { VerticalAlignment = VerticalAlignment.Center };
    private readonly TextBlock _status = ToolKit.StatusLine();
    private readonly TextBlock _current = new() { TextWrapping = TextWrapping.Wrap };
    private readonly ProgressBar _progress = new() { Minimum = 0, Height = 6, IsVisible = false };
    private readonly Border _unavailable;
    private readonly Button _refresh;
    private readonly Button _install;
    private readonly Button _updateSelected;
    private readonly Button _updateAll;
    private readonly Button _cancel;
    private readonly StringBuilder _log = new();
    private CancellationTokenSource? _cts;
    private bool _busy;

    public WinGetManagerWindow(IWinGetService service)
    {
        _service = service;
        Title = "WinGet Manager";
        Width = 960;
        Height = 680;
        MinWidth = 700;
        MinHeight = 460;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        _unavailable = Ui.Banner("", Styling.Theme.Classes.Warning, visible: false);
        _refresh = Ui.Button("Refresh", RefreshAsync);
        ToolTip.SetTip(_refresh, "Reads the installed packages and updates again (winget list).");
        _install = Ui.Button("Install New…", InstallNewAsync);
        ToolTip.SetTip(_install, "Searches the WinGet catalog and installs packages (winget search, winget install).");
        _filters = FilterNames.Select((t, i) => new RadioButton { Content = t, GroupName = "wingetFilter", IsChecked = i == 0 }).ToArray();
        foreach (var f in _filters) f.IsCheckedChanged += (_, _) => ApplyFilter();
        _search.TextChanged += (_, _) => ApplyFilter(); // local filter: no WinGet call per keystroke
        var inputs = new StackPanel
        {
            Spacing = Styling.Theme.SectionGap,
            Children = { _unavailable, _summary, Ui.Row(_search, _refresh, _install), Ui.Row(_filters) },
        };

        _grid = new DataGrid
        {
            ItemsSource = _rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true,
            SelectionMode = DataGridSelectionMode.Extended, MinHeight = 120,
        };
        AutomationProperties.SetName(_grid, "Installed packages");
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Name", Width = new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 180, SortMemberPath = nameof(Row.Name),
            CellTemplate = new FuncDataTemplate<Row>((r, _) =>
            {
                var t = new TextBlock { Text = r?.Name, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0), TextTrimming = TextTrimming.CharacterEllipsis };
                ToolTip.SetTip(t, r?.Tip);
                return t;
            }),
        });
        void Version(string header, string path, Func<Row, string> pick) => _grid.Columns.Add(new DataGridTextColumn
        {
            Header = header, Binding = new Binding(path), Width = new DataGridLength(130), MinWidth = 70, CustomSortComparer = new VersionOrder(pick),
        });
        Version("Installed", nameof(Row.Installed), r => r.P.InstalledVersion);
        Version("Available", nameof(Row.Available), r => r.P.AvailableVersion);
        _grid.Columns.Add(new DataGridTextColumn { Header = "Source", Binding = new Binding(nameof(Row.Source)), Width = new DataGridLength(90), MinWidth = 60 });
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Status", Width = new DataGridLength(160), MinWidth = 100, SortMemberPath = nameof(Row.Status),
            CellTemplate = new FuncDataTemplate<Row>((r, _) =>
            {
                var t = new TextBlock { Text = r?.Status, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0) };
                if (r is not null && WinGet.StateClass(r.State) is { } c) Styling.Theme.SetState(t, c);
                if (r?.Note.Length > 0) ToolTip.SetTip(t, r.Note);
                return t;
            }),
        });
        _grid.SelectionChanged += (_, _) => UpdateButtons();

        _updateSelected = Ui.Button("Update Selected…", () => UpdateAsync(selectedOnly: true));
        ToolTip.SetTip(_updateSelected, "Updates the selected packages that have a confirmed update, one at a time.");
        _updateAll = Ui.Button("Update All…", () => UpdateAsync(selectedOnly: false), accent: true);
        ToolTip.SetTip(_updateAll, "Updates every package with a confirmed update. Pinned and unknown versions are excluded.");
        _cancel = Ui.Button("Cancel", () =>
        {
            CancelQueue();
            _status.Text = "Cancelling: queued updates will not start. A running installer finishes first.";
            return Task.CompletedTask;
        });
        var log = Ui.Button("Log…", ShowLogAsync);
        var actions = Ui.Row(_updateSelected, _updateAll, _cancel, log);
        var main = new DockPanel();
        var progress = new StackPanel { Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0), Children = { _current, _progress, actions } };
        DockPanel.SetDock(progress, Dock.Bottom);
        main.Children.Add(progress);
        main.Children.Add(_grid);
        Content = ToolKit.Layout(inputs, new Control(), main, _status);
        UpdateButtons();
        Opened += async (_, _) => await RefreshAsync();
        Closed += (_, _) => _cts?.Cancel();
    }

    internal IReadOnlyList<Row> Rows => _rows;

    internal void CancelQueue() => _cts?.Cancel();

    internal IReadOnlyList<Row> AllRows => _all;

    internal string LogText => _log.ToString();

    // ---------------- inventory ----------------
    private async Task RefreshAsync()
    {
        if (_busy) return;
        SetBusy(true);
        try
        {
            if (!_service.IsSupported)
            {
                ShowUnavailable("Windows only. WinGet Manager is unavailable on this system.");
                _status.Text = "Windows only.";
                return;
            }

            _status.Text = "Checking WinGet…";
            var info = await _service.DetectAsync(CancellationToken.None);
            if (!info.Available)
            {
                ShowUnavailable($"WinGet is unavailable. {info.Message} See {WinGet.MicrosoftLink}");
                _status.Text = "WinGet is unavailable.";
                return;
            }

            _unavailable.IsVisible = false;
            _status.Text = "Reading installed packages…";
            var inv = await _service.ListAsync(CancellationToken.None);
            _all.Clear();
            _all.AddRange(inv.Packages.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase).Select(p => new Row(p)));
            ApplyFilter();
            _status.Text = inv.Error.Length > 0 && inv.Packages.Count == 0 ? inv.Error
                : $"Ready. WinGet {info.Version}.{(inv.Error.Length > 0 ? " " + inv.Error : "")}";
            Log($"Inventory: {inv.Packages.Count} package(s). {inv.Error}");
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ShowUnavailable(string text)
    {
        _unavailable.Child = new SelectableTextBlock { Text = text, TextWrapping = TextWrapping.Wrap };
        _unavailable.IsVisible = true;
    }

    private void ApplyFilter()
    {
        var filter = (WinGet.Filter)Math.Max(0, Array.FindIndex(_filters, f => f.IsChecked == true));
        var keep = _grid.SelectedItems.OfType<Row>().Select(r => r.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        _rows.Clear();
        foreach (var r in _all.Where(r => Visible(r, filter, _search.Text ?? ""))) _rows.Add(r);
        foreach (var r in _rows.Where(r => keep.Contains(r.Id))) _grid.SelectedItems.Add(r);
        var updates = _all.Count(r => r.State == WinGetStatus.UpdateAvailable);
        var current = _all.Count(r => r.State is WinGetStatus.Current or WinGetStatus.Updated);
        _summary.Text = $"Installed: {_all.Count}     Updates: {updates}     Up to Date: {current}     Other: {_all.Count - updates - current}";
        UpdateButtons();
    }

    /// <summary>Filter by the row's current state; rows of an update run stay under Updates until the next refresh.</summary>
    internal static bool Visible(Row r, WinGet.Filter filter, string search)
    {
        var ok = filter switch
        {
            WinGet.Filter.Updates => r.State is WinGetStatus.UpdateAvailable or WinGetStatus.Updating or WinGetStatus.Failed or WinGetStatus.Unverified || r.Override == WinGetStatus.Updated,
            WinGet.Filter.UpToDate => r.State is WinGetStatus.Current or WinGetStatus.Updated,
            _ => true,
        };
        return ok && WinGet.Matches(r.P, WinGet.Filter.All, search);
    }

    private void UpdateButtons()
    {
        _refresh.IsEnabled = !_busy;
        _install.IsEnabled = !_busy;
        _updateSelected.IsEnabled = !_busy && _grid.SelectedItems.OfType<Row>().Any(r => r.State == WinGetStatus.UpdateAvailable && WinGet.IsEligible(r.P));
        _updateAll.IsEnabled = !_busy && _all.Any(r => r.State == WinGetStatus.UpdateAvailable && WinGet.IsEligible(r.P));
        _cancel.IsEnabled = _busy && _cts is not null;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        UpdateButtons();
    }

    // ---------------- updates ----------------
    private async Task UpdateAsync(bool selectedOnly)
    {
        if (_busy) return;
        var candidates = selectedOnly ? _grid.SelectedItems.OfType<Row>().ToList() : _all.ToList();
        var targets = candidates.Where(r => r.State == WinGetStatus.UpdateAvailable && WinGet.IsEligible(r.P)).ToList();
        var excluded = candidates.Except(targets).Where(r => r.State is WinGetStatus.Pinned or WinGetStatus.Unknown || (selectedOnly && r.State != WinGetStatus.UpdateAvailable)).ToList();
        if (targets.Count == 0) return;
        if (await ConfirmAsync(targets, excluded) is not { } accept)
        {
            _status.Text = "Update cancelled. Nothing was changed.";
            return;
        }

        await RunUpdatesAsync(targets, accept);
    }

    /// <summary>The confirmed queue: one package at a time; a cancel stops before the next package, never inside an installer.</summary>
    internal async Task RunUpdatesAsync(IReadOnlyList<Row> targets, bool accept)
    {
        if (_service.InstallerRunning)
        {
            _status.Text = WinGet.StillRunning;
            return;
        }

        var stillRunning = false;
        _cts = new CancellationTokenSource();
        SetBusy(true);
        _progress.IsVisible = true;
        _progress.Maximum = targets.Count;
        _progress.Value = 0;
        var results = new List<WinGetUpdateResult>();
        try
        {
            for (var i = 0; i < targets.Count; i++)
            {
                if (_cts.IsCancellationRequested) break;
                var row = targets[i];
                Replace(row, row with { Override = WinGetStatus.Updating, Note = "" });
                _current.Text = $"Updating {i + 1} of {targets.Count}: {row.Name} {row.Installed} → {row.Available}";
                _status.Text = "Starting the update…";
                Log($"--- {row.Id} ({row.Source}) {row.Installed} → {row.Available}");
                int? code;
                WinGetPackage? after = null;
                try
                {
                    code = await Task.Run(() => _service.UpgradeAsync(row.P, accept, line => Dispatcher.UIThread.Post(() =>
                    {
                        _status.Text = line;
                        Log(line);
                    }), _cts.Token));
                }
                catch (OperationCanceledException)
                {
                    Replace(Current(row), row);
                    break;
                }
                catch (InvalidOperationException ex)
                {
                    code = -1;
                    Log(ex.Message);
                }

                WinGetUpdateResult result;
                if (code is null)
                {
                    result = new(row.Id, row.Name, row.Installed, null, WinGetStatus.Unverified, 0, "Still running after 60 minutes. Refresh later to check.", false);
                }
                else
                {
                    _status.Text = "Verifying…";
                    after = await Task.Run(() => _service.ReadBackAsync(row.P, CancellationToken.None));
                    result = WinGet.Verify(row.P, code.Value, after);
                }

                results.Add(result);
                var msg = result.Status == WinGetStatus.Updated ? $"{result.FromVersion} → {result.ToVersion}. {result.Message}" : result.Message;
                // the Installed column shows what WinGet reads back; pins cannot change during an update of an unpinned package
                Replace(Current(row), row with { P = after is null ? row.P : after with { IsPinned = row.P.IsPinned }, Override = result.Status, Note = msg });
                Log($"{row.Id}: {msg} (exit {WinGet.Hex(result.ExitCode)})");
                _progress.Value = i + 1;
                if (code is null)
                {
                    stillRunning = true; // the next installer would run beside this one
                    break;
                }
            }
        }
        finally
        {
            var skipped = targets.Count - results.Count;
            var ok = results.Count(r => r.Status == WinGetStatus.Updated);
            var failed = results.Count(r => r.Status == WinGetStatus.Failed);
            var unverified = results.Count - ok - failed;
            var why = stillRunning ? "an installer is still running" : "cancelled";
            _current.Text = $"Done: {ok} updated, {failed} failed, {unverified} not verified{(skipped > 0 ? $", {skipped} not started ({why})" : "")}." + (results.Any(r => r.RestartRequired) ? " Restart required." : "");
            _status.Text = stillRunning ? WinGet.StillRunning : failed > 0 ? "Some updates failed. See the Status column or the log." : skipped > 0 ? "Update cancelled." : "Updates finished.";
            Styling.Theme.SetState(_current, failed > 0 ? Styling.Theme.Classes.Error : skipped > 0 || unverified > 0 ? Styling.Theme.Classes.Warning : Styling.Theme.Classes.Success);
            _progress.IsVisible = false;
            _cts?.Dispose();
            _cts = null;
            SetBusy(false);
            ApplyFilter();
        }
    }

    private Row Current(Row original) => _all.First(r => string.Equals(r.Id, original.Id, StringComparison.OrdinalIgnoreCase) && r.Source == original.Source);

    private void Replace(Row old, Row now)
    {
        var i = _all.IndexOf(old);
        if (i >= 0) _all[i] = now;
        var j = _rows.IndexOf(old);
        if (j >= 0) _rows[j] = now;
    }

    private async Task InstallNewAsync()
    {
        if (_busy) return;
        var installed = _all.GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Installed, StringComparer.OrdinalIgnoreCase);
        var w = new WinGetInstallWindow(_service, installed, Log);
        await w.ShowDialog(this);
        if (w.InstalledAny) await RefreshAsync();
    }

    internal void Log(string line)
    {
        if (_log.Length > 2_000_000) _log.Remove(0, 500_000); // bounded
        _log.Append(DateTime.Now.ToString("HH:mm:ss ", System.Globalization.CultureInfo.InvariantCulture)).AppendLine(line);
    }

    private Task<bool?> ConfirmAsync(IReadOnlyList<Row> targets, IReadOnlyList<Row> excluded) => ConfirmAsync(
        this, "Update Packages", $"Update {targets.Count} package(s)?", targets.Select(r => $"{r.Name}  {r.Installed} → {r.Available}").ToList(),
        excluded.Count > 0 ? $"Excluded: {excluded.Count} (pinned, unknown version or no confirmed update)." : null, "Update");

    /// <summary>Returns whether to accept package/source agreements, or null when cancelled.</summary>
    internal static async Task<bool?> ConfirmAsync(Window owner, string title, string question, IReadOnlyList<string> lines, string? excludedText, string okText)
    {
        var d = Ui.Window(title, 560, 420);
        d.Height = double.NaN;
        d.MinHeight = 0;
        d.SizeToContent = SizeToContent.Height;
        var names = string.Join("\n", lines.Take(15)) + (lines.Count > 15 ? $"\n… and {lines.Count - 15} more" : "");
        var panel = new StackPanel { Spacing = Styling.Theme.SectionGap };
        panel.Children.Add(new TextBlock { Text = question, Classes = { Styling.Theme.Classes.Section } });
        panel.Children.Add(new ScrollViewer { Content = new SelectableTextBlock { Text = names, Classes = { Styling.Theme.Classes.Mono } }, MaxHeight = 220 });
        if (excludedText is not null) panel.Children.Add(new TextBlock { Text = excludedText, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(Ui.Banner("Applications may close or restart. Some installers ask for administrator approval or other input. Packages are processed one at a time.", Styling.Theme.Classes.Warning));
        var accept = new CheckBox { Content = "Accept the package and source agreements of these packages" };
        ToolTip.SetTip(accept, "Off: a package that needs an agreement fails with \"agreement not accepted\".");
        panel.Children.Add(accept);
        bool? result = null;
        var ok = Ui.Button(okText, () =>
        {
            result = accept.IsChecked == true;
            d.Close();
            return Task.CompletedTask;
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            d.Close();
            return Task.CompletedTask;
        });
        cancel.IsCancel = true;
        panel.Children.Add(Ui.Row(cancel, ok));
        d.Content = new ScrollViewer { Content = panel, Padding = Styling.Theme.Page };
        d.Opened += (_, _) => cancel.Focus();
        await d.ShowDialog(owner);
        return result;
    }

    private async Task ShowLogAsync()
    {
        var d = ToolKit.NewToolWindow("WinGet Log", 760, 480);
        var box = ToolKit.ReportBox("WinGet log");
        box.Text = _log.ToString();
        var close = Ui.Button("Close", () =>
        {
            d.Close();
            return Task.CompletedTask;
        });
        close.IsCancel = true;
        var status = ToolKit.StatusLine();
        d.Content = ToolKit.Layout(new Control(), Ui.Row(ToolKit.CopyButton(d, () => box.Text ?? ""), close), box, status);
        await d.ShowDialog(this);
    }
}
