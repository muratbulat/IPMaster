using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>
/// WinGet Manager → Install New (D-109): <c>winget search</c> on request, installs of the selected hits after a confirmation,
/// one at a time, each verified by reading the package back. Already installed packages are shown but not reinstalled.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The token source is disposed when the queue ends.")]
internal sealed class WinGetInstallWindow : Window
{
    internal sealed record Hit(WinGetSearchHit H, string InstalledVersion, WinGetStatus? State = null, string Note = "")
    {
        public string Name => H.Name;

        public string Id => H.Id;

        public string Version => H.Version.Length > 0 ? H.Version : "Unknown";

        public string Source => H.Source.Length > 0 ? H.Source : "—";

        public string Match => H.Match;

        public string Installed => InstalledVersion.Length > 0 ? InstalledVersion : "—";

        public bool CanInstall => InstalledVersion.Length == 0 && State is null or WinGetStatus.Failed && WinGet.IsInstallable(H);

        public WinGetStatus? Shown => State ?? (InstalledVersion.Length > 0 ? WinGetStatus.Installed : null);

        public string Status => Shown is { } s ? WinGet.StatusText(s) : H.Source.Length == 0 ? "No source" : "";
    }

    private readonly IWinGetService _service;
    private readonly IReadOnlyDictionary<string, string> _installed;
    private readonly Action<string> _log;
    private readonly ObservableCollection<Hit> _rows = [];
    private readonly DataGrid _grid;
    private readonly TextBox _query = ToolKit.Text("Search the WinGet catalog", "name, id, moniker or tag", 300);
    private readonly Button _searchButton;
    private readonly Button _installButton;
    private readonly Button _cancel;
    private readonly TextBlock _current = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _status = ToolKit.StatusLine();
    private CancellationTokenSource? _cts;
    private bool _busy;

    public WinGetInstallWindow(IWinGetService service, IReadOnlyDictionary<string, string> installed, Action<string> log)
    {
        _service = service;
        _installed = installed;
        _log = log;
        Title = "Install Packages";
        Width = 900;
        Height = 600;
        MinWidth = 640;
        MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        _searchButton = Ui.Button("Search", SearchAsync, accent: true);
        _query.KeyDown += async (_, e) =>
        {
            if (e.Key != Key.Enter) return;
            e.Handled = true;
            await SearchAsync();
        };

        _grid = new DataGrid
        {
            ItemsSource = _rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true,
            SelectionMode = DataGridSelectionMode.Extended, MinHeight = 120,
        };
        AutomationProperties.SetName(_grid, "Search results");
        void Col(string header, string path, double width) => _grid.Columns.Add(new DataGridTextColumn
        {
            Header = header, Binding = new Binding(path), Width = width > 0 ? new DataGridLength(width) : new DataGridLength(1, DataGridLengthUnitType.Star), MinWidth = 60,
        });
        Col("Name", nameof(Hit.Name), 0);
        Col("Id", nameof(Hit.Id), 200);
        Col("Version", nameof(Hit.Version), 110);
        Col("Source", nameof(Hit.Source), 80);
        Col("Installed", nameof(Hit.Installed), 100);
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Status", Width = new DataGridLength(130), MinWidth = 90, SortMemberPath = nameof(Hit.Status),
            CellTemplate = new FuncDataTemplate<Hit>((r, _) =>
            {
                var t = new TextBlock { Text = r?.Status, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0) };
                if (r?.Shown is { } s && WinGet.StateClass(s) is { } c) Styling.Theme.SetState(t, c);
                ToolTip.SetTip(t, r is null ? null : r.Note.Length > 0 ? r.Note : r.Match.Length > 0 ? "Match: " + r.Match : null);
                return t;
            }),
        });
        _grid.SelectionChanged += (_, _) => UpdateButtons();

        _installButton = Ui.Button("Install Selected…", InstallAsync, accent: true);
        ToolTip.SetTip(_installButton, "Installs the selected packages that are not installed yet, one at a time.");
        _cancel = Ui.Button("Cancel", () =>
        {
            _cts?.Cancel();
            _status.Text = "Cancelling: queued installs will not start. A running installer finishes first.";
            return Task.CompletedTask;
        });
        var close = Ui.Button("Close", () =>
        {
            Close();
            return Task.CompletedTask;
        });
        var main = new DockPanel();
        var bottom = new StackPanel { Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0), Children = { _current, Ui.Row(_installButton, _cancel, close) } };
        DockPanel.SetDock(bottom, Dock.Bottom);
        main.Children.Add(bottom);
        main.Children.Add(_grid);
        Content = ToolKit.Layout(Ui.Row(_query, _searchButton), new Control(), main, _status);
        _status.Text = "Search by name, id, moniker or tag.";
        UpdateButtons();
        Opened += (_, _) => _query.Focus();
        Closing += (_, e) => e.Cancel = _busy && _cts is not null; // an installer is running: the queue must report its result
    }

    /// <summary>True once any package was installed, so the owner refreshes its inventory.</summary>
    public bool InstalledAny { get; private set; }

    internal IReadOnlyList<Hit> Rows => _rows;

    internal async Task SearchAsync()
    {
        if (_busy) return;
        var q = _query.Text ?? "";
        SetBusy(true);
        try
        {
            _status.Text = "Searching…";
            var r = await Task.Run(() => _service.SearchAsync(q, CancellationToken.None));
            _rows.Clear();
            foreach (var h in r.Hits) _rows.Add(new Hit(h, _installed.GetValueOrDefault(h.Id, "")));
            _status.Text = r.Error.Length > 0 ? r.Error
                : $"{r.Hits.Count} package(s){(r.Hits.Count >= WinGet.SearchLimit ? $" (first {WinGet.SearchLimit}; refine the search)" : "")}.";
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task InstallAsync()
    {
        if (_busy) return;
        var targets = _grid.SelectedItems.OfType<Hit>().Where(h => h.CanInstall).ToList();
        if (targets.Count == 0) return;
        var skipped = _grid.SelectedItems.Count - targets.Count;
        if (await WinGetManagerWindow.ConfirmAsync(this, "Install Packages", $"Install {targets.Count} package(s)?", targets.Select(h => $"{h.Name}  {h.Version}  ({h.Id}, {h.Source})").ToList(),
                skipped > 0 ? $"Excluded: {skipped} (already installed or no source)." : null, "Install") is not { } accept)
        {
            _status.Text = "Install cancelled. Nothing was changed.";
            return;
        }

        await RunInstallsAsync(targets, accept);
    }

    /// <summary>The confirmed queue: one package at a time; a cancel stops before the next package, never inside an installer.</summary>
    internal async Task RunInstallsAsync(IReadOnlyList<Hit> targets, bool accept)
    {
        _cts = new CancellationTokenSource();
        SetBusy(true);
        var results = new List<WinGetUpdateResult>();
        try
        {
            for (var i = 0; i < targets.Count; i++)
            {
                if (_cts.IsCancellationRequested) break;
                var row = targets[i];
                Replace(row, row with { State = WinGetStatus.Updating, Note = "" });
                _current.Text = $"Installing {i + 1} of {targets.Count}: {row.Name} {row.Version}";
                _log($"--- install {row.Id} ({row.Source}) {row.Version}");
                int? code;
                try
                {
                    code = await Task.Run(() => _service.InstallAsync(row.H, accept, line => Dispatcher.UIThread.Post(() =>
                    {
                        _status.Text = line;
                        _log(line);
                    }), _cts.Token));
                }
                catch (OperationCanceledException)
                {
                    Replace(Find(row), row);
                    break;
                }
                catch (InvalidOperationException ex)
                {
                    code = -1;
                    _log(ex.Message);
                }

                WinGetUpdateResult result;
                if (code is null)
                {
                    result = new(row.Id, row.Name, "", null, WinGetStatus.Unverified, 0, "Still running after 60 minutes. Refresh later to check.", false);
                }
                else
                {
                    _status.Text = "Verifying…";
                    var after = await Task.Run(() => _service.ReadBackAsync(new WinGetPackage { Id = row.Id, Name = row.Name, Source = row.H.Source }, CancellationToken.None));
                    result = WinGet.VerifyInstall(row.H, code.Value, after);
                }

                results.Add(result);
                InstalledAny |= result.Status is WinGetStatus.Installed or WinGetStatus.Unverified;
                Replace(Find(row), row with { State = result.Status, Note = result.Message, InstalledVersion = result.Status == WinGetStatus.Installed ? result.ToVersion ?? "" : "" });
                _log($"{row.Id}: {result.Message} (exit {WinGet.Hex(result.ExitCode)})");
            }
        }
        finally
        {
            var notStarted = targets.Count - results.Count;
            var ok = results.Count(r => r.Status == WinGetStatus.Installed);
            var failed = results.Count(r => r.Status == WinGetStatus.Failed);
            var unverified = results.Count - ok - failed;
            _current.Text = $"Done: {ok} installed, {failed} failed, {unverified} not verified{(notStarted > 0 ? $", {notStarted} not started (cancelled)" : "")}." + (results.Any(r => r.RestartRequired) ? " Restart required." : "");
            _status.Text = failed > 0 ? "Some installs failed. Hover the Status column or see the log." : notStarted > 0 ? "Install cancelled." : "Installs finished.";
            Styling.Theme.SetState(_current, failed > 0 ? Styling.Theme.Classes.Error : notStarted > 0 || unverified > 0 ? Styling.Theme.Classes.Warning : Styling.Theme.Classes.Success);
            _cts.Dispose();
            _cts = null;
            SetBusy(false);
        }
    }

    private Hit Find(Hit original) => _rows.First(r => string.Equals(r.Id, original.Id, StringComparison.OrdinalIgnoreCase) && r.H.Source == original.H.Source);

    private void Replace(Hit old, Hit now)
    {
        var i = _rows.IndexOf(old);
        if (i >= 0) _rows[i] = now;
    }

    private void UpdateButtons()
    {
        _searchButton.IsEnabled = !_busy;
        _query.IsEnabled = !_busy;
        _installButton.IsEnabled = !_busy && _grid.SelectedItems.OfType<Hit>().Any(h => h.CanInstall);
        _cancel.IsEnabled = _busy && _cts is not null;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        UpdateButtons();
    }
}
