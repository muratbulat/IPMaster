using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → KMS Activation Manager (D-104). Opening reads the local licence state only. Keys and hosts change only through
/// <see cref="IKmsService.ApplyAsync"/> after a confirmation; the result is verified by reading the licence again.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The runner is disposed when the window closes.")]
internal sealed class KmsManagerWindow : Window
{
    /// <summary>One table row. <see cref="StateClass"/> colours the status text; the text itself always carries the meaning.</summary>
    internal sealed record Row(KmsProduct P)
    {
        public string Name => P.Name;

        public string Version => P.Version.Length > 0 ? P.Version : "Unknown";

        public string Channel => Kms.ChannelText(P.Channel);

        public string Status => P.State switch
        {
            ActivationState.Licensed => "✔ Licensed",
            ActivationState.Grace => "⚠ Grace",
            ActivationState.Notification => "⚠ Notification",
            ActivationState.Unlicensed => "✖ Unlicensed",
            _ => "? Unknown",
        };

        public string? StateClass => P.State switch
        {
            ActivationState.Licensed => Styling.Theme.Classes.Success,
            ActivationState.Grace or ActivationState.Notification => Styling.Theme.Classes.Warning,
            ActivationState.Unlicensed => Styling.Theme.Classes.Error,
            _ => null,
        };

        public string Expires => Kms.ExpiresText(P);

        public string KmsKey => P.Key is not null ? "Available" : "No match";
    }

    private readonly MainWindowViewModel _vm;
    private readonly IKmsService _service;
    private readonly ObservableCollection<Row> _rows = [];
    private readonly ObservableCollection<string> _profiles = [];
    private readonly ComboBox _profile;
    private readonly TextBox _server;
    private readonly NumericUpDown _port;
    private readonly TextBox _description;
    private readonly DataGrid _grid;
    private readonly SelectableTextBlock _details = new() { TextWrapping = TextWrapping.NoWrap, Classes = { Styling.Theme.Classes.Mono } };
    private readonly TextBlock _plan = new() { TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _error = new() { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
    private readonly TextBlock _status = ToolKit.StatusLine();
    private readonly ToolRunner _runner;
    private readonly Button _install;
    private readonly Button _activate;
    private Kms.ReportAttempt? _attempt;

    public KmsManagerWindow(MainWindowViewModel vm, IKmsService service)
    {
        _vm = vm;
        _service = service;
        Title = "KMS Activation Manager";
        Width = 980;
        Height = 720;
        MinWidth = 800; // the profile buttons stay on one line
        MinHeight = 560; // profile, server, table and details all stay usable
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _runner = new ToolRunner(_status);

        // ---- profile and server ----
        _profile = new ComboBox { ItemsSource = _profiles, Width = 240, PlaceholderText = "(no profile)" };
        AutomationProperties.SetName(_profile, "KMS profile");
        _server = ToolKit.Text("KMS server", "kms.example.com or 192.0.2.10", 280);
        _port = ToolKit.Number(Kms.DefaultPort, 1, 65535, "Port", 110);
        _description = ToolKit.Text("Profile description", "optional");
        var f = new Form();
        f.Add("Profile", Ui.Row(_profile, Ui.Button("New", NewProfile), Ui.Button("Load", LoadProfile), Ui.Button("Save", SaveAsync),
            Ui.Button("Save As…", SaveAsAsync), Ui.Button("Rename…", RenameAsync), Ui.Button("Delete", DeleteAsync)));
        f.Add("KMS Server", Ui.Row(_server, new TextBlock { Text = "Port", VerticalAlignment = VerticalAlignment.Center }, _port));
        f.Add("Description", _description);
        f.Full(_error);
        RefreshProfiles();

        var test = Ui.Button("Test Connection", TestAsync);
        ToolTip.SetTip(test, "DNS and TCP only. A connection does not prove a working KMS host.");
        var discover = Ui.Button("Discover DNS", DiscoverAsync);
        ToolTip.SetTip(discover, "Looks up _vlmcs._tcp SRV records. Changes nothing.");
        var refresh = Ui.Button("Refresh", () => DetectAsync(null));
        var catalog = Ui.Button("Key Catalog…", () => new KmsCatalogWindow().ShowDialog(this));
        ToolTip.SetTip(catalog, "Official Microsoft KMS client setup keys (offline copy).");
        var cancel = Ui.Button("Cancel", () =>
        {
            _runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        var busyButtons = new[] { test, discover, refresh };
        var actions = Ui.Row(test, discover, refresh, catalog, cancel);

        // ---- products ----
        _grid = new DataGrid
        {
            ItemsSource = _rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true, SelectionMode = DataGridSelectionMode.Single,
            MinHeight = 120, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto,
        };
        AutomationProperties.SetName(_grid, "Installed products");
        void Col(string header, string path, DataGridLength width) => _grid.Columns.Add(new DataGridTextColumn { Header = header, Binding = new Binding(path), Width = width, MinWidth = 60 });
        Col("Product", nameof(Row.Name), new DataGridLength(1, DataGridLengthUnitType.Star));
        _grid.Columns[0].MinWidth = 200;
        Col("Version", nameof(Row.Version), new DataGridLength(90));
        Col("Channel", nameof(Row.Channel), new DataGridLength(110));
        _grid.Columns.Add(new DataGridTemplateColumn
        {
            Header = "Status", Width = new DataGridLength(120), SortMemberPath = nameof(Row.Status),
            CellTemplate = new FuncDataTemplate<Row>((r, _) =>
            {
                var t = new TextBlock { Text = r?.Status, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0) };
                if (r?.StateClass is { } c) Styling.Theme.SetState(t, c);
                return t;
            }),
        });
        Col("Expires", nameof(Row.Expires), new DataGridLength(150));
        Col("KMS Key", nameof(Row.KmsKey), new DataGridLength(90));
        _grid.SelectionChanged += (_, _) => ShowSelected();

        _install = Ui.Button("Install KMS Key…", () => ApplyAsync(KmsAction.InstallKey));
        ToolTip.SetTip(_install, "Installs the matching official KMS client key after a confirmation.");
        _activate = Ui.Button("Activate…", () => ApplyAsync(KmsAction.Activate), accent: true);
        ToolTip.SetTip(_activate, "Sets the KMS server (when entered) for this product only and activates it.");
        _install.IsEnabled = _activate.IsEnabled = false;
        var report = Ui.Row(_install, _activate,
            ToolKit.CopyButton(this, () => Report(false), "Copy Report"),
            Ui.Button("Export TXT…", () => ToolKit.SaveTextAsync(this, Report(false), $"kms-report-{DateTime.Now:yyyyMMdd-HHmmss}.txt")),
            Ui.Button("Export JSON…", () => ToolKit.SaveTextAsync(this, Report(true), $"kms-report-{DateTime.Now:yyyyMMdd-HHmmss}.json")));
        // table and details share the height; the plan and the buttons below them never scroll away
        var main = new Grid { RowDefinitions = new RowDefinitions("3*,Auto,2*,Auto") };
        void Put(Control c, int row)
        {
            Grid.SetRow(c, row);
            main.Children.Add(c);
        }

        _grid.MinHeight = 90;
        Put(_grid, 0);
        Put(new TextBlock { Text = "Selected Product", Classes = { Styling.Theme.Classes.Section }, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, Styling.Theme.TightGap) }, 1);
        Put(new ScrollViewer { Content = _details, MinHeight = 60, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Auto }, 2);
        Put(new StackPanel { Spacing = Styling.Theme.TightGap, Margin = new Thickness(0, Styling.Theme.TightGap, 0, 0), Children = { _plan, report } }, 3);

        Control inputs = f.Grid;
        if (!service.IsSupported) inputs = new StackPanel { Spacing = Styling.Theme.SectionGap, Children = { Ui.Banner("Windows only. Product detection and activation are unavailable on this system.", Styling.Theme.Classes.Warning), f.Grid } };
        Content = ToolKit.Layout(inputs, actions, main, _status);

        _runner.BusyChanged += (_, _) =>
        {
            foreach (var b in busyButtons) b.IsEnabled = !_runner.IsBusy;
            cancel.IsEnabled = _runner.IsBusy;
            UpdateButtons();
        };
        Closed += (_, _) => _runner.Dispose();
        Opened += async (_, _) => await DetectAsync(null);
        _status.Text = "Ready";
    }

    internal IReadOnlyList<Row> Rows => _rows;

    private KmsProduct? Selected => (_grid.SelectedItem as Row)?.P;

    // ---------------- detection ----------------
    private Task DetectAsync(Func<IReadOnlyList<KmsProduct>, string>? after) => _runner.RunAsync("Detecting products", async ct =>
    {
        var r = await _service.DetectAsync(ct);
        var text = r.Error.Length > 0 ? r.Error : "";
        await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var keep = Selected;
            _rows.Clear();
            foreach (var p in r.Products) _rows.Add(new Row(p));
            _grid.SelectedItem = _rows.FirstOrDefault(x => keep is not null && x.P.Family == keep.Family && x.P.Edition == keep.Edition) ?? _rows.FirstOrDefault();
            if (after is not null) text = after(r.Products);
            ShowSelected();
        });
        if (text.Length > 0) return text;
        var office = r.Products.Count(p => p.Family is not (KmsFamily.Windows or KmsFamily.WindowsServer));
        return $"Ready. {r.Products.Count} product(s){(office == 0 && _service.IsSupported ? "; no Office installation found" : "")}.";
    });

    private void ShowSelected()
    {
        if (Selected is not { } p)
        {
            _details.Text = "";
            _plan.Text = "";
        }
        else
        {
            _details.Text = Kms.Report(Environment.MachineName, DateTimeOffset.Now, p, _attempt);
            var plan = Kms.Plan(p);
            _plan.Text = plan.Reason;
            if (plan.Action == KmsAction.None) Styling.Theme.SetState(_plan, Styling.Theme.Classes.Warning);
            else Styling.Theme.SetState(_plan, null);
        }

        UpdateButtons();
    }

    private void UpdateButtons()
    {
        var action = Selected is { } p && _service.IsSupported ? Kms.Plan(p).Action : KmsAction.None;
        _install.IsEnabled = !_runner.IsBusy && action == KmsAction.InstallKey;
        _activate.IsEnabled = !_runner.IsBusy && action == KmsAction.Activate;
    }

    private string Report(bool json)
    {
        if (Selected is not { } p) return "";
        return json ? Kms.ReportJson(Environment.MachineName, DateTimeOffset.Now, p, _attempt) : Kms.Report(Environment.MachineName, DateTimeOffset.Now, p, _attempt);
    }

    // ---------------- profiles ----------------
    private IReadOnlyList<KmsProfile> Profiles => _vm.Settings.Tools.KmsProfiles;

    private void RefreshProfiles(string? select = null)
    {
        var keep = select ?? _profile.SelectedItem as string;
        _profiles.Clear();
        foreach (var p in Profiles.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)) _profiles.Add(p.Name);
        _profile.SelectedItem = keep is not null && _profiles.Contains(keep) ? keep : null;
    }

    private Task NewProfile()
    {
        _profile.SelectedItem = null;
        _server.Text = "";
        _port.Value = Kms.DefaultPort;
        _description.Text = "";
        _status.Text = "New profile. Enter the server, then Save.";
        return Task.CompletedTask;
    }

    /// <summary>Loading only fills the fields: nothing on this computer changes until Install or Activate.</summary>
    private Task LoadProfile()
    {
        if (_profile.SelectedItem is not string name || Profiles.FirstOrDefault(p => p.Name == name) is not { } p) return Task.CompletedTask;
        _server.Text = p.Server;
        _port.Value = p.Port;
        _description.Text = p.Description;
        _status.Text = $"Profile '{name}' loaded. System settings are unchanged.";
        return Task.CompletedTask;
    }

    private async Task SaveAsync()
    {
        var name = _profile.SelectedItem as string ?? await Dialogs.PromptAsync(this, "Save Profile", "Profile name:", (_server.Text ?? "").Trim());
        await SaveAsAsync(name);
    }

    private async Task SaveAsAsync() => await SaveAsAsync(await Dialogs.PromptAsync(this, "Save Profile As", "Profile name:", _profile.SelectedItem as string ?? (_server.Text ?? "").Trim()));

    private async Task SaveAsAsync(string? name)
    {
        name = name?.Trim();
        if (string.IsNullOrEmpty(name)) return;
        if (Kms.ValidateServer(_server.Text ?? "", _port.Value, false) is { } e)
        {
            _error.Text = e;
            return;
        }

        _error.Text = "";
        var p = new KmsProfile { Name = name, Server = (_server.Text ?? "").Trim(), Port = (int)(_port.Value ?? Kms.DefaultPort), Description = (_description.Text ?? "").Trim() };
        await _vm.UpdateSettingsAsync(s => s with { Tools = s.Tools with { KmsProfiles = Kms.Upsert(s.Tools.KmsProfiles, p) } });
        RefreshProfiles(name);
        _status.Text = $"Profile '{name}' saved.";
    }

    private async Task RenameAsync()
    {
        if (_profile.SelectedItem is not string old || await Dialogs.PromptAsync(this, "Rename Profile", "New name:", old) is not { } name) return;
        if (Kms.Rename(Profiles, old, name, out var error) is not { } list)
        {
            await Dialogs.MessageAsync(this, "Rename Profile", error!, false);
            return;
        }

        await _vm.UpdateSettingsAsync(s => s with { Tools = s.Tools with { KmsProfiles = list } });
        RefreshProfiles(name.Trim());
    }

    private async Task DeleteAsync()
    {
        if (_profile.SelectedItem is not string n || !await Dialogs.MessageAsync(this, "Delete Profile", $"Delete the profile '{n}'?", true)) return;
        await _vm.UpdateSettingsAsync(s => s with { Tools = s.Tools with { KmsProfiles = Kms.Delete(s.Tools.KmsProfiles, n) } });
        RefreshProfiles();
        _status.Text = $"Profile '{n}' deleted.";
    }

    // ---------------- network ----------------
    private Task TestAsync()
    {
        var host = (_server.Text ?? "").Trim();
        if (Kms.ValidateServer(host, _port.Value, false) is { } e)
        {
            _error.Text = e;
            return Task.CompletedTask;
        }

        _error.Text = "";
        var port = (int)_port.Value!.Value;
        return _runner.RunAsync($"Testing {host}:{port}", async ct => (await KmsNetwork.TestAsync(host, port, TimeSpan.FromSeconds(5), ct)).Text);
    }

    private async Task DiscoverAsync()
    {
        IReadOnlyList<KmsHostCandidate> found = [];
        await _runner.RunAsync("Looking up _vlmcs._tcp records", async ct =>
        {
            var servers = DnsClient.SystemServers().Select(a => new System.Net.IPEndPoint(a, 53)).ToList();
            var (hosts, detail) = await KmsNetwork.DiscoverAsync(KmsNetwork.SearchDomains(), servers, ct);
            found = hosts;
            return hosts.Count == 0 ? "No KMS host found in DNS. " + detail : $"{hosts.Count} KMS host(s) found in DNS.";
        });
        if (found.Count == 0) return;
        var d = Ui.Window("Discovered KMS Hosts", 520, 320);
        var list = new ListBox { ItemsSource = found.Select(h => $"{h.Host}:{h.Port}   (priority {h.Priority}, weight {h.Weight}, {h.Domain})").ToList(), SelectedIndex = 0, MinHeight = 120 };
        AutomationProperties.SetName(list, "Discovered KMS hosts");
        KmsHostCandidate? chosen = null;
        var use = Ui.Button("Use", () =>
        {
            chosen = list.SelectedIndex >= 0 ? found[list.SelectedIndex] : null;
            d.Close();
            return Task.CompletedTask;
        }, accent: true);
        var close = Ui.Button("Close", () =>
        {
            d.Close();
            return Task.CompletedTask;
        });
        close.IsCancel = true;
        d.Content = Ui.Layout(new TextBlock { Text = "Use fills the server fields only. Save it as a profile to keep it." }, list, Ui.Row(use, close));
        await d.ShowDialog(this);
        if (chosen is null) return;
        _profile.SelectedItem = null;
        _server.Text = chosen.Host;
        _port.Value = chosen.Port;
        _status.Text = $"{chosen.Host}:{chosen.Port} selected. Not saved and not configured.";
    }

    // ---------------- apply ----------------
    private async Task ApplyAsync(KmsAction wanted)
    {
        if (Selected is not { } p || _runner.IsBusy) return;
        var plan = Kms.Plan(p);
        if (plan.Action != wanted) return;
        var host = (_server.Text ?? "").Trim();
        if (Kms.ValidateServer(host, _port.Value, allowEmpty: true) is { } e)
        {
            _error.Text = e;
            return;
        }

        _error.Text = "";
        var port = (int)(_port.Value ?? Kms.DefaultPort);
        if (await ConfirmAsync(p, plan, host, port) is not { } activate)
        {
            _status.Text = Kms.OutcomeText(KmsOutcome.Cancelled);
            return;
        }

        var steps = Kms.Steps(p, plan, host, port, activate);
        var request = new KmsRequest { ApplicationId = p.Family is KmsFamily.Windows or KmsFamily.WindowsServer ? Kms.WindowsApplicationId : Kms.OfficeApplicationId, Steps = steps };
        var operation = wanted == KmsAction.InstallKey ? $"Install KMS key{(activate ? " and activate" : "")}" : "Activate";
        KmsApplyResult result = new();
        await _runner.RunAsync(wanted == KmsAction.InstallKey ? "Installing KMS key" : "Activating", async ct =>
        {
            result = await _service.ApplyAsync(request, ct);
            return result.Error.Length > 0 ? result.Error : "Reading the license state";
        });
        await DetectAsync(products =>
        {
            var after = products.FirstOrDefault(x => result.ProductId.Length > 0 && string.Equals(x.ProductId, result.ProductId, StringComparison.OrdinalIgnoreCase))
                        ?? products.FirstOrDefault(x => string.Equals(x.ProductId, p.ProductId, StringComparison.OrdinalIgnoreCase));
            var outcome = Kms.Verify(result, after, activationAsked: steps.Any(s => s.Kind == KmsStepKind.Activate));
            _attempt = new Kms.ReportAttempt(operation, outcome, result.Steps);
            if (after is not null) _grid.SelectedItem = _rows.FirstOrDefault(r => r.P == after);
            var failed = result.Steps.FirstOrDefault(s => !s.Succeeded);
            return Kms.OutcomeText(outcome) + (failed?.Code is { } c ? $" {Kms.Code(c)}: {failed.Message}" : result.Error.Length > 0 ? " " + result.Error : "");
        });
    }

    /// <summary>Preview of the change; returns whether to activate, or null when cancelled.</summary>
    private async Task<bool?> ConfirmAsync(KmsProduct p, KmsPlan plan, string host, int port)
    {
        var d = Ui.Window(plan.Action == KmsAction.InstallKey ? "Configure KMS Activation" : "Activate", 560, 360);
        d.Height = double.NaN;
        d.MinHeight = 0;
        d.SizeToContent = SizeToContent.Height;
        var text = $"Product:  {p.Name}\nCurrent:  {Kms.ChannelText(p.Channel)}, {p.State}\nTarget:   Volume KMS\nServer:   {(host.Length > 0 ? $"{host}:{port} (this product only)" : "Automatic (DNS discovery)")}";
        if (plan.Action == KmsAction.InstallKey) text += $"\nKey:      {p.Key!.FamilyName} {p.Key.Version} {p.Key.Edition} (official KMS client setup key)";
        var panel = new StackPanel { Spacing = Styling.Theme.SectionGap, Children = { new SelectableTextBlock { Text = text, Classes = { Styling.Theme.Classes.Mono } } } };
        var entitled = new CheckBox { Content = "I confirm that this computer has volume license entitlement for this product." };
        var activate = new CheckBox { Content = "Activate after the key is installed", IsChecked = true };
        if (plan.ReplacesKey)
        {
            panel.Children.Add(Ui.Banner("The installed key is replaced. To go back you need the original key or another authorized recovery. A KMS client key is not a license.", Styling.Theme.Classes.Warning));
            panel.Children.Add(entitled);
        }

        if (plan.Action == KmsAction.InstallKey) panel.Children.Add(activate);
        panel.Children.Add(new TextBlock { Text = "Administrator approval (UAC) is requested when IPMaster is not elevated.", Classes = { Styling.Theme.Classes.Note }, TextWrapping = TextWrapping.Wrap });
        bool? result = null;
        var apply = Ui.Button("Apply", () =>
        {
            result = plan.Action == KmsAction.Activate || activate.IsChecked == true;
            d.Close();
            return Task.CompletedTask;
        }, accent: true);
        apply.IsEnabled = !plan.NeedsEntitlement;
        entitled.IsCheckedChanged += (_, _) => apply.IsEnabled = entitled.IsChecked == true;
        var cancel = Ui.Button("Cancel", () =>
        {
            d.Close();
            return Task.CompletedTask;
        });
        cancel.IsCancel = true;
        panel.Children.Add(Ui.Row(cancel, apply));
        d.Content = new ScrollViewer { Content = panel, Padding = Styling.Theme.Page };
        d.Opened += (_, _) => cancel.Focus();
        await d.ShowDialog(this);
        return result;
    }
}

/// <summary>Searchable offline list of the official GVLKs (secondary view; the main window never lists keys).</summary>
internal sealed class KmsCatalogWindow : Window
{
    private static readonly string[] Filters = ["All", "Windows", "Windows Server", "Office", "Project", "Visio"];

    public KmsCatalogWindow()
    {
        Title = "KMS Client Key Catalog";
        Width = 820;
        Height = 560;
        MinWidth = Styling.Theme.ToolMinWidth;
        MinHeight = Styling.Theme.ToolMinHeight;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var filter = ToolKit.Combo("Product family", Filters, 0, 160);
        var search = ToolKit.Text("Search keys", "version or edition, e.g. 2022 or Pro", 260);
        var rows = new ObservableCollection<GvlkEntry>();
        var grid = new DataGrid { ItemsSource = rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserSortColumns = true, CanUserResizeColumns = true };
        AutomationProperties.SetName(grid, "KMS client setup keys");
        void Col(string header, string path, DataGridLength w) => grid.Columns.Add(new DataGridTextColumn { Header = header, Binding = new Binding(path), Width = w });
        Col("Family", nameof(GvlkEntry.FamilyName), new DataGridLength(120));
        Col("Version", nameof(GvlkEntry.Version), new DataGridLength(1, DataGridLengthUnitType.Star));
        Col("Edition", nameof(GvlkEntry.Edition), new DataGridLength(1, DataGridLengthUnitType.Star));
        Col("KMS Client Key", nameof(GvlkEntry.Key), new DataGridLength(260));
        var status = ToolKit.StatusLine();
        void Apply()
        {
            var fam = Filters[Math.Max(0, filter.SelectedIndex)];
            var q = (search.Text ?? "").Trim();
            rows.Clear();
            foreach (var e in KmsCatalog.All.Where(e => (fam == "All" || e.FamilyName == fam)
                                                        && (q.Length == 0 || $"{e.Version} {e.Edition}".Contains(q, StringComparison.OrdinalIgnoreCase)))) rows.Add(e);
            status.Text = $"{rows.Count} of {KmsCatalog.All.Count} keys. Sources: Microsoft Learn (Windows and Office GVLK pages).";
        }

        filter.SelectionChanged += (_, _) => Apply();
        search.TextChanged += (_, _) => Apply();
        Apply();
        var copy = ToolKit.CopyButton(this, () => grid.SelectedItem is GvlkEntry e ? e.Key : "", "Copy Key");
        var close = Ui.Button("Close", () =>
        {
            Close();
            return Task.CompletedTask;
        });
        close.IsCancel = true;
        Content = ToolKit.Layout(Ui.Row(filter, search), Ui.Row(copy, close), grid, status);
    }
}
