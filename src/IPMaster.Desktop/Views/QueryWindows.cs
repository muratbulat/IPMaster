using System.Net;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Queries;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Management;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Desktop.Views;

/// <summary>Label/control rows in a two-column grid.</summary>
internal sealed class Form
{
    private int _row;

    public Grid Grid { get; } = new() { ColumnDefinitions = new ColumnDefinitions("Auto,*"), RowSpacing = 6, ColumnSpacing = 10 };

    public T Add<T>(string label, T control) where T : Control
    {
        Grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        var l = new TextBlock { Text = label, VerticalAlignment = VerticalAlignment.Center };
        Grid.SetRow(l, _row);
        Grid.SetRow(control, _row);
        Grid.SetColumn(control, 1);
        Grid.Children.Add(l);
        Grid.Children.Add(control);
        _row++;
        return control;
    }

    /// <summary>Adds a labelled row and returns the label and the control (to show or hide the whole row).</summary>
    public Control[] AddPair(string label, Control control)
    {
        Add(label, control);
        return [Grid.Children[^2], control];
    }

    public T Full<T>(T control) where T : Control
    {
        Grid.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
        Grid.SetRow(control, _row);
        Grid.SetColumnSpan(control, 2);
        Grid.Children.Add(control);
        _row++;
        return control;
    }

    public static TextBox Code(string text, double height) => new()
    {
        Text = text, AcceptsReturn = true, AcceptsTab = true, Height = height, TextWrapping = TextWrapping.NoWrap,
        FontFamily = new FontFamily("Cascadia Mono, Consolas, Menlo, monospace"),
    };

    public static ComboBox Combo(IEnumerable<string> items, int selected) => new() { ItemsSource = items.ToList(), SelectedIndex = selected, MinWidth = 220 };

    public static TextBlock Hint(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap, Classes = { "note" } };

    /// <summary>Visible secondary text (data, status, empty state); <see cref="Hint"/> is an explanatory note, hidden in the compact UI (D-083).</summary>
    public static TextBlock Info(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap, Classes = { "hint" } };

    public static Control WithButton(Control main, Button button)
    {
        var d = new DockPanel();
        DockPanel.SetDock(button, Dock.Right);
        button.Margin = new Thickness(6, 0, 0, 0);
        d.Children.Add(button);
        d.Children.Add(main);
        return d;
    }
}

/// <summary>Manual "Options → Remote …" managers (QRY-01): list, enable/disable, new/edit/delete, test, local value.</summary>
internal sealed partial class QueryManagerWindow : Window
{
    public sealed record Row(QueryDefinition Query, string On, string Name, string Summary, string Credential, string Local)
    {
        public bool Enabled => Query.Enabled;

        public string Detail1 { get; init; } = "";

        public string Detail2 { get; init; } = "";
    }

    private readonly MainWindowViewModel _vm;
    private readonly QueryKind _kind;
    private readonly DataGrid _grid;
    private readonly TextBlock _status = new() { TextWrapping = TextWrapping.Wrap, Classes = { "status" } };
    private readonly Dictionary<Guid, string> _local = [];
    private readonly bool _hasLocal;

    public static string TitleFor(QueryKind kind) => kind switch
    {
        QueryKind.Script => "Remote Scripting",
        QueryKind.Nmap => "Integration with Nmap",
        _ => "Remote " + QueryColumns.DisplayName(kind),
    };

    private static string SummaryHeader(QueryKind kind) => kind switch
    {
        QueryKind.Wmi => "WQL Statement",
        QueryKind.Registry => "Root \\ Key → Parameter",
        QueryKind.Files => "Full File Name → Property",
        QueryKind.Services => "Service Name → Parameter",
        QueryKind.Groups => "Query: Group / User Name",
        QueryKind.Performance => "Query",
        QueryKind.PowerShell => "Script Text",
        QueryKind.Script or QueryKind.Python => "Script",
        QueryKind.Snmp => "Version and MIB OID",
        QueryKind.Ssh => "SSH Command",
        QueryKind.Nmap => "Scan Type → Response XPath",
        _ => "HTTP Port, Path → Expression",
    };

    public QueryManagerWindow(MainWindowViewModel vm, QueryKind kind)
    {
        _vm = vm;
        _kind = kind;
        _hasLocal = kind is QueryKind.Registry or QueryKind.Files or QueryKind.Services or QueryKind.Groups or QueryKind.Performance;
        Title = TitleFor(kind);
        Width = 980;
        Height = 520;
        MinWidth = 600;
        MinHeight = 320;
        if (IsToolManager(kind))
        {
            Width = 900;
            Height = 560;
            _grid = ToolGrid();
            _grid.DoubleTapped += async (_, _) => await EditSelected();
            Content = ToolLayout();
            Opened += (_, _) => Refresh();
            return;
        }

        var cols = new List<(string, string, double)> { ("On", "On", 44), ("Item Name", "Name", 190), (SummaryHeader(kind), "Summary", 0), ("Authentication", "Credential", 150) };
        if (_hasLocal) cols.Add(("Local Value", "Local", 240));
        _grid = Ui.Grid([.. cols]);
        _grid.DoubleTapped += async (_, _) => await EditSelected();
        var provider = vm.Queries.Providers(vm.Settings).First(p => p.Kind == kind);
        var top = new StackPanel { Spacing = 6 };
        var capLine = new TextBlock { Text = "Checking availability…", TextWrapping = TextWrapping.Wrap };
        // Capability may start processes (Python, Nmap detection): never on the UI thread (review C-12).
        async Task ShowCapabilityAsync()
        {
            var capability = await Task.Run(() => provider.Capability); // resumes on the UI thread
            capLine.Text = (capability.Available ? "✓ " : "⚠ ") + capability.Description;
            if (!capability.Available) Styling.Theme.SetState(capLine, "warning");
        }

        _ = ShowCapabilityAsync();
        top.Children.Add(capLine);
        if (kind == QueryKind.Python)
        {
            top.Children.Add(Ui.Row(
                Ui.Button("Choose Location…", async () =>
                {
                    var files = await StorageProvider.OpenFilePickerAsync(new Avalonia.Platform.Storage.FilePickerOpenOptions { Title = "Python interpreter" });
                    if (files.Count > 0 && files[0].TryGetLocalPath() is { } p) await _vm.SaveQueriesAsync(_vm.Settings.Queries with { PythonPath = p });
                    Close();
                }),
                Ui.Button("Use Detected", async () => await _vm.SaveQueriesAsync(_vm.Settings.Queries with { PythonPath = "" })),
                Ui.Button("Download Python", () =>
                {
                    _status.Text = Shell.OpenUrl("https://www.python.org/downloads/").Message;
                    return Task.CompletedTask;
                })));
        }

        if (kind == QueryKind.Nmap) top.Children.Add(Ui.Row(Ui.Button("Settings…", NmapSettingsAsync), Form.Info("Nmap: install from nmap.org.")));
        if (kind == QueryKind.Script) top.Children.Add(Form.Hint("Scripts run out of process with Windows Script Host. VBScript is an optional Windows feature that Microsoft is phasing out; JScript and Python remain available."));
        top.Children.Add(Form.Hint("Each item is a result column. Credentials come from Options → Credential Manager; without one the current Windows account is used (Windows queries) or no authentication (HTTP)."));

        var buttons = Ui.Row(
            Ui.Button("New…", async () =>
            {
                if (await QueryEditor.EditAsync(this, _vm, QueryDefinition.New(kind, "")) is { } q) await SaveAsync(items => [.. items, q]);
            }, accent: true),
            Ui.Button("Edit…", EditSelected),
            Ui.Button("Duplicate", async () =>
            {
                if (Selected() is { } q) await SaveAsync(items => [.. items, Clone(q) with { Id = Guid.NewGuid(), Name = q.Name + " (copy)", Enabled = false }]);
            }),
            Ui.Button("Delete", async () =>
            {
                var sel = _grid.SelectedItems.OfType<Row>().Select(r => r.Query.Id).ToHashSet();
                if (sel.Count == 0 || !await Dialogs.MessageAsync(this, "Delete", $"Delete {sel.Count} item(s)?", confirm: true)) return;
                await SaveAsync(items => items.Where(i => !sel.Contains(i.Id)).ToList());
            }),
            Ui.Button("Enable / Disable", async () =>
            {
                var sel = _grid.SelectedItems.OfType<Row>().Select(r => r.Query.Id).ToHashSet();
                await SaveAsync(items => items.Select(i => sel.Contains(i.Id) ? i with { Enabled = !i.Enabled } : i).ToList());
            }),
            Ui.Button("Test…", TestSelected),
            Ui.Button("Close", () =>
            {
                Close();
                return Task.CompletedTask;
            }));
        Content = Ui.Layout(top, _grid, new StackPanel { Spacing = 6, Children = { buttons, _status } });
        Opened += (_, _) =>
        {
            Refresh();
            _ = ComputeLocalAsync();
        };
    }

    private QueryDefinition? Selected() => (_grid.SelectedItem as Row)?.Query;

    private static QueryDefinition Clone(QueryDefinition q) => q with
    {
        Wmi = q.Wmi is null ? null : q.Wmi with { },
        Registry = q.Registry is null ? null : q.Registry with { },
        Files = q.Files is null ? null : q.Files with { },
        Service = q.Service is null ? null : q.Service with { },
        Group = q.Group is null ? null : q.Group with { },
        Performance = q.Performance is null ? null : q.Performance with { },
        PowerShell = q.PowerShell is null ? null : q.PowerShell with { },
        Script = q.Script is null ? null : q.Script with { },
        Snmp = q.Snmp is null ? null : q.Snmp with { },
        Ssh = q.Ssh is null ? null : q.Ssh with { },
        Http = q.Http is null ? null : q.Http with { },
        Nmap = q.Nmap is null ? null : q.Nmap with { },
        Python = q.Python is null ? null : q.Python with { },
    };

    private void Refresh()
    {
        var creds = _vm.Settings.Credentials.ToDictionary(c => c.Id, c => c.Display);
        _grid.ItemsSource = _vm.Settings.Queries.Items.Where(q => q.Kind == _kind).Select(q =>
            {
                var (d1, d2) = ToolDetails(q);
                return new Row(q, q.Enabled ? "✓" : "", q.Name, q.Summary,
                    q.CredentialId is { } id ? creds.GetValueOrDefault(id, "[missing credential]") : "(current account)", _local.GetValueOrDefault(q.Id, _hasLocal ? "…" : ""))
                {
                    Detail1 = d1, Detail2 = d2,
                };
            })
            .Where(Matches).ToList();
    }

    private async Task ComputeLocalAsync()
    {
        if (!_hasLocal || !OperatingSystem.IsWindows()) return;
        foreach (var q in _vm.Settings.Queries.Items.Where(q => q.Kind == _kind).ToList())
        {
            var o = await Task.Run(() => LocalValue(q));
            _local[q.Id] = ObservationText.Render(o, v => v.Replace('\n', ' ')) is { Length: > 0 } t ? t : o.Detail ?? "";
            Refresh();
        }
    }

    public static Observation<string> LocalValue(QueryDefinition q)
    {
        if (!OperatingSystem.IsWindows()) return Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, "Windows only.");
        try
        {
            return q.Kind switch
            {
                QueryKind.Registry => RegistryQueryProvider.ReadLocal(q.Registry ?? new RegistryOptions()),
                QueryKind.Files => FileQueryProvider.Query(q.Files ?? new Core.Queries.FileOptions(), null, CancellationToken.None),
                QueryKind.Services => ServiceQueryProvider.Query(q.Service ?? new ServiceOptions(), "."),
                QueryKind.Groups => GroupQueryProvider.Query(q.Group ?? new GroupOptions(), null),
                QueryKind.Performance => PerformanceQueryProvider.Read(q.Performance ?? new PerformanceOptions(), ".", CancellationToken.None),
                _ => Observation<string>.NotRequested,
            };
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, ex.Message);
        }
    }

    private async Task EditSelected()
    {
        if (Selected() is not { } q) return;
        if (await QueryEditor.EditAsync(this, _vm, Clone(q)) is { } edited)
        {
            _local.Remove(q.Id);
            await SaveAsync(items => items.Select(i => i.Id == q.Id ? edited : i).ToList());
            _ = ComputeLocalAsync();
        }
    }

    /// <summary>Validates names and dependency cycles (QRY-02) before persisting.</summary>
    private async Task<bool> SaveAsync(Func<IReadOnlyList<QueryDefinition>, IReadOnlyList<QueryDefinition>> change)
    {
        var items = change(_vm.Settings.Queries.Items);
        var dup = items.Where(q => q.Name.Length > 0).GroupBy(q => (q.Kind, q.Name.ToUpperInvariant())).FirstOrDefault(g => g.Count() > 1);
        if (dup is not null)
        {
            await Dialogs.MessageAsync(this, Title ?? "", $"There are two {QueryColumns.DisplayName(dup.Key.Kind)} items named '{dup.First().Name}'. Names must be unique per kind (Remote.* calls use them).", confirm: false);
            return false;
        }

        var graph = QueryDependencies.Build(items.Where(q => q.Enabled && q.Name.Length > 0).ToList(), _vm.Settings.VirtualColumns);
        var cycle = graph.Errors.Values.FirstOrDefault(e => e.StartsWith("Dependency cycle", StringComparison.Ordinal));
        if (cycle is not null)
        {
            await Dialogs.MessageAsync(this, Title ?? "", cycle + "\n\nRemove one of the references (Input.Column / Remote.*) or disable an item.", confirm: false);
            return false;
        }

        await _vm.SaveQueriesAsync(_vm.Settings.Queries with { Items = items });
        Refresh();
        _status.Text = graph.Errors.Count > 0 ? string.Join("\n", graph.Errors.Values.Distinct()) : "";
        return true;
    }

    private async Task TestSelected()
    {
        if (Selected() is not { } q) return;
        var target = await Dialogs.PromptAsync(this, "Test " + q.Name, "IP address or host name", _vm.SuggestedTestTarget());
        if (string.IsNullOrWhiteSpace(target)) return;
        _status.Text = $"Testing {q.Name} against {target}…";
        _status.Text = await QueryEditor.RunTestAsync(_vm, q, target.Trim());
    }

    private async Task NmapSettingsAsync()
    {
        var s = _vm.Settings.Queries.Nmap;
        var w = Ui.Window("Nmap Settings", 620, 300);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var f = new Form();
        var path = f.Add("Nmap executable", new TextBox { Text = s.ExecutablePath, PlaceholderText = NmapQueryProvider.Find("") ?? "(not found — install Nmap)" });
        var ports = f.Add("Ports (-p)", new TextBox { Text = s.Ports, PlaceholderText = "e.g. 22,80,443 or 1-1024 (empty = Nmap default)" });
        var exclude = f.Add("Exclude ports", new TextBox { Text = s.ExcludePorts });
        var extra = f.Add("Additional parameters", new TextBox { Text = s.ExtraArguments, PlaceholderText = "-T4 --max-retries 1" });
        f.Full(Form.Hint("Arguments are passed as a list (no shell). Output options (-oX, -oN, …) and input lists are reserved for IPMaster."));
        var ok = Ui.Button("OK", async () =>
        {
            await _vm.SaveQueriesAsync(_vm.Settings.Queries with
            {
                Nmap = new NmapSettings { ExecutablePath = path.Text?.Trim() ?? "", Ports = ports.Text?.Trim() ?? "", ExcludePorts = exclude.Text?.Trim() ?? "", ExtraArguments = extra.Text?.Trim() ?? "" },
            });
            w.Close();
        }, accent: true);
        w.Content = new StackPanel { Margin = new Thickness(16), Spacing = 10, Children = { f.Grid, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) } };
        await w.ShowDialog(this);
    }
}

/// <summary>Item editor for every query family, with Test against a host and the family's browsers/builders.</summary>
internal static class QueryEditor
{
    private const string Unchanged = "(unchanged)";

    public static async Task<string> RunTestAsync(MainWindowViewModel vm, QueryDefinition q, string target)
    {
        IPAddress? ip;
        if (!IPAddress.TryParse(target, out ip))
        {
            try
            {
                ip = (await Dns.GetHostAddressesAsync(target)).FirstOrDefault();
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                return ex.Message;
            }
        }

        if (ip is null) return "Host not found. Check the name.";
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Clamp(q.TimeoutSeconds, 1, 600) + 5));
        var device = vm.Results.Rows.Select(r => r.Result).FirstOrDefault(d => d.Address.Equals(ip));
        var o = await vm.Queries.TestAsync(vm.Settings, q, ip, cts.Token, device);
        return o.State == ObservationState.Success
            ? o.Value!
            : $"{ObservationText.Render(o, v => v)} {o.State}{(o.Detail is { Length: > 0 } d ? ": " + d : "")}".Trim();
    }

    public static async Task<QueryDefinition?> EditAsync(Window owner, MainWindowViewModel vm, QueryDefinition q)
    {
        var w = Ui.Window(QueryManagerWindow.TitleFor(q.Kind) + " Item", 820, 720);
        var f = new Form();
        var apply = new List<Action<QueryDefinition>>();
        var name = f.Add("Item name (column)", new TextBox { Text = q.Name });
        var enabled = f.Add("Enabled", new CheckBox { IsChecked = q.Enabled });
        var credItems = new List<(Guid? Id, string Label)> { (null, q.Kind is QueryKind.Xml or QueryKind.Json or QueryKind.Snmp or QueryKind.Ssh ? "(none)" : "(current Windows account)") };
        credItems.AddRange(vm.Settings.Credentials.Select(c => ((Guid?)c.Id, c.Display)));
        var cred = new ComboBox { ItemsSource = credItems.Select(c => c.Label).ToList(), SelectedIndex = Math.Max(0, credItems.FindIndex(c => c.Id == q.CredentialId)), MinWidth = 260 };
        f.Add("Authentication", Form.WithButton(cred, Ui.Button("Manage…", async () =>
        {
            await CredentialManagerWindow.ShowAsync(w, vm);
            credItems.RemoveRange(1, credItems.Count - 1);
            credItems.AddRange(vm.Settings.Credentials.Select(c => ((Guid?)c.Id, c.Display)));
            cred.ItemsSource = credItems.Select(c => c.Label).ToList();
        })));
        var timeout = f.Add("Timeout, s", new NumericUpDown { Value = q.TimeoutSeconds, Minimum = 1, Maximum = 3600, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left });

        var output = new TextBox { IsReadOnly = true, AcceptsReturn = true, Height = 90, TextWrapping = TextWrapping.Wrap, FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace") };
        var target = new TextBox { Text = vm.SuggestedTestTarget(), Width = 200, PlaceholderText = "IP or host name" };
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };

        BuildKind(w, vm, q, f, apply, target, output, () => credItems[Math.Max(0, cred.SelectedIndex)].Id,
            id => cred.SelectedIndex = Math.Max(0, credItems.FindIndex(c => c.Id == id)));

        QueryDefinition Collect()
        {
            var d = q with
            {
                Name = (name.Text ?? "").Trim(),
                Enabled = enabled.IsChecked == true,
                CredentialId = credItems[Math.Max(0, cred.SelectedIndex)].Id,
                TimeoutSeconds = (int)(timeout.Value ?? 15),
            };
            foreach (var a in apply) a(d);
            if (d.Name.Length == 0) throw new FormatException("Enter an item name.");
            return d;
        }

        QueryDefinition? result = null;
        var ok = Ui.Button("OK", () =>
        {
            try
            {
                result = Collect();
                w.Close();
            }
            catch (Exception ex) when (ex is FormatException or InvalidOperationException or ArgumentException)
            {
                error.Text = ex.Message;
            }

            return Task.CompletedTask;
        }, accent: true);
        var test = Ui.Button("Test", async () =>
        {
            try
            {
                var d = Collect();
                output.Text = $"Running against {target.Text}…";
                output.Text = await RunTestAsync(vm, d, (target.Text ?? "").Trim());
            }
            catch (Exception ex) when (ex is FormatException or InvalidOperationException or ArgumentException)
            {
                output.Text = ex.Message;
            }
        });
        f.Full(new Separator());
        f.Add("Test against", Ui.Row(target, test));
        f.Full(output);
        w.Content = new DockPanel
        {
            Margin = new Thickness(14),
            Children =
            {
                Docked(new StackPanel { Spacing = 6, Margin = new Thickness(0, 10, 0, 0), Children = { error, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) } }, Dock.Bottom),
                new ScrollViewer { Content = f.Grid },
            },
        };
        await w.ShowDialog(owner);
        return result;
    }

    private static Control Docked(Control c, Dock dock)
    {
        DockPanel.SetDock(c, dock);
        return c;
    }

    private static int Index<T>(T value) where T : struct, Enum => Array.IndexOf(Enum.GetValues<T>(), value);

    private static T At<T>(ComboBox c) where T : struct, Enum => Enum.GetValues<T>()[Math.Max(0, c.SelectedIndex)];

    /// <summary>Protected text from a password box: unchanged when left at the placeholder, encrypted otherwise.</summary>
    private static string Protect(MainWindowViewModel vm, TextBox box, string existing)
    {
        var text = box.Text ?? "";
        if (text.Length == 0) return box.Tag is "cleared" ? "" : existing;
        vm.EnsureVaultKey();
        return vm.Vault.Protect(text);
    }

    private static TextBox Secret(string existing) => new()
    {
        PasswordChar = '•', PlaceholderText = existing.Length > 0 ? Unchanged : "", RevealPassword = false,
    };

    private static void BuildKind(Window w, MainWindowViewModel vm, QueryDefinition q, Form f, List<Action<QueryDefinition>> apply, TextBox target, TextBox output,
        Func<Guid?> currentCredential, Action<Guid?> setCredential)
    {
        switch (q.Kind)
        {
            case QueryKind.Wmi:
            {
                var o = q.Wmi ??= new WmiOptions();
                var query = Form.Code(o.Query, 90);
                var ns = new TextBox { Text = o.Namespace };
                var privacy = new CheckBox { Content = "Encrypted connection (packet privacy authentication)", IsChecked = o.PacketPrivacy };
                f.Add("WQL statement", query);
                f.Add("Name space", Form.WithButton(ns, Ui.Button("Query Builder…", async () =>
                {
                    if (await Browsers.WmiBuilderAsync(w, ns.Text ?? @"root\cimv2") is { } r)
                    {
                        query.Text = r.Query;
                        ns.Text = r.Namespace;
                    }
                })));
                f.Full(privacy);
                apply.Add(d => d.Wmi = new WmiOptions { Query = query.Text ?? "", Namespace = ns.Text ?? @"root\cimv2", PacketPrivacy = privacy.IsChecked == true });
                break;
            }

            case QueryKind.Registry:
            {
                var o = q.Registry ??= new RegistryOptions();
                var root = Form.Combo(["HKEY_LOCAL_MACHINE", "HKEY_USERS", "HKEY_CURRENT_USER"], Index(o.Root));
                var key = new TextBox { Text = o.Key };
                var value = new TextBox { Text = o.ValueName };
                var action = Form.Combo(["Read a value from one key: simple path", "Read a value from multiple keys: wildcards allowed", "Check if the key exists"], Index(o.Action));
                f.Add("Root", root);
                var browse = Ui.Button("…", async () =>
                {
                    if (!OperatingSystem.IsWindows()) return;
                    if (await Browsers.RegistryAsync(w, At<RegistryRoot>(root), key.Text ?? "") is { } r)
                    {
                        key.Text = r.Key;
                        if (r.Value is not null) value.Text = r.Value;
                    }
                });
                f.Add("Registry key", Form.WithButton(key, browse));
                f.Add("Parameter name", value);
                f.Add("Action", action);
                f.Full(Form.Hint(@"Alternatives: SOFTWARE\[Microsoft|Policies\Microsoft]\Windows — the first existing path wins. Wildcards * and ? expand to every matching key. Remote HKEY_CURRENT_USER reads each logged-on user's hive."));
                apply.Add(d => d.Registry = new RegistryOptions { Root = At<RegistryRoot>(root), Key = (key.Text ?? "").Trim(), ValueName = value.Text ?? "", Action = At<RegistryAction>(action) });
                break;
            }

            case QueryKind.Files:
            {
                var o = q.Files ??= new Core.Queries.FileOptions();
                var path = new TextBox { Text = o.Path };
                var prop = Form.Combo(["File Size", "Folder Size", "File Exists", "File CRC32", "File MD5", "File SHA1", "File SHA256", "Created Date", "Modified Date", "Accessed Date", "File Version", "Product Version"],
                    Index(o.Property));
                f.Add("Full file name", path);
                f.Add("Property", prop);
                f.Full(Form.Hint(@"Drive letters map to administrative shares (C:\ → \\device\C$). Wildcards * and ? work in any component; [Program Files|Program Files (x86)] tries alternatives in order."));
                apply.Add(d => d.Files = new Core.Queries.FileOptions { Path = (path.Text ?? "").Trim(), Property = At<FileProperty>(prop) });
                break;
            }

            case QueryKind.Services:
            {
                var o = q.Service ??= new ServiceOptions();
                var svc = new TextBox { Text = o.ServiceName };
                var prop = Form.Combo(["Service Status", "Service Image Name", "Service Startup Type"], Index(o.Property));
                f.Add("Service name", Form.WithButton(svc, Ui.Button("…", async () =>
                {
                    if (!OperatingSystem.IsWindows()) return;
                    if (await Browsers.PickAsync(w, "Local Services", Browsers.LocalServices()) is { } s) svc.Text = s;
                })));
                f.Add("Parameter", prop);
                apply.Add(d => d.Service = new ServiceOptions { ServiceName = (svc.Text ?? "").Trim(), Property = At<ServiceProperty>(prop) });
                break;
            }

            case QueryKind.Groups:
            {
                var o = q.Group ??= new GroupOptions();
                var nameBox = new TextBox { Text = o.Name };
                var type = Form.Combo(["Members of a local group", "Members of a global group", "Participation in local groups", "Participation in global groups"], Index(o.Type));
                var strip = new CheckBox { Content = "Strip domain names from output", IsChecked = o.StripDomain };
                var excl = Form.Code(string.Join(Environment.NewLine, o.Exclusions), 70);
                f.Add("Group / user name", Form.WithButton(nameBox, Ui.Button("…", async () =>
                {
                    if (await Browsers.PickAsync(w, "Local Groups and Users", Browsers.LocalAccounts()) is { } s) nameBox.Text = s;
                })));
                f.Add("Query", type);
                f.Full(strip);
                f.Add("Disregard (wildcards)", excl);
                apply.Add(d => d.Group = new GroupOptions
                {
                    Name = (nameBox.Text ?? "").Trim(), Type = At<GroupQueryType>(type), StripDomain = strip.IsChecked == true,
                    Exclusions = (excl.Text ?? "").Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
                });
                break;
            }

            case QueryKind.Performance:
            {
                var o = q.Performance ??= new PerformanceOptions();
                var path = new TextBox { Text = o.CounterPath };
                var sample = new NumericUpDown { Value = o.SampleMilliseconds, Minimum = 100, Maximum = 10_000, Increment = 100, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left };
                f.Add("Performance query", Form.WithButton(path, Ui.Button("…", async () =>
                {
                    if (await Browsers.CountersAsync(w) is { } p) path.Text = p;
                })));
                f.Add("Sampling interval, ms", sample);
                f.Full(Form.Hint(@"Start with a single backslash, e.g. \Processor(_Total)\% Processor Time. Use (*) for every instance. Remote reads need the Remote Registry service on the target."));
                apply.Add(d =>
                {
                    _ = PerformanceQueryProvider.Parse(path.Text ?? "");
                    d.Performance = new PerformanceOptions { CounterPath = (path.Text ?? "").Trim(), SampleMilliseconds = (int)(sample.Value ?? 1000) };
                });
                break;
            }

            case QueryKind.PowerShell:
            {
                var o = q.PowerShell ??= new PowerShellOptions();
                var script = Form.Code(o.Script, 160);
                var ssl = new CheckBox { Content = "Use SSL connection (HTTPS WinRM listener)", IsChecked = o.UseSsl };
                var noProfile = new CheckBox { Content = "Do not load profile", IsChecked = o.NoProfile };
                f.Add("Script", script);
                f.Full(Ui.Row(ssl, noProfile, Ui.Button("Run on this computer", async () =>
                {
                    output.Text = "Running locally (not on the target)…";
                    var r = await PowerShellQueryProvider.RunLocalAsync(script.Text ?? "", CancellationToken.None);
                    output.Text = "[local] " + (r.State == ObservationState.Success ? r.Value : $"{r.State}: {r.Detail}");
                })));
                f.Full(Form.Hint("Remote execution uses Invoke-Command over WinRM (Enable-PSRemoting -Force on targets). 'Run on this computer' executes only locally."));
                apply.Add(d => d.PowerShell = new PowerShellOptions { Script = script.Text ?? "", UseSsl = ssl.IsChecked == true, NoProfile = noProfile.IsChecked == true });
                break;
            }

            case QueryKind.Script:
            {
                var o = q.Script ??= new ScriptOptions();
                var lang = Form.Combo(["VBScript", "JScript"], Index(o.Language));
                var script = Form.Code(o.Script, 200);
                f.Add("Language", Ui.Row(lang, Templates(script, lang)));
                f.Add("Script", script);
                f.Full(Form.Hint("Input.Current = IP address; Input.Column(\"name\") reads another column; Output.Write returns data; Remote.WMI(\"item\") etc. run other items; Internal.CreateObject(\"Process\"|\"DNS\"|\"SNMP\")."));
                apply.Add(d => d.Script = new ScriptOptions { Language = At<ScriptLanguage>(lang), Script = script.Text ?? "" });
                break;
            }

            case QueryKind.Python:
            {
                var o = q.Python ??= new PythonOptions();
                var script = Form.Code(o.Script, 220);
                f.Add("Script", script);
                f.Full(Form.Hint("Input.Current, Input.Column(\"name\"), Output.Write(text) and Remote.WMI(\"item\") … are available. The VBScript Internal objects are not. Runs in isolated mode (-I)."));
                apply.Add(d => d.Python = new PythonOptions { Script = script.Text ?? "" });
                break;
            }

            case QueryKind.Snmp:
                BuildSnmp(w, vm, q, f, apply, target, output, currentCredential, setCredential);
                break;

            case QueryKind.Ssh:
            {
                var o = q.Ssh ??= new SshOptions();
                var cmd = Form.Code(o.Command, 80);
                var port = new NumericUpDown { Value = o.Port, Minimum = 1, Maximum = 65535, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left };
                var keys = Form.Combo(["Strict: only trusted host keys (IPMaster list or known_hosts)", "Trust on first use, reject changed keys", "Accept any host key (lab exception — not verified)"], Index(o.HostKeys));
                f.Add("SSH command", cmd);
                f.Add("Port", port);
                f.Add("Host keys", keys);
                f.Full(Ui.Row(Ui.Button("Trust Host Key of Test Target…", async () =>
                {
                    var host = (target.Text ?? "").Trim();
                    var key = await SshQueryProvider.ProbeHostKeyAsync(host, (int)(port.Value ?? 22), CancellationToken.None);
                    if (key is not { } k)
                    {
                        output.Text = "No SSH host key received from " + host;
                        return;
                    }

                    if (await Dialogs.MessageAsync(w, "Trust host key", $"{host}:{port.Value}\n{k.Algorithm}\nSHA256:{k.Fingerprint}\n\nCompare this fingerprint with the server (ssh-keygen -lf) before trusting it.", confirm: true))
                    {
                        vm.Queries.KnownHosts.Trust(new KnownHostKey { Host = host, Port = (int)(port.Value ?? 22), Algorithm = k.Algorithm, Fingerprint = k.Fingerprint });
                        output.Text = "Host key trusted.";
                    }
                })));
                f.Full(Form.Hint("The credential's password field may hold the full path of an unencrypted private key file instead of a password (manual)."));
                apply.Add(d => d.Ssh = new SshOptions { Command = cmd.Text ?? "", Port = (int)(port.Value ?? 22), HostKeys = At<HostKeyPolicy>(keys) });
                break;
            }

            case QueryKind.Xml:
            case QueryKind.Json:
            {
                var o = q.Http ??= new HttpOptions { Extraction = q.Kind == QueryKind.Json ? HttpExtraction.JsonPath : HttpExtraction.XPath };
                var port = new NumericUpDown { Value = o.Port, Minimum = 1, Maximum = 65535, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left };
                var path = new TextBox { Text = o.Path };
                var https = new CheckBox { Content = "HTTPS", IsChecked = o.UseHttps };
                var basic = new CheckBox { Content = "Basic authentication (uses the selected credential)", IsChecked = o.BasicAuthentication };
                var modes = q.Kind == QueryKind.Json ? new[] { "JSONPath" } : ["XPath (valid XML documents)", "Regex (invalid or non-XML documents)"];
                var mode = Form.Combo(modes, q.Kind == QueryKind.Json ? 0 : o.Extraction == HttpExtraction.Regex ? 1 : 0);
                var expr = new TextBox { Text = o.Expression, FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace") };
                var insecure = new CheckBox { Content = "Accept invalid TLS certificates (lab exception for this item only)", IsChecked = o.AcceptInvalidCertificates };
                f.Add("HTTP port", Ui.Row(port, https));
                f.Add("HTTP path", path);
                f.Full(basic);
                f.Add("Extraction", mode);
                f.Add("Expression", expr);
                f.Full(insecure);
                if (q.Kind == QueryKind.Json)
                {
                    f.Full(Ui.Row(
                        Ui.Button("JSON Query Builder…", async () =>
                        {
                            var r = await Browsers.JsonBuilderAsync(w, vm, (target.Text ?? "").Trim(), (int)(port.Value ?? 80), https.IsChecked == true, path.Text ?? "/", insecure.IsChecked == true, redfish: false);
                            if (r is { } x)
                            {
                                path.Text = x.Path;
                                expr.Text = x.Expression;
                            }
                        }),
                        Ui.Button("Redfish Query Builder…", async () =>
                        {
                            var r = await Browsers.JsonBuilderAsync(w, vm, (target.Text ?? "").Trim(), 443, true, "/redfish/v1", insecure.IsChecked == true, redfish: true);
                            if (r is { } x)
                            {
                                port.Value = 443;
                                https.IsChecked = true;
                                path.Text = x.Path;
                                expr.Text = x.Expression;
                            }
                        })));
                    f.Full(Form.Hint("Builders fetch a sample from the test target without credentials. Redfish usually needs HTTPS and a credential with Basic authentication."));
                }

                apply.Add(d =>
                {
                    var extraction = q.Kind == QueryKind.Json ? HttpExtraction.JsonPath : mode.SelectedIndex == 1 ? HttpExtraction.Regex : HttpExtraction.XPath;
                    d.Http = new HttpOptions
                    {
                        Port = (int)(port.Value ?? 80), Path = (path.Text ?? "/").Trim(), UseHttps = https.IsChecked == true, BasicAuthentication = basic.IsChecked == true,
                        Extraction = extraction, Expression = (expr.Text ?? "").Trim(), AcceptInvalidCertificates = insecure.IsChecked == true,
                    };
                });
                break;
            }

            case QueryKind.Nmap:
            {
                var o = q.Nmap ??= new NmapOptions();
                var type = Form.Combo(["OS detection", "Service version detection", "Execute script (NSE)"], Index(o.ScanType));
                var limit = new CheckBox { Content = "Limit OS detection to promising targets", IsChecked = o.OsLimit };
                var guess = new CheckBox { Content = "Guess OS more aggressively", IsChecked = o.OsGuess };
                var intensity = Form.Combo(["Fast", "Standard", "Thorough"], Index(o.Intensity));
                var script = new TextBox { Text = o.ScriptName, PlaceholderText = "e.g. smb-os-discovery" };
                var args = new TextBox { Text = o.ScriptArgs };
                var xpath = new TextBox { Text = o.XPath, FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace") };
                f.Add("Scan type", type);
                f.Full(Ui.Row(limit, guess));
                f.Add("Version detection", intensity);
                f.Add("NSE script", script);
                f.Add("Script arguments", args);
                f.Add("Response XPath", xpath);
                f.Full(Form.Hint("Examples: /nmaprun/host/os/osmatch[1]/@name · //port[state/@state='open']/service/@product · //script/@output. OS detection needs administrator rights."));
                apply.Add(d => d.Nmap = new NmapOptions
                {
                    ScanType = At<NmapScanType>(type), OsLimit = limit.IsChecked == true, OsGuess = guess.IsChecked == true, Intensity = At<NmapIntensity>(intensity),
                    ScriptName = (script.Text ?? "").Trim(), ScriptArgs = (args.Text ?? "").Trim(), XPath = (xpath.Text ?? "").Trim(),
                });
                break;
            }
        }
    }

    private static void BuildSnmp(Window w, MainWindowViewModel vm, QueryDefinition q, Form f, List<Action<QueryDefinition>> apply, TextBox target, TextBox output,
        Func<Guid?> currentCredential, Action<Guid?> setCredential)
    {
        var o = q.Snmp ??= new SnmpOptions();
        var version = Form.Combo(["SNMPv1", "SNMPv2c", "SNMPv3"], Index(o.Version));
        var communities = Secret(o.Communities);
        var security = Form.Combo(["NoAuthNoPriv", "AuthNoPriv", "AuthPriv"], Index(o.Security));
        var auth = Form.Combo(["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"], Index(o.Auth));
        var priv = Form.Combo(["DES", "3DES", "AES-128", "AES-192 (Reeder extension)", "AES-256 (Reeder extension)", "AES-192-B (Blumenthal)", "AES-256-B (Blumenthal)"], Index(o.Priv));
        var privPass = Secret(o.PrivPassword);
        var oid = new TextBox { Text = o.Oid };
        var symbolic = Form.Info(MibDatabase.SymbolicPath(o.Oid));
        oid.TextChanged += (_, _) => symbolic.Text = MibDatabase.SymbolicPath(oid.Text ?? "");
        var op = Form.Combo(["GET", "GETNEXT", "Walk subtree (GETBULK/GETNEXT)"], Index(o.Operation));
        var display = Form.Combo(["Automatic detection", "ASCII", "HEX"], Index(o.Display));
        var port = new NumericUpDown { Value = o.Port, Minimum = 1, Maximum = 65535, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left };
        var existingCommunities = o.Communities;
        var existingPriv = o.PrivPassword;
        f.Add("Version", version);
        f.Add("Community strings", Form.WithButton(communities, Ui.Button("Clear", () =>
        {
            communities.Text = "";
            communities.Tag = "cleared";
            communities.PlaceholderText = "";
            return Task.CompletedTask;
        })));
        f.Add("v3 security", security);
        f.Add("v3 authentication", auth);
        f.Add("v3 privacy", priv);
        f.Add("v3 privacy password", privPass);
        f.Full(Form.Hint("SNMPv3 user name and authentication password come from the selected credential. An empty privacy password reuses the authentication password. Community strings and passwords are stored encrypted."));
        f.Add("MIB OID", Form.WithButton(oid, Ui.Button("MIB…", async () =>
        {
            if (await Browsers.MibAsync(w) is { } x) oid.Text = x;
        })));
        f.Full(symbolic);
        f.Add("Request", op);
        f.Add("String display", display);
        f.Add("UDP port", port);
        f.Full(Ui.Row(
            Ui.Button("Detect", async () =>
            {
                var cid = currentCredential();
                var credential = cid is { } id ? vm.Vault.Credential(id) : null;
                if (credential is null)
                {
                    output.Text = "Select a credential (user name + authentication password) first, then Detect. Only the supplied credentials are tried.";
                    return;
                }

                if (!IPAddress.TryParse(target.Text, out var ip))
                {
                    output.Text = "Enter the test target as an IP address.";
                    return;
                }

                output.Text = "Detecting with the supplied credentials…";
                var p = (privPass.Text ?? "").Length > 0 ? privPass.Text! : existingPriv.Length > 0 ? vm.Vault.Reveal(existingPriv) : "";
                var (a, pr, msg) = await SnmpQueryProvider.DetectAsync(new IPEndPoint(ip, (int)(port.Value ?? 161)), credential.UserName, credential.Password, p, CancellationToken.None);
                if (a is { } fa) auth.SelectedIndex = Index(fa);
                if (pr is { } fp)
                {
                    priv.SelectedIndex = Index(fp);
                    security.SelectedIndex = Index(SnmpSecurity.AuthPriv);
                }
                else if (a is not null)
                {
                    security.SelectedIndex = Index(SnmpSecurity.AuthNoPriv);
                }

                version.SelectedIndex = Index(SnmpVersion.V3);
                output.Text = msg;
            }),
            Ui.Button("Save Credentials…", async () =>
            {
                var n = await Dialogs.PromptAsync(w, "Save SNMP credentials", "Name", "");
                if (string.IsNullOrWhiteSpace(n)) return;
                var profile = new SnmpProfile
                {
                    Name = n.Trim(), Version = At<SnmpVersion>(version), Communities = Protect(vm, communities, existingCommunities), Security = At<SnmpSecurity>(security),
                    Auth = At<SnmpAuth>(auth), Priv = At<SnmpPriv>(priv), CredentialId = currentCredential(), PrivPassword = Protect(vm, privPass, existingPriv),
                };
                await vm.SaveQueriesAsync(vm.Settings.Queries with { SnmpProfiles = vm.Settings.Queries.SnmpProfiles.Where(x => x.Name != profile.Name).Append(profile).ToList() });
                output.Text = $"Saved '{profile.Name}'.";
            }),
            Ui.Button("Load Credentials…", async () =>
            {
                var profiles = vm.Settings.Queries.SnmpProfiles;
                if (profiles.Count == 0)
                {
                    output.Text = "No saved SNMP credentials.";
                    return;
                }

                if (await Dialogs.ChoiceAsync(w, "Load SNMP credentials", "Choose:", profiles.Select(p => $"{p.Name} ({p.Version})").ToList()) is not { } i) return;
                var pr = profiles[i];
                version.SelectedIndex = Index(pr.Version);
                security.SelectedIndex = Index(pr.Security);
                auth.SelectedIndex = Index(pr.Auth);
                priv.SelectedIndex = Index(pr.Priv);
                existingCommunities = pr.Communities;
                existingPriv = pr.PrivPassword;
                communities.Text = "";
                privPass.Text = "";
                communities.PlaceholderText = pr.Communities.Length > 0 ? Unchanged : "";
                privPass.PlaceholderText = pr.PrivPassword.Length > 0 ? Unchanged : "";
                setCredential(pr.CredentialId);
                output.Text = $"Loaded '{pr.Name}'.";
            })));
        apply.Add(d =>
        {
            var expanded = (oid.Text ?? "").Trim();
            if (!SnmpText.IsOid(expanded.Replace("%0", "0", StringComparison.Ordinal).Replace("%1", "0", StringComparison.Ordinal).TrimStart('.')))
            {
                throw new FormatException("The OID must be numeric (use the MIB browser), e.g. 1.3.6.1.2.1.1.1.0.");
            }

            d.Snmp = new SnmpOptions
            {
                Version = At<SnmpVersion>(version), Communities = Protect(vm, communities, existingCommunities), Security = At<SnmpSecurity>(security), Auth = At<SnmpAuth>(auth),
                Priv = At<SnmpPriv>(priv), PrivPassword = Protect(vm, privPass, existingPriv), Oid = expanded, Operation = At<SnmpOperation>(op),
                Display = At<SnmpDisplay>(display), Port = (int)(port.Value ?? 161),
            };
        });
    }

    private static ComboBox Templates(TextBox script, ComboBox lang)
    {
        (string Name, string Vbs, string Js)[] t =
        [
            ("Insert template…", "", ""),
            ("Write the address", "Output.Write Input.Current", "Output.Write(Input.Current);"),
            ("Read another column", "Output.Write Input.Column(\"Host Name\")", "Output.Write(Input.Column(\"Host Name\"));"),
            ("Run another item", "Output.Write Remote.WMI(\"Windows Name\")", "Output.Write(Remote.WMI(\"Windows Name\"));"),
            ("Run a console program", "Set p = Internal.CreateObject(\"Process\")\r\np.Execute \"ping -n 1 \" & Input.Current\r\nOutput.Write p.ExitCode",
                "var p = Internal.CreateObject(\"Process\");\np.Execute(\"ping -n 1 \" + Input.Current);\nOutput.Write(p.ExitCode);"),
            ("DNS lookup", "Set d = Internal.CreateObject(\"DNS\")\r\nOutput.Write d.GetName(Input.Current, \"ptr\")",
                "var d = Internal.CreateObject(\"DNS\");\nOutput.Write(d.GetName(Input.Current, \"ptr\"));"),
            ("SNMP request", "Set s = Internal.CreateObject(\"SNMP\")\r\ns.Host = Input.Current\r\ns.Query.Community = \"public\"\r\ns.Query.AddOid \"1.3.6.1.2.1.1.5.0\"\r\nIf s.SendRequest Then Output.Write s.Reply.Items(0).Value",
                "var s = Internal.CreateObject(\"SNMP\");\ns.Host = Input.Current;\ns.Query.Community = \"public\";\ns.Query.AddOid(\"1.3.6.1.2.1.1.5.0\");\nif (s.SendRequest()) Output.Write(s.Reply.Items[0].Value);"),
        ];
        var c = Form.Combo(t.Select(x => x.Name), 0);
        c.SelectionChanged += (_, _) =>
        {
            if (c.SelectedIndex <= 0) return;
            var snippet = lang.SelectedIndex == 1 ? t[c.SelectedIndex].Js : t[c.SelectedIndex].Vbs;
            script.Text = (script.Text ?? "").TrimEnd() + (string.IsNullOrWhiteSpace(script.Text) ? "" : Environment.NewLine) + snippet;
            c.SelectedIndex = 0;
        };
        return c;
    }
}
