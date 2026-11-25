using System.Text.Json.Nodes;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Queries;
using IPMaster.Core.Security;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Security;
using Microsoft.Win32;

namespace IPMaster.Desktop.Views;

/// <summary>Builders and browsers used by the query editors (WMI-01, REG-04, PRF-01, SNM-05, HTP-02/03).</summary>
internal static class Browsers
{
    private static Button Cancel(Window w) => Ui.Button("Cancel", () =>
    {
        w.Close();
        return Task.CompletedTask;
    });

    /// <summary>Filterable single-choice list.</summary>
    public static async Task<string?> PickAsync(Window owner, string title, IReadOnlyList<(string Value, string Label)> items)
    {
        var w = Ui.Window(title, 560, 520);
        var filter = new TextBox { PlaceholderText = "Filter" };
        var list = new ListBox { ItemsSource = items.Select(i => i.Label).ToList() };
        filter.TextChanged += (_, _) => list.ItemsSource = items.Where(i => i.Label.Contains(filter.Text ?? "", StringComparison.OrdinalIgnoreCase)).Select(i => i.Label).ToList();
        string? result = null;
        void Accept()
        {
            if (list.SelectedItem is string label) result = items.First(i => i.Label == label).Value;
            w.Close();
        }

        list.DoubleTapped += (_, _) => Accept();
        w.Content = Ui.Layout(filter, list, Ui.Row(Ui.Button("OK", () =>
        {
            Accept();
            return Task.CompletedTask;
        }, accent: true), Cancel(w)));
        await w.ShowDialog(owner);
        return result;
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static IReadOnlyList<(string, string)> LocalServices()
    {
        return System.ServiceProcess.ServiceController.GetServices().OrderBy(s => s.ServiceName, StringComparer.OrdinalIgnoreCase)
            .Select(s => (s.ServiceName, $"{s.ServiceName} — {s.DisplayName}")).ToList();
    }

    public static IReadOnlyList<(string, string)> LocalAccounts()
    {
        if (!OperatingSystem.IsWindows()) return [];
        var list = new List<(string, string)>();
        foreach (var (cls, kind) in new[] { ("Win32_Group", "group"), ("Win32_UserAccount", "user") })
        {
            var r = WmiQueryProvider.Query(new WmiOptions { Query = $"SELECT Name FROM {cls} WHERE LocalAccount = TRUE" }, ".", null, TimeSpan.FromSeconds(20));
            if (r.Value is { } v) list.AddRange(v.Split('\n').Select(n => (n, $"{n} ({kind})")));
        }

        return list;
    }

    public static async Task<(string Query, string Namespace)?> WmiBuilderAsync(Window owner, string ns)
    {
        if (!OperatingSystem.IsWindows())
        {
            await Dialogs.MessageAsync(owner, "WMI Query Builder", "The WMI browser needs Windows.", confirm: false);
            return null;
        }

        var w = Ui.Window("WMI Query Builder", 960, 620);
        var nsBox = new TextBox { Text = ns, Width = 200 };
        var find = new TextBox { PlaceholderText = "Find class or property", Width = 260 };
        var classes = new ListBox();
        var props = Ui.Grid(("Property", "Item1", 220), ("Example value (this computer)", "Item2", 0));
        var status = new TextBlock { Opacity = 0.75 };
        var query = new TextBox { FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace") };
        async Task LoadClasses()
        {
            status.Text = "Reading classes…";
            var n = nsBox.Text ?? @"root\cimv2";
            var f = find.Text ?? "";
            try
            {
                var list = await Task.Run(() => OperatingSystem.IsWindows() ? WmiQueryProvider.LocalClasses(n, f) : []);
                classes.ItemsSource = list;
                status.Text = $"{list.Count} class(es).";
            }
            catch (Exception ex) when (ex is System.Management.ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            {
                status.Text = ex.Message;
            }
        }

        classes.SelectionChanged += async (_, _) =>
        {
            if (classes.SelectedItem is not string cls) return;
            status.Text = "Reading " + cls + "…";
            var n = nsBox.Text ?? @"root\cimv2";
            try
            {
                var p = await Task.Run(() => OperatingSystem.IsWindows() ? WmiQueryProvider.LocalProperties(n, cls) : []);
                props.ItemsSource = p.Select(x => Tuple.Create(x.Name, x.Example)).ToList();
                query.Text = $"SELECT * FROM {cls}";
                status.Text = "Select one or more properties.";
            }
            catch (Exception ex) when (ex is System.Management.ManagementException or UnauthorizedAccessException or System.Runtime.InteropServices.COMException)
            {
                status.Text = ex.Message;
            }
        };
        props.SelectionChanged += (_, _) =>
        {
            if (classes.SelectedItem is not string cls) return;
            var sel = props.SelectedItems.OfType<Tuple<string, string>>().Select(t => t.Item1).ToList();
            query.Text = $"SELECT {(sel.Count == 0 ? "*" : string.Join(", ", sel))} FROM {cls}";
        };
        (string, string)? result = null;
        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("320,*"), ColumnSpacing = 8 };
        Grid.SetColumn(props, 1);
        split.Children.Add(classes);
        split.Children.Add(props);
        w.Content = Ui.Layout(Ui.Row(new TextBlock { Text = "Namespace", VerticalAlignment = VerticalAlignment.Center }, nsBox, find, Ui.Button("Find Class or Property", LoadClasses)),
            split,
            new StackPanel
            {
                Spacing = 6,
                Children =
                {
                    query, status,
                    Ui.Row(Ui.Button("OK", () =>
                    {
                        result = (query.Text ?? "", nsBox.Text ?? @"root\cimv2");
                        w.Close();
                        return Task.CompletedTask;
                    }, accent: true), Cancel(w)),
                },
            });
        w.Opened += async (_, _) => await LoadClasses();
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>Two-panel registry browser of this computer: subkeys on the left, values on the right.</summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public static async Task<(string Key, string? Value)?> RegistryAsync(Window owner, RegistryRoot root, string start)
    {
        var hive = root switch { RegistryRoot.Users => RegistryHive.Users, RegistryRoot.CurrentUser => RegistryHive.CurrentUser, _ => RegistryHive.LocalMachine };
        using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
        var w = Ui.Window("Registry Browser — " + root, 940, 580);
        var path = new TextBox { Text = start.Trim('\\') };
        var keys = new ListBox();
        var values = Ui.Grid(("Name", "Item1", 200), ("Type", "Item2", 110), ("Data", "Item3", 0));
        var status = new TextBlock { Opacity = 0.75 };
        void Show(string p)
        {
            try
            {
                using var k = p.Length == 0 ? null : baseKey.OpenSubKey(p);
                var key = p.Length == 0 ? baseKey : k;
                if (key is null)
                {
                    status.Text = "Key not found.";
                    return;
                }

                path.Text = p;
                keys.ItemsSource = key.GetSubKeyNames().Order(StringComparer.OrdinalIgnoreCase).Prepend("..").ToList();
                values.ItemsSource = key.GetValueNames().Order(StringComparer.OrdinalIgnoreCase).Select(n => Tuple.Create(n.Length == 0 ? "(Default)" : n,
                    key.GetValueKind(n).ToString(), RegistryQueryProvider.Format(key.GetValue(n, "", RegistryValueOptions.DoNotExpandEnvironmentNames) ?? ""))).ToList();
                status.Text = "";
            }
            catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                status.Text = ex.Message;
            }
        }

        keys.DoubleTapped += (_, _) =>
        {
            if (keys.SelectedItem is not string s) return;
            var current = path.Text ?? "";
            Show(s == ".." ? (current.Contains('\\', StringComparison.Ordinal) ? current[..current.LastIndexOf('\\')] : "") : (current.Length == 0 ? s : current + "\\" + s));
        };
        (string, string?)? result = null;
        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("340,*"), ColumnSpacing = 8 };
        Grid.SetColumn(values, 1);
        split.Children.Add(keys);
        split.Children.Add(values);
        w.Content = Ui.Layout(Ui.Row(Ui.Button("Go", () =>
            {
                Show((path.Text ?? "").Trim('\\'));
                return Task.CompletedTask;
            }), path),
            split,
            new StackPanel
            {
                Spacing = 6,
                Children =
                {
                    Form.Hint("Double-click a key to open it. Select a value and press OK to use the key and value name."), status,
                    Ui.Row(Ui.Button("OK", () =>
                    {
                        var v = (values.SelectedItem as Tuple<string, string, string>)?.Item1;
                        result = (path.Text ?? "", v == "(Default)" ? "" : v);
                        w.Close();
                        return Task.CompletedTask;
                    }, accent: true), Cancel(w)),
                },
            });
        path.MinWidth = 600;
        w.Opened += (_, _) => Show(start.Trim('\\'));
        await w.ShowDialog(owner);
        return result;
    }

    public static async Task<string?> CountersAsync(Window owner)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var paths = await Task.Run(() => OperatingSystem.IsWindows() ? PerformanceQueryProvider.LocalCounterPaths("", 20_000) : []);
        return await PickAsync(owner, "Performance Counters (this computer)", paths.Select(p => (p, p)).ToList());
    }

    public static async Task<string?> MibAsync(Window owner)
    {
        var w = Ui.Window("MIB Browser", 940, 560);
        var search = new TextBox { PlaceholderText = "Type a name or an OID (e.g. sysName, 1.3.6.1.2.1.25, toner)" };
        var grid = Ui.Grid(("Name", "Name", 220), ("OID", "Oid", 220), ("Module", "Module", 150), ("Description", "Description", 0));
        var path = new SelectableTextBlock { TextWrapping = TextWrapping.Wrap };
        search.TextChanged += (_, _) => grid.ItemsSource = MibDatabase.Search(search.Text ?? "");
        grid.SelectionChanged += (_, _) =>
        {
            if (grid.SelectedItem is MibEntry e) path.Text = MibDatabase.SymbolicPath(e.Oid) + (e.IsColumn ? "   (table column: append an index, e.g. .1, or use Walk)" : "");
        };
        grid.ItemsSource = MibDatabase.Search("");
        string? result = null;
        grid.DoubleTapped += (_, _) =>
        {
            result = (grid.SelectedItem as MibEntry)?.Oid;
            w.Close();
        };
        w.Content = Ui.Layout(search, grid, new StackPanel
        {
            Spacing = 6,
            Children =
            {
                path, Form.Hint("Built-in standard MIB objects (RFC MIBs). Vendor MIB files are not included; enter vendor OIDs numerically."),
                Ui.Row(Ui.Button("OK", () =>
                {
                    result = (grid.SelectedItem as MibEntry)?.Oid;
                    w.Close();
                    return Task.CompletedTask;
                }, accent: true), Cancel(w)),
            },
        });
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>
    /// JSON / Redfish query builder: fetches a sample from the test target, shows it as a tree and turns the selected
    /// node into a JSONPath. In Redfish mode "@odata.id" links can be followed to browse resources.
    /// </summary>
    public static async Task<(string Path, string Expression)?> JsonBuilderAsync(Window owner, MainWindowViewModel vm, string host, int port, bool https,
        string startPath, bool acceptInvalidCertificates, bool redfish)
    {
        var w = Ui.Window(redfish ? "Redfish Query Builder" : "JSON Query Builder", 900, 640);
        var hostBox = new TextBox { Text = host, Width = 180, PlaceholderText = "IP address" };
        var pathBox = new TextBox { Text = startPath, MinWidth = 300 };
        var tree = new TreeView();
        var expr = new TextBox { FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace") };
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap, Classes = { "status" } };
        var credItems = new List<(Guid? Id, string Label)> { (null, "(no authentication)") };
        credItems.AddRange(vm.Settings.Credentials.Select(c => ((Guid?)c.Id, c.Display)));
        var cred = Form.Combo(credItems.Select(c => c.Label), 0);
        var nodes = 0;

        TreeViewItem Node(string label, JsonNode? n, string jsonPath)
        {
            nodes++;
            var item = new TreeViewItem { Header = label, Tag = jsonPath };
            if (nodes > 5000) return item;
            switch (n)
            {
                case JsonObject o:
                    foreach (var (k, v) in o)
                    {
                        var p = IsSimple(k) ? $"{jsonPath}.{k}" : $"{jsonPath}['{k.Replace("'", "\\'", StringComparison.Ordinal)}']";
                        var child = Node(v is JsonValue ? $"{k}: {JsonPath.Text(v)}" : k, v, p);
                        if (redfish && k == "@odata.id" && v is JsonValue link) child.Header = $"{k}: {JsonPath.Text(link)}   (double-click to open)";
                        if (redfish && k == "@odata.id") child.Tag = "link:" + JsonPath.Text(v);
                        item.Items.Add(child);
                    }

                    break;
                case JsonArray a:
                    for (var i = 0; i < a.Count; i++) item.Items.Add(Node(a[i] is JsonValue ? $"[{i}]: {JsonPath.Text(a[i])}" : $"[{i}]", a[i], $"{jsonPath}[{i}]"));
                    break;
            }

            return item;
        }

        async Task Fetch()
        {
            if (!System.Net.IPAddress.TryParse(hostBox.Text, out var ip))
            {
                status.Text = "Enter the device as an IP address.";
                return;
            }

            var o = new HttpOptions { Port = port, Path = pathBox.Text ?? "/", UseHttps = https, AcceptInvalidCertificates = acceptInvalidCertificates };
            var credential = credItems[Math.Max(0, cred.SelectedIndex)].Id is { } id ? vm.Vault.Credential(id) : null;
            status.Text = "Fetching " + HttpQueryProvider.BuildUri(ip, o) + "…";
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                var (code, body) = await HttpQueryProvider.FetchAsync(HttpQueryProvider.BuildUri(ip, o), credential, acceptInvalidCertificates, cts.Token);
                var root = JsonNode.Parse(body);
                nodes = 0;
                tree.ItemsSource = new[] { Node("$", root, "$") };
                status.Text = $"HTTP {(int)code}. Select a value to build its JSONPath." + (nodes > 5000 ? " (tree truncated)" : "");
            }
            catch (Exception ex) when (ex is HttpRequestException or System.Text.Json.JsonException or InvalidOperationException or TaskCanceledException)
            {
                status.Text = ex.Message;
            }
        }

        tree.SelectionChanged += (_, _) =>
        {
            if (tree.SelectedItem is TreeViewItem { Tag: string p } && !p.StartsWith("link:", StringComparison.Ordinal)) expr.Text = p;
        };
        tree.DoubleTapped += async (_, _) =>
        {
            if (tree.SelectedItem is TreeViewItem { Tag: string p } && p.StartsWith("link:", StringComparison.Ordinal))
            {
                pathBox.Text = p[5..];
                await Fetch();
            }
        };
        (string, string)? result = null;
        w.Content = Ui.Layout(
            new StackPanel
            {
                Spacing = 6,
                Children =
                {
                    Ui.Row(new TextBlock { Text = "Device", VerticalAlignment = VerticalAlignment.Center }, hostBox, new TextBlock { Text = $"{(https ? "https" : "http")}:{port}", VerticalAlignment = VerticalAlignment.Center }, pathBox, Ui.Button("Fetch", Fetch, accent: true)),
                    Ui.Row(new TextBlock { Text = "Authentication", VerticalAlignment = VerticalAlignment.Center }, cred),
                },
            },
            tree,
            new StackPanel
            {
                Spacing = 6,
                Children =
                {
                    Ui.Row(new TextBlock { Text = "JSONPath", VerticalAlignment = VerticalAlignment.Center }), expr, status,
                    Ui.Row(Ui.Button("OK", () =>
                    {
                        result = (pathBox.Text ?? "/", expr.Text ?? "$");
                        w.Close();
                        return Task.CompletedTask;
                    }, accent: true), Cancel(w)),
                },
            });
        w.Opened += async (_, _) =>
        {
            if (hostBox.Text is { Length: > 0 }) await Fetch();
        };
        await w.ShowDialog(owner);
        return result;
    }

    private static bool IsSimple(string k) => k.Length > 0 && k.All(c => char.IsLetterOrDigit(c) || c is '_' or '@') && !char.IsDigit(k[0]);
}

/// <summary>Masked password prompts.</summary>
internal static class PasswordDialog
{
    public static async Task<string?> AskAsync(Window owner, string title, string message, bool confirm)
    {
        var w = Ui.Window(title, 460, 240);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var p1 = new TextBox { PasswordChar = '•' };
        var p2 = new TextBox { PasswordChar = '•', IsVisible = confirm, PlaceholderText = "Repeat" };
        var error = new TextBlock { Classes = { "error" } };
        string? result = null;
        var ok = Ui.Button("OK", () =>
        {
            if (string.IsNullOrEmpty(p1.Text))
            {
                error.Text = "Enter a password.";
                return Task.CompletedTask;
            }

            if (confirm && p1.Text != p2.Text)
            {
                error.Text = "The passwords do not match.";
                return Task.CompletedTask;
            }

            if (confirm && p1.Text.Length < 10)
            {
                error.Text = "Use at least 10 characters.";
                return Task.CompletedTask;
            }

            result = p1.Text;
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        p1.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter && !confirm) ok.Command?.Execute(null);
        };
        w.Content = new StackPanel
        {
            Margin = new Thickness(16), Spacing = 8,
            Children = { new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap }, p1, p2, error, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) },
        };
        w.Opened += (_, _) => p1.Focus();
        await w.ShowDialog(owner);
        return result;
    }
}

/// <summary>Manual "Credential Manager" (SEC-01): user name, hidden password, comment, unique tag; encrypted import/export.</summary>
internal static class CredentialManagerWindow
{
    public sealed record Row(StoredCredential Credential, string UserName, string Password, string Comment, string Tag);

    public static async Task ShowAsync(Window owner, MainWindowViewModel vm)
    {
        var w = Ui.Window("Credential Manager", 760, 460);
        var grid = Ui.Grid(("Username", "UserName", 200), ("Password", "Password", 110), ("Comment", "Comment", 0), ("Tag", "Tag", 120));
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap, Classes = { "status" } };
        var list = vm.Settings.Credentials.ToList();
        void Refresh()
        {
            grid.ItemsSource = list.Select(c => new Row(c, c.UserName, c.Secret.Length > 0 ? "••••••••" : "", c.Comment, c.Tag)).ToList();
            status.Text = vm.Vault.Mode switch
            {
                VaultMode.OsProtected => "Passwords are encrypted with a key protected by Windows for your user account (not portable to other computers or users).",
                VaultMode.MasterPassword => "Passwords and the whole configuration are encrypted with your master password (portable).",
                _ => CredentialVault.OsProtectionAvailable ? "The vault key is created when you save the first credential." : "Set a master password (File → Current Config) before storing credentials.",
            } + (vm.Vault.Problem is { } p ? "\n⚠ " + p : "");
        }

        async Task<bool> Persist()
        {
            if (CredentialVault.ValidateTags(list) is { } err)
            {
                await Dialogs.MessageAsync(w, "Credential Manager", err, confirm: false);
                return false;
            }

            await vm.SaveCredentialsAsync(list.ToList());
            Refresh();
            return true;
        }

        async Task<StoredCredential?> Edit(StoredCredential? existing)
        {
            try
            {
                vm.EnsureVaultKey();
            }
            catch (InvalidOperationException ex)
            {
                await Dialogs.MessageAsync(w, "Credential Manager", ex.Message, confirm: false);
                return null;
            }

            var d = Ui.Window(existing is null ? "Add Credential" : "Edit Credential", 480, 300);
            d.Height = double.NaN;
            d.MinHeight = 0;
            d.SizeToContent = SizeToContent.Height;
            var f = new Form();
            var user = f.Add("Username", new TextBox { Text = existing?.UserName ?? "", PlaceholderText = @"DOMAIN\user, user@domain or user" });
            var pass = f.Add("Password", new TextBox { PasswordChar = '•', PlaceholderText = existing is { Secret.Length: > 0 } ? "(unchanged)" : "" });
            var comment = f.Add("Comment", new TextBox { Text = existing?.Comment ?? "" });
            var tag = f.Add("Tag", new TextBox { Text = existing?.Tag ?? "", PlaceholderText = "unique short name for scripts" });
            f.Full(Form.Hint("For SSH public-key authentication, enter the full path of the private key file as the password."));
            var error = new TextBlock { Classes = { "error" } };
            StoredCredential? result = null;
            var ok = Ui.Button("OK", () =>
            {
                if (string.IsNullOrWhiteSpace(user.Text))
                {
                    error.Text = "Enter a user name.";
                    return Task.CompletedTask;
                }

                result = new StoredCredential
                {
                    Id = existing?.Id ?? Guid.NewGuid(), UserName = user.Text.Trim(), Comment = comment.Text ?? "", Tag = (tag.Text ?? "").Trim(),
                    Secret = string.IsNullOrEmpty(pass.Text) ? existing?.Secret ?? "" : vm.Vault.Protect(pass.Text),
                };
                d.Close();
                return Task.CompletedTask;
            }, accent: true);
            d.Content = new StackPanel { Margin = new Thickness(16), Spacing = 8, Children = { f.Grid, error, Ui.Row(ok, Ui.Button("Cancel", () => { d.Close(); return Task.CompletedTask; })) } };
            await d.ShowDialog(w);
            return result;
        }

        var buttons = Ui.Row(
            Ui.Button("Add…", async () =>
            {
                if (await Edit(null) is { } c)
                {
                    list.Add(c);
                    if (!await Persist()) list.Remove(c);
                }
            }, accent: true),
            Ui.Button("Edit…", async () =>
            {
                if (grid.SelectedItem is not Row r || await Edit(r.Credential) is not { } c) return;
                var i = list.FindIndex(x => x.Id == c.Id);
                var old = list[i];
                list[i] = c;
                if (!await Persist()) list[i] = old;
            }),
            Ui.Button("Delete", async () =>
            {
                if (grid.SelectedItem is not Row r) return;
                var users = vm.Settings.Queries.Items.Where(q => q.CredentialId == r.Credential.Id).Select(q => q.Name).ToList();
                if (!await Dialogs.MessageAsync(w, "Delete", $"Delete {r.UserName}?" + (users.Count > 0 ? $"\nUsed by: {string.Join(", ", users)}" : ""), confirm: true)) return;
                list.Remove(r.Credential);
                await Persist();
            }),
            Ui.Button("Export…", async () =>
            {
                if (list.Count == 0) return;
                var pw = await PasswordDialog.AskAsync(w, "Export Credentials", "Choose a password for the export file. It is needed to import the file.", confirm: true);
                if (pw is null) return;
                var file = await w.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Export", DefaultExtension = "ipmcred", FileTypeChoices = [new("IPMaster credentials") { Patterns = ["*.ipmcred"] }] });
                if (file?.TryGetLocalPath() is not { } path) return;
                try
                {
                    await File.WriteAllBytesAsync(path, vm.Vault.Export(list, pw));
                    status.Text = $"Exported {list.Count} credential(s), encrypted.";
                }
                catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException)
                {
                    status.Text = ex.Message;
                }
            }),
            Ui.Button("Import…", async () =>
            {
                var files = await w.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Import", FileTypeFilter = [new("IPMaster credentials") { Patterns = ["*.ipmcred"] }] });
                if (files.Count == 0 || files[0].TryGetLocalPath() is not { } path) return;
                var pw = await PasswordDialog.AskAsync(w, "Import Credentials", "Password of the export file:", confirm: false);
                if (pw is null) return;
                try
                {
                    vm.EnsureVaultKey();
                    var imported = vm.Vault.Import(await File.ReadAllBytesAsync(path), pw);
                    foreach (var c in imported)
                    {
                        if (c.Tag.Length > 0 && list.Any(x => string.Equals(x.Tag, c.Tag, StringComparison.OrdinalIgnoreCase))) c.Tag += "-imported";
                        list.Add(c);
                    }

                    await Persist();
                    status.Text = $"Imported {imported.Count} credential(s).";
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    status.Text = "Wrong password or damaged file.";
                }
                catch (Exception ex) when (ex is FormatException or InvalidOperationException or IOException or System.Text.Json.JsonException)
                {
                    status.Text = ex.Message;
                }
            }),
            Ui.Button("Close", () =>
            {
                w.Close();
                return Task.CompletedTask;
            }));
        w.Content = Ui.Layout(null, grid, new StackPanel { Spacing = 8, Children = { status, buttons } });
        Refresh();
        await w.ShowDialog(owner);
    }
}
