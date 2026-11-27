using System.Collections.ObjectModel;
using System.Globalization;
using System.Net.Sockets;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Discovery;
using IPMaster.Core.Management;
using IPMaster.Core.Results;
using IPMaster.Infrastructure.Discovery;
using IPMaster.Infrastructure.Management;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Primitives of the design system for code-built windows (D-098, docs/DEVELOPMENT.md): buttons, wrapping rows,
/// grids, banners and the page layout. Tool windows compose these through <see cref="ToolKit"/>; looks come from
/// Styling/Controls.axaml classes and Styling/Theme.cs constants, never from local colours or ad-hoc spacing.
/// </summary>
internal static class Ui
{
    public static Button Button(string text, Func<Task> action, bool accent = false)
    {
        var b = new Button { Content = text };
        if (accent) b.Classes.Add("accent");
        b.Click += async (_, _) => await action();
        return b;
    }

    /// <summary>A row of controls that wraps onto the next line when the window is narrow, so no action is cut off (D-098).</summary>
    public static WrapPanel Row(params Control[] controls)
    {
        var p = new WrapPanel { Orientation = Orientation.Horizontal, ItemSpacing = Styling.Theme.ControlGap, LineSpacing = Styling.Theme.TightGap };
        foreach (var c in controls) p.Children.Add(c);
        return p;
    }

    public static DataGrid Grid(params (string Header, string Path, double Width)[] columns)
    {
        var g = new DataGrid { IsReadOnly = true, HeadersVisibility = DataGridHeadersVisibility.Column, SelectionMode = DataGridSelectionMode.Extended, CanUserSortColumns = true, CanUserResizeColumns = true };
        foreach (var (h, p, w) in columns)
        {
            // never narrower than the header (title plus sort glyph); fill columns keep a usable minimum
            var headerWidth = (h.Length * 8.0) + 44;
            g.Columns.Add(new DataGridTextColumn
            {
                Header = h, Binding = new ReflectionBinding(p), MinWidth = w <= 0 ? Math.Max(headerWidth, 120) : headerWidth,
                Width = w <= 0 ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(Math.Max(w, headerWidth)),
            });
        }

        return g;
    }

    public static DockPanel Layout(Control? top, Control center, Control? bottom)
    {
        var d = new DockPanel { Margin = Styling.Theme.Page };
        if (top is not null)
        {
            top.Margin = new Thickness(0, 0, 0, Styling.Theme.SectionGap);
            DockPanel.SetDock(top, Dock.Top);
            d.Children.Add(top);
        }

        if (bottom is not null)
        {
            bottom.Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0);
            DockPanel.SetDock(bottom, Dock.Bottom);
            d.Children.Add(bottom);
        }

        d.Children.Add(center);
        return d;
    }

    /// <summary>
    /// A tinted message box (classes "banner" plus a state: warning, error, success, info): safety warnings, verdicts.
    /// The text keeps the normal foreground; the state is also in the wording (never colour alone).
    /// </summary>
    public static Border Banner(string text, string state, bool visible = true) => new()
    {
        Classes = { Styling.Theme.Classes.Banner, state }, IsVisible = visible, Child = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap },
    };

    /// <summary>
    /// A short visible line with its full explanation as a tooltip and as accessible help text: utility windows stay
    /// compact without hiding the detail. Safety, privacy and error texts are shown in full instead.
    /// </summary>
    public static TextBlock Explained(string text, string details)
    {
        var t = new TextBlock { Text = text + " ⓘ", Classes = { "hint" } };
        ToolTip.SetTip(t, details);
        Avalonia.Automation.AutomationProperties.SetHelpText(t, details);
        return t;
    }

    public static Window Window(string title, double w, double h) =>
        new() { Title = title, Width = w, Height = h, MinWidth = Styling.Theme.DialogMinWidth, MinHeight = Styling.Theme.DialogMinHeight, WindowStartupLocation = WindowStartupLocation.CenterOwner };

    public static async Task CopyAsync(Window w, string text)
    {
        if (w.Clipboard is not null) await w.Clipboard.SetTextAsync(text);
    }
}

/// <summary>UPnP / mDNS / WSD / ONVIF discovery (manual: Device Type, Device Name, IP, UI URL; ONVIF: brand, firmware, stream).</summary>
internal sealed class DiscoveryWindow : Window
{
    public sealed record Row(string Type, string Name, string Ip, string Url, string BrandModel, string FirmwareSerial, DiscoveredDevice Device);

    public DiscoveryWindow(string title, DiscoveryProtocol protocol, Func<string?, string?, CancellationToken, Task<IReadOnlyList<DiscoveredDevice>>> discover)
    {
        Title = title;
        Width = 900;
        Height = 520;
        MinWidth = 480;
        MinHeight = 300;
        var onvif = protocol == DiscoveryProtocol.Onvif;
        var grid = onvif
            ? Ui.Grid(("Brand & Model", "BrandModel", 220), ("Firmware & Serial", "FirmwareSerial", 200), ("IP Address", "Ip", 140), ("Stream URL", "Url", 0))
            : Ui.Grid(("Device Type", "Type", 180), ("Device Name", "Name", 220), ("IP Address", "Ip", 140), ("Device User Interface", "Url", 0));
        var status = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Classes = { "status" } };
        var user = new TextBox { PlaceholderText = "user", Width = 140 };
        var pass = new TextBox { PlaceholderText = "password", Width = 140, PasswordChar = '•' };
        CancellationTokenSource? cts = null;
        Button? scan = null;

        async Task ScanAsync()
        {
            cts?.Cancel();
            cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            scan!.IsEnabled = false;
            status.Text = "Discovering…";
            try
            {
                var list = await discover(onvif ? user.Text : null, onvif ? pass.Text : null, cts.Token);
                grid.ItemsSource = list.Select(d => new Row(d.DeviceType, d.Name, d.Address.ToString(), d.Url,
                    string.Join(" ", new[] { d.Manufacturer, d.Model }.Where(s => s.Length > 0)),
                    string.Join(" / ", new[] { d.Firmware, d.Serial }.Where(s => s.Length > 0)), d)).ToList();
                status.Text = $"{list.Count} device(s) found." + (list.Count == 0
                    ? " Devices may not answer, multicast may be filtered by the network, or a firewall may block the replies."
                    : "");
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or InvalidOperationException)
            {
                status.Text = "Discovery failed: " + ex.Message;
            }
            finally
            {
                scan!.IsEnabled = true;
            }
        }

        scan = Ui.Button("Scan Devices", ScanAsync, accent: true);
        var open = Ui.Button("Open", () =>
        {
            if (grid.SelectedItem is Row r && r.Url.Length > 0) status.Text = Shell.OpenUrl(r.Url).Message;
            return Task.CompletedTask;
        });
        var props = Ui.Button("Properties", async () =>
        {
            if (grid.SelectedItem is Row r) await Dialogs.MessageAsync(this, r.Name.Length > 0 ? r.Name : r.Ip,
                string.Join(Environment.NewLine, r.Device.Details.Select(kv => $"{kv.Key}: {kv.Value}")), confirm: false);
        });
        var copy = Ui.Button("Copy", () => Ui.CopyAsync(this, string.Join(Environment.NewLine,
            (grid.SelectedItems.Count > 0 ? grid.SelectedItems.OfType<Row>() : (grid.ItemsSource as IEnumerable<Row>) ?? []).Select(r => $"{r.Type}\t{r.Name}\t{r.Ip}\t{r.Url}"))));
        grid.DoubleTapped += (_, _) =>
        {
            if (grid.SelectedItem is Row r && r.Url.Length > 0) status.Text = Shell.OpenUrl(r.Url).Message;
        };
        var top = onvif ? Ui.Row(scan, new TextBlock { Text = "Credentials (optional):", VerticalAlignment = VerticalAlignment.Center }, user, pass) : Ui.Row(scan);
        Content = Ui.Layout(top, grid, Ui.Row(open, props, copy, status));
        Opened += async (_, _) => await ScanAsync();
        Closed += (_, _) => cts?.Cancel();
    }
}

/// <summary>
/// Manual "DHCP Server Discovery" plus DHCP diagnostics (D-095): probe with one DISCOVER (never a REQUEST: no lease is
/// taken or changed) or listen only (sends nothing); adapter choice, response times, expected servers, option comparison.
/// Nothing is sent until the user asks (C-13: the window no longer probes when it opens).
/// </summary>
internal sealed class DhcpWindow : Window
{
    public sealed record Row(string Type, string Server, string Offered, string Gateway, string Dns, string Client, string Response, DhcpOffer Offer);

    public DhcpWindow(DhcpDiscovery dhcp, string customOptions, Func<string, Task> saveCustomOptions)
    {
        Title = "DHCP Server Discovery & Diagnostics";
        Width = 1000;
        Height = 640;
        MinWidth = Styling.Theme.ToolMinWidth;
        MinHeight = Styling.Theme.ToolMinHeight;
        var grid = Ui.Grid(("Type", "Type", 70), ("DHCP Server", "Server", 140), ("Offered Address", "Offered", 130), ("Gateway", "Gateway", 130), ("DNS", "Dns", 160),
            ("Client", "Client", 140), ("Response", "Response", 0));
        var status = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Classes = { "status" }, TextWrapping = TextWrapping.Wrap };
        var custom = new TextBox { Text = customOptions, PlaceholderText = "e.g. 160, 66, 67", Width = 180 };
        var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
            .SelectMany(n => n.GetIPProperties().UnicastAddresses.Where(u => u.Address.AddressFamily == AddressFamily.InterNetwork).Select(u => (n.Name, u.Address))).ToList();
        var adapter = new ComboBox { ItemsSource = Enumerable.Repeat("Default route", 1).Concat(adapters.Select(x => $"{x.Name} ({x.Address})")).ToList(), SelectedIndex = 0, Width = 260 };
        var expected = new TextBox { PlaceholderText = "expected server(s), e.g. 192.0.2.1", Width = 220 };
        var listenSeconds = new NumericUpDown { Value = 30, Minimum = 5, Maximum = 600, Increment = 5, FormatString = "0", Width = 110 };
        var findings = new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0) };
        // grows with its content up to 140 px and gives way at small window sizes (it scrolls inside)
        var comparison = new TextBox { IsReadOnly = true, AcceptsReturn = true, FontFamily = ToolKit.Mono, MinHeight = 48, MaxHeight = 140, TextWrapping = TextWrapping.NoWrap };
        Avalonia.Automation.AutomationProperties.SetName(comparison, "Option comparison");
        Avalonia.Automation.AutomationProperties.SetName(expected, "Expected DHCP servers");
        Avalonia.Automation.AutomationProperties.SetName(adapter, "Adapter");
        var rows = new List<DhcpOffer>();
        Button? probe = null;
        Button? listen = null;

        System.Net.IPAddress? Bind() => adapter.SelectedIndex > 0 ? adapters[adapter.SelectedIndex - 1].Address : null;

        void Show(string? error, bool passive = false)
        {
            grid.ItemsSource = rows.Select(o => new Row(o.MessageType, o.ServerDisplay, o.OfferedAddress.ToString(), string.Join(", ", o.Gateways), string.Join(", ", o.DnsServers),
                o.ClientMac, o.ResponseTime is { } t ? $"{t.TotalMilliseconds:N0} ms" : "seen passively", o)).ToList();
            var expectedList = (expected.Text ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries)
                .Select(x => System.Net.IPAddress.TryParse(x, out var ip) ? ip : null).OfType<System.Net.IPAddress>().ToList();
            findings.Text = error ?? (passive && rows.Count == 0
                ? "No DHCP reply was seen while listening (nothing was sent)."
                : string.Join("\n", DhcpDiagnostics.Assess(rows, expectedList)));
            var cmp = DhcpDiagnostics.Compare(rows);
            var servers = cmp.SelectMany(d => d.ValueByServer.Keys).Distinct().ToList();
            comparison.Text = servers.Count == 0 ? "" : string.Join("\n", new[] { $"{"Option",-26}" + string.Concat(servers.Select(sv => $" | {sv,-24}")) }
                .Concat(cmp.Select(d => $"{(d.Differs ? "* " : "  ") + d.Name,-26}" + string.Concat(servers.Select(sv => $" | {d.ValueByServer.GetValueOrDefault(sv, "—"),-24}")))));
        }

        async Task ProbeAsync()
        {
            var codes = DhcpPacket.ParseOptionCodes(custom.Text ?? "", out var err);
            if (err.Length > 0)
            {
                status.Text = err;
                return;
            }

            await saveCustomOptions(custom.Text ?? "");
            probe!.IsEnabled = listen!.IsEnabled = false;
            status.Text = "Broadcasting one DHCPDISCOVER (no lease is requested)…";
            try
            {
                var (offers, error) = await dhcp.DiscoverAsync(codes, TimeSpan.FromSeconds(4), CancellationToken.None, Bind());
                rows = offers.ToList();
                Show(error);
                status.Text = error ?? $"{offers.Count} offer(s) within 4 s.";
            }
            catch (SocketException ex)
            {
                status.Text = ex.Message;
            }
            finally
            {
                probe!.IsEnabled = listen!.IsEnabled = true;
            }
        }

        async Task ListenAsync()
        {
            probe!.IsEnabled = listen!.IsEnabled = false;
            var seconds = (double)(listenSeconds.Value ?? 30);
            status.Text = $"Listening for DHCP replies for {seconds:0} s (nothing is sent)…";
            try
            {
                var (replies, error) = await dhcp.ListenAsync(TimeSpan.FromSeconds(seconds), CancellationToken.None, Bind());
                rows = replies.ToList();
                Show(error, passive: true);
                status.Text = error ?? $"{replies.Count} DHCP repl(ies) seen. Only broadcast replies (clients that ask for them, relays) reach this computer.";
            }
            finally
            {
                probe!.IsEnabled = listen!.IsEnabled = true;
            }
        }

        probe = Ui.Button("Send DISCOVER", ProbeAsync, accent: true);
        ToolTip.SetTip(probe, "Broadcasts one DHCPDISCOVER and collects offers for 4 s. Never sends a REQUEST: no lease is taken or changed.");
        listen = Ui.Button("Listen", ListenAsync);
        ToolTip.SetTip(listen, "Waits for DHCP server replies to other clients; sends nothing.");
        expected.TextChanged += (_, _) =>
        {
            if (rows.Count > 0) Show(null);
        };
        var props = Ui.Button("Properties", async () =>
        {
            if (grid.SelectedItem is not Row r) return;
            var lines = r.Offer.Options.OrderBy(o => o.Key).Select(o => $"{o.Key,3}  {DhcpPacket.OptionName(o.Key)}: {DhcpPacket.FormatOption(o.Key, o.Value)}");
            await Dialogs.MessageAsync(this, $"DHCP {r.Type} from " + r.Server, $"Offered address: {r.Offered}\nSent from: {r.Offer.ServerAddress}\n\n" + string.Join("\n", lines), confirm: false);
        });
        var top = new StackPanel
        {
            Spacing = 6,
            Children =
            {
                Ui.Row(new TextBlock { Text = "Adapter:", VerticalAlignment = VerticalAlignment.Center }, adapter,
                    new TextBlock { Text = "Expected:", VerticalAlignment = VerticalAlignment.Center }, expected),
                Ui.Row(probe, new TextBlock { Text = "Custom options:", VerticalAlignment = VerticalAlignment.Center }, custom, listen,
                    new TextBlock { Text = "for (s):", VerticalAlignment = VerticalAlignment.Center }, listenSeconds),
            },
        };
        var bottom = new StackPanel { Spacing = 4, Children = { Ui.Row(props, status), findings, comparison } };
        Content = Ui.Layout(top, grid, bottom);
    }
}

/// <summary>Manual "Find Duplicate IP Addresses": interface selection, Go, duplicates with MACs and vendors.</summary>
internal sealed class DuplicateIpWindow : Window
{
    public sealed record Row(string Address, string Mac, string Vendor);

    public DuplicateIpWindow(DuplicateIpScanner scanner, Func<System.Net.NetworkInformation.PhysicalAddress, string> vendor)
    {
        Title = "Find Duplicate IP Addresses";
        Width = 720;
        Height = 480;
        var interfaces = scanner.Interfaces();
        var combo = new ComboBox
        {
            ItemsSource = interfaces.Select(i => $"{i.Adapter.Name} — {i.Address}").ToList(), SelectedIndex = interfaces.Count > 0 ? 0 : -1, MinWidth = 360,
            IsEnabled = interfaces.Count > 0,
        };
        var grid = Ui.Grid(("IP Address", "Address", 160), ("MAC Address", "Mac", 180), ("Vendor", "Vendor", 0));
        var progress = new ProgressBar { Minimum = 0, Maximum = 100, Width = 160, MinWidth = 0 };
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap, Classes = { "status" } };
        var cap = scanner.Capability;
        status.Text = cap.Available
            ? interfaces.Count == 0 ? "No IPv4 interface with a /16–/30 subnet can be opened for capture." : "ARP requests are broadcast to every address of the subnet; replies are collected for 3 seconds. Behind proxy-ARP gateways results are unreliable."
            : cap.Description;
        var go = Ui.Button("Start", async () =>
        {
            if (combo.SelectedIndex < 0) return;
            status.Text = "Scanning…";
            try
            {
                var report = await scanner.ScanAsync(interfaces[combo.SelectedIndex], TimeSpan.FromSeconds(3), new Progress<int>(p => progress.Value = p), CancellationToken.None);
                grid.ItemsSource = report.Duplicates.SelectMany(d => d.Macs.Select((m, i) => new Row(i == 0 ? d.Address.ToString() : "", Formats.Mac(m), vendor(m)))).ToList();
                status.Text = $"{report.AddressesAnswered} address(es) answered; {report.Duplicates.Count} duplicate(s)." + string.Concat(report.Warnings.Select(w => "\n" + w));
            }
            catch (InvalidOperationException ex)
            {
                status.Text = ex.Message;
            }
        }, accent: true);
        go.IsEnabled = cap.Available && interfaces.Count > 0;
        var copy = Ui.Button("Copy", () => Ui.CopyAsync(this, string.Join(Environment.NewLine,
            ((grid.ItemsSource as IEnumerable<Row>) ?? []).Select(r => $"{r.Address}\t{r.Mac}\t{r.Vendor}"))));
        Content = Ui.Layout(Ui.Row(new TextBlock { Text = "Interface:", VerticalAlignment = VerticalAlignment.Center }, combo, go, progress), grid,
            new StackPanel { Spacing = 6, Children = { status, copy } });
    }
}

/// <summary>Manual "Wake-On-LAN manager".</summary>
internal sealed class WolManagerWindow : Window
{
    private readonly ObservableCollection<WolTarget> _items;
    private WolSettings _settings;

    public WolManagerWindow(WolSettings settings, WakeOnLanSender sender, Func<WolSettings, Task> save)
    {
        Title = "Wake-On-LAN Manager";
        Width = 820;
        Height = 480;
        _settings = settings;
        _items = new ObservableCollection<WolTarget>(settings.Targets);
        var grid = Ui.Grid(("MAC Address", nameof(WolTarget.Mac), 170), ("Destination", nameof(WolTarget.Destination), 180),
            ("Host Name", nameof(WolTarget.HostName), 180), ("Friendly Name", nameof(WolTarget.FriendlyName), 0));
        grid.ItemsSource = _items;
        var status = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Classes = { "status" } };
        async Task Persist()
        {
            _settings = _settings with { Targets = _items.ToList() };
            await save(_settings);
        }

        async Task Wake(IReadOnlyList<WolTarget> targets)
        {
            if (targets.Count == 0) return;
            var results = await sender.WakeAllAsync(targets, _settings, CancellationToken.None);
            var failed = results.Where(r => !r.Success).ToList();
            status.Text = failed.Count == 0 ? $"Magic packet sent to {results.Count} device(s)." : $"{failed.Count} failed: {failed[0].Target} — {failed[0].Message}";
        }

        Content = Ui.Layout(null, grid, Ui.Row(
            Ui.Button("Add…", async () =>
            {
                if (await EditAsync(new WolTarget { Destination = WakeOnLan.CombineDestination(_settings.DefaultDestination, null) }) is { } t)
                {
                    _items.Add(t);
                    await Persist();
                }
            }),
            Ui.Button("Edit…", async () =>
            {
                if (grid.SelectedItem is not WolTarget sel) return;
                if (await EditAsync(sel) is { } t)
                {
                    _items[_items.IndexOf(sel)] = t;
                    await Persist();
                }
            }),
            Ui.Button("Delete", async () =>
            {
                foreach (var t in grid.SelectedItems.OfType<WolTarget>().ToList()) _items.Remove(t);
                await Persist();
            }),
            Ui.Button("Wake", () => Wake(grid.SelectedItems.OfType<WolTarget>().ToList()), accent: true),
            Ui.Button("Wake All", () => Wake(_items.ToList())),
            Ui.Button("Settings…", async () =>
            {
                if (await SettingsAsync() is { } s)
                {
                    _settings = s with { Targets = _items.ToList() };
                    await save(_settings);
                }
            }),
            Ui.Button("Export…", async () =>
            {
                var f = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Export", DefaultExtension = "json", FileTypeChoices = [new("JSON") { Patterns = ["*.json"] }] });
                if (f?.TryGetLocalPath() is { } p)
                {
                    await File.WriteAllTextAsync(p, System.Text.Json.JsonSerializer.Serialize(_items.ToList(), Indented));
                    status.Text = $"Exported {_items.Count} device(s).";
                }
            }),
            Ui.Button("Import…", async () =>
            {
                var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Import", FileTypeFilter = [new("JSON or MAC list") { Patterns = ["*.json", "*.txt"] }] });
                var p = files.Count > 0 ? files[0].TryGetLocalPath() : null;
                if (p is null || new FileInfo(p).Length > 4 * 1024 * 1024) return;
                var text = await File.ReadAllTextAsync(p);
                try
                {
                    var imported = p.EndsWith(".json", StringComparison.OrdinalIgnoreCase)
                        ? System.Text.Json.JsonSerializer.Deserialize<List<WolTarget>>(text) ?? []
                        : WakeOnLan.ParseMacList(text).Macs.Select(m => new WolTarget { Mac = Formats.Mac(m), Destination = WakeOnLan.CombineDestination(_settings.DefaultDestination, null) }).ToList();
                    foreach (var t in imported.Where(t => Formats.ParseMac(t.Mac) is not null)) _items.Add(t);
                    await Persist();
                    status.Text = $"Imported {imported.Count} device(s).";
                }
                catch (System.Text.Json.JsonException ex)
                {
                    status.Text = "Import failed: " + ex.Message;
                }
            }),
            status));
    }

    private static readonly System.Text.Json.JsonSerializerOptions Indented = new() { WriteIndented = true };

    private async Task<WolTarget?> EditAsync(WolTarget t)
    {
        var w = Ui.Window("Wake-On-LAN Device", 460, 300);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var mac = new TextBox { Text = t.Mac, PlaceholderText = "AA-BB-CC-DD-EE-FF" };
        var kind = new ComboBox { ItemsSource = new[] { "IPv4 destination", "IPv6 destination", "Host name destination" }, SelectedIndex = (int)t.Kind };
        var dest = new TextBox { Text = t.Destination };
        var host = new TextBox { Text = t.HostName };
        var friendly = new TextBox { Text = t.FriendlyName };
        var error = new TextBlock { Classes = { "error" } };
        WolTarget? result = null;
        var ok = Ui.Button("OK", () =>
        {
            if (Formats.ParseMac(mac.Text) is not { } m)
            {
                error.Text = "Enter a valid MAC address.";
                return Task.CompletedTask;
            }

            var k = (WolDestinationKind)Math.Max(0, kind.SelectedIndex);
            var d = dest.Text?.Trim() ?? "";
            if ((k == WolDestinationKind.IPv4 && !Core.Targets.TargetParser.TryParseStrictIPv4(d, out _))
                || (k == WolDestinationKind.IPv6 && !(System.Net.IPAddress.TryParse(d, out var a6) && a6.AddressFamily == AddressFamily.InterNetworkV6))
                || (k == WolDestinationKind.HostName && !Core.Targets.TargetParser.IsValidHostName(d)))
            {
                error.Text = "The destination does not match its type.";
                return Task.CompletedTask;
            }

            result = new WolTarget { Mac = Formats.Mac(m), Kind = k, Destination = d, HostName = host.Text?.Trim() ?? "", FriendlyName = friendly.Text?.Trim() ?? "" };
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        var form = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), RowDefinitions = new RowDefinitions("Auto,Auto,Auto,Auto,Auto"), RowSpacing = 6, ColumnSpacing = 10 };
        (string, Control)[] rows = [("MAC address", mac), ("Destination type", kind), ("Destination", dest), ("Host name", host), ("Friendly name", friendly)];
        for (var i = 0; i < rows.Length; i++)
        {
            var l = new TextBlock { Text = rows[i].Item1, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetRow(l, i);
            Grid.SetRow(rows[i].Item2, i);
            Grid.SetColumn(rows[i].Item2, 1);
            form.Children.Add(l);
            form.Children.Add(rows[i].Item2);
        }

        w.Content = new StackPanel { Margin = new Thickness(16), Spacing = 8, Children = { form, error, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) } };
        await w.ShowDialog(this);
        return result;
    }

    private async Task<WolSettings?> SettingsAsync()
    {
        var w = Ui.Window("Wake-On-LAN Settings", 460, 260);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var dest = new TextBox { Text = _settings.DefaultDestination };
        var port = new NumericUpDown { Value = _settings.Port, Minimum = 1, Maximum = 65535, FormatString = "0", Width = 140 };
        var delay = new NumericUpDown { Value = _settings.DelayMs, Minimum = 0, Maximum = 60_000, Increment = 100, FormatString = "0", Width = 140 };
        WolSettings? result = null;
        var ok = Ui.Button("OK", () =>
        {
            result = _settings with { DefaultDestination = dest.Text?.Trim() ?? "255.255.255.255", Port = (int)(port.Value ?? 9), DelayMs = (int)(delay.Value ?? 100) };
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        w.Content = new StackPanel
        {
            Margin = new Thickness(16), Spacing = 8,
            Children =
            {
                new TextBlock { Text = "Default destination (zero octets are taken from the device, e.g. 0.0.0.255 = its subnet broadcast):", TextWrapping = TextWrapping.Wrap },
                dest, Ui.Row(new TextBlock { Text = "UDP port", Width = 160 }, port), Ui.Row(new TextBlock { Text = "Delay between packets, ms", Width = 160 }, delay),
                Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })),
            },
        };
        await w.ShowDialog(this);
        return result;
    }
}

internal static class ManagementDialogs
{
    /// <summary>Remote shutdown with a concrete target list (disruptive actions are confirmed).</summary>
    public static async Task RemoteShutdownAsync(Window owner, IReadOnlyList<string> hosts, IRemoteControl control)
    {
        var w = Ui.Window("Remote Shutdown", 560, 460);
        var reboot = new CheckBox { Content = "Reboot the remote device" };
        var force = new CheckBox { Content = "Forcibly close applications (unsaved work is lost)" };
        var showMessage = new CheckBox { Content = "Display the following message for" };
        var seconds = new NumericUpDown { Value = 30, Minimum = 0, Maximum = 3600, FormatString = "0", Width = 110 };
        var message = new TextBox { Text = "This computer will be restarted for maintenance.", AcceptsReturn = true, Height = 60 };
        var results = new TextBlock { TextWrapping = TextWrapping.Wrap };
        Button? go = null;
        go = Ui.Button("Shut Down…", async () =>
        {
            var verb = reboot.IsChecked == true ? "RESTART" : "SHUT DOWN";
            if (!await Dialogs.MessageAsync(w, "Confirm", $"{verb} these {hosts.Count} device(s){(force.IsChecked == true ? " and force applications to close" : "")}?\n\n{string.Join("\n", hosts.Take(30))}{(hosts.Count > 30 ? "\n…" : "")}", confirm: true)) return;
            go!.IsEnabled = false;
            var opts = new ShutdownOptions
            {
                Reboot = reboot.IsChecked == true, ForceAppsClosed = force.IsChecked == true,
                Message = showMessage.IsChecked == true ? message.Text ?? "" : "", TimeoutSeconds = showMessage.IsChecked == true ? (int)(seconds.Value ?? 30) : 0,
            };
            var lines = new List<string>();
            foreach (var h in hosts)
            {
                var r = await control.ShutdownAsync(h, opts, CancellationToken.None);
                lines.Add($"{h}: {(r.Success ? "OK" : "failed")} — {r.Message}");
                results.Text = string.Join("\n", lines);
            }
        }, accent: true);
        go.IsEnabled = control.Capability.Available;
        w.Content = new ScrollViewer
        {
            Content = new StackPanel
            {
                Margin = new Thickness(16), Spacing = 8,
                Children =
                {
                    new TextBlock { Text = $"Targets: {string.Join(", ", hosts.Take(10))}{(hosts.Count > 10 ? $" (+{hosts.Count - 10})" : "")}", TextWrapping = TextWrapping.Wrap, FontWeight = FontWeight.SemiBold },
                    reboot, force, Ui.Row(showMessage, seconds, new TextBlock { Text = "seconds", VerticalAlignment = VerticalAlignment.Center }), message,
                    new TextBlock { Classes = { "hint" }, TextWrapping = TextWrapping.Wrap, Text = control.Capability.Description },
                    go, results,
                },
            },
        };
        await w.ShowDialog(owner);
    }

    public static async Task SendMessageAsync(Window owner, IReadOnlyList<string> hosts, IRemoteControl control)
    {
        var w = Ui.Window("Send Message", 520, 380);
        var text = new TextBox { AcceptsReturn = true, Height = 100, PlaceholderText = "Message" };
        var seconds = new NumericUpDown { Value = 60, Minimum = 1, Maximum = 86_400, FormatString = "0", Width = 120 };
        var results = new TextBlock { TextWrapping = TextWrapping.Wrap };
        var send = Ui.Button("Send", async () =>
        {
            if (string.IsNullOrWhiteSpace(text.Text)) return;
            var lines = new List<string>();
            foreach (var h in hosts)
            {
                var r = await control.SendMessageAsync(h, "Message from IPMaster", text.Text, (int)(seconds.Value ?? 60), CancellationToken.None);
                lines.Add($"{h}: {(r.Success ? "OK" : "failed")} — {r.Message}");
                results.Text = string.Join("\n", lines);
            }
        }, accent: true);
        send.IsEnabled = control.Capability.Available;
        w.Content = new StackPanel
        {
            Margin = new Thickness(16), Spacing = 8,
            Children = { new TextBlock { Text = $"To: {string.Join(", ", hosts.Take(10))}{(hosts.Count > 10 ? " …" : "")}", TextWrapping = TextWrapping.Wrap }, text,
                Ui.Row(new TextBlock { Text = "Display time, s", VerticalAlignment = VerticalAlignment.Center }, seconds), send, results },
        };
        await w.ShowDialog(owner);
    }

    /// <summary>Manual "Create Batch File": template, examples, Preview, Save, Copy.</summary>
    public static async Task<string?> BatchFileAsync(Window owner, string lastTemplate, Func<string, string> generate)
    {
        var w = Ui.Window("Create Batch File", 760, 560);
        var template = new TextBox { Text = lastTemplate.Length > 0 ? lastTemplate : BatchFile.Examples[0].Template, AcceptsReturn = true, Height = 90, FontFamily = new FontFamily("Consolas, Menlo, monospace") };
        var examples = new ComboBox { ItemsSource = BatchFile.Examples.Select(e => e.Name).ToList(), PlaceholderText = "Examples…", Width = 260 };
        examples.SelectionChanged += (_, _) =>
        {
            if (examples.SelectedIndex >= 0) template.Text = BatchFile.Examples[examples.SelectedIndex].Template;
        };
        var preview = new TextBox { IsReadOnly = true, AcceptsReturn = true, FontFamily = new FontFamily("Consolas, Menlo, monospace"), TextWrapping = TextWrapping.NoWrap };
        var status = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Classes = { "status" } };
        Task Preview()
        {
            preview.Text = generate(template.Text ?? "");
            return Task.CompletedTask;
        }

        var save = Ui.Button("Save…", async () =>
        {
            await Preview();
            var f = await w.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Save Batch File", DefaultExtension = "cmd", FileTypeChoices = [new("Batch file") { Patterns = ["*.cmd", "*.bat"] }] });
            if (f?.TryGetLocalPath() is { } p)
            {
                await File.WriteAllTextAsync(p, preview.Text ?? "");
                status.Text = "Saved " + p;
            }
        });
        var copy = Ui.Button("Copy", async () =>
        {
            await Preview();
            await Ui.CopyAsync(w, preview.Text ?? "");
            status.Text = "Copied.";
        });
        var top = new StackPanel
        {
            Spacing = 6,
            Children =
            {
                new TextBlock { Classes = { "note" }, TextWrapping = TextWrapping.Wrap, Text = "%0 = IP address, %1 = share name (one line per shared folder), [Column Name] = any column. Other % sequences are passed to cmd.exe unchanged." },
                Ui.Row(examples), template, Ui.Row(Ui.Button("Preview", Preview, accent: true), save, copy, status),
            },
        };
        w.Content = Ui.Layout(top, preview, null);
        w.Opened += async (_, _) => await Preview();
        await w.ShowDialog(owner);
        return template.Text;
    }

    /// <summary>Asks for prompted application parameters (with defaults and browse buttons for file/path names).</summary>
    public static async Task<Dictionary<string, string>?> PromptParametersAsync(Window owner, string appName, IReadOnlyList<PromptParameter> prompts)
    {
        if (prompts.Count == 0) return [];
        var w = Ui.Window(appName, 520, 300);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var boxes = new List<(PromptParameter P, TextBox Box)>();
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 8 };
        foreach (var p in prompts)
        {
            var box = new TextBox { Text = p.Default, Width = 340, PasswordChar = p.Name.Contains("password", StringComparison.OrdinalIgnoreCase) ? '•' : default };
            boxes.Add((p, box));
            var row = Ui.Row(new TextBlock { Text = p.Name, Width = 120, VerticalAlignment = VerticalAlignment.Center }, box);
            if (p.IsPath)
            {
                row.Children.Add(Ui.Button("…", async () =>
                {
                    var files = await w.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = p.Name });
                    if (files.Count > 0 && files[0].TryGetLocalPath() is { } path) box.Text = path;
                }));
            }

            panel.Children.Add(row);
        }

        Dictionary<string, string>? result = null;
        panel.Children.Add(Ui.Row(Ui.Button("Start", () =>
        {
            result = boxes.ToDictionary(b => b.P.Name, b => b.Box.Text ?? "");
            w.Close();
            return Task.CompletedTask;
        }, accent: true), Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })));
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }
}
