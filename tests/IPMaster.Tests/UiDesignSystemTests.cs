using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Media;
using Avalonia.Styling;
using Avalonia.VisualTree;
using IPMaster.Desktop;
using IPMaster.Desktop.Styling;
using IPMaster.Desktop.ViewModels;
using IPMaster.Desktop.Views;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IPMaster.Tests;

/// <summary>
/// One headless Avalonia session per test process (D-098): the real <see cref="App"/> styles and tokens, Skia rendering
/// so windows can be captured. Settings go to a temporary folder, never the user's. Set IPMASTER_UI_SNAPSHOTS to a folder
/// to keep the rendered PNGs for review (docs/DEVELOPMENT.md, visual QA).
/// </summary>
public static class HeadlessUi
{
    private static readonly Lazy<HeadlessUnitTestSession> Session = new(() =>
    {
        Environment.SetEnvironmentVariable("IPMASTER_CONFIG_DIR", Path.Combine(Path.GetTempPath(), "ipmaster-ui-tests-" + Environment.ProcessId));
        return HeadlessUnitTestSession.StartNew(typeof(HeadlessUi));
    });

    private static readonly Lazy<ServiceProvider> Services = new(() => new ServiceCollection()
        .AddLogging(b => b.SetMinimumLevel(LogLevel.Warning)).AddIPMaster().AddSingleton<MainWindowViewModel>()
        .AddSingleton<IPMaster.Core.Wifi.IWifiProvider>(new SyntheticWifi()) // tests never use the real Wi-Fi adapter
        .BuildServiceProvider());

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UseSkia().UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });

    public static Task Run(Action action) => Session.Value.Dispatch(action, TestContext.Current.CancellationToken);

    public static Task RunAsync(Func<Task> action) => Session.Value.Dispatch(async () =>
    {
        await action();
        return true;
    }, TestContext.Current.CancellationToken);

    internal static MainWindowViewModel Vm => Services.Value.GetRequiredService<MainWindowViewModel>();

    internal static T Service<T>() where T : notnull => Services.Value.GetRequiredService<T>();

    public static string? SnapshotDirectory => Environment.GetEnvironmentVariable("IPMASTER_UI_SNAPSHOTS") is { Length: > 0 } d ? Directory.CreateDirectory(d).FullName : null;

    public static void SetTheme(ThemeVariant variant) => Application.Current!.RequestedThemeVariant = variant;

    public static void Snapshot(Window window, string name)
    {
        if (SnapshotDirectory is not { } dir) return;
        var frame = window.CaptureRenderedFrame();
#pragma warning disable CS0618 // the encoder-options overload is not needed for a review PNG
        frame?.Save(Path.Combine(dir, string.Concat(name.Split(Path.GetInvalidFileNameChars())) + ".png"));
#pragma warning restore CS0618
    }

    /// <summary>WCAG 2 contrast ratio of two opaque colours (alpha composited over <paramref name="over"/>).</summary>
    public static double Contrast(Color fg, Color bg, Color over)
    {
        static Color Blend(Color c, Color under) => c.A == 255 ? c : Color.FromRgb(
            (byte)(((c.R * c.A) + (under.R * (255 - c.A))) / 255), (byte)(((c.G * c.A) + (under.G * (255 - c.A))) / 255), (byte)(((c.B * c.A) + (under.B * (255 - c.A))) / 255));
        static double L(Color c)
        {
            static double Ch(byte v)
            {
                var s = v / 255.0;
                return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
            }

            return (0.2126 * Ch(c.R)) + (0.7152 * Ch(c.G)) + (0.0722 * Ch(c.B));
        }

        var b = Blend(bg, over);
        double l1 = L(Blend(fg, b)), l2 = L(b);
        return (Math.Max(l1, l2) + 0.05) / (Math.Min(l1, l2) + 0.05);
    }
}

[CollectionDefinition("Headless UI", DisableParallelization = true)]
public class HeadlessUiGroup;

[Collection("Headless UI")]
public class UiDesignSystemTests
{
    private static readonly ThemeVariant[] Variants = [ThemeVariant.Light, ThemeVariant.Dark];

    [Fact]
    public Task Every_token_resolves_in_both_themes() => HeadlessUi.Run(() =>
    {
        foreach (var variant in Variants)
        {
            foreach (var key in Theme.AllBrushKeys) Assert.True(Theme.Brush(key, variant) is ISolidColorBrush, $"{key} missing in {variant}");
        }

        // text tokens really differ between the themes (no dark-only or light-only value)
        foreach (var key in new[] { "IpmTextPrimary", "IpmTextSecondary", "IpmError", "IpmResultsSurface", "IpmChartText" })
            Assert.NotEqual(((ISolidColorBrush)Theme.Brush(key, ThemeVariant.Light)!).Color, ((ISolidColorBrush)Theme.Brush(key, ThemeVariant.Dark)!).Color);
    });

    [Fact]
    public Task Text_tokens_meet_wcag_aa_contrast_on_the_window_and_results_surfaces() => HeadlessUi.Run(() =>
    {
        var surfaces = new Dictionary<ThemeVariant, Color[]>
        {
            [ThemeVariant.Light] = [Colors.White, Color.Parse("#FFF3F3F3")], // theme-exception: Fluent light window and chrome surfaces
            [ThemeVariant.Dark] = [Color.Parse("#FF353535"), Color.Parse("#FF292929"), Color.Parse("#FF2D2D2D")], // theme-exception: D-072 surfaces
        };
        foreach (var (variant, backgrounds) in surfaces)
        {
            foreach (var key in new[] { "IpmTextPrimary", "IpmTextSecondary", "IpmSuccess", "IpmWarning", "IpmError", "IpmInfo", "IpmChartText" })
            {
                var fg = ((ISolidColorBrush)Theme.Brush(key, variant)!).Color;
                foreach (var bg in backgrounds)
                {
                    var ratio = HeadlessUi.Contrast(fg, bg, bg);
                    Assert.True(ratio >= 4.5, $"{key} on {bg} in {variant}: {ratio:0.00}:1");
                }
            }

            // banner tints keep normal text readable
            var text = ((ISolidColorBrush)Theme.Brush("IpmTextPrimary", variant)!).Color;
            foreach (var key in new[] { "IpmSuccessSurface", "IpmWarningSurface", "IpmErrorSurface", "IpmInfoSurface" })
            {
                var tint = ((ISolidColorBrush)Theme.Brush(key, variant)!).Color;
                Assert.True(HeadlessUi.Contrast(text, tint, backgrounds[0]) >= 4.5, $"text on {key} in {variant}");
            }
        }
    });

    [Fact]
    public Task Style_classes_follow_a_runtime_theme_switch() => HeadlessUi.Run(() =>
    {
        var error = new TextBlock { Text = "failed", Classes = { Theme.Classes.Error } };
        var status = new TextBlock { Text = "ok", Classes = { Theme.Classes.Status } };
        var window = new Window { Content = new StackPanel { Children = { error, status } }, Width = 200, Height = 100 };
        window.Show();
        try
        {
            HeadlessUi.SetTheme(ThemeVariant.Light);
            Dispatch();
            var light = ((ISolidColorBrush)error.Foreground!).Color;
            Assert.Equal(((ISolidColorBrush)Theme.Brush("IpmError", ThemeVariant.Light)!).Color, light);
            HeadlessUi.SetTheme(ThemeVariant.Dark);
            Dispatch();
            Assert.Equal(((ISolidColorBrush)Theme.Brush("IpmError", ThemeVariant.Dark)!).Color, ((ISolidColorBrush)error.Foreground!).Color);
            Assert.Equal(((ISolidColorBrush)Theme.Brush("IpmTextSecondary", ThemeVariant.Dark)!).Color, ((ISolidColorBrush)status.Foreground!).Color);
            Theme.SetState(status, Theme.Classes.Warning);
            Dispatch();
            Assert.Equal(((ISolidColorBrush)Theme.Brush("IpmWarning", ThemeVariant.Dark)!).Color, ((ISolidColorBrush)status.Foreground!).Color);
            Theme.SetState(status, null);
            Assert.DoesNotContain(Theme.Classes.Warning, status.Classes);
        }
        finally
        {
            window.Close();
            HeadlessUi.SetTheme(ThemeVariant.Default);
        }
    });

    public static TheoryData<string> ToolNames() => [.. MainWindow.ToolEntries.Select(t => t.Header)];

    [Theory]
    [MemberData(nameof(ToolNames))]
    public Task Every_tool_window_opens_in_both_themes_with_no_action_cut_off(string header) => HeadlessUi.Run(() =>
    {
        var entry = MainWindow.ToolEntries.Single(t => t.Header == header);
        foreach (var variant in Variants)
        {
            HeadlessUi.SetTheme(variant);
            var window = entry.Open(null!, HeadlessUi.Vm);
            try
            {
                window.Show();
                Dispatch();
                var name = header.Replace("_", "", StringComparison.Ordinal).TrimEnd('…');
                HeadlessUi.Snapshot(window, $"{name} - {variant}");
                window.Width = Math.Max(window.MinWidth, 400);
                window.Height = Math.Max(window.MinHeight, 300);
                Dispatch();
                HeadlessUi.Snapshot(window, $"{name} - {variant} - minimum size");
                AssertNoActionCutOff(window, name);
            }
            finally
            {
                window.Close();
            }
        }

        HeadlessUi.SetTheme(ThemeVariant.Default);
    });

    /// <summary>The other registered windows (menus outside Tools): the same theme, render and minimum-size checks.</summary>
    internal static readonly Dictionary<string, Func<Window>> OtherWindows = new()
    {
        ["Options"] = () => new OptionsWindow { DataContext = new OptionsViewModel(HeadlessUi.Vm.SettingsForEditing(), HeadlessUi.Vm.Probes) },
        ["Navigator"] = () => new NavigatorWindow([new IPMaster.Core.Navigation.NavigatorItem(IPMaster.Core.Navigation.NavigatorKind.Command, "Options", "Options", "Options")]),
        ["UPnP Discovery"] = () => new DiscoveryWindow("UPnP Devices", IPMaster.Core.Discovery.DiscoveryProtocol.Ssdp, (_, _, _) => Task.FromResult<IReadOnlyList<IPMaster.Core.Discovery.DiscoveredDevice>>([])),
        ["DHCP Server Discovery"] = () => new DhcpWindow(new IPMaster.Infrastructure.Discovery.DhcpDiscovery(), "", _ => Task.CompletedTask),
        ["Duplicate IP Detection"] = () => new DuplicateIpWindow(HeadlessUi.Service<IPMaster.Infrastructure.Discovery.DuplicateIpScanner>(), _ => ""),
        ["Compare Columns"] = () => new CompareWindow(IPMaster.Core.Results.ColumnCatalog.All, HeadlessUi.Vm.Format),
        ["Device Inventory"] = () => new InventoryWindow(HeadlessUi.Vm),
        ["Background Scan Log"] = () => new ScanLogWindow(HeadlessUi.Vm.Ops.Log),
        ["Remote Query Manager - SNMP"] = () => new QueryManagerWindow(HeadlessUi.Vm, IPMaster.Core.Queries.QueryKind.Snmp),
        ["Remote Query Manager - Scripting"] = () => new QueryManagerWindow(HeadlessUi.Vm, IPMaster.Core.Queries.QueryKind.Script),
        ["Remote Query Manager - Nmap"] = () => new QueryManagerWindow(HeadlessUi.Vm, IPMaster.Core.Queries.QueryKind.Nmap),
        ["DNS Tools - Bulk Audit"] = () => new DnsToolsWindow(tab: DnsToolsWindow.BulkAuditTab),
        ["SNMP Tools - Interface Monitor"] = () => new SnmpToolsWindow(HeadlessUi.Vm, tab: SnmpToolsWindow.InterfaceMonitorTab),
        ["SNMP Tools - Queries"] = () => new SnmpToolsWindow(HeadlessUi.Vm, tab: SnmpToolsWindow.QueriesTab),
        ["IP Address Tools - From Host Name"] = () => new IpAddressToolsWindow(HeadlessUi.Vm, IpAddressToolsWindow.FromHostNameTab),
        // selected after construction: opening on this tab would ask the public service at once
        ["IP Address Tools - External IP"] = () =>
        {
            var w = new IpAddressToolsWindow(HeadlessUi.Vm);
            w.Tabs.SelectedIndex = IpAddressToolsWindow.ExternalIpTab;
            return w;
        },
        ["WMI Query Examples"] = () => new QueryExamplesWindow(IPMaster.Core.Queries.QueryKind.Wmi),
        ["PowerShell Query Examples"] = () => new QueryExamplesWindow(IPMaster.Core.Queries.QueryKind.PowerShell),
        ["WinGet Install Packages"] = () => new WinGetInstallWindow(new FakeWinGet(), new Dictionary<string, string>(), _ => { }),
    };

    public static TheoryData<string> OtherWindowNames() => [.. OtherWindows.Keys];

    [Theory]
    [MemberData(nameof(OtherWindowNames))]
    public Task Other_windows_open_in_both_themes_with_no_action_cut_off(string name) => HeadlessUi.Run(() =>
    {
        foreach (var variant in Variants)
        {
            HeadlessUi.SetTheme(variant);
            var window = OtherWindows[name]();
            try
            {
                window.Show();
                Dispatch();
                HeadlessUi.Snapshot(window, $"{name} - {variant}");
                window.Width = Math.Max(window.MinWidth, 400);
                window.Height = Math.Max(window.MinHeight, 300);
                Dispatch();
                HeadlessUi.Snapshot(window, $"{name} - {variant} - minimum size");
                AssertNoActionCutOff(window, name);
            }
            finally
            {
                window.Close();
            }
        }

        HeadlessUi.SetTheme(ThemeVariant.Default);
    });

    [Fact]
    public Task A_message_dialog_follows_its_owner_theme() => HeadlessUi.Run(() =>
    {
        HeadlessUi.SetTheme(ThemeVariant.Dark);
        var owner = new Window { Width = 600, Height = 400 };
        owner.Show();
        try
        {
            _ = Dialogs.MessageAsync(owner, "Confirm", "Delete the selected item?", confirm: true);
            Dispatch();
            var dialog = Assert.Single(owner.OwnedWindows);
            Assert.Equal(ThemeVariant.Dark, dialog.ActualThemeVariant);
            HeadlessUi.Snapshot(dialog, "Message dialog - Dark");
            AssertNoActionCutOff(dialog, "Message dialog");
            dialog.Close();
        }
        finally
        {
            owner.Close();
            HeadlessUi.SetTheme(ThemeVariant.Default);
        }
    });

    [Fact]
    public Task Charts_redraw_with_the_new_theme_tokens() => HeadlessUi.Run(() =>
    {
        var chart = new LatencyChart { Width = 300, Height = 120, Samples = [new IPMaster.Core.Monitoring.MonitorSample(DateTimeOffset.UtcNow, 12)] };
        var window = new Window { Content = chart, Width = 300, Height = 120 };
        window.Show();
        try
        {
            HeadlessUi.SetTheme(ThemeVariant.Light);
            Dispatch();
            var light = Pixel(window.CaptureRenderedFrame()!, 150, 60);
            HeadlessUi.SetTheme(ThemeVariant.Dark);
            Dispatch();
            var dark = Pixel(window.CaptureRenderedFrame()!, 150, 60);
            Assert.NotEqual(light, dark);
            Assert.True(Luma(light) > Luma(dark), $"light {light} should be brighter than dark {dark}");
        }
        finally
        {
            window.Close();
            HeadlessUi.SetTheme(ThemeVariant.Default);
        }
    });

    private static Color Pixel(Avalonia.Media.Imaging.WriteableBitmap frame, int x, int y)
    {
        using var fb = frame.Lock();
        var bytes = new byte[4];
        System.Runtime.InteropServices.Marshal.Copy(fb.Address + (y * fb.RowBytes) + (x * 4), bytes, 0, 4);
        return fb.Format == Avalonia.Platform.PixelFormat.Bgra8888 ? Color.FromArgb(bytes[3], bytes[2], bytes[1], bytes[0]) : Color.FromArgb(bytes[3], bytes[0], bytes[1], bytes[2]); // theme-exception: test pixel decoding
    }

    private static double Luma(Color c) => (0.2126 * c.R) + (0.7152 * c.G) + (0.0722 * c.B);

    internal static void Dispatch()
    {
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
        AvaloniaHeadlessPlatform.ForceRenderTimerTick();
        Avalonia.Threading.Dispatcher.UIThread.RunJobs();
    }

    /// <summary>A visible button must lie inside the window, unless it sits in a scrollable area.</summary>
    internal static void AssertNoActionCutOff(Window window, string name)
    {
        var client = new Rect(window.ClientSize);
        foreach (var button in window.GetVisualDescendants().OfType<Button>().Where(b => b.IsEffectivelyVisible && b.Bounds.Width > 0))
        {
            if (button.GetVisualAncestors().Any(a => a is ScrollViewer) || button.TemplatedParent is not null) continue;
            if (button.TranslatePoint(new Point(0, 0), window) is not { } p) continue;
            var r = new Rect(p, button.Bounds.Size);
            Assert.True(client.Contains(r.BottomRight - new Point(1, 1)) && client.Contains(r.TopLeft),
                $"{name}: '{button.Content}' at {r} is outside {client.Size} at the minimum window size");
        }
    }
}

/// <summary>
/// Lint (D-098): views take colours from design tokens. A presentation colour in a view (named brush, colour literal,
/// hex colour, opacity-dimmed text in AXAML) fails the build unless the line says why with a "theme-exception:" comment.
/// </summary>
public class UiColourLintTests
{
    private static readonly System.Text.RegularExpressions.Regex Forbidden = new(
        @"Brushes\.(?!Transparent\b)\w+|Colors\.(?!Transparent\b)\w+|Color\.(FromArgb|FromRgb|FromUInt32|Parse)\(|""#[0-9A-Fa-f]{6,8}""|(Foreground|Background|BorderBrush)=""(?!\{|Transparent"")[A-Za-z#]|Opacity=""0\.",
        System.Text.RegularExpressions.RegexOptions.Compiled);

    private static string Root()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IPMaster.slnx"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repository root not found");
    }

    [Fact]
    public void Views_use_design_tokens_not_hard_coded_colours()
    {
        var desktop = Path.Combine(Root(), "src", "IPMaster.Desktop");
        var files = Directory.EnumerateFiles(desktop, "*.*", SearchOption.AllDirectories)
            .Where(f => f.EndsWith(".cs", StringComparison.Ordinal) || f.EndsWith(".axaml", StringComparison.Ordinal))
            .Where(f => !f.Contains(Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                        && !f.Contains(Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                        && !f.Contains(Path.DirectorySeparatorChar + "Styling" + Path.DirectorySeparatorChar, StringComparison.Ordinal)
                        && !f.EndsWith("App.axaml", StringComparison.Ordinal) && !f.EndsWith("Icons.axaml", StringComparison.Ordinal));
        var hits = new List<string>();
        foreach (var file in files)
        {
            var lines = File.ReadAllLines(file);
            for (var i = 0; i < lines.Length; i++)
            {
                if (Forbidden.IsMatch(lines[i]) && !lines[i].Contains("theme-exception:", StringComparison.Ordinal))
                    hits.Add($"{Path.GetRelativePath(desktop, file)}:{i + 1}: {lines[i].Trim()}");
            }
        }

        Assert.True(hits.Count == 0, "Use a token or class from Styling/ (docs/DEVELOPMENT.md), or mark a justified exception:\n" + string.Join('\n', hits));
    }
}

/// <summary>Synthetic Wi-Fi environment for the window tests: a few networks in every band and a 5 GHz connection.</summary>
internal sealed class SyntheticWifi : IPMaster.Core.Wifi.IWifiProvider
{
    private static readonly IPMaster.Core.Wifi.WifiBss[] Networks =
    [
        WifiFixtures.Bss("Office", "02:10:00:00:00:01", -48, 5180, WifiFixtures.Rsn(2, 8), WifiFixtures.VhtOperation(1, 42), WifiFixtures.BssLoad(7, 60), WifiFixtures.Ie(70, 0, 0, 0, 0, 0), WifiFixtures.Ie(127, 0, 0, 0x08)),
        WifiFixtures.Bss("Office", "02:10:00:00:00:02", -71, 2437, WifiFixtures.Rsn(2), WifiFixtures.HtOperation(6, 0)),
        WifiFixtures.Bss("Office", "02:10:00:00:00:03", -66, 5500, WifiFixtures.Rsn(2), WifiFixtures.VhtOperation(1, 106)),
        WifiFixtures.Bss("Neighbour", "02:20:00:00:00:01", -60, 2412, WifiFixtures.Rsn(2), WifiFixtures.HtOperation(1, 1), WifiFixtures.Ie(7, (byte)'D', (byte)'E', (byte)' ')),
        WifiFixtures.Bss("Cafe", "02:30:00:00:00:01", -82, 2462, WifiFixtures.Rsn(2), WifiFixtures.HtOperation(11, 0)),
        WifiFixtures.Bss("", "02:40:00:00:00:01", -77, 5200, WifiFixtures.Rsn(2), WifiFixtures.VhtOperation(1, 42)),
        WifiFixtures.Bss("Lab6", "02:50:00:00:00:01", -63, 6135, WifiFixtures.Rsn(2), WifiFixtures.Ie(255, 36, 0x00, 0x00, 0x02, 0x01, 0xFF, 0xFF, 37, 0x02, 39, 0, 6)),
    ];

    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("synthetic");

    public Task<Observation<IReadOnlyList<IPMaster.Core.Wifi.WifiAdapter>>> AdaptersAsync(CancellationToken ct) =>
        Task.FromResult(Observation<IReadOnlyList<IPMaster.Core.Wifi.WifiAdapter>>.Ok(
            [new IPMaster.Core.Wifi.WifiAdapter(WifiFixtures.Adapter, "Synthetic Wi-Fi adapter", "connected", null, [])], DateTimeOffset.UtcNow));

    public Task<Observation<IReadOnlyList<IPMaster.Core.Wifi.WifiBss>>> ScanAsync(Guid adapter, bool fresh, CancellationToken ct) =>
        Task.FromResult(Observation<IReadOnlyList<IPMaster.Core.Wifi.WifiBss>>.Ok([.. Networks.Select(n => n with { SeenAt = DateTimeOffset.UtcNow })], DateTimeOffset.UtcNow));

    public Task<Observation<IPMaster.Core.Wifi.WifiConnection>> ConnectionAsync(Guid adapter, CancellationToken ct) =>
        Task.FromResult(Observation<IPMaster.Core.Wifi.WifiConnection>.Ok(WifiFixtures.Connection("Office", "02:10:00:00:00:01", -48, 5180), DateTimeOffset.UtcNow));
}

[Collection("Headless UI")]
public class WifiWindowTests
{
    /// <summary>Clicks the plan three times (each a synthetic fresh scan) and shows the heatmap of one network.</summary>
    private static void MeasureThreePoints(Window window)
    {
        var canvas = window.GetVisualDescendants().OfType<SurveyCanvas>().Single();
        var status = window.GetVisualDescendants().OfType<TextBlock>().Last(t => t.Classes.Contains("status"));
        var spots = new[] { (0.15, 0.2), (0.8, 0.3), (0.5, 0.85) };
        for (var n = 0; n < spots.Length; n++)
        {
            var r = canvas.ImageRect();
            var p = canvas.TranslatePoint(new Point(r.X + (spots[n].Item1 * r.Width), r.Y + (spots[n].Item2 * r.Height)), window)!.Value;
            window.MouseDown(p, Avalonia.Input.MouseButton.Left);
            window.MouseUp(p, Avalonia.Input.MouseButton.Left);
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (!(status.Text ?? "").StartsWith($"Point {n + 1}:", StringComparison.Ordinal) && DateTime.UtcNow < deadline)
            {
                UiDesignSystemTests.Dispatch();
                Thread.Sleep(20);
            }

            Assert.StartsWith($"Point {n + 1}:", status.Text, StringComparison.Ordinal);
        }

        var target = window.GetVisualDescendants().OfType<ComboBox>().First(c => Avalonia.Automation.AutomationProperties.GetName(c) == "Heatmap network");
        target.SelectedItem = "SSID: Office";
        UiDesignSystemTests.Dispatch();
        Assert.NotNull(canvas.Heatmap);
    }

    [Fact]
    public Task Every_tab_renders_synthetic_data_in_both_themes() => HeadlessUi.Run(() =>
    {
        foreach (var variant in new[] { ThemeVariant.Light, ThemeVariant.Dark })
        {
            HeadlessUi.SetTheme(variant);
            var window = MainWindow.ToolEntries.Single(t => t.Header.Contains("Wi-Fi", StringComparison.Ordinal)).Open(null!, HeadlessUi.Vm);
            try
            {
                window.Show();
                var networks = window.GetVisualDescendants().OfType<DataGrid>().First(g => Avalonia.Automation.AutomationProperties.GetName(g) == "Networks");
                var deadline = DateTime.UtcNow.AddSeconds(10);
                while ((networks.ItemsSource as System.Collections.ICollection)?.Count is null or 0 && DateTime.UtcNow < deadline)
                {
                    UiDesignSystemTests.Dispatch();
                    Thread.Sleep(20);
                }

                Assert.Equal(7, ((System.Collections.ICollection)networks.ItemsSource!).Count);
                var tabs = window.GetVisualDescendants().OfType<TabControl>().First();
                for (var i = 0; i < tabs.ItemCount; i++)
                {
                    tabs.SelectedIndex = i;
                    UiDesignSystemTests.Dispatch();
                    if (((TabItem)tabs.Items[i]!).Header as string == "Optimization")
                    {
                        var analyse = window.GetVisualDescendants().OfType<Button>().First(b => b.Content as string == "Analyse");
                        analyse.Command?.Execute(null);
                        analyse.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
                        UiDesignSystemTests.Dispatch();
                        var advice = window.GetVisualDescendants().OfType<Border>().Count(b => b.Classes.Contains("banner") && b.IsEffectivelyVisible);
                        Assert.True(advice > 0, "the advisor shows recommendations");
                    }

                    if (((TabItem)tabs.Items[i]!).Header as string == "Site Survey") MeasureThreePoints(window);
                    HeadlessUi.Snapshot(window, $"Wi-Fi Analyzer - {((TabItem)tabs.Items[i]!).Header} - {variant}");
                }
            }
            finally
            {
                window.Close();
            }
        }

        HeadlessUi.SetTheme(ThemeVariant.Default);
    });
}

/// <summary>Long table values stay readable: trimmed cells show the full value as a tooltip; short ones get none.</summary>
[Collection("Headless UI")]
public class TableReadabilityTests
{
    public sealed record Row(string Host, string Address, string Error);

    [Fact]
    public Task Shortened_cells_show_the_full_value_and_columns_fit_their_headers() => HeadlessUi.Run(() =>
    {
        const string host = "very-long-host-name-for-a-storage-array-in-building-7.branch-office.example.internal";
        const string v6 = "2001:db8:85a3:1234:5678:8a2e:370:7334";
        const string error = "The remote host closed the connection while the TLS handshake was in progress (timeout after 15 s)";
        var grid = IPMaster.Desktop.Views.Ui.Grid(("Host Name", nameof(Row.Host), 160), ("IPv6 Address", nameof(Row.Address), 40), ("Error", nameof(Row.Error), 0));
        grid.ItemsSource = new[] { new Row(host, v6, error), new Row("nas", "::1", "") };
        var window = new Window { Content = grid, Width = 700, Height = 300 };
        window.Show();
        try
        {
            UiDesignSystemTests.Dispatch();
            Assert.All(grid.Columns, c => Assert.True(c.ActualWidth >= ((string)c.Header!).Length * 7.5, $"{c.Header} narrower than its header"));
            Assert.True(grid.CanUserResizeColumns);
            var cells = window.GetVisualDescendants().OfType<TextBlock>().Where(t => t.FindAncestorOfType<DataGridCell>() is not null).ToList();
            TextBlock Cell(string text) => cells.Single(t => t.Text == text);
            void Hover(TextBlock t)
            {
                var p = t.TranslatePoint(new Point(2, t.Bounds.Height / 2), window)!.Value;
                window.MouseMove(p);
                UiDesignSystemTests.Dispatch();
            }

            Hover(Cell(host));
            Assert.Equal(host, ToolTip.GetTip(Cell(host)));
            Assert.True(IPMaster.Desktop.Styling.TrimmedTextTips.IsTrimmed(Cell(host)));
            Hover(Cell(error));
            Assert.Equal(error, ToolTip.GetTip(Cell(error)));
            Hover(Cell("nas"));
            Assert.Null(ToolTip.GetTip(Cell("nas"))); // not shortened: no tooltip
            HeadlessUi.Snapshot(window, "Table with long values");
        }
        finally
        {
            window.Close();
        }
    });
}

/// <summary>Layout survey (also a regression check): at the default and the minimum size, no control or text of any window lies outside it.</summary>
[Collection("Headless UI")]
public class WindowFitTests
{
    internal static List<string> Problems(Window window, string name)
    {
        var client = new Rect(window.ClientSize).Inflate(0.5);
        var list = new List<string>();
        foreach (var c in window.GetVisualDescendants().OfType<Control>().Where(c => c.IsEffectivelyVisible && c.Bounds.Width > 0 && c is Button or TextBox or ComboBox or CheckBox or RadioButton or TextBlock))
        {
            if (c.GetVisualAncestors().Any(a => a is ScrollViewer or DataGrid or Avalonia.Controls.Primitives.Popup) || c.TemplatedParent is not null) continue;
            if (c is TextBlock t && (t.TextTrimming != Avalonia.Media.TextTrimming.None || string.IsNullOrEmpty(t.Text))) continue;
            if (c.TranslatePoint(new Point(0, 0), window) is not { } p) continue;
            var r = new Rect(p, c.Bounds.Size);
            if (!client.Contains(r.TopLeft) || !client.Contains(r.BottomRight))
                list.Add($"{name}: {c.GetType().Name} '{(c as TextBlock)?.Text ?? (c as ContentControl)?.Content?.ToString() ?? Avalonia.Automation.AutomationProperties.GetName(c)}' {r.Right - client.Right:+0;-0} px wide, {r.Bottom - client.Bottom:+0;-0} px tall over {client.Size}");
        }

        return list;
    }

    public static TheoryData<string> AllWindows() => [.. MainWindow.ToolEntries.Select(t => "tool:" + t.Header), .. UiDesignSystemTests.OtherWindows.Keys];

    [Theory]
    [MemberData(nameof(AllWindows))]
    public Task Nothing_lies_outside_the_window_at_default_and_minimum_size(string id) => HeadlessUi.Run(() =>
    {
        var window = id.StartsWith("tool:", StringComparison.Ordinal)
            ? MainWindow.ToolEntries.Single(t => "tool:" + t.Header == id).Open(null!, HeadlessUi.Vm)
            : UiDesignSystemTests.OtherWindows[id]();
        var name = id.Replace("tool:", "", StringComparison.Ordinal).Replace("_", "", StringComparison.Ordinal);
        try
        {
            window.Show();
            UiDesignSystemTests.Dispatch();
            var problems = Problems(window, name + " (default)");
            var defaultSize = window.ClientSize;
            window.Width = window.MinWidth > 0 ? window.MinWidth : 400;
            window.Height = window.MinHeight > 0 ? window.MinHeight : 300;
            UiDesignSystemTests.Dispatch();
            problems.AddRange(Problems(window, name + " (minimum)"));
            // 1366×768 at 125 % with a 40 px taskbar: the size ScreenFit leaves (D-113)
            var (w, h, minW, minH) = IPMaster.Desktop.Platform.ScreenFit.Fit(defaultSize.Width, defaultSize.Height, window.MinWidth, window.MinHeight, new Size(1366 / 1.25, (768 - 40) / 1.25), new Size(16, 40));
            (window.MinWidth, window.MinHeight) = (minW, minH);
            (window.Width, window.Height) = (w, h);
            UiDesignSystemTests.Dispatch();
            problems.AddRange(Problems(window, name + $" (small screen {w:0}×{h:0})"));
            Assert.True(problems.Count == 0, string.Join('\n', problems));
        }
        finally
        {
            window.Close();
        }
    });
}
