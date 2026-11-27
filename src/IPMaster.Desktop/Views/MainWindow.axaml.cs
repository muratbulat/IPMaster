using System.Diagnostics;
using System.Globalization;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Input;
using Avalonia.Input.Platform;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Export;

namespace IPMaster.Desktop.Views;

public partial class MainWindow : Window, IDialogs
{
    private KeyModifiers _modifiers;
    private IBrush? _oddBrush;
    private IBrush? _evenBrush;
    private IBrush _highlightBrush = Brushes.Khaki; // theme-exception: default of the user's View → Highlight colour setting
    private bool _closingHandled;
    private bool _closing;

    public MainWindow()
    {
        InitializeComponent();
        ActualThemeVariantChanged += (_, _) => BuildColumns(); // status dots and glyphs pick up the new palette (D-072)
        BuildToolsMenu();
        Grid.Sorting += OnSorting;
        Grid.LoadingRow += OnLoadingRow;
        Grid.UnloadingRow += OnUnloadingRow;
        Grid.ContextRequested += OnGridContextRequested;
        DataContextChanged += (_, _) =>
        {
            if (Vm is null) return;
            Grid.ItemsSource = Vm.Results.Rows;
            Vm.Results.Rows.CollectionChanged += (_, _) => ScheduleAutoFit();
            Vm.ViewChanged += (_, _) => ApplyView();
            Vm.MenusChanged += (_, _) => BuildMenus();
            ApplyView();
            BuildMenus();
        };
        Opened += async (_, _) =>
        {
            await UnlockAtStartupAsync();
            Vm?.InitContinuous();
            HookContinuous();
            InitPhase6();
            if (Vm?.StartupMessage is { } msg) await ShowMessageAsync("Settings", msg);
            if (Vm is not null) await Vm.AutoLoadAsync();
        };
        Closing += async (_, e) =>
        {
            if (_closingHandled || Vm is null) return;
            e.Cancel = true; // close again once everything is stopped and saved (D-086)
            if (_closing) return;
            _closing = true;
            IsEnabled = false;
            var error = await Vm.ShutdownAsync(CurrentLayout());
            IsEnabled = true;
            if (error is not null && !await ConfirmAsync("Closing IPMaster", error + "\n\nClose anyway? Unsaved changes will be lost."))
            {
                _closing = false; // stay open; the user can fix the cause and close again
                Vm.ResumeAfterCancelledClose();
                return;
            }

            _closingHandled = true;
            Close();
        };
    }

    private MainWindowViewModel? Vm => DataContext as MainWindowViewModel;

    public Task<bool> ConfirmAsync(string title, string message) => Dialogs.MessageAsync(this, title, message, confirm: true);

    public Task ShowMessageAsync(string title, string message) => Dialogs.MessageAsync(this, title, message, confirm: false);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        _modifiers = e.KeyModifiers;
        base.OnKeyDown(e);
        if (e.Handled) return;
        if (TryLaunchHotkey(e))
        {
            e.Handled = true;
            return;
        }

        if (TryShortcut(e)) e.Handled = true;
    }

    protected override void OnKeyUp(KeyEventArgs e)
    {
        _modifiers = e.KeyModifiers;
        base.OnKeyUp(e);
    }

    // ---------------- columns and view ----------------
    private void ApplyView()
    {
        if (Vm is null) return;
        var v = Vm.Settings.View;
        _oddBrush = ParseBrush(v.OddRowColor);
        _evenBrush = ParseBrush(v.EvenRowColor);
        _highlightBrush = ParseBrush(v.HighlightColor) ?? Brushes.Khaki; // theme-exception: user setting default
        Grid.GridLinesVisibility = v.GridLines ? DataGridGridLinesVisibility.All : DataGridGridLinesVisibility.None;
        Grid.Classes.Set("multiline", v.MultiLineCells);
        Grid.RowHeight = v.MultiLineCells ? double.NaN : v.RowSpacing switch
        {
            RowSpacing.Compact => 22,
            RowSpacing.Expanded => 36,
            _ => 28,
        };
        if (!string.IsNullOrWhiteSpace(v.FontFamily)) Grid.FontFamily = new FontFamily(v.FontFamily);
        else Grid.ClearValue(FontFamilyProperty);
        if (v.FontSize > 0) Grid.FontSize = v.FontSize;
        else Grid.ClearValue(FontSizeProperty);
        AutoExpandItem.IsChecked = v.AutoExpand;
        BuildColumns();
        Vm.Results.Rebuild();
        Vm.UpdateDeviceCount();
    }

    private static IBrush? ParseBrush(string s) => !string.IsNullOrWhiteSpace(s) && Color.TryParse(s, out var c) ? new SolidColorBrush(c) : null;

    private void BuildColumns()
    {
        if (Vm is null) return;
        var layout = Vm.Settings.View.Columns.ToDictionary(c => c.Id, StringComparer.OrdinalIgnoreCase);
        Grid.Columns.Clear();
        _fitted.Clear();
        foreach (var col in Vm.DisplayColumns)
        {
            var width = layout.TryGetValue(col.Id, out var l) && l.Width > 20 ? new DataGridLength(l.Width) : new DataGridLength(DefaultWidth(col.Id));
            DataGridColumn gridColumn = col.Id switch { "ip" => FirstColumn(), "deviceType" => DeviceTypeColumn(), _ => CellColumn(col.Id) };
            gridColumn.Header = HeaderText(col.Id, col.Header);
            gridColumn.Tag = col.Id;
            gridColumn.Width = width;
            gridColumn.CanUserSort = true;
            Grid.Columns.Add(gridColumn);
        }

        if (Vm.Settings.Scan.ScanShares)
        {
            foreach (var (id, header, _) in ShareGridColumns.All)
            {
                if (id == "share.permissions" && !Vm.Settings.Scan.ShareSecurity) continue;
                if (id == "share.disk" && !Vm.Settings.Scan.ShareDiskSpace) continue;
                Grid.Columns.Add(new DataGridTextColumn
                {
                    Header = header,
                    Tag = id,
                    Binding = new ReflectionBinding($"[{Vm.Results.KeyFor(id)}]"),
                    Width = new DataGridLength(layout.TryGetValue(id, out var l) && l.Width > 20 ? l.Width : 140),
                    CanUserSort = false,
                });
            }
        }

        Grid.FrozenColumnCount = Math.Min(Vm.Settings.View.FrozenColumns, Grid.Columns.Count);
        AutoFitColumns();
    }

    private Avalonia.Threading.DispatcherTimer? _fitTimer;

    /// <summary>Refits the columns at most twice a second while rows arrive (D-083).</summary>
    private void ScheduleAutoFit()
    {
        _fitTimer ??= new Avalonia.Threading.DispatcherTimer(TimeSpan.FromMilliseconds(500), Avalonia.Threading.DispatcherPriority.Background, (_, _) =>
        {
            _fitTimer!.Stop();
            AutoFitColumns();
        });
        if (!_fitTimer.IsEnabled) _fitTimer.Start();
    }

    /// <summary>
    /// Each column as wide as its longest value or its header (D-083). Only the three longest strings per column are
    /// measured, so 50,000 rows stay cheap; capped so one huge value cannot push everything off screen.
    /// </summary>
    private void AutoFitColumns()
    {
        if (Vm is null || Grid.Columns.Count == 0) return;
        // the cell theme may use another font size than the grid itself: measure with a rendered cell's text when there is one
        var cell = Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(Grid).OfType<DataGridCell>()
            .SelectMany(c => Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(c).OfType<TextBlock>()).FirstOrDefault();
        var typeface = cell is null ? new Typeface(Grid.FontFamily, Grid.FontStyle, Grid.FontWeight) : new Typeface(cell.FontFamily, cell.FontStyle, cell.FontWeight);
        var size = cell?.FontSize ?? Grid.FontSize;
        double Measure(string s)
        {
            if (s.Length == 0) return 0;
            using var layout = new Avalonia.Media.TextFormatting.TextLayout(s, typeface, size, null);
            return layout.WidthIncludingTrailingWhitespace;
        }

        var rows = Vm.Results.Rows;
        foreach (var gc in Grid.Columns)
        {
            if (gc.Tag is not string id) continue;
            // a width that is no longer the one fitted here was dragged by the user: keep it (until the columns are rebuilt)
            if (_fitted.TryGetValue(gc, out var fitted) && Math.Abs(gc.Width.Value - fitted) > 0.5) continue;
            var key = Vm.Results.KeyFor(id);
            var longest = LongestThree(rows, key).Select(Measure).DefaultIfEmpty(0).Max();
            var extra = id switch { "ip" => 64, "deviceType" => 44, _ => 28 }; // expander + status dot, category icon, cell padding
            var header = Measure(gc.Header?.ToString() ?? "") + 36; // header padding and sort arrow
            var width = Math.Clamp(Math.Max(longest + extra, header), 48, 700);
            gc.Width = new DataGridLength(width);
            _fitted[gc] = width;
        }
    }

    private readonly Dictionary<DataGridColumn, double> _fitted = [];

    /// <summary>The three longest non-empty cell texts in one pass (no sort of every row on each refit).</summary>
    internal static List<string> LongestThree(IEnumerable<ResultRow> rows, string key)
    {
        var top = new List<string>(4);
        foreach (var r in rows)
        {
            var s = r[key] ?? "";
            if (s.Length == 0 || (top.Count == 3 && s.Length <= top[2].Length)) continue;
            var i = top.FindIndex(t => s.Length > t.Length);
            top.Insert(i < 0 ? top.Count : i, s);
            if (top.Count > 3) top.RemoveAt(3);
        }

        return top;
    }

    private static double DefaultWidth(string id) => id switch
    {
        "ip" => 150,
        "status" or "ttl" or "pingMethod" => 90,
        "rtt" or "jitter" => 125,
        "mac" => 160,
        "deviceType" => 280,
        "hostName" or "banners" or "apps" or "shares" or "os" => 240,
        "lastScanned" or "lastSeen" or "remoteTime" or "tlsExpiry" => 180,
        _ => 150,
    };

    private string HeaderText(string id, string header)
    {
        if (Vm?.Results.SortColumn != id) return header;
        return header + (Vm.Results.SortDescending ? " ▼" : " ▲");
    }

    /// <summary>Plain text column, or a template column with conditional formatting when the column has a style.</summary>
    private DataGridColumn CellColumn(string id)
    {
        var key = Vm!.Results.KeyFor(id);
        var boldable = id == "ip" && Vm.Settings.History.Enabled;
        if (!boldable && (!Vm.Results.Styles.TryGetValue(id, out var style) || !style.HasFormatting)) return new DataGridTextColumn { Binding = new ReflectionBinding($"[{key}]") };
        return new DataGridTemplateColumn
        {
            CellTemplate = new FuncDataTemplate<ResultRow>((_, _) =>
            {
                var tb = new TextBlock { VerticalAlignment = VerticalAlignment.Center, Padding = new Thickness(12, 0) };
                tb[!TextBlock.TextProperty] = new ReflectionBinding($"[{key}]");
                tb[!TextBlock.ForegroundProperty] = new ReflectionBinding($"[{key}_fg]") { Converter = StyleConverter.Brush };
                tb[!TextBlock.BackgroundProperty] = new ReflectionBinding($"[{key}_bg]") { Converter = StyleConverter.Brush };
                tb[!TextBlock.FontWeightProperty] = new ReflectionBinding($"[{key}_fw]") { Converter = StyleConverter.Weight };
                tb[!TextBlock.FontStyleProperty] = new ReflectionBinding($"[{key}_fs]") { Converter = StyleConverter.Style };
                tb[!TextBlock.TextDecorationsProperty] = new ReflectionBinding($"[{key}_td]") { Converter = StyleConverter.Decorations };
                return tb;
            }),
        };
    }

    private sealed class StyleConverter(Func<string, object?> convert) : Avalonia.Data.Converters.IValueConverter
    {
        public static readonly StyleConverter Brush = new(s => Color.TryParse(s, out var c) ? new SolidColorBrush(c) : null);
        public static readonly StyleConverter Weight = new(s => s == "Bold" ? FontWeight.Bold : null);
        public static readonly StyleConverter Style = new(s => s == "Italic" ? FontStyle.Italic : null);
        public static readonly StyleConverter Decorations = new(s =>
        {
            var d = new TextDecorationCollection();
            if (s.Contains("Underline", StringComparison.Ordinal)) d.AddRange(TextDecorations.Underline);
            if (s.Contains("Strikethrough", StringComparison.Ordinal)) d.AddRange(TextDecorations.Strikethrough);
            return d.Count > 0 ? d : null;
        });

        // Empty or invalid values fall back to the default (unset) so unstyled cells keep the theme.
        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            value is string { Length: > 0 } s && convert(s) is { } v ? v : AvaloniaProperty.UnsetValue;

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    /// <summary>IP column: expander for devices with shares, indentation and share name for share rows.</summary>
    private DataGridTemplateColumn FirstColumn() => new()
    {
        CellTemplate = new FuncDataTemplate<ResultRow>((row, _) =>
        {
            var glyph = new Button
            {
                Padding = new Thickness(4, 0),
                MinWidth = 18,
                Background = Brushes.Transparent,
                BorderThickness = default,
                VerticalAlignment = VerticalAlignment.Center,
                [!ContentControl.ContentProperty] = new ReflectionBinding(nameof(ResultRow.Glyph)),
            };
            glyph.Click += (s, e) =>
            {
                if ((s as Control)?.DataContext is ResultRow r && !r.IsShare)
                {
                    Vm?.Results.ToggleExpand(r.Node);
                    e.Handled = true;
                }
            };
            var text = new TextBlock { VerticalAlignment = VerticalAlignment.Center, [!TextBlock.TextProperty] = new ReflectionBinding($"[{Vm!.Results.KeyFor("ip")}]") };
            // small status indicator (D-072): online / not online, also told by the tooltip (not by colour alone)
            var dot = new Avalonia.Controls.Shapes.Ellipse { Width = 8, Height = 8, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 4, 0) };
            dot[!Avalonia.Controls.Shapes.Shape.FillProperty] = new ReflectionBinding(nameof(ResultRow.IsOnline)) { Converter = OnlineBrushConverter.Instance };
            dot[!ToolTip.TipProperty] = new ReflectionBinding(nameof(ResultRow.IsOnline)) { Converter = OnlineTextConverter.Instance };
            dot[!IsVisibleProperty] = new ReflectionBinding(nameof(ResultRow.IsShare)) { Converter = Avalonia.Data.Converters.BoolConverters.Not };
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 2 };
            panel.Children.Add(glyph);
            panel.Children.Add(dot);
            panel.Children.Add(text);
            panel[!MarginProperty] = new ReflectionBinding(nameof(ResultRow.Indent)) { Converter = IndentConverter.Instance };
            return panel;
        }),
    };

    /// <summary>Device Type (D-072): glyph for an observed category, then the evidence text; empty when nothing was observed.</summary>
    private DataGridTemplateColumn DeviceTypeColumn() => new()
    {
        CellTemplate = new FuncDataTemplate<ResultRow>((_, _) =>
        {
            var icon = new PathIcon { Width = 14, Height = 14, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) };
            icon[!PathIcon.DataProperty] = new ReflectionBinding(nameof(ResultRow.DeviceCategory)) { Converter = CategoryGeometryConverter.Instance };
            icon[!IsVisibleProperty] = new ReflectionBinding(nameof(ResultRow.DeviceCategory)) { Converter = KnownCategoryConverter.Instance };
            var text = new TextBlock { VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis };
            text[!TextBlock.TextProperty] = new ReflectionBinding($"[{Vm!.Results.KeyFor("deviceType")}]");
            text[!ToolTip.TipProperty] = new ReflectionBinding(nameof(ResultRow.DeviceTypeTip));
            var panel = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(10, 0, 4, 0), Children = { icon, text } };
            return panel;
        }),
    };

    private sealed class CategoryGeometryConverter : Avalonia.Data.Converters.IValueConverter
    {
        public static readonly CategoryGeometryConverter Instance = new();

        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
        {
            var key = value switch
            {
                Core.Results.DeviceCategory.Computer => "IconComputer",
                Core.Results.DeviceCategory.Printer => "IconPrinter",
                Core.Results.DeviceCategory.Camera => "IconCamera",
                Core.Results.DeviceCategory.FileServer => "IconServer",
                _ => null,
            };
            return key is not null && Application.Current?.TryFindResource(key, out var g) == true ? g : null;
        }

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    private sealed class KnownCategoryConverter : Avalonia.Data.Converters.IValueConverter
    {
        public static readonly KnownCategoryConverter Instance = new();

        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is Core.Results.DeviceCategory c && c != Core.Results.DeviceCategory.Unknown;

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    private sealed class OnlineBrushConverter : Avalonia.Data.Converters.IValueConverter
    {
        public static readonly OnlineBrushConverter Instance = new();

        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
            Application.Current?.TryFindResource(value is true ? "IpmOnline" : "IpmOffline", Application.Current.ActualThemeVariant, out var b) == true ? b : null;

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    private sealed class OnlineTextConverter : Avalonia.Data.Converters.IValueConverter
    {
        public static readonly OnlineTextConverter Instance = new();

        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is true ? "Online" : "Not responding";

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    private sealed class IndentConverter : Avalonia.Data.Converters.IValueConverter
    {
        public static readonly IndentConverter Instance = new();

        public object? Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => new Thickness(value is double d ? d : 0, 0, 0, 0);

        public object? ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
    }

    private IReadOnlyList<ColumnLayout> CurrentLayout()
    {
        if (Vm is null) return [];
        var visible = Grid.Columns.OrderBy(c => c.DisplayIndex)
            .Where(c => c.Tag is string)
            .Select(c => new ColumnLayout { Id = (string)c.Tag!, Visible = true, Width = c.ActualWidth > 0 ? c.ActualWidth : c.Width.Value })
            .ToList();
        // keep hidden columns from the saved layout
        var hidden = Vm.Settings.View.Columns.Where(l => !l.Visible && visible.All(v => v.Id != l.Id));
        return visible.Concat(hidden).ToList();
    }

    private async Task SaveLayoutAsync()
    {
        if (Vm is null) return;
        await Vm.ApplySettingsAsync(Vm.Settings with { View = Vm.Settings.View with { Columns = CurrentLayout() } });
    }

    // ---------------- rows ----------------
    private void OnLoadingRow(object? sender, DataGridRowEventArgs e)
    {
        if (e.Row.DataContext is not ResultRow row) return;
        StyleRow(e.Row, row);
        row.PropertyChanged += RowChanged;
        e.Row.Tag = row;

        void RowChanged(object? s, System.ComponentModel.PropertyChangedEventArgs a)
        {
            if (a.PropertyName == nameof(ResultRow.IsFilterMatch) && e.Row.DataContext == row) StyleRow(e.Row, row);
        }

        e.Row.DetachedFromVisualTree += (_, _) => row.PropertyChanged -= RowChanged;
    }

    private void OnUnloadingRow(object? sender, DataGridRowEventArgs e) => e.Row.ClearValue(BackgroundProperty);

    private void StyleRow(DataGridRow gridRow, ResultRow row)
    {
        var index = gridRow.Index;
        var stripe = index % 2 == 0 ? _oddBrush : _evenBrush;
        var bg = row.Node.UserHighlighted ? Styling.Theme.Brush(Styling.Theme.Keys.UserHighlight) : row.IsFilterMatch && !row.IsShare ? _highlightBrush : stripe;
        if (bg is null) gridRow.ClearValue(BackgroundProperty);
        else gridRow.Background = bg;
        gridRow.Opacity = row.IsOnline || row.IsShare ? 1 : 0.55;
        gridRow.FontStyle = row.IsShare ? FontStyle.Italic : FontStyle.Normal;
        if (row.IsFilterMatch && bg == _highlightBrush) gridRow.Foreground = Brushes.Black; // theme-exception: text on the user's light highlight colour
        else gridRow.ClearValue(ForegroundProperty);
    }

    private async void OnSorting(object? sender, DataGridColumnEventArgs e)
    {
        e.Handled = true;
        if (Vm is null || e.Column.Tag is not string id || id.StartsWith("share.", StringComparison.Ordinal)) return;
        var desc = Vm.Results.SortColumn == id && !Vm.Results.SortDescending;
        await Vm.SetSortAsync(id, desc);
        RefreshHeaders();
    }

    private void RefreshHeaders()
    {
        if (Vm is null) return;
        foreach (var c in Grid.Columns)
        {
            if (c.Tag is string id && Vm.DisplayColumns.FirstOrDefault(x => x.Id == id) is { } col) c.Header = HeaderText(id, col.Header);
        }
    }

    private async void OnRemoveSorting(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await Vm.SetSortAsync(null, false);
        RefreshHeaders();
    }

    private IReadOnlyList<ResultRow> SelectedRows() => Grid.SelectedItems.OfType<ResultRow>().ToList();

    private IReadOnlyList<DeviceNode> SelectedNodes() => SelectedRows().Select(r => r.Node).Distinct().ToList();

    private void OnGridDoubleTapped(object? sender, TappedEventArgs e)
    {
        if (Grid.SelectedItem is not ResultRow row) return;
        if (row.IsShare) OpenShare(row);
        else OpenProperties(row.Node);
    }

    private void OnGridKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.C && e.KeyModifiers == KeyModifiers.Control)
        {
            OnCopy(sender, e);
            e.Handled = true;
        }
        else if (e.Key == Key.Delete && SelectedNodes() is { Count: > 0 } nodes)
        {
            Vm?.DeleteDevices(nodes);
            e.Handled = true;
        }
        else if (e.Key is Key.Add or Key.Subtract && Grid.SelectedItem is ResultRow { IsShare: false } r && r.Node.ShareRows.Count > 0)
        {
            if (r.Node.Expanded != (e.Key == Key.Add)) Vm?.Results.ToggleExpand(r.Node);
            e.Handled = true;
        }
    }

    private void OnGridContextRequested(object? sender, ContextRequestedEventArgs e)
    {
        if (Vm is null) return;
        var rows = SelectedRows();
        if (rows.Count == 0) return;
        var menu = new ContextMenu();
        MenuItem Item(string header, Action action)
        {
            var mi = new MenuItem { Header = header };
            mi.Click += (_, _) => action();
            return mi;
        }

        if (rows.Count == 1 && rows[0].IsShare)
        {
            var share = rows[0];
            menu.Items.Add(Item("Explore", async () => { if (await ConfirmReachableAsync(share.Node)) OpenShare(share); }));
            menu.Items.Add(Item("Copy Path", async () => await CopyTextAsync(SharePath(share))));
            AddShareManagementItems(menu, share, Item);
            menu.Items.Add(Item("Properties", () => OpenProperties(share.Node)));
        }
        else
        {
            var nodes = SelectedNodes();
            menu.Items.Add(Item("Properties", () => OpenProperties(nodes[0])));
            menu.Items.Add(Item("Assign Friendly Name…  (F2)", async () => await AssignFriendlyNameAsync(nodes[0])));
            menu.Items.Add(Item("Copy", () => OnCopy(this, new RoutedEventArgs())));
            menu.Items.Add(Item("Rescan Device", async () => await Vm.RescanAsync(RescanMode.Listed, nodes)));
            var cellValue = CurrentCell(rows[0]);
            if (cellValue is { } cv)
            {
                menu.Items.Add(Item($"Setup Filter: {cv.Header} = {Shorten(cv.Text)}", () => Vm.AddFilterCondition(cv.Id, FilterOperation.EqualTo, cv.Text)));
            }

            menu.Items.Add(new Separator());
            AddDeviceManagementItems(menu, nodes, Item);
            AddToolItems(menu, nodes[0], Item);
            AddQueryRescanItems(menu, nodes, Item);
            AddContinuousItems(menu, nodes, Item);
            menu.Items.Add(new Separator());
            menu.Items.Add(Item(nodes.All(n => n.UserHighlighted) ? "Clear Highlight" : "Highlight Current Line", () =>
            {
                var on = !nodes.All(n => n.UserHighlighted);
                foreach (var n in nodes) n.UserHighlighted = on;
                Vm.Results.Rebuild();
            }));
            if (nodes.Any(n => n.ShareRows.Count > 0))
            {
                menu.Items.Add(Item(nodes.All(n => n.Expanded) ? "Collapse" : "Expand", () =>
                {
                    var expand = !nodes.All(n => n.Expanded);
                    foreach (var n in nodes.Where(n => n.ShareRows.Count > 0)) n.Expanded = expand;
                    Vm.Results.Rebuild();
                }));
            }

            menu.Items.Add(new Separator());
            menu.Items.Add(Item(nodes.Count == 1 ? "Delete from List" : $"Delete {nodes.Count} Devices from List", () => Vm.DeleteDevices(nodes)));
        }

        menu.Open(Grid);
        e.Handled = true;
    }

    private static string Shorten(string s) => s.Length > 30 ? s[..30] + "…" : s;

    private (string Id, string Header, string Text)? CurrentCell(ResultRow row)
    {
        if (Grid.CurrentColumn?.Tag is not string id || Vm?.DisplayColumns.FirstOrDefault(c => c.Id == id) is not { } col) return null;
        var text = row.RawText(id);
        return text.Length == 0 ? null : (id, col.Header, text);
    }

    private static string SharePath(ResultRow share) => $@"\\{share.Result.Key}\{share.Share!.Name}";

    private void OpenShare(ResultRow share)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe") { ArgumentList = { SharePath(share) }, UseShellExecute = false });
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            _ = ShowMessageAsync("Explore", ex.Message);
        }
    }

    private void OpenProperties(DeviceNode node)
    {
        if (Vm is null) return;
        var w = new PropertiesWindow(Vm, node.Result);
        w.Show(this);
    }

    private async Task CopyTextAsync(string text)
    {
        if (Clipboard is not null) await Clipboard.SetTextAsync(text);
    }

    private async void OnCopy(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var rows = SelectedRows().Where(r => !r.IsShare).Select(r => r.Result).ToList();
        if (rows.Count == 0) return;
        var cols = Vm.DisplayColumns;
        using var sw = new StringWriter(CultureInfo.InvariantCulture);
        CsvExporter.WriteRow(sw, cols.Select(c => c.Header), '\t', protectFormulas: false);
        foreach (var r in rows) CsvExporter.WriteRow(sw, cols.Select(c => c.Text(r, Vm.Format)), '\t', protectFormulas: false);
        await CopyTextAsync(sw.ToString());
        Vm.StatusText = $"Copied {rows.Count} row(s).";
    }

    // ---------------- menus ----------------
    private void BuildMenus()
    {
        if (Vm is null) return;
        var s = Vm.Settings;

        RecentMenu.Items.Clear();
        foreach (var f in s.RecentFiles)
        {
            var mi = new MenuItem { Header = f };
            mi.Click += async (_, _) => await LoadWithDialogAsync(f);
            RecentMenu.Items.Add(mi);
        }

        RecentMenu.IsEnabled = s.RecentFiles.Count > 0;
        AutoLoadSaveItem.IsChecked = s.AutoLoadSaveRecent;

        BookmarksMenu.Items.Clear();
        var add = new MenuItem { Header = "_Add Current Range…" };
        add.Click += OnAddBookmark;
        var manage = new MenuItem { Header = "_Manage Bookmarks…" };
        manage.Click += OnManageBookmarks;
        BookmarksMenu.Items.Add(add);
        BookmarksMenu.Items.Add(manage);
        if (s.Bookmarks.Count > 0) BookmarksMenu.Items.Add(new Separator());
        foreach (var b in s.Bookmarks.OrderBy(b => b.Name, StringComparer.CurrentCultureIgnoreCase))
        {
            var parts = b.Name.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
            var parent = BookmarksMenu;
            foreach (var group in parts.SkipLast(1))
            {
                var existing = parent.Items.OfType<MenuItem>().FirstOrDefault(m => m.Header as string == group && m.Tag as string == "group");
                if (existing is null)
                {
                    existing = new MenuItem { Header = group, Tag = "group" };
                    parent.Items.Add(existing);
                }

                parent = existing;
            }

            var item = new MenuItem { Header = parts.LastOrDefault() ?? b.Name };
            ToolTip.SetTip(item, b.RangeInfo + "\nClick: replace ranges · Ctrl+click: append");
            item.Click += async (_, _) =>
            {
                // manual: Ctrl appends, Shift opens the bookmark in a new window
                if (_modifiers.HasFlag(KeyModifiers.Shift)) await OpenNewWindowAsync(b.Ranges.Where(r => r.Enabled).Select(r => r.Target).ToList());
                else Vm.OpenBookmark(b, append: _modifiers.HasFlag(KeyModifiers.Control));
            };
            parent.Items.Add(item);
        }

        QuickFilterMenu.Items.Clear();
        var shared = new MenuItem { Header = "_Shared Folders", ToggleType = MenuItemToggleType.CheckBox, IsChecked = Vm.OnlySharedFolders };
        shared.Click += (_, _) => Vm.OnlySharedFolders = !Vm.OnlySharedFolders;
        QuickFilterMenu.Items.Add(shared);
        foreach (var f in s.SavedFilters)
        {
            var mi = new MenuItem { Header = f.Name };
            mi.Click += (_, _) => Vm.LoadFilter(f);
            QuickFilterMenu.Items.Add(mi);
        }

        QuickFilterMenu.Items.Add(new Separator());
        var settings = new MenuItem { Header = "S_ettings…" };
        settings.Click += OnManageFilters;
        QuickFilterMenu.Items.Add(settings);
    }

    // ---------------- file ----------------
    private static readonly FilePickerFileType XmlType = new("IPMaster results (XML)") { Patterns = ["*.xml"] };

    private async void OnLoad(object? sender, RoutedEventArgs e)
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Load Results", FileTypeFilter = [XmlType] });
        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path) await LoadWithDialogAsync(path);
    }

    private async Task LoadWithDialogAsync(string path)
    {
        if (Vm is null) return;
        var choice = await Dialogs.LoadOptionsAsync(this);
        if (choice is not { } c) return;
        await Vm.LoadAsync(path, c.Mode, c.Append);
    }

    private async void OnSave(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (Vm.Results.Count == 0)
        {
            await ShowMessageAsync("Save Results", "There are no results to save.");
            return;
        }

        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save Results",
            SuggestedFileName = $"ipmaster_{DateTime.Now:yyyyMMdd_HHmm}",
            DefaultExtension = "xml",
            FileTypeChoices =
            [
                XmlType,
                new FilePickerFileType("CSV (comma-separated values)") { Patterns = ["*.csv"] },
                new FilePickerFileType("HTML report") { Patterns = ["*.htm", "*.html"] },
                new FilePickerFileType("Text table") { Patterns = ["*.txt"] },
                new FilePickerFileType("JSON") { Patterns = ["*.json"] },
                new FilePickerFileType("SQLite database") { Patterns = ["*.db"] },
            ],
        });
        var path = file?.TryGetLocalPath();
        if (path is null) return;
        try
        {
            await Vm.ExportAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or Microsoft.Data.Sqlite.SqliteException)
        {
            await ShowMessageAsync("Save Results", ex.Message);
        }
    }

    private async void OnToggleAutoLoadSave(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await Vm.SetAutoLoadSaveAsync(!Vm.Settings.AutoLoadSaveRecent);
        AutoLoadSaveItem.IsChecked = Vm.Settings.AutoLoadSaveRecent;
    }

    private async void OnImport(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var text = await Dialogs.EditTextAsync(this, "Import IP/Host Name List",
            "One entry per line: address, start-end range, address/prefix or host name (IPv4 or IPv6). Unrecognised lines are reported and skipped.",
            "", allowLoadFile: true);
        if (string.IsNullOrWhiteSpace(text)) return;
        var parsed = TargetParser.ParseList(text);
        if (parsed.Targets.Count == 0)
        {
            await ShowMessageAsync("Import", "No valid entries were found.");
            return;
        }

        var entry = new RangeEntryViewModel
        {
            Target = string.Join(", ", parsed.Targets.Select(t => t.Original)),
            Comment = $"Imported list ({parsed.Targets.Count} entries)",
        };
        var append = await ConfirmAsync("Import", $"{parsed.Targets.Count} entries imported" +
            (parsed.Rejected.Count > 0 ? $", {parsed.Rejected.Count} lines skipped (first: line {parsed.Rejected[0].LineNumber}: {parsed.Rejected[0].Reason})" : "") +
            ".\n\nAppend to the current ranges? Choose No to replace them.");
        Vm.SetRanges([entry], append);
    }

    private static readonly FilePickerFileType ConfigType = new("IPMaster configuration (XML)") { Patterns = ["*.xml"] };

    private async void OnSaveConfig(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save Configuration", SuggestedFileName = "ipmaster-config", DefaultExtension = "xml", FileTypeChoices = [ConfigType],
        });
        if (file?.TryGetLocalPath() is { } path) await Vm.SaveConfigAsync(path);
    }

    private async void OnLoadConfig(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Load Configuration", FileTypeFilter = [ConfigType] });
        if (files.Count > 0 && files[0].TryGetLocalPath() is { } path) await Vm.LoadConfigAsync(path);
    }

    private async void OnResetConfig(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (await ConfirmAsync("Reset to Default", "Restore all settings, ranges, bookmarks and saved filters to their defaults?")) await Vm.ResetConfigAsync();
    }

    private void OnExit(object? sender, RoutedEventArgs e) => Close();

    // ---------------- view ----------------
    private async void OnColumns(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await SaveLayoutAsync();
        var result = await Dialogs.ColumnsAsync(this, Vm.EnabledColumns, Vm.Settings.View.Columns, Vm.Settings.View.FrozenColumns);
        if (result is not { } r) return;
        await Vm.ApplySettingsAsync(Vm.Settings with { View = Vm.Settings.View with { Columns = r.Layout, FrozenColumns = r.Frozen } });
    }

    private async void OnFreeze(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var upTo = Grid.CurrentColumn is { } c ? c.DisplayIndex + 1 : 1;
        await SaveLayoutAsync();
        await Vm.ApplySettingsAsync(Vm.Settings with { View = Vm.Settings.View with { FrozenColumns = Math.Max(1, upTo) } });
    }

    private async void OnUnfreeze(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await SaveLayoutAsync();
        await Vm.ApplySettingsAsync(Vm.Settings with { View = Vm.Settings.View with { FrozenColumns = 0 } });
    }

    private async void OnToggleAutoExpand(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await Vm.ApplySettingsAsync(Vm.Settings with { View = Vm.Settings.View with { AutoExpand = !Vm.Settings.View.AutoExpand } });
    }

    private void OnCollapseAll(object? sender, RoutedEventArgs e) => Vm?.Results.ExpandAll(false);

    private void OnExpandAll(object? sender, RoutedEventArgs e) => Vm?.Results.ExpandAll(true);

    private async void OnRowSpacing(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || (sender as MenuItem)?.Tag is not string tag) return;
        await Vm.ApplySettingsAsync(Vm.Settings with { View = Vm.Settings.View with { RowSpacing = Enum.Parse<RowSpacing>(tag) } });
    }

    private async void OnLegend(object? sender, RoutedEventArgs e) => await ShowMessageAsync("Legend", """
        Row styles
          Normal text — device answered (online)
          Faded text — device did not answer (shown when inactive devices are displayed or it is a rescan)
          Highlight colour — row matches the advanced filter
          Blue tint — row highlighted by you (context menu → Highlight Current Line)
          Italic, indented — shared resource of the device above; + / − expands or collapses shares

        Cell markers
          …                 value still being collected
          [timeout] [no response] [access denied] [unsupported] [failed] [cancelled] — why a value is missing
          (duplicate)       MAC address answers for more than one IP address
          (unverified)      reverse DNS name does not resolve back to the address
          (untrusted)       TLS certificate chain is not trusted by this computer
          (open|filtered)   UDP port without reply (never reported as open)
          〃                 same value as the row above (repeated-value folding)

        Share flags: C common · R restricted · W writable · A administrative · P printer
        """);

    private async void OnStatistic(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || (sender as MenuItem)?.Tag is not string tag) return;
        await Vm.SetStatusStatisticAsync(Enum.Parse<StatusStatistic>(tag));
    }

    // ---------------- filters and find ----------------
    private void OnAddCondition(object? sender, RoutedEventArgs e) => Vm?.AddFilterCondition();

    private void OnRemoveCondition(object? sender, RoutedEventArgs e)
    {
        if ((sender as Control)?.DataContext is FilterConditionViewModel c) Vm?.RemoveFilterCondition(c);
    }

    private async void OnSaveFilter(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var name = await Dialogs.PromptAsync(this, "Save Filter", "Filter name:", "");
        if (!string.IsNullOrWhiteSpace(name)) await Vm.SaveFilterAsync(name.Trim());
    }

    private async void OnManageFilters(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var list = await Dialogs.ManageListAsync(this, "Saved Filters", Vm.Settings.SavedFilters, f => f.Name,
            f => string.Join(f.MatchAll ? " AND " : " OR ", f.Conditions.Select(c => $"{c.ColumnId} {c.Operation} '{c.Value}'")),
            (f, n) => f with { Name = n }, null);
        if (list is not null) await Vm.SetSavedFiltersAsync(list);
    }

    private void OnShareCategory(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || sender is not CheckBox { Tag: string tag } cb) return;
        Vm.SetShareCategory(Enum.Parse<ShareCategory>(tag), cb.IsChecked == true);
    }

    private void OnFind(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        Vm.FindVisible = true;
        FindBox.Focus();
        FindBox.SelectAll();
    }

    private void OnFindKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) FindStep(e.KeyModifiers.HasFlag(KeyModifiers.Shift));
        else if (e.Key == Key.Escape) OnFindClose(sender, e);
    }

    private void OnFindNext(object? sender, RoutedEventArgs e) => FindStep(false);

    private void OnFindPrevious(object? sender, RoutedEventArgs e) => FindStep(true);

    private void OnFindClose(object? sender, RoutedEventArgs e)
    {
        if (Vm is not null) Vm.FindVisible = false;
        FindStatus.Text = "";
    }

    private void FindStep(bool backwards)
    {
        if (Vm is null) return;
        var start = Grid.SelectedIndex < 0 ? (backwards ? 0 : -1) : Grid.SelectedIndex;
        var idx = Vm.FindNext(start, backwards);
        if (idx < 0)
        {
            FindStatus.Text = "Not found";
            return;
        }

        FindStatus.Text = "";
        Grid.SelectedIndex = idx;
        Grid.ScrollIntoView(Vm.Results.Rows[idx], null);
    }

    // ---------------- actions ----------------
    private async void OnRescanAll(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || (sender as MenuItem)?.Tag is not string tag) return;
        await Vm.RescanAsync(Enum.Parse<RescanMode>(tag));
    }

    private async void OnDeleteInactive(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var inactive = Vm.InactiveDevices();
        if (inactive.Count == 0)
        {
            await ShowMessageAsync("Delete Inactive Devices", "There are no inactive devices in the list.");
            return;
        }

        if (await ConfirmAsync("Delete Inactive Devices", $"Delete {inactive.Count:N0} inactive device(s) from the list?")) Vm.DeleteDevices(inactive);
    }

    private async void OnPaste(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || Clipboard is null) return;
        var text = (await Clipboard.TryGetTextAsync())?.Trim() ?? "";
        if (!TargetParser.TryParseAddress(text, out var key))
        {
            await ShowMessageAsync("Paste", "The clipboard does not contain an IP address.");
            return;
        }

        string? target;
        if (key.IsV6)
        {
            target = key.ToString(); // IPv6: as-is only (manual)
        }
        else
        {
            var choice = await Dialogs.ChoiceAsync(this, "Paste", $"Use {key} as:",
                ["As is", $"Class C range ({MainWindowViewModel.ExpandPasted(text, 24)})", $"Class B range ({MainWindowViewModel.ExpandPasted(text, 16)})",
                    $"Class A range ({MainWindowViewModel.ExpandPasted(text, 8)})"]);
            if (choice is not { } c) return;
            target = MainWindowViewModel.ExpandPasted(text, c switch { 1 => 24, 2 => 16, 3 => 8, _ => 32 });
        }

        if (target is not null) Vm.SetRanges([new RangeEntryViewModel { Target = target }], append: true);
    }

    // ---------------- options ----------------
    private async void OnIgnored(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var text = await Dialogs.EditTextAsync(this, "Ignored IP Addresses",
            "Addresses that are never scanned. One per line: address, range, CIDR, or wildcard pattern such as 10.0.0.* or 192.168.1.? (IPv4 wildcards apply per octet).",
            string.Join(Environment.NewLine, Vm.Settings.IgnoredAddresses), allowLoadFile: false,
            validate: t =>
            {
                var list = new IgnoreList(t.Split('\n').Select(l => l.TrimEnd('\r')));
                return list.Rejected.Count == 0 ? null : $"Line {list.Rejected[0].LineNumber}: {list.Rejected[0].Reason}";
            });
        if (text is null) return;
        var lines = text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).ToList();
        await Vm.ApplySettingsAsync(Vm.Settings with { IgnoredAddresses = lines });
    }

    /// <summary>Toolbar "Detect local IP range": Tools → Discovery → IP Address Tools on the Local Range tab (D-111).</summary>
    private void OnDetect(object? sender, RoutedEventArgs e)
    {
        if (Vm is not null) new IpAddressToolsWindow(Vm).Show(this);
    }

    private async void OnOptions(object? sender, RoutedEventArgs e) => await ShowOptionsAsync(null);

    private async Task ShowOptionsAsync(Action<OptionsWindow>? prepare)
    {
        if (Vm is null) return;
        await SaveLayoutAsync();
        var options = new OptionsViewModel(Vm.SettingsForEditing(), Vm.Probes, DownloadOuiAsync);
        var window = new OptionsWindow { DataContext = options };
        prepare?.Invoke(window);
        if (await window.ShowDialog<bool>(this)) await Vm.ApplySettingsAsync(options.ToSettings());
    }

    private async Task<string> DownloadOuiAsync()
    {
        if (Vm is null) return "";
        if (!await ConfirmAsync("Download OUI database", "Download the IEEE MA-L, MA-M and MA-S registries (about 6 MB) from standards-oui.ieee.org into the settings folder?\n\nThis is the only network request IPMaster makes to the internet for this feature."))
        {
            return Vm.Oui.Capability.Description;
        }

        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("IPMaster/0.2");
        var msg = await Vm.Oui.DownloadAsync(http, CancellationToken.None);
        return msg + ". " + Vm.Oui.Capability.Description;
    }

    // ---------------- bookmarks ----------------
    private async void OnAddBookmark(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var name = await Dialogs.PromptAsync(this, "Add Bookmark", "Bookmark name (use | for groups, e.g. London | Subnet 1):",
            Vm.Ranges.FirstOrDefault(r => r.Comment.Length > 0)?.Comment ?? "");
        if (!string.IsNullOrWhiteSpace(name)) await Vm.AddBookmarkAsync(name.Trim());
    }

    private async void OnManageBookmarks(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var list = await Dialogs.ManageListAsync(this, "Bookmarks", Vm.Settings.Bookmarks, b => b.Name, b => b.RangeInfo,
            (b, n) => b with { Name = n }, Dialogs.BookmarkTransfer);
        if (list is not null) await Vm.SetBookmarksAsync(list);
    }

    // ---------------- customisation ----------------
    private async Task AssignFriendlyNameAsync(DeviceNode node)
    {
        if (Vm is null) return;
        var fn = Vm.Settings.FriendlyNames;
        if (!fn.Enabled)
        {
            await ShowMessageAsync("Assign Friendly Name", "Friendly names are disabled (No mapping). Choose identifying columns in Options → Friendly Names / Comments.");
            return;
        }

        var key = Vm.FriendlyKeyFor(node);
        if (key is null)
        {
            await ShowMessageAsync("Assign Friendly Name", $"This device has no value for the identifying column(s): {string.Join(", ", fn.IdentifyBy)}.");
            return;
        }

        var existing = Vm.FriendlyEntryFor(node) ?? new FriendlyEntry { Key = key };
        var edited = await Dialogs.FriendlyEntryAsync(this, existing with { Key = key }, fn.Parameters, keyEditable: false);
        if (edited is not null) await Vm.AssignFriendlyNameAsync(edited);
    }

    private async void OnFriendlyNames(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var result = await FriendlyNamesWindow.ShowAsync(this, Vm.Settings.FriendlyNames, ColumnCatalog.All);
        if (result is not null) await Vm.SetFriendlyNamesAsync(result);
    }

    private async void OnVirtualColumns(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var list = await Dialogs.VirtualColumnsAsync(this, Vm.Settings);
        if (list is not null) await Vm.SetVirtualColumnsAsync(list);
    }

    private async void OnChangeColumnView(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var current = Grid.CurrentColumn?.Tag as string;
        var result = await Dialogs.ColumnViewAsync(this, Vm.DisplayColumns, current, Vm.Settings.ColumnStyles);
        if (result is { } r) await Vm.SetColumnStyleAsync(r.ColumnId, r.Style);
    }

    // ---------------- reports / help ----------------
    private void OnCompare(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        new CompareWindow(ColumnCatalog.All, Vm.Format).Show(this);
    }

    /// <summary>About → author line, from the assembly metadata (Directory.Build.props).</summary>
    public static string AuthorLine => "Author: " + (typeof(MainWindow).Assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyCompanyAttribute), false).OfType<System.Reflection.AssemblyCompanyAttribute>().FirstOrDefault()?.Company ?? "");

    private async void OnAbout(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var p = Vm.Probes;
        var sb = new StringBuilder();
        var c = CultureInfo.CurrentCulture;
        sb.AppendLine(c, $"IPMaster {typeof(MainWindow).Assembly.GetName().Version?.ToString(3)}");
        sb.AppendLine("Portable network scanner. All scanning runs locally; no account or online service is used.");
        sb.AppendLine(AuthorLine);
        sb.AppendLine();
        sb.AppendLine("Capabilities on this computer:");
        void Line(string name, CapabilityStatus s) => sb.AppendLine(c, $"  {name}: {(s.Available ? "available" : "unavailable")} — {s.Description}");
        Line("ICMP", p.Icmp.Capability);
        Line("ARP", p.Arp.Capability);
        Line("Neighbour cache", p.Neighbors.Capability);
        Line("Vendor database", p.Vendors.Capability);
        Line("Windows lookups and shares", p.Windows.Capability);
        sb.AppendLine();
        sb.AppendLine(c, $"Settings file: {Vm.ConfigPath}");
        await ShowMessageAsync("About IPMaster", sb.ToString());
    }
}
