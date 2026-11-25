using System.Globalization;
using System.Numerics;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Templates;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → IP Calculator: non-modal utility window. Calculator, Split Subnet and Range Tools tabs; every number comes from
/// Core's <see cref="IpCalculator"/>. Visualisations are built from theme resources so they follow light/dark and scaling.
/// </summary>
internal sealed class IpCalculatorWindow : Window
{
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas, Menlo, monospace");
    private readonly IpCalculatorViewModel _vm;
    private readonly ContentControl _breakdown = new();
    private readonly ContentControl _range = new();
    private readonly DataGrid _subnets;
    private Grid? _results;

    public IpCalculatorWindow(IpCalculatorViewModel vm)
    {
        _vm = vm;
        DataContext = vm;
        Title = "IP Calculator";
        Width = 1180;
        Height = 860;
        MinWidth = 640;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _subnets = Ui.Grid(("#", nameof(SubnetRow.Number), 70), ("Subnet", nameof(SubnetRow.Subnet), 230), ("First", nameof(SubnetRow.First), 200),
            ("Last", nameof(SubnetRow.Last), 200), ("Broadcast Address", nameof(SubnetRow.Broadcast), 150), ("Address Count", nameof(SubnetRow.Count), 0));
        _subnets.CanUserSortColumns = false; // the order is the address order; sorting one page would mislead
        AutomationProperties.SetName(_subnets, "Subnets on this page");

        var tabs = new TabControl
        {
            Margin = new Thickness(12, 6, 12, 0),
            Items =
            {
                new TabItem { Header = "Calculator", Content = Scroll(CalculatorTab()) },
                new TabItem { Header = "Split Subnet", Content = SplitTab() },
                new TabItem { Header = "Range Tools", Content = Scroll(RangeTab()) },
            },
        };
        var status = new Border
        {
            Padding = new Thickness(12, 4),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Child = Bound(new TextBlock { TextWrapping = TextWrapping.Wrap }, TextBlock.TextProperty, nameof(vm.Status)),
        };
        status.Bind(Border.BorderBrushProperty, status.GetResourceObservable("SystemControlForegroundBaseLowBrush"));
        AutomationProperties.SetLiveSetting(status.Child!, AutomationLiveSetting.Polite);
        var dock = new DockPanel();
        DockPanel.SetDock(status, Dock.Bottom);
        dock.Children.Add(status);
        dock.Children.Add(tabs);
        Content = dock;

        vm.PropertyChanged += (_, e) =>
        {
            switch (e.PropertyName)
            {
                case nameof(vm.Result):
                    RebuildVisuals();
                    break;
                case nameof(vm.Split):
                    ConfigureSubnetColumns();
                    break;
            }
        };
        ActualThemeVariantChanged += (_, _) => RebuildVisuals();
        SizeChanged += (_, _) => Reflow();
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape && vm.IsExporting)
            {
                vm.CancelExport();
                e.Handled = true;
            }
        };
        Closed += (_, _) => vm.Dispose();
        Opened += (_, _) =>
        {
            RebuildVisuals();
            ConfigureSubnetColumns();
            _address?.Focus();
        };
    }

    private TextBox? _address;

    // ---------------------------------------------------------------- helpers

    private static T Bound<T>(T control, AvaloniaProperty property, string path, BindingMode mode = BindingMode.OneWay) where T : Control
    {
        control.Bind(property, new Binding(path) { Mode = mode });
        return control;
    }

    private static TextBox Text(string path, string name, string placeholder = "", double width = double.NaN)
    {
        var t = new TextBox { PlaceholderText = placeholder, Width = width, HorizontalAlignment = double.IsNaN(width) ? HorizontalAlignment.Stretch : HorizontalAlignment.Left };
        AutomationProperties.SetName(t, name);
        return Bound(t, TextBox.TextProperty, path, BindingMode.TwoWay);
    }

    /// <summary>Names the spinner and its inner edit box, which screen readers announce on focus (review R-16).</summary>
    private static void NameSpinner(NumericUpDown spinner, string name)
    {
        AutomationProperties.SetName(spinner, name);
        spinner.TemplateApplied += (_, e) =>
        {
            if (e.NameScope.Find<TextBox>("PART_TextBox") is { } box) AutomationProperties.SetName(box, name);
        };
    }

    private static Label Caption(string text, Control target) => new() { Content = text, Target = target, VerticalAlignment = VerticalAlignment.Center, Padding = new Thickness(0) };

    private static Control Scroll(Control c) => new ScrollViewer { Content = c, Padding = new Thickness(0, 10, 12, 12), HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };

    private static TextBlock Section(string text) => new() { Text = text, FontSize = 15, FontWeight = FontWeight.SemiBold, Margin = new Thickness(0, 12, 0, 6) };

    private static TextBlock Error(string path, string visiblePath = "")
    {
        var t = Bound(new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap }, TextBlock.TextProperty, path);
        AutomationProperties.SetLiveSetting(t, AutomationLiveSetting.Assertive);
        if (visiblePath.Length > 0) Bound(t, IsVisibleProperty, visiblePath);
        return t;
    }

    private static Border Card(Control child)
    {
        var b = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 12), Child = child };
        b.Bind(Border.BorderBrushProperty, b.GetResourceObservable("SystemControlForegroundBaseLowBrush"));
        return b;
    }

    private Button CopyButton(Func<string> value, string what)
    {
        var b = new Button { Content = "Copy", Classes = { "tool" }, FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
        ToolTip.SetTip(b, "Copy " + what);
        AutomationProperties.SetName(b, "Copy " + what);
        b.Click += async (_, _) =>
        {
            var v = value();
            if (v.Length == 0) return;
            await Ui.CopyAsync(this, v);
            _vm.Status = $"Copied {what}: {(v.Length > 80 ? v[..80] + "…" : v)}";
        };
        return b;
    }

    /// <summary>Label | value | Copy rows. Values are selectable; Copy puts the plain exact value on the clipboard.</summary>
    private ItemsControl FieldList(System.Collections.IEnumerable source, bool prominent)
    {
        return new ItemsControl
        {
            ItemsSource = source,
            ItemTemplate = new FuncDataTemplate<IpField>((f, _) =>
            {
                if (f is null) return new TextBlock();
                var g = new Grid { ColumnDefinitions = new ColumnDefinitions("180,*,Auto"), Margin = new Thickness(0, prominent ? 2 : 1) };
                var label = new TextBlock { Text = f.Label, Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap };
                var value = new SelectableTextBlock
                {
                    Text = f.Display, TextWrapping = TextWrapping.Wrap, VerticalAlignment = VerticalAlignment.Center,
                    FontFamily = f.Label.Contains("Classification", StringComparison.Ordinal) || f.Label.Contains("Historical", StringComparison.Ordinal) ? FontFamily.Default : Mono,
                    FontWeight = prominent && f.Label is "Network Address" or "Network Prefix" or "Usable Addresses" or "Total Addresses" ? FontWeight.SemiBold : FontWeight.Normal,
                };
                if (f.Hint.Length > 0)
                {
                    ToolTip.SetTip(label, f.Hint);
                    ToolTip.SetTip(value, f.Hint);
                }

                Grid.SetColumn(value, 1);
                g.Children.Add(label);
                g.Children.Add(value);
                if (f.Copy.Length > 0)
                {
                    var copy = CopyButton(() => f.Copy, f.Label);
                    Grid.SetColumn(copy, 2);
                    g.Children.Add(copy);
                }

                AutomationProperties.SetName(g, $"{f.Label}: {f.Display}");
                return g;
            }, supportsRecycling: false),
        };
    }

    // ---------------------------------------------------------------- calculator tab

    private Control CalculatorTab()
    {
        var root = new StackPanel { Spacing = 10 };
        root.Children.Add(InputCard());
        var headline = Bound(new SelectableTextBlock { FontSize = 20, FontWeight = FontWeight.SemiBold, FontFamily = Mono, TextWrapping = TextWrapping.Wrap }, TextBlock.TextProperty, nameof(_vm.Headline));
        AutomationProperties.SetLiveSetting(headline, AutomationLiveSetting.Polite);
        root.Children.Add(headline);

        var left = new StackPanel { Spacing = 2 };
        left.Children.Add(Section("Results"));
        left.Children.Add(FieldList(_vm.PrimaryFields, prominent: true));
        var notes = Bound(new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0), FontStyle = FontStyle.Italic }, TextBlock.TextProperty, nameof(_vm.NotesText));
        left.Children.Add(notes);
        left.Children.Add(new Expander
        {
            Header = "Advanced details",
            Margin = new Thickness(0, 10, 0, 0),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Content = new StackPanel
            {
                Spacing = 4,
                Children =
                {
                    FieldList(_vm.AdvancedFields, prominent: false),
                    Form.Hint(IpSpecialRanges.Source),
                },
            },
        });

        var right = new StackPanel { Spacing = 4 };
        var breakdownHead = new DockPanel { Margin = new Thickness(0, 12, 0, 6) };
        var binary = new ToggleButton { Content = "Show binary details" };
        AutomationProperties.SetName(binary, "Show binary details");
        Bound(binary, ToggleButton.IsCheckedProperty, nameof(_vm.ShowBinary), BindingMode.TwoWay);
        DockPanel.SetDock(binary, Dock.Right);
        breakdownHead.Children.Add(binary);
        breakdownHead.Children.Add(new TextBlock { Text = "Address Breakdown", FontSize = 15, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center });
        right.Children.Add(breakdownHead);
        right.Children.Add(_breakdown);
        right.Children.Add(Section("Subnet Range"));
        right.Children.Add(_range);

        _results = new Grid { ColumnDefinitions = new ColumnDefinitions("4*,24,5*") };
        _results.Children.Add(left);
        Grid.SetColumn(right, 2);
        _results.Children.Add(right);
        Bound(_results, IsVisibleProperty, nameof(_vm.HasResult));
        root.Children.Add(_results);
        return root;
    }

    private Control InputCard()
    {
        var v4 = new RadioButton { Content = "IPv_4", GroupName = "family" };
        var v6 = new RadioButton { Content = "IPv_6", GroupName = "family" };
        void SyncRadios()
        {
            v4.IsChecked = _vm.IsV4;
            v6.IsChecked = _vm.IsV6;
        }

        v4.IsCheckedChanged += (_, _) =>
        {
            if (v4.IsChecked == true) _vm.FamilyIndex = 0;
        };
        v6.IsCheckedChanged += (_, _) =>
        {
            if (v6.IsChecked == true) _vm.FamilyIndex = 1;
        };
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(_vm.FamilyIndex)) SyncRadios();
        };
        SyncRadios();
        var family = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 16, Children = { v4, v6 } };
        AutomationProperties.SetName(family, "Address family");

        _address = Text(nameof(_vm.AddressText), "IP Address", "192.168.10.25/24, 10.0.0.1 255.255.255.0 or 2001:db8::1/64");
        _address.FontFamily = Mono;
        _address.FontSize = 15;

        var number = new NumericUpDown { Minimum = 0, Increment = 1, FormatString = "0", Width = 120, VerticalAlignment = VerticalAlignment.Center, ParsingNumberStyle = NumberStyles.Integer };
        NameSpinner(number, "Prefix length");
        Bound(number, NumericUpDown.MaximumProperty, nameof(_vm.MaxPrefix));
        Bound(number, NumericUpDown.ValueProperty, nameof(_vm.PrefixNumber), BindingMode.TwoWay);
        var slider = new Slider { Minimum = 0, TickFrequency = 1, IsSnapToTickEnabled = true, SmallChange = 1, LargeChange = 8, MinWidth = 200, VerticalAlignment = VerticalAlignment.Center };
        AutomationProperties.SetName(slider, "Prefix length slider");
        Bound(slider, RangeBase.MaximumProperty, nameof(_vm.MaxPrefix));
        Bound(slider, RangeBase.ValueProperty, nameof(_vm.PrefixSlider), BindingMode.TwoWay);
        var prefixRow = new DockPanel();
        DockPanel.SetDock(number, Dock.Left);
        number.Margin = new Thickness(0, 0, 12, 0);
        prefixRow.Children.Add(number);
        prefixRow.Children.Add(slider);

        var mask = Text(nameof(_vm.MaskText), "Subnet mask", "255.255.255.0", 200);
        mask.FontFamily = Mono;

        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), RowDefinitions = new RowDefinitions("Auto,Auto,Auto,Auto,Auto,Auto,Auto"), RowSpacing = 8, ColumnSpacing = 12 };
        void Put(Control c, int row, int col, int span = 1)
        {
            Grid.SetRow(c, row);
            Grid.SetColumn(c, col);
            Grid.SetColumnSpan(c, span);
            g.Children.Add(c);
        }

        Put(new TextBlock { Text = "Address Family", VerticalAlignment = VerticalAlignment.Center }, 0, 0);
        Put(family, 0, 1);
        Put(Caption("IP _Address", _address), 1, 0);
        Put(_address, 1, 1);
        Put(Caption("_Prefix Length", number), 2, 0);
        Put(prefixRow, 2, 1);
        var maskLabel = Bound(Caption("Subnet _Mask", mask), IsVisibleProperty, nameof(_vm.IsV4));
        Put(maskLabel, 3, 0);
        var maskHint = Form.Hint("Dotted-decimal; must be contiguous (no gaps).");
        maskHint.VerticalAlignment = VerticalAlignment.Center;
        maskHint.Margin = new Thickness(10, 0, 0, 0);
        DockPanel.SetDock(mask, Dock.Left);
        Put(Bound(new DockPanel { Children = { mask, maskHint } }, IsVisibleProperty, nameof(_vm.IsV4)), 3, 1);
        var empty = Bound(Form.Info("Enter an address, e.g. 192.168.1.10/24."), IsVisibleProperty, nameof(_vm.InputEmpty));
        Put(new StackPanel { Children = { Error(nameof(_vm.Validation)), empty } }, 4, 1);

        var examples = new WrapPanel { Orientation = Orientation.Horizontal };
        examples.Children.Add(new TextBlock { Text = "Examples:", VerticalAlignment = VerticalAlignment.Center, Classes = { "label" }, Margin = new Thickness(0, 0, 8, 4) });
        foreach (var ex in IpCalculatorViewModel.Examples)
        {
            var b = new Button { Content = ex, FontFamily = Mono, Classes = { "tool" }, Margin = new Thickness(0, 0, 6, 4), Cursor = new Avalonia.Input.Cursor(Avalonia.Input.StandardCursorType.Hand) };
            b.Bind(ForegroundProperty, b.GetResourceObservable("SystemControlHighlightAccentBrush"));
            AutomationProperties.SetName(b, "Example " + ex);
            ToolTip.SetTip(b, "Calculate " + ex);
            b.Click += (_, _) => _vm.UseExample(ex);
            examples.Children.Add(b);
        }

        Put(examples, 5, 1);

        var export = new Button { Content = "_Export Results ▾" };
        export.Flyout = new MenuFlyout
        {
            Items =
            {
                Item("Summary as Text (.txt)…", () => ExportSummaryAsync(json: false)),
                Item("Summary as JSON (.json)…", () => ExportSummaryAsync(json: true)),
            },
        };
        Bound(export, IsEnabledProperty, nameof(_vm.HasResult));
        var copy = Ui.Button("_Copy Summary", async () =>
        {
            if (_vm.SummaryText() is { Length: > 0 } s)
            {
                await Ui.CopyAsync(this, s);
                _vm.Status = "Summary copied.";
            }
        });
        Bound(copy, IsEnabledProperty, nameof(_vm.HasResult));
        var reset = Ui.Button("Rese_t", () =>
        {
            _vm.Reset();
            _address?.Focus();
            return Task.CompletedTask;
        });
        AutomationProperties.SetName(reset, "Reset");
        AutomationProperties.SetName(copy, "Copy Summary");
        AutomationProperties.SetName(export, "Export Results");
        Put(Ui.Row(reset, copy, export), 6, 1);
        return Card(g);
    }

    private static MenuItem Item(string header, Func<Task> run)
    {
        var m = new MenuItem { Header = header };
        m.Click += async (_, _) => await run();
        return m;
    }

    /// <summary>Two columns when there is room; results above the visualisations when narrow.</summary>
    private void Reflow()
    {
        if (_results is null) return;
        var narrow = Bounds.Width < 1000;
        var right = _results.Children[1];
        if (narrow)
        {
            _results.ColumnDefinitions = new ColumnDefinitions("*");
            _results.RowDefinitions = new RowDefinitions("Auto,Auto");
            Grid.SetColumn(right, 0);
            Grid.SetRow(right, 1);
        }
        else
        {
            _results.ColumnDefinitions = new ColumnDefinitions("4*,24,5*");
            _results.RowDefinitions = new RowDefinitions("Auto");
            Grid.SetColumn(right, 2);
            Grid.SetRow(right, 0);
        }
    }

    // ---------------------------------------------------------------- visualisations

    // design tokens (D-098); the visuals are rebuilt on a theme change (ActualThemeVariantChanged above)
    private IBrush Res(string key) => this.TryFindResource(key, ActualThemeVariant, out var v) && v is IBrush b ? b : Styling.Theme.Brush(key)!;

    private IBrush NetBrush => Res(Styling.Theme.Keys.BitNetwork);

    private IBrush HostBrush => Res(Styling.Theme.Keys.BitHost);

    private IBrush ReservedBrush => Res(Styling.Theme.Keys.BitReserved);

    private void RebuildVisuals()
    {
        if (_vm.Result is not { } r)
        {
            _breakdown.Content = null;
            _range.Content = null;
            return;
        }

        _breakdown.Content = r.IsV6 ? BreakdownV6(r) : BreakdownV4(r);
        _range.Content = RangeBar(r);
    }

    private Control Legend(IpCalcResult r)
    {
        Border Swatch(IBrush b) => new() { Width = 14, Height = 14, Background = b, CornerRadius = new CornerRadius(2), VerticalAlignment = VerticalAlignment.Center };
        var p = r.Block.Prefix;
        var legend = new WrapPanel { Margin = new Thickness(0, 6, 0, 0) };
        legend.Children.Add(Ui.Row(Swatch(NetBrush), new TextBlock { Text = $"Network bits: {p} (bold)", VerticalAlignment = VerticalAlignment.Center }));
        legend.Children.Add(new Border { Width = 18 });
        legend.Children.Add(Ui.Row(Swatch(HostBrush), new TextBlock { Text = $"Host bits: {r.Block.HostBits}", VerticalAlignment = VerticalAlignment.Center }));
        legend.Children.Add(new Border { Width = 18 });
        legend.Children.Add(new TextBlock { Text = $"┃ boundary after bit {p} (/{p})", VerticalAlignment = VerticalAlignment.Center });
        return legend;
    }

    /// <summary>One digit cell: accent background + bold for network, neutral for host; a thick left edge marks the boundary.</summary>
    private Border Cell(string text, bool network, bool boundaryBefore, double width, bool mixed = false)
    {
        var t = new TextBlock
        {
            Text = text, FontFamily = Mono, FontSize = 13, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
            FontWeight = network ? FontWeight.Bold : FontWeight.Normal,
        };
        if (network && !mixed) t.Foreground = Res(Styling.Theme.Keys.TextOnAccent);
        var cell = new Border
        {
            Width = width, Height = 24, Child = t, Margin = new Thickness(boundaryBefore ? 0 : 1, 0, 1, 0),
            Background = mixed ? HostBrush : network ? NetBrush : HostBrush,
            BorderThickness = new Thickness(boundaryBefore ? 3 : 0, 0, 0, 0),
            CornerRadius = new CornerRadius(2),
        };
        cell.Bind(Border.BorderBrushProperty, cell.GetResourceObservable("SystemControlForegroundBaseHighBrush"));
        if (mixed)
        {
            cell.BorderThickness = new Thickness(boundaryBefore ? 3 : 1, 1, 1, 1);
            cell.BorderBrush = NetBrush;
            t.FontWeight = FontWeight.SemiBold;
        }

        return cell;
    }

    private Control BreakdownV4(IpCalcResult r)
    {
        var p = r.Block.Prefix;
        var bits = IpText.Binary(r.Address.Value, 32);
        var octets = new WrapPanel();
        for (var o = 0; o < 4; o++)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            for (var i = 0; i < 8; i++)
            {
                var n = (o * 8) + i;
                row.Children.Add(Cell(bits[n].ToString(), n < p, n == p && n > 0, 14));
            }

            var netBits = Math.Clamp(p - (o * 8), 0, 8);
            var caption = netBits switch { 8 => "network", 0 => "host", _ => $"{netBits} network + {8 - netBits} host" };
            var value = (int)((uint)r.Address.Value >> (24 - (8 * o)) & 0xFF);
            var block = new StackPanel
            {
                Margin = new Thickness(0, 0, 8, 6),
                Children =
                {
                    new TextBlock { Text = value.ToString(CultureInfo.InvariantCulture), FontFamily = Mono, FontSize = 16, FontWeight = FontWeight.SemiBold, HorizontalAlignment = HorizontalAlignment.Center },
                    row,
                    new TextBlock { Text = caption, FontSize = 11, Classes = { "label" }, HorizontalAlignment = HorizontalAlignment.Center },
                },
            };
            AutomationProperties.SetName(block, $"Octet {o + 1}: {value}, binary {bits.Substring(o * 8, 8)}, {caption}");
            octets.Children.Add(block);
        }

        var panel = new StackPanel { Children = { octets, Legend(r) } };
        if (_vm.ShowBinary)
        {
            panel.Children.Add(BinaryTable(r, [
                ("Address", r.Address.Value),
                ("Subnet mask", r.Mask),
                ("Wildcard", r.Wildcard),
                ("Network", r.Block.Network),
                ("Last address", r.Block.Last),
            ]));
        }

        return panel;
    }

    private Control BreakdownV6(IpCalcResult r)
    {
        var p = r.Block.Prefix;
        var hex = IpText.Expanded(r.Address.Value).Replace(":", "", StringComparison.Ordinal);
        var hextets = new UniformGrid { Columns = 4, HorizontalAlignment = HorizontalAlignment.Left }; // two rows of four: the /64 halves line up
        for (var h = 0; h < 8; h++)
        {
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            for (var i = 0; i < 4; i++)
            {
                var nibble = (h * 4) + i;
                var startBit = nibble * 4;
                var mixed = p > startBit && p < startBit + 4;
                row.Children.Add(Cell(hex[nibble].ToString(), startBit < p, startBit == p && p > 0, 15, mixed));
            }

            var netBits = Math.Clamp(p - (h * 16), 0, 16);
            var caption = netBits switch { 16 => "network", 0 => "host", _ => $"{netBits} net / {16 - netBits} host" };
            var block = new StackPanel
            {
                Margin = new Thickness(0, 0, 8, 6),
                Children =
                {
                    row,
                    new TextBlock { Text = caption, FontSize = 11, Classes = { "label" }, HorizontalAlignment = HorizontalAlignment.Center },
                },
            };
            AutomationProperties.SetName(block, $"Hextet {h + 1}: {hex.Substring(h * 4, 4)}, {caption}");
            hextets.Children.Add(block);
        }

        var panel = new StackPanel { Children = { hextets, Legend(r) } };
        if (p % 4 != 0)
        {
            panel.Children.Add(Form.Hint($"The /{p} boundary falls inside a hex digit (outlined): {p % 4} of its 4 bits are network bits. Show binary details for the exact bits."));
        }

        if (_vm.ShowBinary)
        {
            panel.Children.Add(BinaryTable(r, [("Address", r.Address.Value), ("Network", r.Block.Network), ("Last address", r.Block.Last)]));
        }

        return panel;
    }

    /// <summary>Expanded binary rows (IPv4 octets / IPv6 hextets per line) with the network part bold and a '|' at the boundary.</summary>
    private Control BinaryTable(IpCalcResult r, (string Label, UInt128 Value)[] rows)
    {
        var p = r.Block.Prefix;
        var bits = r.Block.Bits;
        var group = r.IsV6 ? 16 : 8;
        var panel = new StackPanel { Margin = new Thickness(0, 10, 0, 0), Spacing = 6 };
        foreach (var (label, value) in rows)
        {
            var b = IpText.Binary(value, bits);
            var text = new SelectableTextBlock { FontFamily = Mono, FontSize = 12, TextWrapping = TextWrapping.Wrap };
            var plain = new System.Text.StringBuilder();
            for (var i = 0; i < bits; i++)
            {
                if (i == p && p > 0 && p < bits)
                {
                    text.Inlines!.Add(new Avalonia.Controls.Documents.Run("┃") { Foreground = NetBrush, FontWeight = FontWeight.Bold });
                    plain.Append('|');
                }
                else if (i > 0 && i % group == 0 && !(r.IsV6 && i % 64 == 0)) // no separator right after the line break
                {
                    text.Inlines!.Add(new Avalonia.Controls.Documents.Run(r.IsV6 ? ":" : "."));
                    plain.Append(r.IsV6 ? ':' : '.');
                }

                text.Inlines!.Add(new Avalonia.Controls.Documents.Run(b[i].ToString()) { FontWeight = i < p ? FontWeight.Bold : FontWeight.Normal });
                plain.Append(b[i]);
                if (r.IsV6 && (i + 1) % 64 == 0 && i + 1 < bits) text.Inlines.Add(new Avalonia.Controls.Documents.LineBreak());
            }

            var g = new Grid { ColumnDefinitions = new ColumnDefinitions("110,*") };
            g.Children.Add(new TextBlock { Text = label, Classes = { "label" } });
            Grid.SetColumn(text, 1);
            g.Children.Add(text);
            AutomationProperties.SetName(g, $"{label} in binary: {plain}");
            panel.Children.Add(g);
        }

        panel.Children.Add(Form.Hint("Bold digits are network bits; ┃ marks the prefix boundary."));
        return panel;
    }

    /// <summary>
    /// Network → last address bar. Reserved IPv4 endpoints (network, broadcast) are separate, labelled cells; the entered
    /// address is a marker placed by its exact offset (BigInteger → double only for the drawing position).
    /// </summary>
    private Control RangeBar(IpCalcResult r)
    {
        var b = r.Block;
        string F(UInt128 v) => IpText.Format(v, r.IsV6);
        var offset = (BigInteger)(r.Address.Value - b.Network);
        var reservedEnds = !r.IsV6 && b.Prefix <= 30;
        var anycastFirst = r.IsV6 && b.Prefix < 127;

        Border Segment(IBrush brush, string label, double width = double.NaN)
        {
            var s = new Border
            {
                Height = 26, Width = width, Background = brush, CornerRadius = new CornerRadius(3), Margin = new Thickness(1, 0),
                Child = new TextBlock { Text = label, FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
            };
            if (brush == NetBrush) ((TextBlock)s.Child).Foreground = Res(Styling.Theme.Keys.TextOnAccent);
            return s;
        }

        var bar = new Grid { ColumnDefinitions = new ColumnDefinitions(reservedEnds ? "64,*,64" : anycastFirst ? "64,*" : "*") };
        if (reservedEnds)
        {
            bar.Children.Add(Segment(ReservedBrush, "network"));
            var usable = Segment(NetBrush, "usable hosts");
            Grid.SetColumn(usable, 1);
            bar.Children.Add(usable);
            var bc = Segment(ReservedBrush, "broadcast");
            Grid.SetColumn(bc, 2);
            bar.Children.Add(bc);
        }
        else if (anycastFirst)
        {
            bar.Children.Add(Segment(ReservedBrush, "anycast"));
            var rest = Segment(NetBrush, "interface addresses");
            Grid.SetColumn(rest, 1);
            bar.Children.Add(rest);
        }
        else
        {
            bar.Children.Add(Segment(NetBrush, b.Prefix == b.Bits ? "single address" : "both addresses usable (point-to-point)"));
        }

        // marker row: proportional columns put the ▼ above the address's position within its segment
        var total = b.Count;
        double fraction;
        int column;
        if (reservedEnds && offset == 0) (column, fraction) = (0, 0.5);
        else if (reservedEnds && offset == total - 1) (column, fraction) = (2, 0.5);
        else if (reservedEnds) (column, fraction) = (1, Ratio(offset - 1, total - 3));
        else if (anycastFirst && offset == 0) (column, fraction) = (0, 0.5);
        else if (anycastFirst) (column, fraction) = (1, Ratio(offset - 1, total - 2));
        else (column, fraction) = (0, total == 1 ? 0.5 : Ratio(offset, total - 1));

        var marker = new Grid { ColumnDefinitions = new ColumnDefinitions($"{F2(fraction)}*,Auto,{F2(1 - fraction)}*") };
        var arrow = new TextBlock { Text = "▼", FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center };
        arrow.Bind(TextBlock.ForegroundProperty, arrow.GetResourceObservable("SystemControlForegroundBaseHighBrush"));
        Grid.SetColumn(arrow, 1);
        marker.Children.Add(arrow);
        var markerHost = new Grid { ColumnDefinitions = bar.ColumnDefinitions.Count switch { 3 => new ColumnDefinitions("64,*,64"), 2 => new ColumnDefinitions("64,*"), _ => new ColumnDefinitions("*") } };
        Grid.SetColumn(marker, column);
        markerHost.Children.Add(marker);

        var position = $"Entered address {F(r.Address.Value)} is address {IpText.Grouped(offset + 1)} of {IpText.Readable(total)}"
                       + (reservedEnds && offset == 0 ? " — the network address (reserved)" : reservedEnds && offset == total - 1 ? " — the broadcast address (reserved)" : anycastFirst && offset == 0 ? " — the Subnet-Router anycast address" : "") + ".";
        var ends = new Grid { ColumnDefinitions = new ColumnDefinitions("*,*") };
        ends.Children.Add(new SelectableTextBlock { Text = F(b.Network), FontFamily = Mono, FontSize = 12 });
        var last = new SelectableTextBlock { Text = F(b.Last), FontFamily = Mono, FontSize = 12, HorizontalAlignment = HorizontalAlignment.Right };
        Grid.SetColumn(last, 1);
        ends.Children.Add(last);
        var detail = reservedEnds
            ? $"Network {F(b.Network)} and broadcast {F(b.Last)} are reserved; hosts use {F(r.FirstUsable)} – {F(r.LastUsable)}."
            : r.IsV6
                ? anycastFirst ? $"No broadcast. The first address {F(b.Network)} is the Subnet-Router anycast address; it is not normally assigned to a host." : "No broadcast; both addresses are used on point-to-point links (RFC 6164)."
                : b.Prefix == 31 ? "No network or broadcast address: both addresses are usable (RFC 3021)." : "A single-host route.";
        var panel = new StackPanel
        {
            Spacing = 2,
            Children =
            {
                new TextBlock { Text = position, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 4) },
                markerHost, bar, ends,
                Form.Info(detail),
            },
        };
        AutomationProperties.SetName(panel, $"Subnet range {F(b.Network)} to {F(b.Last)}. {position} {detail}");
        return panel;
    }

    private static double Ratio(BigInteger n, BigInteger d) => d <= 0 ? 0.5 : Math.Clamp((double)n / (double)d, 0, 1);

    private static string F2(double x) => Math.Max(x, 0.0001).ToString("0.####", CultureInfo.InvariantCulture);

    private async Task ExportSummaryAsync(bool json)
    {
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export IP Calculation",
            SuggestedFileName = "ip-calculation" + (json ? ".json" : ".txt"),
            DefaultExtension = json ? "json" : "txt",
            FileTypeChoices = [json ? new FilePickerFileType("JSON") { Patterns = ["*.json"] } : new FilePickerFileType("Text") { Patterns = ["*.txt"] }],
        });
        if (file?.TryGetLocalPath() is { } path) await _vm.ExportSummaryAsync(path, json);
    }

    // ---------------------------------------------------------------- split tab

    private Control SplitTab()
    {
        var parent = Text(nameof(_vm.SplitParent), "Parent network", "10.0.0.0/16 or 2001:db8::/48");
        parent.FontFamily = Mono;
        var use = Ui.Button("Use Calculator Network", () =>
        {
            _vm.UseCalculatorNetwork();
            return Task.CompletedTask;
        });
        ToolTip.SetTip(use, "Copy the network from the Calculator tab.");

        var byPrefix = new RadioButton { Content = "New prefix length", GroupName = "splitmode", IsChecked = true };
        var byHosts = new RadioButton { Content = "Usable hosts per subnet (IPv4)", GroupName = "splitmode" };
        byPrefix.IsCheckedChanged += (_, _) =>
        {
            if (byPrefix.IsChecked == true) _vm.SplitModeIndex = 0;
        };
        byHosts.IsCheckedChanged += (_, _) =>
        {
            if (byHosts.IsChecked == true) _vm.SplitModeIndex = 1;
        };
        var prefix = new NumericUpDown { Minimum = 0, Maximum = 128, Increment = 1, FormatString = "0", Width = 120, ParsingNumberStyle = NumberStyles.Integer };
        NameSpinner(prefix, "New prefix length");
        Bound(prefix, NumericUpDown.ValueProperty, nameof(_vm.SplitPrefix), BindingMode.TwoWay);
        Bound(prefix, IsEnabledProperty, nameof(_vm.ByPrefix));
        var hosts = Text(nameof(_vm.SplitHosts), "Usable hosts per subnet", "e.g. 50", 120);
        Bound(hosts, IsEnabledProperty, nameof(_vm.ByHosts));
        var p2p = new CheckBox { Content = "Allow /31 point-to-point for two hosts (RFC 3021)" };
        Bound(p2p, ToggleButton.IsCheckedProperty, nameof(_vm.AllowPointToPoint), BindingMode.TwoWay);
        Bound(p2p, IsEnabledProperty, nameof(_vm.ByHosts));
        ToolTip.SetTip(p2p, "Off: two hosts get a /30 (network + broadcast reserved). On: a /31 with both addresses usable, for router links only.");

        var f = new Form();
        f.Add("Parent Network", Form.WithButton(parent, use));
        f.Add("Split By", Ui.Row(byPrefix, prefix));
        f.Add("", Ui.Row(byHosts, hosts));
        f.Add("", p2p);
        f.Full(Error(nameof(_vm.SplitError)));
        f.Full(Bound(new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, FontStyle = FontStyle.Italic }, TextBlock.TextProperty, nameof(_vm.SplitNote)));
        var top = new StackPanel { Spacing = 8, Children = { Card(f.Grid) } };
        var summary = FieldList(_vm.SplitFields, prominent: true);
        summary.MaxWidth = 760;
        summary.HorizontalAlignment = HorizontalAlignment.Left;
        top.Children.Add(Bound(summary, IsVisibleProperty, nameof(_vm.HasSplit)));

        Button Nav(string text, string name, Action a)
        {
            var b = new Button { Content = text };
            AutomationProperties.SetName(b, name);
            ToolTip.SetTip(b, name);
            b.Click += (_, _) => a();
            return b;
        }

        var go = Text(nameof(_vm.GoToPage), "Page number", "", 110);
        go.KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Enter)
            {
                _vm.GoTo();
                e.Handled = true;
            }
        };
        var nav = Ui.Row(Nav("First", "First page", _vm.FirstPage), Nav("◀ Previous", "Previous page", _vm.PreviousPage), go, Nav("Go", "Go to page", _vm.GoTo),
            Nav("Next ▶", "Next page", _vm.NextPage), Nav("Last", "Last page", _vm.LastPage));
        foreach (var c in nav.Children) c.VerticalAlignment = VerticalAlignment.Center;
        var pageText = Bound(new TextBlock { VerticalAlignment = VerticalAlignment.Center, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(12, 0, 0, 0) }, TextBlock.TextProperty, nameof(_vm.PageText));
        AutomationProperties.SetLiveSetting(pageText, AutomationLiveSetting.Polite);

        var export = new Button { Content = "Export Subnets ▾" };
        export.Flyout = new MenuFlyout
        {
            Items =
            {
                Item("Current Page as CSV…", () => ExportSplitAsync(json: false, complete: false)),
                Item("Current Page as JSON…", () => ExportSplitAsync(json: true, complete: false)),
                new Separator(),
                Item("Complete Set as CSV…", () => ExportSplitAsync(json: false, complete: true)),
                Item("Complete Set as JSON…", () => ExportSplitAsync(json: true, complete: true)),
            },
        };
        ((MenuFlyout)export.Flyout).Opening += (_, _) =>
        {
            foreach (var item in ((MenuFlyout)export.Flyout).Items.OfType<MenuItem>().Skip(2)) item.IsEnabled = _vm.CanExportAll;
        };
        ToolTip.SetTip(export, "The complete set can be exported up to " + IpText.Grouped(SubnetSplit.MaxExportRows) + " subnets; larger splits page by page.");
        Bound(export, IsEnabledProperty, nameof(_vm.HasSplit));
        var cancel = Ui.Button("Cancel Export", () =>
        {
            _vm.CancelExport();
            return Task.CompletedTask;
        });
        Bound(cancel, IsVisibleProperty, nameof(_vm.IsExporting));
        var bar = new DockPanel { Margin = new Thickness(0, 10, 0, 6) };
        var right = Ui.Row(export, cancel);
        DockPanel.SetDock(right, Dock.Right);
        bar.Children.Add(right);
        bar.Children.Add(new WrapPanel { Children = { nav, pageText } });
        Bound(bar, IsVisibleProperty, nameof(_vm.HasSplit));

        Bound(_subnets, DataGrid.ItemsSourceProperty, nameof(_vm.SplitRows));
        Bound(_subnets, IsVisibleProperty, nameof(_vm.HasSplit));
        var g = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*"), Margin = new Thickness(0, 10, 12, 12) };
        var topScroll = new ScrollViewer { Content = top, MaxHeight = 420 };
        g.Children.Add(topScroll);
        Grid.SetRow(bar, 1);
        g.Children.Add(bar);
        Grid.SetRow(_subnets, 2);
        _subnets.MinHeight = 160;
        g.Children.Add(_subnets);
        return g;
    }

    private void ConfigureSubnetColumns()
    {
        if (_vm.Split is not { } s) return;
        _subnets.Columns[2].Header = s.FirstHeader;
        _subnets.Columns[3].Header = s.LastHeader;
        _subnets.Columns[4].IsVisible = s.HasBroadcast;
    }

    private async Task ExportSplitAsync(bool json, bool complete)
    {
        var ext = json ? "json" : "csv";
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = complete ? "Export All Subnets" : "Export Subnets on This Page",
            SuggestedFileName = $"subnets-{(complete ? "complete" : "page")}.{ext}",
            DefaultExtension = ext,
            FileTypeChoices = [new FilePickerFileType(json ? "JSON" : "CSV") { Patterns = ["*." + ext] }],
        });
        if (file?.TryGetLocalPath() is { } path) await _vm.ExportSplitAsync(path, json, complete);
    }

    // ---------------------------------------------------------------- range tools tab

    private Control RangeTab()
    {
        Control Tool(string title, string explanation, Control body)
        {
            var p = new StackPanel { Spacing = 8, Children = { new TextBlock { Text = title, FontSize = 15, FontWeight = FontWeight.SemiBold }, Form.Hint(explanation), body } };
            return Card(p);
        }

        TextBox Field(string path, string name, string placeholder)
        {
            var t = Text(path, name, placeholder);
            t.FontFamily = Mono;
            return t;
        }

        SelectableTextBlock Outcome(string path, string errorPath, Func<bool> isError)
        {
            var t = Bound(new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, FontWeight = FontWeight.SemiBold }, TextBlock.TextProperty, path);
            _vm.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName != errorPath) return;
                if (isError()) Styling.Theme.SetState(t, "error");
                else Styling.Theme.SetState(t, null);
            };
            AutomationProperties.SetLiveSetting(t, AutomationLiveSetting.Polite);
            return t;
        }

        var contains = new Form();
        contains.Add("Subnet", Field(nameof(_vm.ContainsNetwork), "Contains: subnet", "10.20.28.0/22 or 2001:db8::/32"));
        contains.Add("Address", Field(nameof(_vm.ContainsAddress), "Contains: address", "10.20.31.7"));
        contains.Full(Outcome(nameof(_vm.ContainsResult), nameof(_vm.ContainsError), () => _vm.ContainsError));

        var compare = new Form();
        compare.Add("A", Field(nameof(_vm.CompareA), "Compare: A", "10.0.0.0/16, or a range 10.0.0.1-10.0.0.99"));
        compare.Add("B", Field(nameof(_vm.CompareB), "Compare: B", "10.0.4.0/22"));
        compare.Full(Outcome(nameof(_vm.CompareResult), nameof(_vm.CompareError), () => _vm.CompareError));

        var range = new Form();
        range.Add("Start Address", Field(nameof(_vm.RangeStart), "Range start", "192.168.1.10"));
        range.Add("End Address", Field(nameof(_vm.RangeEnd), "Range end (inclusive)", "192.168.1.200"));
        range.Full(Outcome(nameof(_vm.RangeResult), nameof(_vm.RangeError), () => _vm.RangeError));
        var list = Bound(new TextBox { IsReadOnly = true, AcceptsReturn = true, FontFamily = Mono, MaxHeight = 220, TextWrapping = TextWrapping.NoWrap }, TextBox.TextProperty, nameof(_vm.RangeCidrs));
        AutomationProperties.SetName(list, "CIDR blocks");
        range.Full(Bound(Form.WithButton(list, CopyButton(() => _vm.RangeCidrs, "CIDR blocks")), IsVisibleProperty, nameof(_vm.HasRangeCidrs)));

        return new StackPanel
        {
            Spacing = 12,
            Children =
            {
                Tool("Contains Address", "Is an address inside a subnet? Works for IPv4 and IPv6; host bits in the subnet are normalised.", contains.Grid),
                Tool("Compare Subnets", "Equal, disjoint, overlapping, or one containing the other. Each side may be a CIDR block, a start-end range or one address.", compare.Grid),
                Tool("Range to CIDR", "The smallest set of CIDR blocks that covers exactly the inclusive range (computed per block, never per address).", range.Grid),
            },
        };
    }
}
