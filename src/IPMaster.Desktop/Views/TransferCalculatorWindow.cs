using Avalonia;
using Avalonia.Animation;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Styling;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Calculators → Download Calculator (D-102, redesigned D-112): file size and transfer speed (field, log slider and
/// quick speeds) in a bordered card like the IP Calculator, the estimated time as the focal result, a short summary and
/// collapsible technical details with the efficiency assumption. Everything recalculates live; there is no Calculate button.
/// </summary>
internal sealed class TransferCalculatorWindow : Window
{
    private readonly TransferCalculatorViewModel _vm;

    public TransferCalculatorWindow(TransferCalculatorViewModel vm)
    {
        _vm = vm ?? throw new ArgumentNullException(nameof(vm));
        Title = "Download Calculator";
        Width = 600;
        Height = 640;
        MinWidth = 460;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        // --- inputs ---
        var size = Number("File size", nameof(vm.SizeText));
        var sizeUnit = Unit("File size unit", TransferCalculatorViewModel.SizeUnits, nameof(vm.SizeUnit));
        var speed = Number("Transfer speed", nameof(vm.SpeedText));
        var speedUnit = Unit("Transfer speed unit", TransferCalculatorViewModel.SpeedUnits, nameof(vm.SpeedUnit));
        var slider = new Slider
        {
            Minimum = 0, Maximum = SpeedScale.Maximum, SmallChange = 0.05, LargeChange = 1, TickPlacement = TickPlacement.BottomRight,
            Ticks = [.. Enumerable.Range(0, SpeedScale.Labels.Count).Select(i => (double)i)], Margin = new Thickness(0, 4, 0, 0),
        };
        slider.Bind(RangeBase.ValueProperty, new ReflectionBinding(nameof(vm.SpeedPosition)) { Source = vm, Mode = BindingMode.TwoWay });
        AutomationProperties.SetName(slider, "Transfer speed, 1 Mbps to 200 Gbps");
        ToolTip.SetTip(slider, "Drag or use the arrow keys (Page Up / Page Down: next mark). Type a value in the field for an exact speed.");

        var presets = TransferCalculatorViewModel.QuickSpeeds.Select(p =>
        {
            var b = new ToggleButton { Content = p, Padding = new Thickness(10, 3) };
            AutomationProperties.SetName(b, "Set speed to " + p);
            b.Click += (_, _) =>
            {
                vm.ApplyPreset(p);
                b.IsChecked = vm.ActivePreset == p; // a click on the active preset keeps it selected
            };
            return b;
        }).ToList();
        void ShowPreset()
        {
            foreach (var b in presets) b.IsChecked = (string)b.Content! == vm.ActivePreset;
        }

        var card = Card(new StackPanel
        {
            Spacing = Styling.Theme.TightGap,
            Children =
            {
                Heading("FILE SIZE", size), Field(size, sizeUnit),
                Spacer(), Heading("TRANSFER SPEED", speed), Field(speed, speedUnit), Bound(new TextBlock { Classes = { "hint" } }, nameof(vm.SpeedNote)),
                slider, TickLabels(slider), Ui.Row([.. presets]),
            },
        });

        // --- result ---
        var result = Bound(new SelectableTextBlock { Classes = { "result" }, HorizontalAlignment = HorizontalAlignment.Center, RenderTransform = new TranslateTransform() }, nameof(vm.Result));
        AutomationProperties.SetName(result, "Estimated transfer time");
        AutomationProperties.SetLiveSetting(result, AutomationLiveSetting.Polite);
        var note = Bound(new TextBlock { Classes = { "label" }, HorizontalAlignment = HorizontalAlignment.Center, TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center }, nameof(vm.ResultNote));
        var error = Bound(new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Center, TextAlignment = TextAlignment.Center }, nameof(vm.Error));
        var output = new StackPanel
        {
            Spacing = 2, Margin = new Thickness(0, Styling.Theme.SectionGap * 2, 0, Styling.Theme.SectionGap),
            Children = { new TextBlock { Text = "ESTIMATED TRANSFER TIME", Classes = { "label" }, FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center }, result, note, error },
        };

        // --- summary and technical details ---
        var efficiencyValue = Value(nameof(vm.EfficiencyText));
        var summary = Rows(("Throughput", Value(nameof(vm.Throughput))), ("Total size", Value(nameof(vm.TotalSize))), ("Total data", Value(nameof(vm.TotalData))),
            ("Efficiency", efficiencyValue));
        var efficiency = ToolKit.Combo("Efficiency", TransferCalculatorViewModel.Efficiencies.Select(e => e.Label), 0, 200);
        efficiency.Bind(SelectingItemsControl.SelectedIndexProperty, new ReflectionBinding(nameof(vm.EfficiencyIndex)) { Source = vm, Mode = BindingMode.TwoWay });
        ToolTip.SetTip(efficiency, "A planning assumption: the share of the link speed the transfer reaches (protocol overhead, disks, other traffic). It is not a measurement.");
        var formula = Value(nameof(vm.Formula));
        formula.TextWrapping = TextWrapping.Wrap;
        var details = new StackPanel
        {
            Spacing = Styling.Theme.TightGap,
            Children =
            {
                Rows(("Efficiency", efficiency)),
                Rows(("Link speed", Value(nameof(vm.BitsPerSecond))), ("", Value(nameof(vm.BytesPerSecond))), ("Effective speed", Value(nameof(vm.EffectiveSpeed))),
                    ("Total bytes", Value(nameof(vm.TotalBytes))), ("Total bits", Value(nameof(vm.TotalBits))), ("Seconds", Value(nameof(vm.Seconds))),
                    ("Minutes", Value(nameof(vm.Minutes))), ("Hours", Value(nameof(vm.Hours))), ("Days", Value(nameof(vm.Days)))),
                new TextBlock { Text = "Formula", Classes = { "label" }, Margin = new Thickness(0, 4, 0, 0) }, formula,
                new TextBlock { Text = TransferCalculatorViewModel.UnitsNote, Classes = { "hint" }, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 4, 0, 0) },
            },
        };
        var expander = new Expander { Header = "Technical Details", Content = details, HorizontalAlignment = HorizontalAlignment.Stretch, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0) };
        AutomationProperties.SetName(expander, "Technical details");

        // --- actions ---
        var reset = Ui.Button("Reset", () =>
        {
            vm.Reset();
            return Task.CompletedTask;
        });
        ToolTip.SetTip(reset, "10 GB at 100 Mbps, 100 % efficiency");
        var copy = ToolKit.CopyButton(this, vm.CopyText, "Copy Result");
        ToolTip.SetTip(copy, "Copy the inputs and the result as text");
        var buttons = new DockPanel { LastChildFill = false, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0) };
        DockPanel.SetDock(reset, Dock.Left);
        DockPanel.SetDock(copy, Dock.Right);
        buttons.Children.Add(reset);
        buttons.Children.Add(copy);

        var body = new StackPanel { Children = { card, output, Card(summary), expander } };
        var page = new DockPanel { Margin = Styling.Theme.Page };
        DockPanel.SetDock(buttons, Dock.Bottom);
        page.Children.Add(buttons);
        page.Children.Add(new ScrollViewer { Content = body, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new Thickness(0, 0, 4, 0) });
        Content = page;

        void Refresh()
        {
            ShowPreset();
            Styling.Theme.SetState(efficiencyValue, vm.IsEstimate ? Styling.Theme.Classes.Warning : null);
            Styling.Theme.SetState(note, vm.IsEstimate ? Styling.Theme.Classes.Warning : null);
        }

        CancellationTokenSource? running = null;
        void OnRecalculated(object? sender, EventArgs e)
        {
            if (!IsVisible || Platform.Motion.Reduced) return;
            running?.Cancel();
            running?.Dispose();
            running = new CancellationTokenSource();
            _ = Settle.RunAsync(result, running.Token); // animates the result's TranslateTransform
        }

        vm.PropertyChanged += OnVmChanged;
        vm.Recalculated += OnRecalculated;
        Closed += (_, _) =>
        {
            vm.PropertyChanged -= OnVmChanged;
            vm.Recalculated -= OnRecalculated;
            running?.Cancel();
            running?.Dispose();
        };
        Refresh();
        Opened += (_, _) => size.Focus();

        void OnVmChanged(object? s, System.ComponentModel.PropertyChangedEventArgs e)
        {
            if (e.PropertyName is nameof(vm.ActivePreset) or nameof(vm.IsEstimate)) Refresh();
        }
    }

    /// <summary>A brief upward settle of the result (160 ms) after a change; none when Windows animations are off (<see cref="Platform.Motion"/>).</summary>
    private static readonly Animation Settle = new()
    {
        Duration = TimeSpan.FromMilliseconds(160), Easing = new Avalonia.Animation.Easings.CubicEaseOut(),
        Children =
        {
            new KeyFrame { Cue = new Cue(0), Setters = { new Setter(TranslateTransform.YProperty, 3d) } },
            new KeyFrame { Cue = new Cue(1), Setters = { new Setter(TranslateTransform.YProperty, 0d) } },
        },
    };

    private static Border Card(Control child)
    {
        var card = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 12), Child = child };
        card.Bind(Border.BorderBrushProperty, card.GetResourceObservable(Styling.Theme.Keys.Border));
        return card;
    }

    private static Label Heading(string text, Control target) =>
        new() { Content = new TextBlock { Text = text, Classes = { "label" }, FontSize = 11, FontWeight = FontWeight.SemiBold }, Target = target, Padding = new Thickness(0) };

    private static Control Spacer() => new Border { Height = Styling.Theme.TightGap };

    private static Grid Field(Control input, Control unit)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("*,Auto"), ColumnSpacing = Styling.Theme.ControlGap };
        Grid.SetColumn(unit, 1);
        g.Children.Add(input);
        g.Children.Add(unit);
        return g;
    }

    /// <summary>
    /// Labels under the slider, one per stop, each centred under its tick: n equal columns, widened by half a column at both
    /// ends so column i's centre falls at i/(n−1) of the thumb's travel (the track less the thumb's 10 px half width per side).
    /// </summary>
    private static Grid TickLabels(Slider slider)
    {
        var n = SpeedScale.Labels.Count;
        var g = new Grid();
        for (var i = 0; i < n; i++)
        {
            g.ColumnDefinitions.Add(new ColumnDefinition(1, GridUnitType.Star));
            var t = new TextBlock { Text = SpeedScale.Labels[i], Classes = { "label" }, FontSize = 11, HorizontalAlignment = HorizontalAlignment.Center };
            Grid.SetColumn(t, i);
            g.Children.Add(t);
        }

        slider.PropertyChanged += (_, e) =>
        {
            if (e.Property != BoundsProperty) return;
            var half = Math.Max(0, slider.Bounds.Width - 20) / (2 * (n - 1));
            g.Margin = new Thickness(10 - half, 0, 10 - half, 0);
        };
        AutomationProperties.SetAccessibilityView(g, AccessibilityView.Raw); // the slider's name states the range
        return g;
    }

    private static Grid Rows(params (string Label, Control Value)[] rows)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), ColumnSpacing = 16, RowSpacing = 3 };
        for (var i = 0; i < rows.Length; i++)
        {
            g.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var label = new TextBlock { Text = rows[i].Label, Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center, MinWidth = 110 };
            Grid.SetRow(label, i);
            Grid.SetRow(rows[i].Value, i);
            Grid.SetColumn(rows[i].Value, 1);
            g.Children.Add(label);
            g.Children.Add(rows[i].Value);
        }

        return g;
    }

    private SelectableTextBlock Value(string path)
    {
        var t = new SelectableTextBlock { TextTrimming = TextTrimming.CharacterEllipsis };
        t.Bind(TextBlock.TextProperty, new ReflectionBinding(path) { Source = _vm });
        t.Bind(ToolTip.TipProperty, new ReflectionBinding(path) { Source = _vm });
        return t;
    }

    private T Bound<T>(T text, string path)
        where T : TextBlock
    {
        text.Bind(TextBlock.TextProperty, new ReflectionBinding(path) { Source = _vm });
        text.Bind(IsVisibleProperty, new ReflectionBinding(path) { Source = _vm, Converter = Avalonia.Data.Converters.StringConverters.IsNotNullOrEmpty });
        return text;
    }

    private TextBox Number(string name, string path)
    {
        var t = ToolKit.Text(name);
        t.Bind(TextBox.TextProperty, new ReflectionBinding(path) { Source = _vm, Mode = BindingMode.TwoWay });
        return t;
    }

    private ComboBox Unit(string name, string[] units, string path)
    {
        var c = ToolKit.Combo(name, units, 0, 100);
        c.Bind(SelectingItemsControl.SelectedItemProperty, new ReflectionBinding(path) { Source = _vm, Mode = BindingMode.TwoWay });
        return c;
    }
}
