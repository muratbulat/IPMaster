using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Download / Transfer Calculator (D-102): offline, exact. Two modes (transfer time, required speed), unit
/// pickers grouped SI/IEC × bytes/bits with the common units first, logarithmic sliders, quick speeds, effective
/// throughput presets, a large result, details, a speed comparison and the full calculation. Built on the design system.
/// </summary>
internal sealed class TransferCalculatorWindow : Window
{
    private readonly TransferCalculatorViewModel _vm;

    public TransferCalculatorWindow(TransferCalculatorViewModel vm)
    {
        _vm = vm ?? throw new ArgumentNullException(nameof(vm));
        Title = "Download / Transfer Calculator";
        Width = 860;
        Height = 820;
        MinWidth = Styling.Theme.ToolMinWidth;
        MinHeight = Styling.Theme.ToolMinHeight;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var modeTime = new RadioButton { Content = "Transfer Time", GroupName = "transferMode", IsChecked = true };
        var modeSpeed = new RadioButton { Content = "Required Speed", GroupName = "transferMode" };
        modeTime.IsCheckedChanged += (_, _) => vm.Mode = modeTime.IsChecked == true ? TransferMode.TransferTime : TransferMode.RequiredSpeed;

        var size = Number("File size", nameof(vm.SizeText));
        var sizeUnit = UnitCombo("File size unit", rate: false, () => vm.SizeUnit, u => vm.SizeUnit = u, nameof(vm.SizeUnit));
        var fromFile = Ui.Button("From File…", PickFileAsync);
        ToolTip.SetTip(fromFile, "Use a local file's size (only its size is read; nothing is uploaded)");
        var sizeSlider = Slider("File size slider", TransferCalculatorViewModel.SizeSliderMin, TransferCalculatorViewModel.SizeSliderMax, nameof(vm.SizeSlider));

        var speed = Number("Connection speed", nameof(vm.SpeedText));
        var speedUnit = UnitCombo("Connection speed unit", rate: true, () => vm.SpeedUnit, u => vm.SpeedUnit = u, nameof(vm.SpeedUnit));
        var speedSlider = Slider("Connection speed slider", TransferCalculatorViewModel.SpeedSliderMin, TransferCalculatorViewModel.SpeedSliderMax, nameof(vm.SpeedSlider));
        var quick = Ui.Row([.. TransferCalculatorViewModel.QuickSpeeds.Select(s => (Control)Ui.Button(s, () =>
        {
            vm.ApplySpeedPreset(s);
            return Task.CompletedTask;
        }))]);
        var speedBlock = Section("Connection speed", Ui.Row(speed, speedUnit), Bound(new TextBlock { Classes = { "hint" } }, nameof(vm.SpeedConversion)), speedSlider,
            Hint("1 Mbps … 400 Gbps (logarithmic); type any value, any unit"), quick);

        var duration = Number("Target duration", nameof(vm.DurationText));
        var durationUnit = new ComboBox { ItemsSource = TransferCalculatorViewModel.DurationUnits, Width = 90 };
        durationUnit.Bind(SelectingItemsControl.SelectedItemProperty, new ReflectionBinding(nameof(vm.DurationUnit)) { Source = vm, Mode = BindingMode.TwoWay });
        AutomationProperties.SetName(durationUnit, "Duration unit");
        var durationBlock = Section("Target duration", Ui.Row(duration, durationUnit));

        var efficiency = Number("Effective throughput percent", nameof(vm.EfficiencyText), 80);
        var presets = Ui.Row(efficiency, new TextBlock { Text = "%", VerticalAlignment = VerticalAlignment.Center },
            Preset("Theoretical 100 %", 100), Preset("Typical estimate 90 %", 90), Preset("Conservative 75 %", 75));
        var effBlock = Section("Effective throughput", presets,
            Hint("An assumption about protocol overhead and contention, not a measurement of your connection: 100 % gives the theoretical minimum."));

        void ApplyMode()
        {
            speedBlock.IsVisible = vm.Mode == TransferMode.TransferTime;
            durationBlock.IsVisible = vm.Mode == TransferMode.RequiredSpeed;
        }

        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(vm.Mode)) ApplyMode();
        };
        ApplyMode();

        // result: the focal point
        var details = new ItemsControl
        {
            ItemsSource = vm.Details,
            ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<DetailRow>((row, _) => row is null ? new TextBlock() : new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("170,*"),
                Children = { new TextBlock { Text = row.Label, Classes = { "label" } }, Col(new SelectableTextBlock { Text = row.Value, TextWrapping = TextWrapping.Wrap }, 1) },
            }),
        };
        var result = new Border
        {
            Classes = { "banner" }, Padding = new Thickness(16, 10),
            Child = new StackPanel
            {
                Spacing = 4,
                Children =
                {
                    Bound(new TextBlock { Classes = { "section" } }, nameof(vm.ResultLabel)),
                    Live(Bound(new SelectableTextBlock { Classes = { "result" }, TextWrapping = TextWrapping.Wrap }, nameof(vm.ResultMain))),
                    Bound(new TextBlock { Classes = { "status" } }, nameof(vm.ResultSub)),
                    Live(Bound(new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap }, nameof(vm.Error))),
                    details,
                },
            },
        };

        var compSpeeds = ToolKit.Text("Comparison speeds", "e.g. 100 Mbps, 1 Gbps, 10 Gbps");
        compSpeeds.Bind(TextBox.TextProperty, new ReflectionBinding(nameof(vm.ComparisonSpeedsText)) { Source = vm, Mode = BindingMode.TwoWay });
        var compEff = new CheckBox { Content = "Apply the effective throughput" };
        compEff.Bind(ToggleButton.IsCheckedProperty, new ReflectionBinding(nameof(vm.ComparisonUsesEfficiency)) { Source = vm, Mode = BindingMode.TwoWay });
        var compList = new ItemsControl
        {
            ItemsSource = vm.Comparison,
            ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<ComparisonRow>((row, _) => row is null ? new TextBlock() : new Grid
            {
                ColumnDefinitions = new ColumnDefinitions("150,*"),
                Children = { new TextBlock { Text = row.Speed, Classes = { "label" } }, Col(new TextBlock { Text = row.Time }, 1) },
            }),
        };
        var comparison = new Expander
        {
            Header = "Speed comparison", HorizontalAlignment = HorizontalAlignment.Stretch,
            Content = new StackPanel { Spacing = 4, Children = { compSpeeds, compEff, Bound(new TextBlock { Classes = { "hint" } }, nameof(vm.ComparisonNote)), compList } },
        };
        var breakdown = new SelectableTextBlock { Classes = { "mono" }, TextWrapping = TextWrapping.NoWrap };
        breakdown.Bind(TextBlock.TextProperty, new ReflectionBinding(nameof(vm.Breakdown)) { Source = vm });
        var calc = new Expander
        {
            Header = "Calculation details", HorizontalAlignment = HorizontalAlignment.Stretch,
            Content = new ScrollViewer { Content = breakdown, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto },
        };

        var reset = Ui.Button("Reset", () =>
        {
            vm.Reset();
            modeTime.IsChecked = true;
            return Task.CompletedTask;
        });
        var copy = ToolKit.CopyButton(this, vm.CopyText, "Copy Result");
        var form = new StackPanel
        {
            Spacing = Styling.Theme.SectionGap,
            Children =
            {
                Ui.Row(modeTime, modeSpeed),
                Section("File size", Ui.Row(size, sizeUnit, fromFile), sizeSlider, Hint("1 MB … 1 PB (logarithmic); any size up to QB and QiB can be typed")),
                speedBlock, durationBlock, effBlock, result, comparison, calc,
                Hint("Offline: nothing is downloaded, uploaded or measured. SI units are powers of 1000 (MB, Mbps), IEC units powers of 1024 (MiB); 1 byte = 8 bits."),
            },
        };
        var footer = Ui.Row(reset, copy);
        footer.Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0);
        var page = new DockPanel { Margin = Styling.Theme.Page };
        DockPanel.SetDock(footer, Dock.Bottom);
        page.Children.Add(footer);
        page.Children.Add(new ScrollViewer { Content = form, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled });
        Content = page;
        Opened += (_, _) => size.Focus();
    }

    private static T Col<T>(T control, int column)
        where T : Control
    {
        Grid.SetColumn(control, column);
        return control;
    }

    private static T Live<T>(T control)
        where T : Control
    {
        AutomationProperties.SetLiveSetting(control, AutomationLiveSetting.Polite);
        return control;
    }

    private T Bound<T>(T text, string path)
        where T : TextBlock
    {
        text.Bind(TextBlock.TextProperty, new ReflectionBinding(path) { Source = _vm });
        text.Bind(IsVisibleProperty, new ReflectionBinding(path) { Source = _vm, Converter = Avalonia.Data.Converters.StringConverters.IsNotNullOrEmpty });
        return text;
    }

    private static TextBlock Hint(string text) => new() { Text = text, Classes = { "hint" } };

    private static StackPanel Section(string title, params Control[] children)
    {
        var p = new StackPanel { Spacing = Styling.Theme.TightGap, Children = { new TextBlock { Text = title, Classes = { "section" } } } };
        foreach (var c in children) p.Children.Add(c);
        return p;
    }

    private TextBox Number(string name, string path, double width = 170)
    {
        var t = ToolKit.Text(name, "", width);
        t.Bind(TextBox.TextProperty, new ReflectionBinding(path) { Source = _vm, Mode = BindingMode.TwoWay });
        return t;
    }

    private Slider Slider(string name, double min, double max, string path)
    {
        var s = new Slider { Minimum = min, Maximum = max, SmallChange = 0.1, LargeChange = 1, MinWidth = 300, MaxWidth = 560, HorizontalAlignment = HorizontalAlignment.Left };
        s.Bind(RangeBase.ValueProperty, new ReflectionBinding(path) { Source = _vm, Mode = BindingMode.TwoWay });
        AutomationProperties.SetName(s, name);
        return s;
    }

    private Button Preset(string label, int percent) => Ui.Button(label, () =>
    {
        _vm.ApplyEfficiencyPreset(percent);
        return Task.CompletedTask;
    });

    /// <summary>Units grouped: common first, then decimal bytes, binary bytes, decimal bits, binary bits (headers are not selectable).</summary>
    private ComboBox UnitCombo(string name, bool rate, Func<DataUnit> get, Action<DataUnit> set, string property)
    {
        var items = new List<object>();
        string Show(DataUnit u) => rate ? u.RateSymbol : u.Symbol;
        void Header(string text) => items.Add(new ComboBoxItem { Content = text, IsEnabled = false, Classes = { "section" } });
        Header("Common");
        foreach (var s in rate ? DataUnits.CommonRates : DataUnits.CommonSizes) items.Add(new ComboBoxItem { Content = Show(DataUnits.Get(s)), Tag = DataUnits.Get(s) });
        foreach (var (group, title) in new[] { (UnitGroup.DecimalBytes, "Decimal (SI) bytes"), (UnitGroup.BinaryBytes, "Binary (IEC) bytes"), (UnitGroup.DecimalBits, "Decimal (SI) bits"), (UnitGroup.BinaryBits, "Binary (IEC) bits") })
        {
            Header(title + (rate ? " per second" : ""));
            foreach (var u in DataUnits.All.Where(u => u.Group == group)) items.Add(new ComboBoxItem { Content = Show(u) + "   " + u.Name + (rate ? "s per second" : ""), Tag = u });
        }

        var combo = new ComboBox { ItemsSource = items, Width = 130, MaxDropDownHeight = 420 };
        AutomationProperties.SetName(combo, name);
        var updating = false;
        void Select()
        {
            updating = true;
            var unit = get();
            combo.SelectedItem = items.OfType<ComboBoxItem>().FirstOrDefault(i => Equals(i.Tag, unit));
            updating = false;
        }

        combo.SelectionChanged += (_, _) =>
        {
            if (!updating && combo.SelectedItem is ComboBoxItem { Tag: DataUnit u }) set(u);
        };
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == property) Select();
        };
        Select();
        return combo;
    }

    private async Task PickFileAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Use a file's size", AllowMultiple = false });
        if (files.Count == 0) return;
        var props = await files[0].GetBasicPropertiesAsync(); // metadata only; the path is not kept
        if (props.Size is { } bytes) _vm.SetSizeBytes((long)Math.Min(bytes, long.MaxValue));
    }
}
