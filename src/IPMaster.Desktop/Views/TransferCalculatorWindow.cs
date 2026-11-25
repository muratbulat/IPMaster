using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Layout;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Download Calculator: file size and connection speed in, estimated time out (live). Laid out like the IP
/// Calculator: a bordered input card, then the result, then Reset and Copy.
/// </summary>
internal sealed class TransferCalculatorWindow : Window
{
    private readonly TransferCalculatorViewModel _vm;

    public TransferCalculatorWindow(TransferCalculatorViewModel vm)
    {
        _vm = vm ?? throw new ArgumentNullException(nameof(vm));
        Title = "Download Calculator";
        Width = 560;
        Height = 340;
        MinWidth = 440;
        MinHeight = 320;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;

        var size = Number("File size", nameof(vm.SizeText));
        var sizeUnit = Unit("File size unit", TransferCalculatorViewModel.SizeUnits, nameof(vm.SizeUnit));
        var speed = Number("Connection speed", nameof(vm.SpeedText));
        var speedUnit = Unit("Connection speed unit", TransferCalculatorViewModel.SpeedUnits, nameof(vm.SpeedUnit));
        var presets = Ui.Row([.. TransferCalculatorViewModel.QuickSpeeds.Select(s => (Control)Ui.Button(s, () =>
        {
            vm.ApplyPreset(s);
            return Task.CompletedTask;
        }))]);

        var form = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), RowDefinitions = new RowDefinitions("Auto,Auto,Auto"), RowSpacing = Styling.Theme.FormRowGap, ColumnSpacing = 12 };
        Add(form, Caption("File Size", size), 0, 0);
        Add(form, Ui.Row(size, sizeUnit), 0, 1);
        Add(form, Caption("Connection Speed", speed), 1, 0);
        Add(form, new StackPanel { Spacing = 2, Children = { Ui.Row(speed, speedUnit), Bound(new TextBlock { Classes = { "hint" } }, nameof(vm.SpeedNote)) } }, 1, 1);
        Add(form, Caption("Quick Speeds", presets.Children[0]), 2, 0);
        Add(form, presets, 2, 1);
        var card = new Border { BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6), Padding = new Thickness(14, 12), Child = form };
        card.Bind(Border.BorderBrushProperty, card.GetResourceObservable(Styling.Theme.Keys.Border));

        var result = Bound(new SelectableTextBlock { Classes = { "result" }, HorizontalAlignment = HorizontalAlignment.Center }, nameof(vm.Result));
        AutomationProperties.SetName(result, "Estimated time");
        AutomationProperties.SetLiveSetting(result, AutomationLiveSetting.Polite);
        var error = Bound(new TextBlock { Classes = { "error" }, TextWrapping = Avalonia.Media.TextWrapping.Wrap, HorizontalAlignment = HorizontalAlignment.Center }, nameof(vm.Error));
        var output = new StackPanel
        {
            Spacing = 2, Margin = new Thickness(0, Styling.Theme.SectionGap * 2, 0, 0),
            Children = { new TextBlock { Text = "Estimated Time", Classes = { "label" }, HorizontalAlignment = HorizontalAlignment.Center }, result, error },
        };

        var reset = Ui.Button("Reset", () =>
        {
            vm.Reset();
            return Task.CompletedTask;
        });
        var copy = ToolKit.CopyButton(this, vm.CopyText);
        ToolTip.SetTip(copy, "Copy the result");
        var buttons = Ui.Row(reset, copy);
        buttons.HorizontalAlignment = HorizontalAlignment.Right;
        buttons.Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0);

        var page = new DockPanel { Margin = Styling.Theme.Page };
        DockPanel.SetDock(buttons, Dock.Bottom);
        DockPanel.SetDock(card, Dock.Top);
        page.Children.Add(buttons);
        page.Children.Add(card);
        page.Children.Add(output);
        Content = page;
        Opened += (_, _) => size.Focus();
    }

    private static void Add(Grid grid, Control control, int row, int column)
    {
        Grid.SetRow(control, row);
        Grid.SetColumn(control, column);
        grid.Children.Add(control);
    }

    private static Label Caption(string text, Control target) =>
        new() { Content = text, Target = target, VerticalAlignment = VerticalAlignment.Center, Padding = new Thickness(0) };

    private T Bound<T>(T text, string path)
        where T : TextBlock
    {
        text.Bind(TextBlock.TextProperty, new ReflectionBinding(path) { Source = _vm });
        text.Bind(IsVisibleProperty, new ReflectionBinding(path) { Source = _vm, Converter = Avalonia.Data.Converters.StringConverters.IsNotNullOrEmpty });
        return text;
    }

    private TextBox Number(string name, string path)
    {
        var t = ToolKit.Text(name, "", 140);
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
