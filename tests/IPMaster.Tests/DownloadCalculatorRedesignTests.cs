using System.Globalization;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Interactivity;
using Avalonia.VisualTree;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;
using IPMaster.Desktop.Views;

namespace IPMaster.Tests;

/// <summary>D-112: speed scale, compact durations, high link speeds, efficiency, slider/field synchronisation.</summary>
public class SpeedScaleTests
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    private static Rational Q(decimal v) => Rational.FromDecimal(v);

    private static Rational Bits(decimal value, string unit) => Q(value) * DataUnits.Get(unit).Factor;

    [Fact]
    public void Every_stop_is_its_integer_position_both_ways()
    {
        for (var i = 0; i < SpeedScale.Stops.Count; i++)
        {
            Assert.Equal(i, SpeedScale.ToPosition(SpeedScale.Stops[i]), 9);
            Assert.Equal(SpeedScale.Stops[i], SpeedScale.FromPosition(i));
        }

        Assert.Equal(Bits(2.5m, "Gb"), SpeedScale.Stops[4]);
        Assert.Equal(Bits(200, "Gb"), SpeedScale.Stops[^1]);
    }

    [Fact]
    public void Positions_are_monotonic_logarithmic_and_clamped()
    {
        Assert.Equal(Bits(316, "Mb"), SpeedScale.FromPosition(2.5)); // √(100 M × 1 G) = 316.2 M, three digits
        Assert.Equal(Bits(5, "Gb"), SpeedScale.FromPosition(4.5)); // √(2.5 G × 10 G)
        Assert.Equal(SpeedScale.Stops[3], SpeedScale.FromPosition(3.01)); // snaps near a stop
        Assert.Equal(SpeedScale.Stops[0], SpeedScale.FromPosition(-4));
        Assert.Equal(SpeedScale.Stops[^1], SpeedScale.FromPosition(99));
        Assert.Equal(0, SpeedScale.ToPosition(Bits(56, "kb")));
        Assert.Equal(SpeedScale.Maximum, SpeedScale.ToPosition(Bits(400, "Gb")));
        Assert.InRange(SpeedScale.ToPosition(Bits(316.227766m, "Mb")), 2.4999, 2.5001);
        var last = -1.0;
        for (var p = 0.0; p <= SpeedScale.Maximum; p += 0.07)
        {
            var at = SpeedScale.ToPosition(SpeedScale.FromPosition(p));
            Assert.True(at >= last, $"not monotonic at {p}");
            Assert.InRange(at, p - 0.03, p + 0.03); // three digits (and the 0.02 snap) keep the thumb where it was dragged
            last = at;
        }
    }

    [Theory]
    [InlineData(0.25, "0.25 seconds")]
    [InlineData(1, "1 second")]
    [InlineData(8.5, "8.5 seconds")]
    [InlineData(25, "25 seconds")]
    [InlineData(272, "4m 32s")]
    [InlineData(4530, "1h 16m")]   // 75.5 min → nearest minute, half away from zero
    [InlineData(4500, "1h 15m")]
    [InlineData(194_400, "2d 6h")]
    [InlineData(3599.6, "1h 0m")]
    [InlineData(0.001, "1 ms")]
    public void Compact_durations(double seconds, string expected) => Assert.Equal(expected, SpeedScale.CompactDuration(Q((decimal)seconds), Inv));

    [Fact]
    public void Years_use_the_long_form() => Assert.StartsWith("≈ ", SpeedScale.CompactDuration(Q(31_557_600m * 3), Inv), StringComparison.Ordinal);

    [Theory]
    [InlineData(1, "125")]
    [InlineData(10, "1250")]
    [InlineData(25, "3125")]
    [InlineData(40, "5000")]
    [InlineData(100, "12500")]
    [InlineData(200, "25000")]
    public void Gbps_to_MB_per_second_is_exact(decimal gbps, string megabytes) =>
        Assert.Equal(Q(decimal.Parse(megabytes, Inv)), TransferCalculator.In(Bits(gbps, "Gb"), DataUnits.Get("MB")));

    [Theory]
    [InlineData(250, "GB", 1, "Gb", 100, "2000")]       // 2 Tb ÷ 1 Gb/s
    [InlineData(1, "TB", 200, "Gb", 100, "40")]
    [InlineData(1, "TB", 40, "Gb", 100, "200")]
    [InlineData(1, "TB", 25, "Gb", 100, "320")]
    [InlineData(10, "GB", 100, "Mb", 90, "888.888888888889")]
    [InlineData(10, "GB", 100, "Mb", 80, "1000")]
    [InlineData(1.5, "PB", 100, "Gb", 95, "126315.789473684211")]
    public void High_speeds_and_efficiency_are_exact(decimal size, string sizeUnit, decimal speed, string speedUnit, int percent, string seconds)
    {
        Assert.True(TransferCalculator.TryEfficiency(Rational.FromInteger(percent), out var e, out _));
        var r = TransferCalculator.Time(Bits(size, sizeUnit), Bits(speed, speedUnit), e);
        Assert.Equal(seconds, r.Seconds.ToFixed(12, Inv));
        Assert.Equal(Bits(speed, speedUnit) * e, r.EffectiveBitsPerSecond); // link speed × efficiency
    }
}

public class TransferCalculatorSliderTests
{
    private static TransferCalculatorViewModel Vm() => new(CultureInfo.InvariantCulture);

    [Fact]
    public void Dragging_writes_a_three_digit_speed_and_keeps_the_thumb()
    {
        var vm = Vm();
        vm.SpeedPosition = 2.5;
        Assert.Equal(("316", "Mbps"), (vm.SpeedText, vm.SpeedUnit));
        Assert.Equal(2.5, vm.SpeedPosition); // not moved back to the rounded value while dragging
        vm.SpeedPosition = 8;
        Assert.Equal(("100", "Gbps"), (vm.SpeedText, vm.SpeedUnit));
        Assert.Equal("100 Gbps", vm.ActivePreset);
        Assert.Equal("0.8 seconds", vm.Result); // 10 GB at 100 Gbps
    }

    [Fact]
    public void Typing_moves_the_slider_and_is_never_rounded()
    {
        var vm = Vm();
        vm.SpeedUnit = "Gbps";
        vm.SpeedText = "1.2345";
        Assert.Equal("1.2345", vm.SpeedText);
        Assert.InRange(vm.SpeedPosition, 3.0, 4.0);
        Assert.Equal(SpeedScale.ToPosition(Rational.FromDecimal(1.2345m) * DataUnits.Get("Gb").Factor), vm.SpeedPosition);
        Assert.Equal("", vm.ActivePreset);
        vm.SpeedText = "500"; // 500 Gbps: beyond the slider, still calculated exactly
        Assert.Equal(SpeedScale.Maximum, vm.SpeedPosition);
        Assert.Equal("500", vm.SpeedText);
        Assert.Equal("0.16 seconds", vm.Result);
    }

    [Fact]
    public void A_byte_unit_stays_a_byte_unit_when_dragging()
    {
        var vm = Vm();
        vm.SpeedUnit = "MB/s";
        vm.SpeedPosition = 3; // 1 Gbps
        Assert.Equal(("125", "MB/s"), (vm.SpeedText, vm.SpeedUnit));
        vm.SpeedPosition = 9; // 200 Gbps = 25 GB/s
        Assert.Equal(("25", "GB/s"), (vm.SpeedText, vm.SpeedUnit));
    }

    [Fact]
    public void Presets_update_field_slider_and_highlight()
    {
        var vm = Vm();
        Assert.Equal("100 Mbps", vm.ActivePreset);
        foreach (var (preset, position) in new[] { ("1 Gbps", 3.0), ("10 Gbps", 5.0), ("25 Gbps", 6.0), ("100 Gbps", 8.0), ("100 Mbps", 2.0) })
        {
            vm.ApplyPreset(preset);
            Assert.Equal(preset, vm.ActivePreset);
            Assert.Equal(position, vm.SpeedPosition, 9);
        }

        vm.SpeedUnit = "MB/s"; // 100 MB/s = 800 Mbps: no preset
        Assert.Equal("", vm.ActivePreset);
    }

    [Fact]
    public void Efficiency_changes_the_time_and_is_marked_as_an_estimate()
    {
        var vm = Vm(); // 10 GB at 100 Mbps = 800 s
        Assert.Equal(("100 %", "Theoretical throughput", false), (vm.EfficiencyText, vm.ResultNote, vm.IsEstimate));
        vm.EfficiencyIndex = 3; // 80 %
        Assert.Equal("1,000", vm.Seconds);
        Assert.Equal("16m 40s", vm.Result);
        Assert.Equal("10 MB/s", vm.Throughput);
        Assert.True(vm.IsEstimate);
        Assert.Contains("80 %", vm.ResultNote, StringComparison.Ordinal);
        Assert.Contains("× 80 %", vm.Formula, StringComparison.Ordinal);
        vm.Reset();
        Assert.Equal((0, "800"), (vm.EfficiencyIndex, vm.Seconds));
    }

    [Fact]
    public void Technical_figures_are_exact()
    {
        var vm = Vm();
        vm.ApplyPreset("1 Gbps");
        vm.SizeText = "250";
        Assert.Equal("33m 20s", vm.Result);
        Assert.Equal(("125 MB/s", "250 GB", "2 Tb"), (vm.Throughput, vm.TotalSize, vm.TotalData));
        Assert.Equal(("1,000,000,000 bit/s", "125,000,000 B/s"), (vm.BitsPerSecond, vm.BytesPerSecond));
        Assert.Equal(("250,000,000,000 B", "2,000,000,000,000 bit"), (vm.TotalBytes, vm.TotalBits));
        Assert.Equal(("2,000", "33.333", "0.5556", "0.02315"), (vm.Seconds, vm.Minutes, vm.Hours, vm.Days));
        Assert.Equal("1 Gbps = 125 MB/s", vm.EffectiveSpeed);
    }

    [Fact]
    public void Extremely_large_and_tiny_values_stay_readable()
    {
        var vm = Vm();
        vm.SizeUnit = "PB";
        vm.SizeText = "1e20";
        vm.SpeedUnit = "kbps";
        vm.SpeedText = "1";
        Assert.Equal("", vm.Error);
        Assert.Contains("years", vm.Result, StringComparison.Ordinal);
        Assert.Contains("10^", vm.TotalBits, StringComparison.Ordinal);
        vm.SizeUnit = "KB";
        vm.SizeText = "1";
        vm.SpeedUnit = "Gbps";
        vm.SpeedText = "200";
        Assert.Equal("", vm.Error);
        Assert.EndsWith("µs", vm.Result, StringComparison.Ordinal);
    }
}

[Collection("Headless UI")]
public class TransferCalculatorWindowTests
{
    [Fact]
    public Task Slider_field_and_presets_stay_in_step_in_the_window() => HeadlessUi.Run(() =>
    {
        var vm = new TransferCalculatorViewModel(CultureInfo.InvariantCulture);
        var w = new TransferCalculatorWindow(vm);
        w.Show();
        try
        {
            UiDesignSystemTests.Dispatch();
            var slider = w.GetVisualDescendants().OfType<Slider>().Single();
            var speed = w.GetVisualDescendants().OfType<TextBox>().Single(t => AutomationProperties.GetName(t) == "Transfer speed");
            var presets = w.GetVisualDescendants().OfType<ToggleButton>().Where(b => b.Content is string s && s.EndsWith("bps", StringComparison.Ordinal)).ToList();
            Assert.Equal(TransferCalculatorViewModel.QuickSpeeds, presets.Select(b => (string)b.Content!));
            Assert.Equal(2, slider.Value, 9);
            Assert.True(presets.Single(b => (string)b.Content! == "100 Mbps").IsChecked);

            slider.Value = 5; // keyboard or drag ends here
            UiDesignSystemTests.Dispatch();
            Assert.Equal("10", speed.Text);
            Assert.True(presets.Single(b => (string)b.Content! == "10 Gbps").IsChecked);
            Assert.Single(presets, b => b.IsChecked == true);

            speed.Text = "40";
            UiDesignSystemTests.Dispatch();
            Assert.Equal(7, slider.Value, 9);
            Assert.All(presets, b => Assert.False(b.IsChecked));

            presets.Single(b => (string)b.Content! == "25 Gbps").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            UiDesignSystemTests.Dispatch();
            Assert.Equal(("25", 6.0), (speed.Text, slider.Value));
            Assert.Equal("3.2 seconds", vm.Result);

            w.GetVisualDescendants().OfType<Button>().Single(b => b.Content as string == "Reset").RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            UiDesignSystemTests.Dispatch();
            Assert.Equal(("100", 2.0), (speed.Text, slider.Value));

            // expanded details, an estimate and extreme values: rendered in both themes, nothing cut off
            w.GetVisualDescendants().OfType<Expander>().Single().IsExpanded = true;
            vm.EfficiencyIndex = 2;
            vm.SizeUnit = "PB";
            vm.SpeedPosition = SpeedScale.Maximum;
            foreach (var variant in new[] { Avalonia.Styling.ThemeVariant.Light, Avalonia.Styling.ThemeVariant.Dark })
            {
                HeadlessUi.SetTheme(variant);
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(w, $"Download Calculator details - {variant}");
                UiDesignSystemTests.AssertNoActionCutOff(w, "Download Calculator details");
            }

            Assert.Equal(("200", "Gbps", "5d 3h"), (vm.SpeedText, vm.SpeedUnit, vm.Result)); // 10 PB = 8e16 b ÷ 1.8e11 b/s = 444,444 s
        }
        finally
        {
            w.Close();
            HeadlessUi.SetTheme(Avalonia.Styling.ThemeVariant.Default);
        }
    });
}
