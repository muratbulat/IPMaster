using System.Globalization;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

/// <summary>Live behaviour of the calculator's view model (D-102), with a fixed culture.</summary>
public class TransferCalculatorViewModelTests
{
    private static TransferCalculatorViewModel Vm() => new(CultureInfo.InvariantCulture);

    [Fact]
    public void Defaults_give_the_classic_example_and_results_update_on_every_input()
    {
        var vm = Vm(); // 10 GB at 100 Mbps, 100 %
        Assert.Equal("13 min 20 sec", vm.ResultMain);
        Assert.Contains("100 Mbps = 12.5 MB/s", vm.SpeedConversion, StringComparison.Ordinal);
        vm.EfficiencyText = "90";
        Assert.Equal("14 min 49 sec", vm.ResultMain);
        Assert.Contains(vm.Details, d => d.Label == "Theoretical minimum" && d.Value.StartsWith("13 min 20 sec", StringComparison.Ordinal));
        Assert.Contains("90 Mbps / 11.25 MB/s", vm.ResultSub, StringComparison.Ordinal);
        vm.SizeText = "1";
        vm.SizeUnit = DataUnits.Get("GiB"); // a unit switch keeps the quantity: 1 GB shown as 0.931323 GiB
        Assert.Equal("0.931323", vm.SizeText);
        vm.SizeText = "1"; // typing sets the quantity: now 1 GiB
        vm.EfficiencyText = "100";
        Assert.Equal("1 min 26 sec", vm.ResultMain); // 85.9 s
        Assert.Contains("exactly", vm.Breakdown, StringComparison.Ordinal);
        Assert.Contains("85.89934592 s", vm.Breakdown, StringComparison.Ordinal);
    }

    [Fact]
    public void Speed_unit_switch_converts_the_shown_number()
    {
        var vm = Vm();
        vm.SpeedUnit = DataUnits.Get("MB");
        Assert.Equal("12.5", vm.SpeedText);
        Assert.Equal("13 min 20 sec", vm.ResultMain); // same quantity, same result
        vm.SpeedUnit = DataUnits.Get("Gb");
        Assert.Equal("0.1", vm.SpeedText);
    }

    [Fact]
    public void Presets_and_sliders_stay_in_step_without_loops()
    {
        var vm = Vm();
        vm.ApplySpeedPreset("1 Gbps");
        Assert.Equal("1", vm.SpeedText);
        Assert.Equal("Gb", vm.SpeedUnit.Symbol);
        Assert.Equal(9, vm.SpeedSlider, 6);
        Assert.Equal("1 min 20 sec", vm.ResultMain);
        vm.SpeedSlider = 10; // 10 Gbps
        Assert.Equal("10", vm.SpeedText);
        Assert.Equal("8.0 sec".Replace(".0", "", StringComparison.Ordinal), vm.ResultMain);
        vm.SizeSlider = 12; // 1 TB, shown in the current byte unit
        Assert.Equal("1000", vm.SizeText);
        Assert.Equal("GB", vm.SizeUnit.Symbol);
        vm.SizeText = "5";
        vm.SizeUnit = DataUnits.Get("QB"); // the quantity stays: 5 GB shown in QB, never as "0"
        Assert.Equal("0.000000000000000000005", vm.SizeText);
        vm.SizeText = "5"; // typed values are not limited by the slider
        Assert.Equal(TransferCalculatorViewModel.SizeSliderMax, vm.SizeSlider);
        Assert.StartsWith("≈", vm.ResultMain, StringComparison.Ordinal);
        vm.ApplyEfficiencyPreset(75);
        Assert.Equal("75", vm.EfficiencyText);
    }

    [Fact]
    public void Invalid_inputs_show_a_reason_and_no_result()
    {
        var vm = Vm();
        vm.SpeedText = "0";
        Assert.Equal("Connection speed: must be more than zero.", vm.Error);
        Assert.Equal("—", vm.ResultMain);
        vm.SpeedText = "100";
        vm.EfficiencyText = "120";
        Assert.Contains("cannot exceed 100", vm.Error, StringComparison.Ordinal);
        vm.EfficiencyText = "0";
        Assert.Contains("more than 0", vm.Error, StringComparison.Ordinal);
        vm.EfficiencyText = "100";
        vm.SizeText = "-1";
        Assert.Contains("negative", vm.Error, StringComparison.Ordinal);
        vm.SizeText = "";
        Assert.Equal("File size: Enter a number.", vm.Error);
        vm.SizeText = "10";
        Assert.Equal("", vm.Error);
    }

    [Fact]
    public void Required_speed_mode_and_comparison()
    {
        var vm = Vm();
        vm.Mode = TransferMode.RequiredSpeed;
        vm.DurationText = "800";
        vm.DurationUnit = "sec";
        Assert.StartsWith("100 Mbps / 12.5 MB/s", vm.ResultMain, StringComparison.Ordinal);
        vm.EfficiencyText = "80";
        Assert.StartsWith("125 Mbps", vm.ResultMain, StringComparison.Ordinal);
        vm.Mode = TransferMode.TransferTime;
        vm.EfficiencyText = "100";
        Assert.Equal(["13 min 20 sec", "1 min 20 sec", "8 sec", "3.2 sec", "0.8 sec"], vm.Comparison.Select(c => c.Time));
        vm.ComparisonSpeedsText = "1 Gbps, fast";
        Assert.Equal("not a speed (e.g. \"10 Gbps\")", vm.Comparison[1].Time);
    }

    [Fact]
    public void File_size_copy_and_reset()
    {
        var vm = Vm();
        vm.SetSizeBytes(1_073_741_824);
        Assert.Equal("1.073742", vm.SizeText); // the decimal family (GB) is kept
        Assert.Equal("GB", vm.SizeUnit.Symbol);
        vm.SizeUnit = DataUnits.Get("GiB");
        vm.SetSizeBytes(1_073_741_824);
        Assert.Equal("1", vm.SizeText); // binary family: exactly 1 GiB
        Assert.Contains("1,073,741,824 bytes", string.Join(" ", vm.Details.Select(d => d.Value)), StringComparison.Ordinal);
        var text = vm.CopyText();
        Assert.StartsWith("Estimated transfer time: ", text, StringComparison.Ordinal);
        Assert.Contains("Formula", text, StringComparison.Ordinal);
        vm.EfficiencyText = "50";
        vm.Reset();
        Assert.Equal("10", vm.SizeText);
        Assert.Equal("100", vm.EfficiencyText);
        Assert.Equal("13 min 20 sec", vm.ResultMain);
    }

    [Fact]
    public void Decimal_input_follows_the_culture()
    {
        var vm = new TransferCalculatorViewModel(CultureInfo.GetCultureInfo("de-DE"));
        vm.SizeText = "10,5";
        Assert.Equal("", vm.Error);
        Assert.Equal("14 min", vm.ResultMain[..6]); // 10.5 GB at 100 Mbps = 840 s
        Assert.Contains("12,5 MB/s", vm.SpeedConversion, StringComparison.Ordinal);
    }
}
