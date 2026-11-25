using System.Globalization;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

/// <summary>The simplified Download Calculator: decimal units, live result, presets, validation, copy and reset.</summary>
public class TransferCalculatorViewModelTests
{
    private static TransferCalculatorViewModel Vm() => new(CultureInfo.InvariantCulture);

    [Theory]
    [InlineData("1", "GB", "100", "Mbps", "1 min 20 sec")]    // 80 s
    [InlineData("10", "GB", "100", "Mbps", "13 min 20 sec")]  // 800 s
    [InlineData("1", "GB", "1", "Gbps", "8 sec")]
    [InlineData("1", "GB", "100", "MB/s", "10 sec")]
    [InlineData("500", "KB", "8", "kbps", "8 min 20 sec")]    // 500,000 B × 8 ÷ 8,000 b/s = 500 s
    [InlineData("1", "PB", "25", "Gbps", "3 days 16 h 53 min")]
    [InlineData("2", "TB", "1", "GB/s", "33 min 20 sec")]
    public void Results_use_decimal_units_and_keep_bits_and_bytes_apart(string size, string sizeUnit, string speed, string speedUnit, string expected)
    {
        var vm = Vm();
        vm.SizeUnit = sizeUnit;
        vm.SizeText = size;
        vm.SpeedUnit = speedUnit;
        vm.SpeedText = speed;
        Assert.Equal("", vm.Error);
        Assert.Equal(expected, vm.Result);
    }

    [Fact]
    public void Defaults_and_the_bits_bytes_note()
    {
        var vm = Vm();
        Assert.Equal("13 min 20 sec", vm.Result);
        Assert.Equal("100 Mbps = 12.5 MB/s", vm.SpeedNote);
        vm.SpeedUnit = "MB/s";
        Assert.Equal("100 MB/s = 800 Mbps", vm.SpeedNote);
    }

    [Fact]
    public void Unit_switching_keeps_the_number_and_recalculates()
    {
        var vm = Vm();
        vm.SizeUnit = "TB"; // 10 TB at 100 Mbps
        Assert.Equal("10", vm.SizeText);
        Assert.Equal("9 days 6 h 13 min", vm.Result);
    }

    [Theory]
    [InlineData("", "100", "File size: Enter a number.")]
    [InlineData("-1", "100", "File size: The value cannot be negative.")]
    [InlineData("abc", "100", "File size: 'abc' is not a number.")]
    [InlineData("10", "0", "Connection speed: must be more than zero.")]
    [InlineData("10", "-5", "Connection speed: The value cannot be negative.")]
    public void Invalid_inputs_explain_and_clear_the_result(string size, string speed, string error)
    {
        var vm = Vm();
        vm.SizeText = size;
        vm.SpeedText = speed;
        Assert.Equal(error, vm.Error);
        Assert.Equal("—", vm.Result);
        Assert.Equal("", vm.CopyText());
    }

    [Fact]
    public void Presets_copy_and_reset()
    {
        var vm = Vm();
        vm.ApplyPreset("1 Gbps");
        Assert.Equal(("1", "Gbps"), (vm.SpeedText, vm.SpeedUnit));
        Assert.Equal("1 min 20 sec", vm.Result);
        Assert.Equal("10 GB at 1 Gbps: 1 min 20 sec", vm.CopyText());
        vm.SizeText = "3";
        vm.Reset();
        Assert.Equal(("10", "GB", "100", "Mbps"), (vm.SizeText, vm.SizeUnit, vm.SpeedText, vm.SpeedUnit));
        Assert.Equal("13 min 20 sec", vm.Result);
    }

    [Fact]
    public void Decimal_separator_follows_the_culture()
    {
        var vm = new TransferCalculatorViewModel(CultureInfo.GetCultureInfo("de-DE"));
        vm.SizeText = "1,5"; // 1.5 GB at 100 Mbps = 120 s
        Assert.Equal("2 min 0 sec", vm.Result);
        Assert.Equal("100 Mbps = 12,5 MB/s", vm.SpeedNote);
    }
}
