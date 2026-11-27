using System.Globalization;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

/// <summary>The simplified Download Calculator: decimal units, live result, presets, validation, copy and reset.</summary>
public class TransferCalculatorViewModelTests
{
    private static TransferCalculatorViewModel Vm() => new(CultureInfo.InvariantCulture);

    [Theory]
    [InlineData("1", "GB", "100", "Mbps", "1m 20s")]    // 80 s
    [InlineData("10", "GB", "100", "Mbps", "13m 20s")]  // 800 s
    [InlineData("1", "GB", "1", "Gbps", "8 seconds")]
    [InlineData("1", "GB", "100", "MB/s", "10 seconds")]
    [InlineData("500", "KB", "8", "kbps", "8m 20s")]    // 500,000 B × 8 ÷ 8,000 b/s = 500 s
    [InlineData("1", "PB", "25", "Gbps", "3d 17h")]    // 320,000 s = 88.9 h
    [InlineData("2", "TB", "1", "GB/s", "33m 20s")]
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
        Assert.Equal("13m 20s", vm.Result);
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
        Assert.Equal("9d 6h", vm.Result); // 800,000 s = 222.2 h
    }

    [Theory]
    [InlineData("", "100", "File size: Enter a number.")]
    [InlineData("0", "100", "File size: must be more than zero.")]
    [InlineData("-1", "100", "File size: The value cannot be negative.")]
    [InlineData("abc", "100", "File size: 'abc' is not a number.")]
    [InlineData("10", "0", "Transfer speed: must be more than zero.")]
    [InlineData("10", "-5", "Transfer speed: The value cannot be negative.")]
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
        Assert.Equal("1m 20s", vm.Result);
        Assert.Equal("10 GB at 1 Gbps, 100 % efficiency: 1m 20s (80 s; throughput 125 MB/s)", vm.CopyText());
        vm.SizeText = "3";
        vm.Reset();
        Assert.Equal(("10", "GB", "100", "Mbps"), (vm.SizeText, vm.SizeUnit, vm.SpeedText, vm.SpeedUnit));
        Assert.Equal("13m 20s", vm.Result);
    }

    [Fact]
    public void Decimal_separator_follows_the_culture()
    {
        var vm = new TransferCalculatorViewModel(CultureInfo.GetCultureInfo("de-DE"));
        vm.SizeText = "1,5"; // 1.5 GB at 100 Mbps = 120 s
        Assert.Equal("2m 0s", vm.Result);
        Assert.Equal("100 Mbps = 12,5 MB/s", vm.SpeedNote);
    }
}
