using System.Numerics;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

/// <summary>Field synchronisation and planning state of the IP Calculator window's view-model (no UI needed).</summary>
public class IpCalculatorViewModelTests
{
    [Fact]
    public void Cidr_input_drives_prefix_slider_and_mask()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "10.20.30.40/22" };
        Assert.Equal(22, vm.Prefix);
        Assert.Equal(22m, vm.PrefixNumber);
        Assert.Equal(22d, vm.PrefixSlider);
        Assert.Equal("255.255.252.0", vm.MaskText);
        Assert.Equal("10.20.28.0/22", vm.Result!.Block.ToString());
        Assert.Equal("", vm.Validation);
    }

    [Fact]
    public void Prefix_field_rewrites_cidr_suffix_and_mask_once()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "192.168.10.25/24" };
        var changes = 0;
        vm.PropertyChanged += (_, e) => changes += e.PropertyName == nameof(vm.AddressText) ? 1 : 0;
        vm.PrefixNumber = 26;
        Assert.Equal("192.168.10.25/26", vm.AddressText);
        Assert.Equal("255.255.255.192", vm.MaskText);
        Assert.Equal(1, changes); // no recursive update loop
        Assert.Equal("192.168.10.0/26", vm.Result!.Block.ToString());
    }

    [Fact]
    public void Mask_field_sets_prefix()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "192.168.10.25/24" };
        vm.MaskText = "255.255.0.0";
        Assert.Equal(16, vm.Prefix);
        Assert.Equal("192.168.10.25/16", vm.AddressText);
        Assert.Equal(16d, vm.PrefixSlider);
    }

    [Fact]
    public void Bare_address_uses_separate_prefix_and_is_not_rewritten()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "172.16.5.4" };
        vm.PrefixSlider = 12;
        Assert.Equal("172.16.5.4", vm.AddressText);
        Assert.Equal("255.240.0.0", vm.MaskText);
        Assert.Equal("172.16.0.0/12", vm.Result!.Block.ToString());
    }

    [Fact]
    public void Noncontiguous_mask_is_inline_error_and_clears_results()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "192.168.10.25/24" };
        vm.MaskText = "255.0.255.0";
        Assert.Null(vm.Result);
        Assert.Contains("contiguous", vm.Validation, StringComparison.Ordinal);
        Assert.Equal("192.168.10.25/24", vm.AddressText); // not silently changed
        Assert.Equal(24, vm.Prefix);
    }

    [Fact]
    public void Contradictory_address_and_mask_text_is_rejected()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "10.0.0.1/24 255.255.0.0" };
        Assert.Null(vm.Result);
        Assert.Contains("disagree", vm.Validation, StringComparison.Ordinal);
    }

    [Fact]
    public void Examples_select_family_and_calculate()
    {
        using var vm = new IpCalculatorViewModel();
        vm.UseExample("2001:db8:1234::25/64");
        Assert.True(vm.IsV6);
        Assert.Equal(128, vm.MaxPrefix);
        Assert.Equal(BigInteger.One << 64, vm.Result!.Total);
        vm.UseExample("192.0.2.10/31");
        Assert.True(vm.IsV4);
        Assert.Equal(2, vm.Result!.Usable);
    }

    [Fact]
    public void Wrong_family_for_selector_is_reported()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "2001:db8::1/64" };
        Assert.Null(vm.Result);
        Assert.Contains("IPv4 is selected", vm.Validation, StringComparison.Ordinal);
    }

    [Fact]
    public void Prefix_change_does_not_rewrite_address_of_other_family()
    {
        using var vm = new IpCalculatorViewModel();
        vm.UseExample("2001:db8:1234::25/64");
        vm.AddressText = "172.16.5.4/20"; // IPv6 still selected: reported, not switched
        vm.PrefixNumber = 66;
        Assert.Equal("172.16.5.4/20", vm.AddressText);
        Assert.Contains("IPv6 is selected", vm.Validation, StringComparison.Ordinal);
    }

    [Fact]
    public void Reset_clears_everything()
    {
        using var vm = new IpCalculatorViewModel();
        vm.UseExample("2001:db8:1234::25/64");
        vm.Reset();
        Assert.True(vm.IsV4);
        Assert.Equal("", vm.AddressText);
        Assert.Equal(24, vm.Prefix);
        Assert.Null(vm.Result);
        Assert.Equal("", vm.Validation);
    }

    [Fact]
    public void Split_normalises_parent_and_pages()
    {
        using var vm = new IpCalculatorViewModel { SplitParent = "10.1.2.3/16", SplitPrefix = 24 };
        Assert.Contains("normalised", vm.SplitNote, StringComparison.Ordinal);
        Assert.Equal(256, vm.Split!.SubnetCount);
        Assert.Equal(SubnetSplit.PageSize, vm.SplitRows.Count);
        Assert.Contains("of 256 in total", vm.PageText, StringComparison.Ordinal);

        vm.SplitPrefix = 30;
        Assert.Equal(16384, vm.Split!.SubnetCount);
        vm.LastPage();
        Assert.Equal("10.1.255.252/30", vm.SplitRows[^1].Subnet);
        Assert.Contains("Page 64 of 64", vm.PageText, StringComparison.Ordinal);
        vm.GoToPage = "2";
        vm.GoTo();
        Assert.Equal("10.1.4.0/30", vm.SplitRows[0].Subnet);
    }

    [Fact]
    public void Split_rejects_less_specific_prefix()
    {
        using var vm = new IpCalculatorViewModel { SplitParent = "10.0.0.0/16", SplitPrefix = 8 };
        Assert.Null(vm.Split);
        Assert.Contains("at least as specific", vm.SplitError, StringComparison.Ordinal);
    }

    [Fact]
    public void Split_by_hosts_explains_point_to_point()
    {
        using var vm = new IpCalculatorViewModel { SplitParent = "192.0.2.0/24", SplitHosts = "2", SplitModeIndex = 1 };
        Assert.Equal(30, vm.Split!.NewPrefix);
        Assert.Contains("/31", vm.SplitNote, StringComparison.Ordinal);
        vm.AllowPointToPoint = true;
        Assert.Equal(31, vm.Split!.NewPrefix);
        Assert.Contains("RFC 3021", vm.SplitNote, StringComparison.Ordinal);
    }

    [Fact]
    public void Enormous_split_shows_total_separately_and_refuses_complete_export()
    {
        using var vm = new IpCalculatorViewModel { SplitParent = "2001:db8::/32", SplitPrefix = 64 };
        Assert.Equal(BigInteger.One << 32, vm.Split!.SubnetCount);
        Assert.Equal(SubnetSplit.PageSize, vm.SplitRows.Count);
        Assert.False(vm.CanExportAll);
        Assert.Contains("4,294,967,296 in total", vm.PageText, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Export_writes_complete_set_or_refuses_it()
    {
        var dir = Directory.CreateTempSubdirectory("ipcalc-");
        try
        {
            using var vm = new IpCalculatorViewModel { SplitParent = "10.0.0.0/22", SplitPrefix = 24 };
            var path = Path.Combine(dir.FullName, "all.csv");
            await vm.ExportSplitAsync(path, json: false, complete: true);
            var text = await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken);
            Assert.Contains("complete set, all 4 subnets", text, StringComparison.Ordinal);
            Assert.Contains("10.0.3.0/24", text, StringComparison.Ordinal);

            vm.SplitParent = "10.0.0.0/8";
            vm.SplitPrefix = 32;
            var big = Path.Combine(dir.FullName, "big.csv");
            await vm.ExportSplitAsync(big, json: false, complete: true);
            Assert.False(File.Exists(big));
            Assert.Contains("export limit", vm.Status, StringComparison.Ordinal);

            var page = Path.Combine(dir.FullName, "page.json");
            await vm.ExportSplitAsync(page, json: true, complete: false);
            var json = await File.ReadAllTextAsync(page, TestContext.Current.CancellationToken);
            Assert.Contains("\"scope\": \"page\"", json, StringComparison.Ordinal);
            Assert.Contains("current page only, page 1 of 65,536", json, StringComparison.Ordinal);
        }
        finally
        {
            dir.Delete(recursive: true);
        }
    }

    [Fact]
    public void Range_tools_update_as_you_type()
    {
        using var vm = new IpCalculatorViewModel { ContainsNetwork = "10.20.28.0/22", ContainsAddress = "10.20.31.7" };
        Assert.StartsWith("Yes", vm.ContainsResult, StringComparison.Ordinal);
        vm.ContainsAddress = "2001:db8::1";
        Assert.True(vm.ContainsError);

        vm.CompareA = "10.0.0.0/8";
        vm.CompareB = "10.1.0.0/16";
        Assert.StartsWith("A contains B", vm.CompareResult, StringComparison.Ordinal);

        vm.RangeStart = "10.0.0.1";
        vm.RangeEnd = "10.0.0.6";
        Assert.Equal(4, vm.RangeCidrs.Split(Environment.NewLine).Length);
        Assert.False(vm.RangeError);
    }
}
