using System.Net;
using Avalonia.Controls;
using Avalonia.Styling;
using IPMaster.Core.Network;
using IPMaster.Desktop.ViewModels;
using IPMaster.Desktop.Views;

namespace IPMaster.Tests;

/// <summary>Synthetic adapters modelled on real machines (Hyper-V, Fortinet, WSL, VMware, Wi-Fi Direct, Docker).</summary>
internal static class Adapters
{
    public static NetworkAdapterInfo Make(string id, string name, string description, string type, string? mac, string[] addresses, string[]? gateways = null) =>
        new(id, name, description, type, mac,
            [.. addresses.Select(a => a.Split('/') is [var ip, var p] ? new AdapterAddress(IPAddress.Parse(ip), int.Parse(p, System.Globalization.CultureInfo.InvariantCulture)) : throw new ArgumentException(a))],
            [.. (gateways ?? []).Select(IPAddress.Parse)], 1_000_000_000);

    public static NetworkAdapterInfo Wired => Make("{wired}", "Ethernet", "Intel(R) Ethernet Controller I225-V", "Ethernet", "00-00-5E-00-53-01",
        ["192.168.10.25/24", "172.20.10.50/24", "fe80::1%7/64"], ["192.168.10.1"]);

    public static NetworkAdapterInfo Wifi => Make("{wifi}", "Wi-Fi", "MediaTek Wi-Fi 6E MT7922", "Wireless80211", "00-00-5E-00-53-02", ["192.0.2.100/24"], ["192.0.2.1"]);

    public static NetworkAdapterInfo HyperV => Make("{hv}", "vEthernet (FSE HostVnic)", "Hyper-V Virtual Ethernet Container Adapter", "Ethernet", "00-15-5D-00-00-01", ["172.28.64.1/20"]);

    public static NetworkAdapterInfo Wsl => Make("{wsl}", "vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter", "Ethernet", "00-15-5D-01-02-03", ["172.28.64.1/20"]);

    public static NetworkAdapterInfo Fortinet => Make("{forti}", "Ethernet 4", "Fortinet Virtual Ethernet Adapter (NDIS 6.30) #2", "Ethernet", "00-09-0F-FE-00-01", ["198.51.100.10/24"], ["198.51.100.1"]);

    public static NetworkAdapterInfo VMware => Make("{vmnet8}", "VMware Network Adapter VMnet8", "VMware Virtual Ethernet Adapter for VMnet8", "Ethernet", "00-50-56-C0-00-08", ["192.168.80.1/24"]);

    public static NetworkAdapterInfo Big => Make("{big}", "Lab", "Some NIC", "Ethernet", "BC-00-00-00-00-01", ["10.0.0.5/8", "2001:db8::5/64"]);
}

public class AdapterClassifierTests
{
    [Fact]
    public void Kinds_come_from_reliable_evidence_and_unknown_is_not_guessed()
    {
        Assert.Equal((AdapterKind.Ethernet, (bool?)true), (AdapterClassifier.Classify(Adapters.Wired).Kind, AdapterClassifier.Classify(Adapters.Wired).Physical));
        Assert.Equal(AdapterKind.WiFi, AdapterClassifier.Classify(Adapters.Wifi).Kind);
        var hv = AdapterClassifier.Classify(Adapters.HyperV);
        Assert.Equal(AdapterKind.Virtual, hv.Kind);
        Assert.Contains("Hyper-V", hv.Evidence, StringComparison.Ordinal);
        Assert.Equal(AdapterKind.Vpn, AdapterClassifier.Classify(Adapters.Fortinet).Kind);
        Assert.Equal(AdapterKind.Virtual, AdapterClassifier.Classify(Adapters.VMware).Kind);
        Assert.Equal(AdapterKind.Vpn, AdapterClassifier.Classify(Adapters.Make("p", "Dial-up", "WAN Miniport (PPPOE)", "Ppp", null, [])).Kind);
        Assert.Equal(AdapterKind.Virtual, AdapterClassifier.Classify(Adapters.Make("d", "Local Area Connection* 10", "Microsoft Wi-Fi Direct Virtual Adapter #2", "Wireless80211", "86-9E-56-1D-24-07", [])).Kind);
        Assert.Equal(AdapterKind.Vpn, AdapterClassifier.Classify(Adapters.Make("w", "wg0", "WireGuard Tunnel", "Unknown", null, [])).Kind);
        var odd = AdapterClassifier.Classify(Adapters.Make("x", "Thing", "Some adapter", "Fddi", null, []));
        Assert.Equal(AdapterKind.Unknown, odd.Kind);
        Assert.Null(odd.Physical);
        var la = AdapterClassifier.Classify(Adapters.Make("l", "eth1", "USB NIC", "Ethernet", "02-11-22-33-44-55", []));
        Assert.Null(la.Physical); // locally administered MAC: not proof of hardware
    }
}

public class AdapterPickerViewModelTests
{
    private static readonly NetworkAdapterInfo[] Mixed = [Adapters.Wired, Adapters.HyperV, Adapters.Wsl, Adapters.Fortinet, Adapters.VMware];

    private static AdapterAddressItem Item(AdapterPickerViewModel vm, string address) => vm.Groups.SelectMany(g => g.Addresses).First(a => a.Address.ToString() == address);

    [Fact]
    public void Only_the_single_physical_adapter_with_a_gateway_is_preselected()
    {
        var vm = new AdapterPickerViewModel(Mixed);
        Assert.True(Item(vm, "192.168.10.25/24").IsSelected);
        Assert.True(Item(vm, "172.20.10.50/24").IsSelected);
        Assert.False(Item(vm, "fe80::1%7/64").IsSelected); // IPv6 never preselected
        Assert.False(vm.Groups.Single(g => g.Adapter.Id == "{forti}").Addresses[0].IsSelected); // a VPN with a gateway is not
        Assert.All(vm.Groups.Where(g => g.Class.Kind == AdapterKind.Virtual), g => Assert.All(g.Addresses, a => Assert.False(a.IsSelected)));
        Assert.StartsWith("Preselected: Ethernet", vm.DefaultNote, StringComparison.Ordinal);

        var two = new AdapterPickerViewModel([Adapters.Wired, Adapters.Wifi]);
        Assert.Empty(two.Result()); // two plausible adapters: the user chooses
        Assert.StartsWith("Several connected adapters", two.DefaultNote, StringComparison.Ordinal);
        Assert.False(two.CanSubmit);
    }

    [Fact]
    public void Search_and_filters_change_visibility_only_and_keep_selections()
    {
        var vm = new AdapterPickerViewModel(Mixed);
        vm.Search = "vmnet";
        Assert.Equal(["{vmnet8}"], vm.Groups.Where(g => g.IsShown).Select(g => g.Adapter.Id));
        Assert.True(Item(vm, "192.168.10.25/24").IsSelected); // hidden selection kept
        Assert.Contains("hidden by the filters", vm.Summary, StringComparison.Ordinal);
        vm.SelectVisible();
        Assert.True(Item(vm, "192.168.80.1/24").IsSelected);
        vm.Search = "";
        vm.Filter = AdapterFilter.Vpn;
        Assert.Equal(["{forti}"], vm.Groups.Where(g => g.IsShown).Select(g => g.Adapter.Id));
        vm.Search = "198.51.100.1"; // gateway search
        Assert.Single(vm.Groups, g => g.IsShown);
        vm.Search = "00-15-5D";
        vm.Filter = AdapterFilter.Virtual;
        Assert.Equal(2, vm.Groups.Count(g => g.IsShown));
        vm.ClearVisible();
        Assert.True(Item(vm, "192.168.10.25/24").IsSelected); // not visible, not cleared
        vm.ClearAll();
        Assert.Empty(vm.Result());
    }

    [Fact]
    public void Ip_family_filter_and_group_checkbox_act_on_shown_eligible_addresses()
    {
        var vm = new AdapterPickerViewModel([Adapters.Wired]);
        var g = vm.Groups[0];
        Assert.True(g.GroupChecked); // both IPv4 selected; IPv6 hidden by default
        vm.ShowIPv6 = true;
        Assert.Null(g.GroupChecked); // the link-local address is shown and not selected
        g.GroupChecked = true;
        Assert.True(Item(vm, "fe80::1%7/64").IsSelected);
        Assert.Contains(vm.Result(), r => r.Range == "ff02::1%7"); // neighbour discovery kept from the old dialog
        g.GroupChecked = false;
        Assert.Empty(vm.Result());
    }

    [Fact]
    public void Identical_subnets_are_merged_and_oversized_ranges_are_disabled_with_a_reason()
    {
        var vm = new AdapterPickerViewModel([Adapters.HyperV, Adapters.Wsl, Adapters.Big]);
        foreach (var g in vm.Groups) g.GroupChecked = true;
        vm.ShowIPv6 = true;
        var ranges = vm.Result();
        Assert.Single(ranges, r => r.Range == "172.28.64.0/20");
        Assert.Contains("duplicate subnet", vm.Summary, StringComparison.Ordinal);
        var v6 = Item(vm, "2001:db8::5/64");
        Assert.False(v6.Eligible);
        Assert.Contains("too large", v6.Detail, StringComparison.Ordinal);
        v6.IsSelected = true; // even if forced, an ineligible address never becomes a range
        Assert.DoesNotContain(vm.Result(), r => r.Address.Address.Equals(IPAddress.Parse("2001:db8::5")));
    }

    [Fact]
    public void Large_selections_warn_and_nothing_selected_cannot_be_submitted()
    {
        var vm = new AdapterPickerViewModel([Adapters.Big], largeThreshold: 65_536);
        Assert.False(vm.CanSubmit);
        vm.Groups[0].GroupChecked = true; // 10.0.0.0/8
        Assert.True(vm.CanSubmit);
        Assert.True(vm.IsLarge);
        Assert.Contains("16,777,216", vm.Warning.Replace('.', ','), StringComparison.Ordinal);
    }

    [Fact]
    public void Refresh_keeps_selections_that_still_exist_and_reports_the_rest()
    {
        var vm = new AdapterPickerViewModel(Mixed);
        Item(vm, "192.168.80.1/24").IsSelected = true;
        var wiredChanged = Adapters.Make("{wired}", "Ethernet (renamed)", "Intel(R) Ethernet Controller I225-V", "Ethernet", "00-00-5E-00-53-01", ["192.168.10.25/24"], ["192.168.10.1"]);
        vm.Refresh([wiredChanged, Adapters.HyperV]); // 172.20.10.50 and VMnet8 gone; renamed adapter keeps its id
        Assert.True(Item(vm, "192.168.10.25/24").IsSelected);
        Assert.Contains("172.20.10.50/24", vm.RefreshNote, StringComparison.Ordinal);
        Assert.Contains("VMware Network Adapter VMnet8", vm.RefreshNote, StringComparison.Ordinal);
        Assert.Equal(["192.168.10.0/24"], vm.Result().Select(r => r.Range));
    }
}

[Collection("Headless UI")]
public class AdapterPickerWindowTests
{
    public static TheoryData<int> Counts() => [1, 30];

    [Theory]
    [MemberData(nameof(Counts))]
    public Task Picker_renders_and_keeps_its_actions_reachable(int count) => HeadlessUi.Run(() =>
    {
        var list = new List<NetworkAdapterInfo> { Adapters.Wired };
        for (var i = 1; i < count; i++)
        {
            list.Add(i % 3 == 0 ? Adapters.Make($"{{v{i}}}", $"vEthernet (Switch {i})", "Hyper-V Virtual Ethernet Adapter", "Ethernet", $"00-15-5D-00-00-{i:X2}", [$"172.{16 + i}.0.1/20"])
                : i % 3 == 1 ? Adapters.Make($"{{t{i}}}", $"VPN {i}", "WireGuard Tunnel", "Unknown", null, [$"10.{i}.0.2/24"])
                : Adapters.Make($"{{e{i}}}", $"Ethernet {i}", "USB Ethernet", "Ethernet", $"BC-00-00-00-00-{i:X2}", [$"192.168.{i}.10/24", $"fe80::{i}%{i}/64"]));
        }

        foreach (var variant in new[] { ThemeVariant.Light, ThemeVariant.Dark })
        {
            HeadlessUi.SetTheme(variant);
            // as in IP Address Tools → Local Range (D-111): a tab of a window at that window's sizes
            var picker = Dialogs.AdapterPicker(() => list, 65_536, (_, _) => "");
            var dialog = new Window { Width = 800, Height = 620, MinWidth = 560, MinHeight = 400, Content = new TabControl { Items = { new TabItem { Header = "Local Range", Content = picker } } } };
            dialog.Show();
            try
            {
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(dialog, $"Adapter picker {count} - {variant}");
                dialog.Width = dialog.MinWidth;
                dialog.Height = dialog.MinHeight;
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(dialog, $"Adapter picker {count} - {variant} - minimum size");
                UiDesignSystemTests.AssertNoActionCutOff(dialog, "Adapter picker");
            }
            finally
            {
                dialog.Close();
            }
        }

        HeadlessUi.SetTheme(ThemeVariant.Default);
    });
}
