using System.Net;
using IPMaster.Core.Network;
using IPMaster.Infrastructure.Network;

namespace IPMaster.Tests;

/// <summary>Temporary laptop address (D-090): planning and command building only. No test changes an adapter.</summary>
public class TemporaryAddressTests
{
    private static NetworkAdapterInfo Adapter(string id, params string[] cidrs) => new(id, id, id, "Ethernet", "00-00-00-AA-BB-CC",
        cidrs.Select(c => new AdapterAddress(IPAddress.Parse(c.Split('/')[0]), int.Parse(c.Split('/')[1], System.Globalization.CultureInfo.InvariantCulture))).ToList(), [], 1_000_000_000);

    [Fact]
    public void Suggests_the_nearest_free_neighbour_inside_the_subnet()
    {
        var device = IPAddress.Parse("172.20.30.45");
        Assert.Equal(IPAddress.Parse("172.20.30.46"), TemporaryAddressPlanner.Suggest(device, 24, new HashSet<IPAddress>()));
        Assert.Equal(IPAddress.Parse("172.20.30.44"), TemporaryAddressPlanner.Suggest(device, 24, new HashSet<IPAddress> { IPAddress.Parse("172.20.30.46") }));
        Assert.Equal(IPAddress.Parse("192.168.1.253"), TemporaryAddressPlanner.Suggest(IPAddress.Parse("192.168.1.254"), 24, new HashSet<IPAddress>())); // never .255
        Assert.Equal(IPAddress.Parse("10.0.0.2"), TemporaryAddressPlanner.Suggest(IPAddress.Parse("10.0.0.1"), 30, new HashSet<IPAddress>()));
        Assert.Null(TemporaryAddressPlanner.Suggest(IPAddress.Parse("10.0.0.1"), 30, new HashSet<IPAddress> { IPAddress.Parse("10.0.0.2") }));
        Assert.Null(TemporaryAddressPlanner.Suggest(IPAddress.Parse("fe80::1"), 64, new HashSet<IPAddress>()));
    }

    [Fact]
    public void Check_reports_existing_addresses_overlapping_subnets_and_bad_values()
    {
        var target = Adapter("eth", "169.254.10.20/16");
        var wifi = Adapter("wifi", "172.20.30.100/24");
        Assert.Empty(TemporaryAddressPlanner.Check([target], target, IPAddress.Parse("172.20.30.46"), 24));
        Assert.Contains(TemporaryAddressPlanner.Check([target, wifi], target, IPAddress.Parse("172.20.30.46"), 24), p => p.Contains("already in this subnet", StringComparison.Ordinal));
        Assert.Contains(TemporaryAddressPlanner.Check([target], target, IPAddress.Parse("169.254.10.20"), 16), p => p.Contains("already an address", StringComparison.Ordinal));
        Assert.Contains(TemporaryAddressPlanner.Check([target], target, IPAddress.Parse("172.20.30.255"), 24), p => p.Contains("broadcast", StringComparison.Ordinal));
        Assert.Contains(TemporaryAddressPlanner.Check([target], target, IPAddress.Parse("172.20.30.46"), 31), p => p.Contains("between 8 and 30", StringComparison.Ordinal));
    }

    [Fact]
    public void Commands_use_the_active_store_and_never_add_a_gateway()
    {
        var add = TemporaryAddressManager.AddArguments(12, IPAddress.Parse("172.20.30.46"), 24);
        var command = add[^1];
        Assert.Equal("New-NetIPAddress -InterfaceIndex 12 -IPAddress 172.20.30.46 -PrefixLength 24 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null", command);
        Assert.DoesNotContain("Gateway", command, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("-NonInteractive", add);
        Assert.Contains("-PolicyStore ActiveStore", TemporaryAddressManager.RemoveArguments(12, IPAddress.Parse("172.20.30.46"))[^1], StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => TemporaryAddressManager.AddArguments(12, IPAddress.Parse("fe80::1"), 64));
    }

    [Fact]
    public void Recovery_text_names_the_address_and_the_manual_steps()
    {
        var t = new TemporaryAddress("id", "Ethernet", 12, IPAddress.Parse("172.20.30.46"), 24, DateTimeOffset.Now);
        Assert.Contains("Remove-NetIPAddress -IPAddress 172.20.30.46", t.Recovery, StringComparison.Ordinal);
        Assert.Contains("restart", t.Recovery, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_prefix_is_refused_before_anything_runs()
    {
        var m = new TemporaryAddressManager();
        if (!m.Capability.Available)
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => m.AddAsync(Adapter("x"), IPAddress.Parse("10.0.0.2"), 24, CancellationToken.None));
            return;
        }

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => m.AddAsync(Adapter("x"), IPAddress.Parse("10.0.0.2"), 31, CancellationToken.None));
        Assert.Empty(m.Active);
        Assert.Empty(await m.RemoveAllAsync(CancellationToken.None));
    }
}
