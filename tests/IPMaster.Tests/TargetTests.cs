using IPMaster.Core.Configuration;
using IPMaster.Core.Targets;

namespace IPMaster.Tests;

public class TargetParserTests
{
    [Theory]
    [InlineData("10.0.0.5", TargetKind.SingleAddress, "10.0.0.5", "10.0.0.5")]
    [InlineData("10.0.0.1-10.0.0.255", TargetKind.Range, "10.0.0.1", "10.0.0.255")]
    [InlineData("10.0.0.1 - 10.0.0.255", TargetKind.Range, "10.0.0.1", "10.0.0.255")]
    [InlineData("10.0.0.1–10.0.0.9", TargetKind.Range, "10.0.0.1", "10.0.0.9")]
    [InlineData("10.0.0.1/24", TargetKind.Cidr, "10.0.0.0", "10.0.0.255")]
    [InlineData("192.168.1.77/255.255.255.0", TargetKind.Cidr, "192.168.1.0", "192.168.1.255")]
    [InlineData("10.0.0.6/31", TargetKind.Cidr, "10.0.0.6", "10.0.0.7")]
    [InlineData("10.0.0.6/32", TargetKind.Cidr, "10.0.0.6", "10.0.0.6")]
    [InlineData("2001:db8::1", TargetKind.SingleAddress, "2001:db8::1", "2001:db8::1")]
    [InlineData("2001:db8::1-2001:db8::ffff", TargetKind.Range, "2001:db8::1", "2001:db8::ffff")]
    [InlineData("2001:db8::/120", TargetKind.Cidr, "2001:db8::", "2001:db8::ff")]
    [InlineData("2001:db8::5/128", TargetKind.Cidr, "2001:db8::5", "2001:db8::5")]
    [InlineData("[2001:db8::7]", TargetKind.SingleAddress, "2001:db8::7", "2001:db8::7")]
    public void Parses_documented_formats(string text, TargetKind kind, string start, string end)
    {
        Assert.True(TargetParser.TryParse(text, out var spec, out var error), error);
        Assert.Equal(kind, spec.Kind);
        Assert.Equal(start, spec.Start.ToString());
        Assert.Equal(end, spec.End.ToString());
    }

    [Theory]
    [InlineData("google.com")]
    [InlineData("my-host")]
    [InlineData("server01.corp.example")]
    public void Parses_host_names(string text)
    {
        Assert.True(TargetParser.TryParse(text, out var spec, out _));
        Assert.Equal(TargetKind.HostName, spec.Kind);
        Assert.Equal(text, spec.HostName);
    }

    [Theory]
    [InlineData("10.1")]               // IPAddress.TryParse would accept this as 10.0.0.1
    [InlineData("10.0.0.256")]
    [InlineData("10.0.0.1-10.0.0.0")]  // reversed
    [InlineData("10.0.0.1/33")]
    [InlineData("10.0.0.1/255.0.255.0")] // non-contiguous mask
    [InlineData("10.0.0.1-2001:db8::1")]
    [InlineData("-bad-.example")]
    [InlineData("1.2.3")]
    [InlineData("")]
    public void Rejects_malformed_input(string text)
    {
        Assert.False(TargetParser.TryParse(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Ipv6_scope_id_preserved()
    {
        Assert.True(TargetParser.TryParse("fe80::1%12", out var spec, out _));
        Assert.Equal(12, spec.Start.ScopeId);
        Assert.Equal("fe80::1%12", spec.Start.ToIPAddress().ToString());

        Assert.True(TargetParser.TryParse("fe80::1%7-fe80::5", out var range, out _));
        Assert.Equal(7, range.End.ScopeId);
        Assert.False(TargetParser.TryParse("fe80::1%7-fe80::5%8", out _, out _));
    }

    [Fact]
    public void Import_accepts_documented_lines_and_reports_rejects()
    {
        var text = """
            10.0.0.1
            10.0.0.1-10.0.0.255
            10.0.0.1/24
            2001:db8::1
            2001:db8::1-2001:db8::ffff
            2001:db8::/120
            google.com
            # comment
            not an address!
            10.0.0.300
            """;
        var r = TargetParser.ParseList(text);
        Assert.Equal(7, r.Targets.Count);
        Assert.Equal(2, r.Rejected.Count);
        Assert.Equal(9, r.Rejected[0].LineNumber);
        Assert.Equal(10, r.Rejected[1].LineNumber);
    }

    [Fact]
    public void Import_rejects_overlong_line()
    {
        var r = TargetParser.ParseList(new string('a', 5000));
        Assert.Empty(r.Targets);
        Assert.Single(r.Rejected);
    }

    [Fact]
    public void Disabled_ranges_are_skipped_and_comments_label_errors()
    {
        var (specs, errors) = AppSettings.ParseRanges([
            new RangeEntry { Target = "10.1.0.0/24", Comment = "London" },
            new RangeEntry { Target = "10.2.0.0/24", Enabled = false, Comment = "Berlin" },
            new RangeEntry { Target = "10.3.0.0/33", Comment = "Sydney" },
        ]);
        Assert.Single(specs);
        Assert.Equal("10.1.0.0", specs[0].Start.ToString());
        Assert.Single(errors);
        Assert.StartsWith("Sydney:", errors[0], StringComparison.Ordinal);
    }
}

public class OctetRangeTests
{
    [Fact]
    public void Manual_example_generates_exactly_45_addresses()
    {
        Assert.True(TargetParser.TryParse("10.1.254.1-10.9.254.5", octetMode: true, out var spec, out var e), e);
        var built = TargetPlanBuilder.BuildAsync([spec], new PlanOptions { Confirmed = true }, null).Result.Plan;
        var list = built.Addresses();
        Assert.Equal(45, list.Count);
        Assert.Equal(45UL, built.CountExact());
        Assert.Equal("10.1.254.1", list[0]);
        Assert.Equal("10.1.254.5", list[4]);
        Assert.Equal("10.2.254.1", list[5]);
        Assert.Equal("10.9.254.5", list[^1]);
        Assert.All(list, a => Assert.EndsWith(".254." + a.Split('.')[3], a, StringComparison.Ordinal));
    }

    [Fact]
    public void Vlan_scenario_counts_256_subnets_times_5()
    {
        Assert.True(TargetParser.TryParse("10.0.0.1-10.0.255.5", true, out var spec, out _));
        Assert.Equal((UInt128)(256 * 5), spec.RawCount);
    }

    [Fact]
    public void Octet_mode_rejects_decreasing_octets()
    {
        Assert.False(TargetParser.TryParse("10.0.5.1-10.1.2.9", true, out _, out var error));
        Assert.Contains("octet", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Octet_mode_rejects_ipv6()
    {
        Assert.False(TargetParser.TryParse("2001:db8::1-2001:db8::5", true, out _, out _));
    }
}

public class TargetPlanTests
{
    [Fact]
    public void Network_and_broadcast_skipped_for_cidr_by_default()
    {
        var plan = TestPlans.Plan("192.168.1.0/24");
        var list = plan.Addresses();
        Assert.Equal(254, list.Count);
        Assert.Equal("192.168.1.1", list[0]);
        Assert.Equal("192.168.1.254", list[^1]);
    }

    [Fact]
    public void Network_and_broadcast_included_when_enabled()
    {
        var plan = TestPlans.Plan(new PlanOptions { PingNetworkAndBroadcast = true }, "192.168.1.0/24");
        Assert.Equal(256UL, plan.CountExact());
    }

    [Fact]
    public void Network_and_broadcast_of_local_subnet_skipped_in_plain_range()
    {
        var local = new LocalSubnet(AddressKey.From(System.Net.IPAddress.Parse("10.0.1.10")), 24);
        var plan = TestPlans.Plan(new PlanOptions { LocalSubnets = [local] }, "10.0.0.250-10.0.2.5");
        var list = plan.Addresses();
        Assert.DoesNotContain("10.0.1.0", list);
        Assert.DoesNotContain("10.0.1.255", list);
        Assert.Contains("10.0.0.255", list); // not a network/broadcast of a known subnet
        Assert.Equal(12 - 2 + 256, list.Count);
    }

    [Fact]
    public void Slash31_and_slash32_keep_all_addresses()
    {
        Assert.Equal(["10.0.0.6", "10.0.0.7"], TestPlans.Plan("10.0.0.6/31").Addresses());
        Assert.Equal(["10.0.0.6"], TestPlans.Plan("10.0.0.6/32").Addresses());
        Assert.Equal(["2001:db8::5"], TestPlans.Plan("2001:db8::5/128").Addresses());
    }

    [Fact]
    public void Explicit_single_address_is_never_excluded_as_network_address()
    {
        var plan = TestPlans.Plan("192.168.1.0/24", "192.168.1.0");
        // the single entry is listed explicitly, but the CIDR source comes first and excludes it;
        // the explicit list must still produce it.
        Assert.Contains("192.168.1.0", plan.Addresses());
    }

    [Fact]
    public void Overlapping_ranges_deduplicated()
    {
        var plan = TestPlans.Plan("10.0.0.1-10.0.0.10", "10.0.0.5-10.0.0.20", "10.0.0.7", "10.0.0.15-10.0.0.25", "10.0.0.3-10.0.0.4");
        var list = plan.Addresses();
        Assert.Equal(list.Distinct().Count(), list.Count);
        Assert.Equal(25, list.Count);
    }

    [Fact]
    public void Octet_and_sequential_overlap_deduplicated()
    {
        Assert.True(TargetParser.TryParse("10.0.0.1-10.0.3.2", true, out var octet, out _));
        Assert.True(TargetParser.TryParse("10.0.0.0/24", out var cidr, out _));
        var plan = TargetPlanBuilder.BuildAsync([cidr, octet], new PlanOptions { Confirmed = true }, null).Result.Plan;
        var list = plan.Addresses();
        Assert.Equal(list.Distinct().Count(), list.Count);
        // cidr: 254 (.1-.254) + octet: 4*2=8 minus 10.0.0.1,10.0.0.2 already in cidr = 6
        Assert.Equal(260, list.Count);
    }

    [Fact]
    public void Ipv6_large_range_is_lazy()
    {
        // 2^24 addresses; enumerating the first few must not allocate the set.
        var plan = TestPlans.Plan(new PlanOptions { Limits = new PlanLimits { MaxTargets = 1UL << 24 } }, "2001:db8::/104");
        Assert.Equal(1UL << 24, plan.RawCount);
        var before = GC.GetAllocatedBytesForCurrentThread();
        var first = plan.Enumerate().Take(1000).Count();
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.Equal(1000, first);
        Assert.True(allocated < 1_000_000, $"allocated {allocated} bytes");
    }

    [Fact]
    public void Random_order_is_permutation()
    {
        var plan = TestPlans.Plan("10.0.0.0/22", "10.9.9.9", "2001:db8::/120");
        var seq = plan.Enumerate().ToList();
        var rnd = plan.Enumerate(randomOrder: true, seed: 42).ToList();
        Assert.Equal(seq.Count, rnd.Count);
        Assert.Equal(seq.OrderBy(a => a), rnd.OrderBy(a => a));
        Assert.NotEqual(seq, rnd);
        Assert.Equal(rnd, plan.Enumerate(true, 42).ToList()); // deterministic for a seed
    }

    [Theory]
    [InlineData(1UL)]
    [InlineData(2UL)]
    [InlineData(3UL)]
    [InlineData(1000UL)]
    [InlineData(65_537UL)]
    public void Index_permutation_is_bijective(ulong n)
    {
        var p = new IndexPermutation(n, 7);
        var seen = new bool[n];
        for (ulong i = 0; i < n; i++)
        {
            var m = p.Map(i);
            Assert.False(seen[m]);
            seen[m] = true;
        }
    }
}

public class TargetPlanBuilderTests
{
    private static TargetSpec S(string t)
    {
        Assert.True(TargetParser.TryParse(t, out var s, out var e), e);
        return s;
    }

    [Fact]
    public async Task Huge_ipv6_range_rejected_before_enumeration()
    {
        var r = await TargetPlanBuilder.BuildAsync([S("2001:db8::/64")], new PlanOptions(), null);
        Assert.Equal(PlanStatus.TooLarge, r.Status);
        Assert.False(r.CanStart);
        Assert.Equal(UInt128.One << 64, r.RawCount);
    }

    [Fact]
    public async Task Large_range_needs_confirmation_then_runs()
    {
        var r = await TargetPlanBuilder.BuildAsync([S("10.0.0.0/15")], new PlanOptions(), null);
        Assert.Equal(PlanStatus.NeedsConfirmation, r.Status);
        r = await TargetPlanBuilder.BuildAsync([S("10.0.0.0/15")], new PlanOptions { Confirmed = true }, null);
        Assert.Equal(PlanStatus.Ready, r.Status);
    }

    [Fact]
    public async Task Unresolved_host_names_reported_not_dropped_silently()
    {
        var r = await TargetPlanBuilder.BuildAsync([S("good.example"), S("bad.example"), S("10.0.0.1")], new PlanOptions(),
            (h, _) => Task.FromResult(h == "good.example" ? System.Net.IPAddress.Parse("10.0.0.9") : null));
        Assert.Equal(PlanStatus.Ready, r.Status);
        Assert.Single(r.Errors);
        Assert.Contains("bad.example", r.Errors[0], StringComparison.Ordinal);
        Assert.Equal(["10.0.0.9", "10.0.0.1"], r.Plan.Addresses());
    }

    [Fact]
    public async Task Empty_input_is_reported()
    {
        var r = await TargetPlanBuilder.BuildAsync([], new PlanOptions(), null);
        Assert.Equal(PlanStatus.Empty, r.Status);
    }

    [Fact]
    public async Task Ignore_list_applies()
    {
        var r = await TargetPlanBuilder.BuildAsync([S("10.0.0.0/24")], new PlanOptions { Ignore = new IgnoreList(["10.0.0.1?", "10.0.0.200-10.0.0.254"]) }, null);
        var list = r.Plan.Addresses();
        Assert.DoesNotContain("10.0.0.10", list);
        Assert.DoesNotContain("10.0.0.19", list);
        Assert.Contains("10.0.0.1", list);
        Assert.Contains("10.0.0.100", list);
        Assert.Equal(254 - 10 - 55, list.Count);
    }
}

public class IgnoreListTests
{
    private static bool Ignored(IgnoreList l, string ip) => l.IsIgnored(AddressKey.From(System.Net.IPAddress.Parse(ip)));

    [Fact]
    public void Wildcard_last_octet()
    {
        var l = new IgnoreList(["10.0.0.*"]);
        Assert.True(Ignored(l, "10.0.0.0"));
        Assert.True(Ignored(l, "10.0.0.255"));
        Assert.False(Ignored(l, "10.0.1.1"));
    }

    [Fact]
    public void Question_mark_matches_single_digit()
    {
        var l = new IgnoreList(["192.168.1.?"]);
        Assert.True(Ignored(l, "192.168.1.7"));
        Assert.False(Ignored(l, "192.168.1.17"));
    }

    [Fact]
    public void Partial_octet_wildcards()
    {
        var l = new IgnoreList(["10.*.1*.1"]);
        Assert.True(Ignored(l, "10.200.15.1"));
        Assert.True(Ignored(l, "10.0.1.1"));
        Assert.False(Ignored(l, "10.0.21.1"));
    }

    [Fact]
    public void Exact_range_and_cidr_lines()
    {
        var l = new IgnoreList(["10.0.0.5", "10.0.1.0/30", "10.0.2.1-10.0.2.3", "2001:db8::*"]);
        Assert.True(Ignored(l, "10.0.0.5"));
        Assert.True(Ignored(l, "10.0.1.3"));
        Assert.False(Ignored(l, "10.0.1.4"));
        Assert.True(Ignored(l, "10.0.2.2"));
        Assert.True(Ignored(l, "2001:db8::abcd"));
        Assert.False(Ignored(l, "2001:db9::1"));
    }

    [Fact]
    public void Invalid_lines_reported()
    {
        var l = new IgnoreList(["10.0.*", "host.example", "nonsense!", ""]);
        Assert.Equal(3, l.Rejected.Count);
    }
}

public class CidrConverterTests
{
    [Theory]
    [InlineData("192.168.1.0/24", "192.168.1.0-192.168.1.255")]
    [InlineData("192.168.1.0-192.168.1.255", "192.168.1.0/24")]
    [InlineData("10.0.0.1-10.0.0.6", "10.0.0.1/32, 10.0.0.2/31, 10.0.0.4/31, 10.0.0.6/32")]
    [InlineData("10.0.0.5", "10.0.0.5/32")]
    [InlineData("0.0.0.0-255.255.255.255", "0.0.0.0/0")]
    [InlineData("2001:db8::-2001:db8::ff", "2001:db8::/120")]
    public void Converts(string input, string expected)
    {
        Assert.True(CidrConverter.TryConvert(input, out var converted, out var error), error);
        Assert.Equal(expected, converted);
    }

    [Fact]
    public void Host_name_cannot_be_converted()
    {
        Assert.False(CidrConverter.TryConvert("example.com", out _, out _));
    }
}
