using System.Numerics;
using IPMaster.Core.Targets;
using IPMaster.Core.Tools;

namespace IPMaster.Tests;

public class IpCalculatorTests
{
    private static IpCalcResult Calc(string input)
    {
        Assert.True(IpCalculator.TryParseInput(input, null, out var a, out var p, out var error), error);
        Assert.NotNull(p);
        return IpCalculator.Calculate(a, p.Value);
    }

    private static string Field(IpCalcResult r, string label) => r.Primary.Concat(r.Advanced).Single(f => f.Label == label).Display;

    private static string Copy(IpCalcResult r, string label) => r.Primary.Concat(r.Advanced).Single(f => f.Label == label).Copy;

    // ---------------------------------------------------------------- reference cases

    [Fact]
    public void Reference_192_168_10_25_slash24()
    {
        var r = Calc("192.168.10.25/24");
        Assert.Equal("192.168.10.0", Field(r, "Network Address"));
        Assert.Equal("192.168.10.255", Field(r, "Broadcast Address"));
        Assert.Equal("192.168.10.1", Field(r, "First Usable Address"));
        Assert.Equal("192.168.10.254", Field(r, "Last Usable Address"));
        Assert.Equal("256", Copy(r, "Total Addresses"));
        Assert.Equal("254", Copy(r, "Usable Addresses"));
        Assert.Equal("255.255.255.0", Field(r, "Subnet Mask"));
        Assert.Equal("0.0.0.255", Field(r, "Wildcard Mask"));
        Assert.Equal("Private-Use", r.Classification.Name);
        Assert.True(r.Normalized);
    }

    [Fact]
    public void Reference_10_20_30_40_slash22()
    {
        var r = Calc("10.20.30.40/22");
        Assert.Equal("10.20.28.0", Field(r, "Network Address"));
        Assert.Equal("10.20.31.255", Field(r, "Broadcast Address"));
        Assert.Equal("1,024", Field(r, "Total Addresses"));
        Assert.Equal("1022", Copy(r, "Usable Addresses"));
        Assert.Equal("255.255.252.0", Field(r, "Subnet Mask"));
        Assert.Equal("0.0.3.255", Field(r, "Wildcard Mask"));
    }

    [Fact]
    public void Reference_192_0_2_10_slash31_is_point_to_point()
    {
        var r = Calc("192.0.2.10/31");
        Assert.Equal("192.0.2.10", Field(r, "First Usable Address"));
        Assert.Equal("192.0.2.11", Field(r, "Last Usable Address"));
        Assert.Null(r.Broadcast);
        Assert.StartsWith("None", Field(r, "Broadcast Address"));
        Assert.Equal("2", Copy(r, "Usable Addresses"));
        Assert.Contains(r.Notes, n => n.Contains("RFC 3021", StringComparison.Ordinal));
        Assert.StartsWith("Documentation", r.Classification.Name);
    }

    [Fact]
    public void Reference_2001_db8_1234__25_slash64()
    {
        var r = Calc("2001:db8:1234::25/64");
        Assert.Equal("2001:db8:1234::/64", Field(r, "Network Prefix"));
        Assert.Equal(BigInteger.One << 64, r.Total);
        Assert.Equal("18446744073709551616", Copy(r, "Total Addresses"));
        Assert.StartsWith("2^64", Field(r, "Total Addresses"));
        Assert.Null(r.Broadcast);
        Assert.DoesNotContain(r.Primary, f => f.Label.Contains("Broadcast", StringComparison.Ordinal) || f.Label.Contains("Usable", StringComparison.Ordinal));
        Assert.Equal("2001:db8:1234::", Field(r, "First Address"));
        Assert.Equal("2001:db8:1234:0:ffff:ffff:ffff:ffff", Field(r, "Last Address"));
        Assert.Equal("2001:0db8:1234:0000:0000:0000:0000:0025", Field(r, "Expanded Address"));
        Assert.Equal("5.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.3.2.1.8.b.d.0.1.0.0.2.ip6.arpa", Field(r, "Reverse DNS Name"));
        Assert.Equal("Documentation", r.Classification.Name);
        Assert.Contains(r.Notes, n => n.Contains("no broadcast", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------- IPv4 prefixes

    [Fact]
    public void IPv4_slash0_is_exact_without_overflow()
    {
        var r = Calc("192.168.10.25/0");
        Assert.Equal("0.0.0.0", Field(r, "Network Address"));
        Assert.Equal("255.255.255.255", Field(r, "Broadcast Address"));
        Assert.Equal("4294967296", Copy(r, "Total Addresses"));
        Assert.Equal("4294967294", Copy(r, "Usable Addresses"));
        Assert.Equal("0.0.0.0", Field(r, "Subnet Mask"));
        Assert.Equal("255.255.255.255", Field(r, "Wildcard Mask"));
    }

    [Fact]
    public void IPv4_slash30_has_two_usable()
    {
        var r = Calc("10.0.0.5/30");
        Assert.Equal("10.0.0.4", Field(r, "Network Address"));
        Assert.Equal("10.0.0.7", Field(r, "Broadcast Address"));
        Assert.Equal("10.0.0.5", Field(r, "First Usable Address"));
        Assert.Equal("10.0.0.6", Field(r, "Last Usable Address"));
        Assert.Equal("2", Copy(r, "Usable Addresses"));
    }

    [Fact]
    public void IPv4_slash32_is_single_host_route()
    {
        var r = Calc("203.0.113.7/32");
        Assert.Equal("203.0.113.7", Field(r, "First Usable Address"));
        Assert.Equal("203.0.113.7", Field(r, "Last Usable Address"));
        Assert.Equal("1", Copy(r, "Total Addresses"));
        Assert.Equal("1", Copy(r, "Usable Addresses"));
        Assert.Null(r.Broadcast);
        Assert.False(r.Normalized);
    }

    [Theory]
    [InlineData("192.168.10.25 255.255.255.0", 24)]
    [InlineData("192.168.10.25/255.255.252.0", 22)]
    [InlineData("192.168.10.25/24 255.255.255.0", 24)]
    [InlineData("10.0.0.1/0.0.0.0", 0)]
    public void Mask_and_prefix_forms_agree(string input, int prefix)
    {
        Assert.True(IpCalculator.TryParseInput(input, IpFamily.IPv4, out _, out var p, out var error), error);
        Assert.Equal(prefix, p);
    }

    [Fact]
    public void Contradictory_prefix_and_mask_are_rejected()
    {
        Assert.False(IpCalculator.TryParseInput("10.0.0.1/24 255.255.0.0", IpFamily.IPv4, out _, out _, out var error));
        Assert.Contains("disagree", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("255.255.0.255", "contiguous")]
    [InlineData("255.0.255.0", "contiguous")]
    [InlineData("0.0.0.255", "wildcard")]
    public void Noncontiguous_masks_are_rejected_with_reason(string mask, string reason)
    {
        Assert.False(IpCalculator.TryParseMask(mask, out _, out var error));
        Assert.Contains(reason, error, StringComparison.Ordinal);
        Assert.False(IpCalculator.TryParseInput("10.0.0.1 " + mask, IpFamily.IPv4, out _, out _, out _));
    }

    [Theory]
    [InlineData("256.1.1.1")]
    [InlineData("10.1")]
    [InlineData("10.0.0.01")]
    [InlineData("1.2.3.4.5")]
    [InlineData("a.b.c.d")]
    [InlineData("2001:db8::1::2")]
    [InlineData("2001:db8:0:0:0:0:0:0:1")]
    [InlineData("gggg::1")]
    [InlineData("10.0.0.1%3")]
    [InlineData("")]
    public void Invalid_addresses_are_rejected(string text)
    {
        Assert.False(IpCalculator.TryParseAddress(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Theory]
    [InlineData("10.0.0.1/33")]
    [InlineData("10.0.0.1/-1")]
    [InlineData("10.0.0.1/")]
    [InlineData("10.0.0.1/x")]
    [InlineData("2001:db8::1/129")]
    [InlineData("2001:db8::1/255.255.0.0")]
    [InlineData("2001:db8::1 ffff::")]
    public void Invalid_prefixes_are_rejected(string text)
    {
        Assert.False(IpCalculator.TryParseInput(text, null, out _, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Family_selector_mismatch_is_reported_not_switched()
    {
        Assert.False(IpCalculator.TryParseInput("2001:db8::1/64", IpFamily.IPv4, out _, out _, out var e1));
        Assert.Contains("IPv6 address, but IPv4 is selected", e1, StringComparison.Ordinal);
        Assert.False(IpCalculator.TryParseInput("10.0.0.1/8", IpFamily.IPv6, out _, out _, out var e2));
        Assert.Contains("::ffff:10.0.0.1", e2, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- IPv6

    [Fact]
    public void IPv6_slash0_counts_2_pow_128()
    {
        var r = Calc("2001:db8::1/0");
        Assert.Equal("::/0", Field(r, "Network Prefix"));
        Assert.Equal("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Field(r, "Last Address"));
        Assert.Equal(BigInteger.Pow(2, 128), r.Total);
        Assert.Equal("340282366920938463463374607431768211456", Copy(r, "Total Addresses"));
    }

    [Fact]
    public void IPv6_slash127_and_slash128()
    {
        var p2p = Calc("2001:db8::1/127");
        Assert.Equal("2001:db8::/127", Field(p2p, "Network Prefix"));
        Assert.Equal("2001:db8::1", Field(p2p, "Last Address"));
        Assert.Equal("2", Copy(p2p, "Total Addresses"));
        Assert.Contains(p2p.Notes, n => n.Contains("RFC 6164", StringComparison.Ordinal));

        var host = Calc("2001:db8::1/128");
        Assert.Equal("2001:db8::1", Field(host, "First Address"));
        Assert.Equal("2001:db8::1", Field(host, "Last Address"));
        Assert.Equal("1", Copy(host, "Total Addresses"));
    }

    [Theory]
    [InlineData("2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1")]
    [InlineData("2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1")] // first of two equal runs is compressed
    [InlineData("2001:db8:0:1:1:1:1:1", "2001:db8:0:1:1:1:1:1")] // a single zero hextet is not compressed
    [InlineData("0:0:0:0:0:0:0:0", "::")]
    [InlineData("::1", "::1")]
    [InlineData("fe80:0:0:0:0:0:0:0", "fe80::")]
    [InlineData("::ffff:192.0.2.1", "::ffff:192.0.2.1")]
    [InlineData("64:ff9b::192.0.2.33", "64:ff9b::c000:221")]
    public void IPv6_compression_follows_RFC5952(string input, string expected)
    {
        Assert.True(IpCalculator.TryParseAddress(input, out var a, out var error), error);
        Assert.Equal(expected, a.ToString());
    }

    [Fact]
    public void Embedded_IPv4_notation_is_parsed_and_reported()
    {
        var mapped = Calc("::ffff:192.0.2.1/128");
        Assert.True(mapped.IsV6); // not folded into IPv4
        Assert.True(mapped.Address.UsedEmbeddedIPv4Notation);
        Assert.Equal("IPv4-mapped Address", mapped.Classification.Name);
        Assert.Equal("192.0.2.1", Field(mapped, "Embedded IPv4 (IPv4-mapped)"));

        var nat64 = Calc("64:ff9b::192.0.2.33/96");
        Assert.Equal("192.0.2.33", Field(nat64, "Embedded IPv4 (NAT64 64:ff9b::/96)"));
        var sixToFour = Calc("2002:c000:0204::1/48");
        Assert.Equal("192.0.2.4", Field(sixToFour, "Embedded IPv4 (6to4)"));
    }

    [Fact]
    public void Zone_id_is_kept_apart_from_arithmetic()
    {
        Assert.True(IpCalculator.TryParseInput("fe80::1%eth0/64", IpFamily.IPv6, out var a, out var p, out var error), error);
        Assert.Equal("eth0", a.Zone);
        var r = IpCalculator.Calculate(a, p!.Value, "fe80::1");
        Assert.Equal("fe80::/64", Field(r, "Network Prefix"));
        Assert.Equal("fe80::1%eth0", Field(r, "Original Address"));
        Assert.Equal("eth0", Field(r, "Zone ID"));
        Assert.Equal("Link-Local Unicast", r.Classification.Name);
    }

    [Fact]
    public void Eui64_interface_identifier_reveals_mac()
    {
        var r = Calc("fe80::21a:2bff:fe3c:4d5e/64");
        Assert.Equal("00-1A-2B-3C-4D-5E", Field(r, "Modified EUI-64 MAC"));
    }

    // ---------------------------------------------------------------- classification

    [Theory]
    [InlineData("100.64.1.1", "Shared Address Space", false)]
    [InlineData("169.254.10.1", "Link-Local", false)]
    [InlineData("127.0.0.1", "Loopback", false)]
    [InlineData("198.19.0.1", "Benchmarking", false)]
    [InlineData("192.0.0.9", "Port Control Protocol Anycast", true)]
    [InlineData("224.0.0.251", "Multicast · Local Network Control Block", false)]
    [InlineData("255.255.255.255", "Limited Broadcast", false)]
    [InlineData("8.8.8.8", "Not special-purpose", null)]
    [InlineData("2001:db8::1", "Documentation", false)]
    [InlineData("fd12:3456::1", "Unique-Local", false)]
    [InlineData("ff02::1", "Multicast · Link-Local", false)]
    [InlineData("2606:4700::1", "Global Unicast", null)]
    [InlineData("::", "Unspecified Address", false)]
    public void Classification_uses_most_specific_registry_entry(string address, string name, bool? global)
    {
        Assert.True(IpCalculator.TryParseAddress(address, out var a, out _));
        var c = IpSpecialRanges.Classify(a.Value, a.IsV6);
        Assert.Equal(name, c.Name);
        Assert.Equal(global, c.GloballyReachable);
    }

    [Fact]
    public void Non_special_address_is_not_called_public()
    {
        var c = IpSpecialRanges.Classify(0x08080808, false);
        Assert.DoesNotContain("public", c.Display, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("does not make it publicly routable", c.Description, StringComparison.Ordinal);
    }

    [Fact]
    public void Wide_network_notes_mixed_contents()
    {
        var r = Calc("192.168.1.1/8");
        Assert.Contains(r.Notes, n => n.Contains("larger than", StringComparison.Ordinal));
    }

    // ---------------------------------------------------------------- normalisation, membership, comparison

    [Fact]
    public void Network_normalisation_is_reported()
    {
        Assert.True(IpCalculator.TryParseNetwork("10.1.2.3/16", null, out var b, out var normalized, out _));
        Assert.True(normalized);
        Assert.Equal("10.1.0.0/16", b.ToString());
        Assert.True(IpCalculator.TryParseNetwork("10.1.0.0/16", null, out _, out var clean, out _));
        Assert.False(clean);
    }

    [Theory]
    [InlineData("10.20.28.0/22", "10.20.31.255", true)]
    [InlineData("10.20.28.0/22", "10.20.32.0", false)]
    [InlineData("10.20.28.0/22", "10.20.27.255", false)]
    [InlineData("0.0.0.0/0", "255.255.255.255", true)]
    [InlineData("2001:db8:1234::/64", "2001:db8:1234:0:ffff:ffff:ffff:ffff", true)]
    [InlineData("2001:db8:1234::/64", "2001:db8:1234:1::", false)]
    [InlineData("::/0", "ffff::1", true)]
    public void Contains_checks_subnet_boundaries(string net, string address, bool expected)
    {
        Assert.True(IpCalculator.TryContains(net, address, out var r, out var error), error);
        Assert.Equal(expected, r.Contains);
    }

    [Fact]
    public void Contains_rejects_mixed_families()
    {
        Assert.False(IpCalculator.TryContains("10.0.0.0/8", "2001:db8::1", out _, out var error));
        Assert.Contains("families", error, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("10.0.0.0/8", "10.0.0.0/8", SubnetRelation.Equal)]
    [InlineData("10.0.0.0/8", "10.1.0.0/16", SubnetRelation.AContainsB)]
    [InlineData("10.1.0.0/16", "10.0.0.0/8", SubnetRelation.BContainsA)]
    [InlineData("10.0.0.0/16", "10.1.0.0/16", SubnetRelation.Disjoint)]
    [InlineData("10.0.0.0-10.0.0.100", "10.0.0.50-10.0.0.200", SubnetRelation.Overlapping)]
    [InlineData("2001:db8::/32", "2001:db8:1::/48", SubnetRelation.AContainsB)]
    [InlineData("::/0", "2001:db8::/32", SubnetRelation.AContainsB)]
    public void Compare_reports_relationship(string a, string b, SubnetRelation relation)
    {
        Assert.True(IpCalculator.TryCompare(a, b, out var r, out var error), error);
        Assert.Equal(relation, r.Relation);
    }

    [Fact]
    public void Compare_notes_adjacent_blocks_that_aggregate()
    {
        Assert.True(IpCalculator.TryCompare("10.0.0.0/25", "10.0.0.128/25", out var r, out _));
        Assert.Contains("aggregate exactly into 10.0.0.0/24", r.Text, StringComparison.Ordinal);
    }

    // ---------------------------------------------------------------- range to CIDR

    [Theory]
    [InlineData("10.0.0.0", "10.0.0.255", "10.0.0.0/24")]
    [InlineData("10.0.0.1", "10.0.0.6", "10.0.0.1/32,10.0.0.2/31,10.0.0.4/31,10.0.0.6/32")]
    [InlineData("0.0.0.0", "255.255.255.255", "0.0.0.0/0")]
    [InlineData("192.168.1.5", "192.168.1.5", "192.168.1.5/32")]
    [InlineData("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "::/0")]
    [InlineData("2001:db8::", "2001:db8::ffff", "2001:db8::/112")]
    public void Range_to_cidr_is_exact_and_minimal(string start, string end, string expected)
    {
        Assert.True(IpCalculator.TryRangeToCidr(start, end, out var blocks, out var total, out var error), error);
        Assert.Equal(expected, string.Join(",", blocks.Select(b => b.ToString())));
        Assert.Equal(blocks.Aggregate(BigInteger.Zero, (s, b) => s + b.Count), total);
    }

    [Fact]
    public void Range_to_cidr_worst_case_is_bounded()
    {
        // 0.0.0.1 – 255.255.255.254 is the classic worst case: 62 blocks
        Assert.True(IpCalculator.TryRangeToCidr("0.0.0.1", "255.255.255.254", out var v4, out _, out _));
        Assert.Equal(62, v4.Count);
        Assert.True(IpCalculator.TryRangeToCidr("::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", out var v6, out var total, out _));
        Assert.Equal(254, v6.Count);
        Assert.Equal(BigInteger.Pow(2, 128) - 2, total);
    }

    [Fact]
    public void Range_to_cidr_validates_order_and_family()
    {
        Assert.False(IpCalculator.TryRangeToCidr("10.0.0.9", "10.0.0.1", out _, out _, out var e1));
        Assert.Contains("after", e1, StringComparison.Ordinal);
        Assert.False(IpCalculator.TryRangeToCidr("10.0.0.1", "2001:db8::1", out _, out _, out var e2));
        Assert.Contains("families", e2, StringComparison.Ordinal);
    }

    [Fact]
    public void Existing_cidr_button_still_converts_full_ipv6_space()
    {
        var blocks = CidrConverter.RangeToCidrs(new AddressKey(UInt128.Zero, true), new AddressKey(UInt128.MaxValue, true));
        Assert.Equal(["::/0"], blocks);
    }

    // ---------------------------------------------------------------- splitting

    [Fact]
    public void Split_ipv4_parent_into_prefix()
    {
        Assert.True(IpCalculator.TryParseNetwork("10.0.0.0/22", null, out var parent, out _, out _));
        var s = new SubnetSplit(parent, 24);
        Assert.Equal(4, s.SubnetCount);
        Assert.Equal(256, s.AddressesPerSubnet);
        Assert.Equal(254, s.UsablePerSubnet);
        var rows = s.Page(0);
        Assert.Equal(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"], rows.Select(r => r.Subnet));
        Assert.Equal("10.0.3.1", rows[3].First);
        Assert.Equal("10.0.3.254", rows[3].Last);
        Assert.Equal("10.0.3.255", rows[3].Broadcast);
        Assert.Equal("First Usable", s.FirstHeader);
    }

    [Fact]
    public void Split_into_slash31_and_slash32_has_no_broadcast()
    {
        Assert.True(IpCalculator.TryParseNetwork("192.0.2.0/30", null, out var parent, out _, out _));
        var p2p = new SubnetSplit(parent, 31);
        Assert.False(p2p.HasBroadcast);
        Assert.Equal(2, p2p.UsablePerSubnet);
        Assert.Equal("192.0.2.2", p2p.Page(0)[1].First);
        Assert.Equal("192.0.2.3", p2p.Page(0)[1].Last);
        var hosts = new SubnetSplit(parent, 32);
        Assert.Equal(1, hosts.UsablePerSubnet);
        Assert.Equal("192.0.2.3/32", hosts.Page(0)[3].Subnet);
    }

    [Fact]
    public void Enormous_split_is_generated_lazily_by_index()
    {
        Assert.True(IpCalculator.TryParseNetwork("::/0", null, out var parent, out _, out _));
        var s = new SubnetSplit(parent, 128);
        Assert.Equal(BigInteger.Pow(2, 128), s.SubnetCount);
        Assert.Equal(BigInteger.Pow(2, 128) / SubnetSplit.PageSize, s.PageCount);
        var last = s.Page(s.PageCount - 1);
        Assert.Equal(SubnetSplit.PageSize, last.Count);
        Assert.Equal("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", last[^1].Subnet);
        Assert.Throws<ArgumentOutOfRangeException>(() => s.At(s.SubnetCount));
        Assert.Equal(3, s.Rows(s.SubnetCount - 3, 1000).Count()); // bounded by the end of the set
    }

    [Fact]
    public void Split_ipv6_slash48_into_slash64()
    {
        Assert.True(IpCalculator.TryParseNetwork("2001:db8:1234::/48", null, out var parent, out _, out _));
        var s = new SubnetSplit(parent, 64);
        Assert.Equal(65536, s.SubnetCount);
        Assert.Equal(256, s.PageCount);
        Assert.Equal("2001:db8:1234:ffff::/64", s.Page(255)[^1].Subnet);
        Assert.Equal("First Address", s.FirstHeader);
        Assert.Equal("18446744073709551616", s.Page(0)[0].Count);
    }

    [Fact]
    public void Split_rejects_less_specific_prefix()
    {
        Assert.True(IpCalculator.TryParseNetwork("10.0.0.0/16", null, out var parent, out _, out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SubnetSplit(parent, 15));
        Assert.Throws<ArgumentOutOfRangeException>(() => new SubnetSplit(parent, 33));
    }

    [Theory]
    [InlineData(1, false, 32)]
    [InlineData(2, false, 30)]
    [InlineData(2, true, 31)]
    [InlineData(3, false, 29)]
    [InlineData(254, false, 24)]
    [InlineData(255, false, 23)]
    [InlineData(1000, false, 22)]
    public void Host_count_planning_picks_smallest_prefix(int hosts, bool p2p, int expected)
    {
        Assert.True(IpCalculator.TryPrefixForHosts(hosts, p2p, out var prefix, out var note));
        Assert.Equal(expected, prefix);
        if (hosts == 2) Assert.Contains(p2p ? "Clear the /31 option" : "tick the /31 option", note, StringComparison.Ordinal);
    }

    [Fact]
    public void Host_count_planning_rejects_impossible_counts()
    {
        Assert.False(IpCalculator.TryPrefixForHosts(0, false, out _, out _));
        Assert.False(IpCalculator.TryPrefixForHosts(BigInteger.Pow(2, 32), false, out _, out _));
        Assert.True(IpCalculator.TryPrefixForHosts(4294967294, false, out var p, out _));
        Assert.Equal(0, p);
    }

    // ---------------------------------------------------------------- export

    [Fact]
    public async Task Csv_export_is_bounded_and_labelled()
    {
        Assert.True(IpCalculator.TryParseNetwork("10.0.0.0/16", null, out var parent, out _, out _));
        var s = new SubnetSplit(parent, 24);
        var w = new StringWriter();
        await s.WriteCsvAsync(w, 0, SubnetSplit.PageSize, "complete set", TestContext.Current.CancellationToken);
        var lines = w.ToString().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.StartsWith("# IPMaster subnet export: complete set", IPMaster.Core.Results.FriendlyNameMap.ParseCsv(lines[0])[0][0], StringComparison.Ordinal);
        Assert.Equal("Index,Subnet,First Usable,Last Usable,Broadcast Address,Address Count", lines[1]);
        Assert.Equal(2 + 256, lines.Length);
        Assert.Equal("256,10.0.255.0/24,10.0.255.1,10.0.255.254,10.0.255.255,256", lines[^1]);
    }

    [Fact]
    public async Task Json_export_keeps_exact_ipv6_counts()
    {
        Assert.True(IpCalculator.TryParseNetwork("::/0", null, out var parent, out _, out _));
        var s = new SubnetSplit(parent, 1);
        using var ms = new MemoryStream();
        await s.WriteJsonAsync(ms, 0, 2, "complete set", complete: true, TestContext.Current.CancellationToken);
        using var doc = System.Text.Json.JsonDocument.Parse(ms.ToArray());
        Assert.Equal("complete", doc.RootElement.GetProperty("scope").GetString());
        Assert.Equal("170141183460469231731687303715884105728", doc.RootElement.GetProperty("addressesPerSubnet").GetString());
        Assert.Equal("8000::/1", doc.RootElement.GetProperty("subnets")[1].GetProperty("subnet").GetString());
    }

    [Fact]
    public async Task Export_honours_cancellation()
    {
        Assert.True(IpCalculator.TryParseNetwork("10.0.0.0/8", null, out var parent, out _, out _));
        var s = new SubnetSplit(parent, 32);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.WriteCsvAsync(new StringWriter(), 0, SubnetSplit.MaxExportRows, "complete", cts.Token));
    }

    [Fact]
    public void Summary_contains_primary_values_and_source()
    {
        var text = Calc("192.168.10.25/24").Summary();
        Assert.Contains("Network Address: 192.168.10.0", text, StringComparison.Ordinal);
        Assert.Contains("IANA", text, StringComparison.Ordinal);
    }
}
