using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using IPMaster.Core.Scanning;
using IPMaster.Core.Wifi;
using IPMaster.Infrastructure.Wifi;

namespace IPMaster.Tests;

/// <summary>Synthetic Wi-Fi fixtures (D-097): no test needs a wireless adapter or network.</summary>
internal static class WifiFixtures
{
    public static readonly Guid Adapter = Guid.Parse("11111111-2222-3333-4444-555555555555");

    public static byte[] Ie(int id, params byte[] body) => [(byte)id, (byte)body.Length, .. body];

    public static byte[] HtOperation(int primary, int offset) => Ie(61, (byte)primary, (byte)((offset == 1 ? 1 : offset == -1 ? 3 : 0) | (offset != 0 ? 0x04 : 0)), 0, 0, 0, 0);

    public static byte[] VhtOperation(int width, int ccfs0, int ccfs1 = 0) => Ie(192, (byte)width, (byte)ccfs0, (byte)ccfs1, 0, 0);

    public static byte[] BssLoad(int stations, int utilization255) => Ie(11, (byte)stations, 0, (byte)utilization255, 0, 0);

    public static byte[] Rsn(params int[] akms)
    {
        var b = new List<byte> { 1, 0, 0x00, 0x0F, 0xAC, 4, 1, 0, 0x00, 0x0F, 0xAC, 4, (byte)akms.Length, 0 };
        foreach (var a in akms) b.AddRange([0x00, 0x0F, 0xAC, (byte)a]);
        b.AddRange([0, 0]);
        return Ie(48, [.. b]);
    }

    public static PhysicalAddress Mac(string s) => PhysicalAddress.Parse(s.Replace(':', '-'));

    public static WifiBss Bss(string ssid, string mac, int rssi, int mhz, params byte[][] ies) =>
        new(Adapter, ssid, Mac(mac), rssi, 80, mhz, 0x0011, 7, InformationElements.Parse([.. ies.SelectMany(x => x)]), DateTimeOffset.UtcNow);

    public static WifiConnection Connection(string ssid, string mac, int rssi = -50, int mhz = 5180) =>
        new(Adapter, ssid, ssid, Mac(mac), 90, rssi, mhz, null, 8, 866_000, 866_000, "WPA2-Personal", "CCMP (AES)");
}

internal sealed class FakeWifi : IWifiProvider
{
    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("fake");

    public Func<Observation<WifiConnection>> Connection { get; set; } = () => Observation<WifiConnection>.Of(ObservationState.Empty, DateTimeOffset.UtcNow, "Not connected.");

    public IPAddress Gateway { get; set; } = IPAddress.Parse("192.0.2.1");

    public int ConnectionCalls;

    public Task<Observation<IReadOnlyList<WifiAdapter>>> AdaptersAsync(CancellationToken ct) =>
        Task.FromResult(Observation<IReadOnlyList<WifiAdapter>>.Ok([new WifiAdapter(WifiFixtures.Adapter, "fake", "connected", Gateway, [])], DateTimeOffset.UtcNow));

    public Task<Observation<IReadOnlyList<WifiBss>>> ScanAsync(Guid adapter, bool fresh, CancellationToken ct) =>
        Task.FromResult(Observation<IReadOnlyList<WifiBss>>.Of(ObservationState.Empty, DateTimeOffset.UtcNow));

    public Task<Observation<WifiConnection>> ConnectionAsync(Guid adapter, CancellationToken ct)
    {
        Interlocked.Increment(ref ConnectionCalls);
        return Task.FromResult(Connection());
    }
}

public class WifiChannelTests
{
    [Theory]
    [InlineData(2412, 1, WifiBand.Band24)]
    [InlineData(2437, 6, WifiBand.Band24)]
    [InlineData(2472, 13, WifiBand.Band24)]
    [InlineData(2484, 14, WifiBand.Band24)]
    [InlineData(5180, 36, WifiBand.Band5)]
    [InlineData(5500, 100, WifiBand.Band5)]
    [InlineData(5825, 165, WifiBand.Band5)]
    [InlineData(5935, 2, WifiBand.Band6)]
    [InlineData(5955, 1, WifiBand.Band6)]
    [InlineData(6135, 37, WifiBand.Band6)]
    [InlineData(7115, 233, WifiBand.Band6)]
    public void Frequency_and_channel_convert_both_ways(int mhz, int channel, WifiBand band)
    {
        Assert.Equal(channel, WifiChannels.ChannelOf(mhz));
        Assert.Equal(band, WifiChannels.BandOf(mhz));
        Assert.Equal(mhz, WifiChannels.FrequencyOf(band, channel));
    }

    [Theory]
    [InlineData(2413)]
    [InlineData(4000)]
    [InlineData(5000)]
    public void Unknown_frequencies_have_no_channel(int mhz) => Assert.Null(WifiChannels.ChannelOf(mhz));

    [Theory]
    [InlineData(WifiBand.Band5, 36, 80, 42)]
    [InlineData(WifiBand.Band5, 48, 80, 42)]
    [InlineData(WifiBand.Band5, 100, 160, 114)]
    [InlineData(WifiBand.Band5, 157, 80, 155)]
    [InlineData(WifiBand.Band5, 44, 40, 46)]
    [InlineData(WifiBand.Band6, 37, 80, 39)]
    [InlineData(WifiBand.Band6, 1, 160, 15)]
    [InlineData(WifiBand.Band6, 1, 320, 31)]
    public void Bonded_blocks_use_the_standard_alignment(WifiBand band, int primary, int width, int center) =>
        Assert.Equal(center, WifiChannels.AlignedCenter(band, primary, width));

    [Fact]
    public void Channels_1_6_11_do_not_overlap_but_neighbours_do()
    {
        var one = WifiChannels.Span(WifiBand.Band24, 1, 20);
        Assert.Equal(0, WifiChannels.Overlap(one, WifiChannels.Span(WifiBand.Band24, 6, 20)));
        Assert.True(WifiChannels.Overlap(one, WifiChannels.Span(WifiBand.Band24, 3, 20)) > 0.5);
        Assert.Equal(1, WifiChannels.Overlap(one, one));
        var forty = WifiChannels.Span(WifiBand.Band24, 1, 40, secondaryOffset: 1); // 1 + 5
        Assert.True(WifiChannels.Overlap(forty, WifiChannels.Span(WifiBand.Band24, 6, 20)) > 0.5);
    }

    [Fact]
    public void Dfs_psc_and_regulatory_domains()
    {
        Assert.True(WifiChannels.IsDfs(WifiBand.Band5, 100));
        Assert.False(WifiChannels.IsDfs(WifiBand.Band5, 36));
        Assert.True(WifiChannels.IsPsc(37));
        Assert.False(WifiChannels.IsPsc(33));
        var etsi = RegulatoryDomain.For("de");
        Assert.True(etsi.Known);
        Assert.Contains(13, etsi.Channels24);
        Assert.DoesNotContain(144, etsi.Channels5);
        var fcc = RegulatoryDomain.For("US");
        Assert.DoesNotContain(13, fcc.Channels24);
        Assert.Contains(149, fcc.Channels5);
        var unknown = RegulatoryDomain.For(null);
        Assert.False(unknown.Known);
        Assert.DoesNotContain(149, unknown.Channels5); // conservative subset
    }
}

public class WifiElementTests
{
    [Fact]
    public void Parses_generation_width_security_and_roaming_capabilities()
    {
        var ies = InformationElements.Parse([
            .. WifiFixtures.Ie(7, (byte)'T', (byte)'R', (byte)' '),
            .. WifiFixtures.BssLoad(12, 128),
            .. WifiFixtures.Ie(45, new byte[26]),
            .. WifiFixtures.HtOperation(36, 1),
            .. WifiFixtures.Ie(191, new byte[12]),
            .. WifiFixtures.VhtOperation(1, 42),
            .. WifiFixtures.Rsn(2, 8),
            .. WifiFixtures.Ie(54, 1, 2, 3),
            .. WifiFixtures.Ie(70, 0, 0, 0, 0, 0),
            .. WifiFixtures.Ie(127, 0, 0, 0x08),
            .. WifiFixtures.Ie(255, 35, 0, 0, 0),
        ]);
        Assert.False(ies.Malformed);
        Assert.Equal("TR", ies.Country);
        Assert.Equal(12, ies.StationCount);
        Assert.Equal(50.2, ies.ChannelUtilizationPercent!.Value, 1);
        Assert.Equal(80, ies.ChannelWidthMhz);
        Assert.Equal(42, ies.CenterChannel);
        Assert.True(ies.He);
        Assert.True(ies.RadioMeasurement);
        Assert.True(ies.BssTransition);
        Assert.True(ies.FastTransition);
        Assert.Equal("Wi-Fi 6 (802.11ax)", WifiStandards.Describe(10, ies, WifiBand.Band5));
        Assert.Equal("WPA3-Personal / WPA2-Personal", WifiSecurity.Describe(0x11, ies));
    }

    [Fact]
    public void Vht_160_is_recognised_from_ccfs1()
    {
        var ies = InformationElements.Parse(WifiFixtures.VhtOperation(1, 42, 50));
        Assert.Equal(160, ies.ChannelWidthMhz);
        Assert.Equal(50, ies.CenterChannel);
    }

    [Fact]
    public void He_6ghz_operation_information_gives_the_width()
    {
        // parameters with bit 17 (6 GHz info present), BSS colour, basic MCS, then primary, control (80 MHz), ccfs0, ccfs1, min rate
        var ies = InformationElements.Parse(WifiFixtures.Ie(255, 36, 0x00, 0x00, 0x02, 0x01, 0xFF, 0xFF, 37, 0x02, 39, 0, 6));
        Assert.Equal(80, ies.ChannelWidthMhz);
        Assert.Equal(39, ies.CenterChannel);
        Assert.Equal("Wi-Fi 6E (802.11ax)", WifiStandards.Describe(0, ies, WifiBand.Band6));
    }

    [Fact]
    public void No_elements_means_unknown_width_not_20()
    {
        Assert.Null(InformationElements.Parse([]).ChannelWidthMhz);
        Assert.Equal(20, InformationElements.Parse(WifiFixtures.Ie(0, (byte)'x')).ChannelWidthMhz);
    }

    [Theory]
    [InlineData(new byte[] { 45 })] // header cut
    [InlineData(new byte[] { 45, 10, 1, 2 })] // length past the end
    [InlineData(new byte[] { 7, 2, (byte)'D', (byte)'E', 61, 200, 1 })] // a good element, then a broken one
    public void Malformed_elements_stop_parsing_without_throwing(byte[] data)
    {
        var ies = InformationElements.Parse(data);
        Assert.True(ies.Malformed);
        if (data[0] == 7) Assert.Equal("DE", ies.Country);
    }

    [Fact]
    public void Short_bodies_are_ignored_not_guessed()
    {
        var ies = InformationElements.Parse([.. WifiFixtures.Ie(61, 1), .. WifiFixtures.Ie(48, 1, 0), .. WifiFixtures.Ie(11, 1)]);
        Assert.False(ies.Malformed);
        Assert.Empty(ies.AkmSuites);
        Assert.Null(ies.StationCount);
        Assert.Equal(20, ies.ChannelWidthMhz);
    }

    [Fact]
    public void Open_wep_and_wpa1_security()
    {
        Assert.Equal("Open", WifiSecurity.Describe(0x0001, InformationElements.None));
        Assert.Equal("WEP", WifiSecurity.Describe(0x0011, InformationElements.None));
        Assert.Equal("WPA", WifiSecurity.Describe(0x0011, InformationElements.Parse(WifiFixtures.Ie(221, 0x00, 0x50, 0xF2, 1, 1, 0))));
    }
}

public class WindowsWifiLayoutTests
{
    private static byte[] Entry(string ssid, byte[] mac, int rssi, uint khz, byte[] ies)
    {
        var e = new byte[360];
        BinaryPrimitives.WriteInt32LittleEndian(e, ssid.Length);
        Encoding.UTF8.GetBytes(ssid).CopyTo(e, 4);
        mac.CopyTo(e, 40);
        BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(52), 10);
        BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(56), rssi);
        BinaryPrimitives.WriteInt32LittleEndian(e.AsSpan(60), 77);
        BinaryPrimitives.WriteUInt16LittleEndian(e.AsSpan(88), 0x0011);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(92), khz);
        return e;
    }

    [Fact]
    public void Bss_list_entries_and_their_elements_are_read()
    {
        var ies1 = WifiFixtures.HtOperation(6, 0);
        var e1 = Entry("Lab", [2, 0, 0, 0, 0, 1], -55, 2_437_000, ies1);
        var e2 = Entry("", [2, 0, 0, 0, 0, 2], -80, 5_180_000, []);
        var raw = new byte[8 + 720 + ies1.Length];
        BinaryPrimitives.WriteInt32LittleEndian(raw, raw.Length);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(4), 2);
        // first entry's elements follow both entries: offset relative to the entry start
        BinaryPrimitives.WriteUInt32LittleEndian(e1.AsSpan(352), 720);
        BinaryPrimitives.WriteUInt32LittleEndian(e1.AsSpan(356), (uint)ies1.Length);
        e1.CopyTo(raw, 8);
        e2.CopyTo(raw, 368);
        ies1.CopyTo(raw, 728);
        var list = WlanLayout.ParseBssList(raw, WifiFixtures.Adapter, DateTimeOffset.UnixEpoch);
        Assert.Equal(2, list.Count);
        Assert.Equal("Lab", list[0].Ssid);
        Assert.Equal("02:00:00:00:00:01", WifiFormat.Bssid(list[0].Bssid));
        Assert.Equal(-55, list[0].RssiDbm);
        Assert.Equal(6, list[0].Channel);
        Assert.Equal(20, list[0].WidthMhz);
        Assert.True(list[0].Ies.Ht);
        Assert.True(list[1].Hidden);
        Assert.Equal(36, list[1].Channel);
        Assert.Null(list[1].WidthMhz);
    }

    [Fact]
    public void Truncated_lists_and_out_of_range_element_offsets_are_safe()
    {
        var e = Entry("X", [2, 0, 0, 0, 0, 3], -60, 2_412_000, []);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(352), 100_000);
        BinaryPrimitives.WriteUInt32LittleEndian(e.AsSpan(356), 50);
        var raw = new byte[8 + 360];
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(4), 5); // claims 5 entries, holds 1
        e.CopyTo(raw, 8);
        var list = WlanLayout.ParseBssList(raw, WifiFixtures.Adapter, DateTimeOffset.UnixEpoch);
        Assert.Single(list);
        Assert.Equal(0, list[0].Ies.Count);
        Assert.Empty(WlanLayout.ParseBssList(new byte[3], WifiFixtures.Adapter, DateTimeOffset.UnixEpoch));
    }

    [Fact]
    public void Connection_attributes_are_read_and_disconnected_is_null()
    {
        var raw = new byte[604];
        BinaryPrimitives.WriteInt32LittleEndian(raw, 1);
        Encoding.Unicode.GetBytes("Home").CopyTo(raw, 8);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(520), 4);
        Encoding.UTF8.GetBytes("Home").CopyTo(raw, 524);
        new byte[] { 2, 0, 0, 0, 0, 9 }.CopyTo(raw, 560);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(568), 10);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(576), 88);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(580), 1_201_000);
        BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(584), 960_000);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(596), 9);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(600), 4);
        var c = WlanLayout.ParseConnection(raw, WifiFixtures.Adapter, -52)!;
        Assert.Equal("Home", c.Ssid);
        Assert.Equal("Home", c.ProfileName);
        Assert.Equal("02:00:00:00:00:09", WifiFormat.Bssid(c.Bssid));
        Assert.Equal(88, c.SignalQuality);
        Assert.Equal(1_201_000, c.RxRateKbps);
        Assert.Equal(960_000, c.TxRateKbps);
        Assert.Equal("WPA3-Personal (SAE)", c.Authentication);
        Assert.Equal("CCMP (AES)", c.Cipher);
        BinaryPrimitives.WriteInt32LittleEndian(raw, 4);
        Assert.Null(WlanLayout.ParseConnection(raw, WifiFixtures.Adapter, null));
        Assert.Null(WlanLayout.ParseConnection(new byte[100], WifiFixtures.Adapter, null));
    }
}

public class ChannelPlannerTests
{
    private static readonly RegulatoryDomain Etsi = RegulatoryDomain.For("DE");

    [Fact]
    public void One_strong_network_outweighs_several_faint_ones()
    {
        var visible = new[]
        {
            WifiFixtures.Bss("Strong", "02:00:00:00:01:01", -45, 2437),
            WifiFixtures.Bss("Faint1", "02:00:00:00:01:02", -88, 2412),
            WifiFixtures.Bss("Faint2", "02:00:00:00:01:03", -89, 2412),
            WifiFixtures.Bss("Faint3", "02:00:00:00:01:04", -88, 2412),
            WifiFixtures.Bss("Mid", "02:00:00:00:01:05", -60, 2462),
        };
        var plan = ChannelPlanner.Plan(visible, WifiBand.Band24, 20, Etsi);
        Assert.Equal(1, plan.Best!.Primary); // three faint networks on 1 beat one strong on 6 and a medium one on 11
        var one = plan.Candidates.Single(c => c.Primary == 1);
        Assert.Equal(3, one.CoChannel);
        Assert.Contains(one.Evidence, e => e.Contains("inferred", StringComparison.Ordinal));
        Assert.All(plan.Candidates.Where(c => c.Primary is 2 or 3 or 4 or 5), c => Assert.False(c.Preferred));
    }

    [Fact]
    public void Partial_overlap_counts_more_than_co_channel()
    {
        var co = ChannelPlanner.Plan([WifiFixtures.Bss("A", "02:00:00:00:02:01", -60, 2412)], WifiBand.Band24, 20, Etsi).Candidates.Single(c => c.Primary == 1);
        var adj = ChannelPlanner.Plan([WifiFixtures.Bss("A", "02:00:00:00:02:01", -60, 2422)], WifiBand.Band24, 20, Etsi).Candidates.Single(c => c.Primary == 1);
        Assert.Equal(1, co.CoChannel);
        Assert.Equal(1, adj.Overlapping);
        Assert.Equal(0, adj.CoChannel);
        var overlap = WifiChannels.Overlap(WifiChannels.Span(WifiBand.Band24, 1, 20), WifiChannels.Span(WifiBand.Band24, 3, 20));
        Assert.Equal(co.Score * overlap * 1.5, adj.Score, 2); // partial overlap weighs 1.5× per MHz shared
    }

    [Fact]
    public void Measured_utilisation_is_reported_as_measured()
    {
        var plan = ChannelPlanner.Plan([WifiFixtures.Bss("Busy", "02:00:00:00:03:01", -70, 5180, WifiFixtures.BssLoad(5, 204))], WifiBand.Band5, 20, Etsi);
        var c36 = plan.Candidates.Single(c => c.Primary == 36);
        Assert.Equal(80, c36.MeasuredUtilizationPercent!.Value, 0);
        Assert.Contains(c36.Evidence, e => e.Contains("measured", StringComparison.Ordinal));
        Assert.NotEqual(36, plan.Best!.Primary);
    }

    [Fact]
    public void Disallowed_channels_are_never_recommended_and_dfs_is_flagged()
    {
        var visible = Enumerable.Range(0, 4).Select(i => WifiFixtures.Bss("N" + i, $"02:00:00:00:04:0{i}", -50, 5180 + (i * 20))).ToArray(); // 36–48 busy
        var plan = ChannelPlanner.Plan(visible, WifiBand.Band5, 80, RegulatoryDomain.For(null));
        Assert.True(plan.Best!.Allowed);
        Assert.NotEqual(36, plan.Best.Primary);
        Assert.DoesNotContain(plan.Candidates, c => c.Primary == 149 && c.Allowed);
        Assert.True(plan.Candidates.Single(c => c.Primary == 52).Dfs);
        Assert.Contains(plan.Candidates.Single(c => c.Primary == 52).Evidence, e => e.StartsWith("DFS", StringComparison.Ordinal));
    }

    [Fact]
    public void The_planned_access_point_itself_and_its_virtual_bssids_are_left_out()
    {
        var own = WifiFixtures.Mac("00:00:5e:00:53:15");
        var visible = new[]
        {
            WifiFixtures.Bss("Home", "00:00:5e:00:53:15", -40, 5180),
            WifiFixtures.Bss("", "02:00:5e:00:53:15", -40, 5180),
            WifiFixtures.Bss("Other", "02:11:22:33:44:55", -85, 5180),
        };
        var plan = ChannelPlanner.Plan(visible, WifiBand.Band5, 20, Etsi, own, 5180);
        Assert.Equal(2, plan.Excluded);
        Assert.Equal(1, plan.Candidates.Single(c => c.Primary == 36).CoChannel);
    }

    [Fact]
    public void Five_ghz_blocks_skip_the_gap_between_64_and_100()
    {
        var blocks = ChannelPlanner.Blocks(WifiBand.Band5, 80).Select(b => b.Primary).ToList();
        Assert.Equal([36, 52, 100, 116, 132, 149, 165], blocks);
        Assert.Equal([36, 100, 149], ChannelPlanner.Blocks(WifiBand.Band5, 160).Select(b => b.Primary)); // 149–177: UNII-3/4
    }
}

public class RoamingTrackerTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 25, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Bssid_changes_disconnects_and_channel_changes_become_events()
    {
        var t = new RoamingTracker();
        t.Observe(T0, WifiFixtures.Connection("Net", "02:00:00:00:00:01", -70, 2412));
        t.Observe(T0.AddSeconds(1), WifiFixtures.Connection("Net", "02:00:00:00:00:02", -50, 5180));
        t.Observe(T0.AddSeconds(2), null);
        t.Observe(T0.AddSeconds(3), null);
        t.Observe(T0.AddSeconds(6), WifiFixtures.Connection("Net", "02:00:00:00:00:02", -52, 5180));
        t.Observe(T0.AddSeconds(7), WifiFixtures.Connection("Net", "02:00:00:00:00:02", -52, 5500));
        var e = t.Events;
        Assert.Equal([WifiEventKind.Connected, WifiEventKind.Roamed, WifiEventKind.Disconnected, WifiEventKind.Connected, WifiEventKind.ChannelChanged], e.Select(x => x.Kind));
        Assert.Equal(-70, e[1].RssiBefore);
        Assert.Equal(-50, e[1].RssiAfter);
        Assert.Contains("2.4 GHz → 5 GHz", e[1].Detail, StringComparison.Ordinal);
        Assert.Equal(TimeSpan.FromSeconds(4), e[3].Interruption);
        Assert.Contains("same access point", e[3].Detail, StringComparison.Ordinal);
        Assert.Equal(1, t.Roams);
        Assert.Equal(1, t.Disconnects);
    }

    [Fact]
    public void Back_and_forth_roams_are_counted()
    {
        var t = new RoamingTracker();
        for (var i = 0; i < 6; i++) t.Observe(T0.AddSeconds(i * 10), WifiFixtures.Connection("Net", i % 2 == 0 ? "02:00:00:00:00:01" : "02:00:00:00:00:02"));
        Assert.Equal(5, t.Roams);
        Assert.Equal(4, t.PingPongs(TimeSpan.FromMinutes(1)));
        Assert.Equal(0, t.PingPongs(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public void Gateway_impact_counts_lost_pings_around_an_event()
    {
        var ev = new WifiEvent(T0, WifiEventKind.Roamed, "Net", null, null, null, null, null, null, null, "");
        var samples = Enumerable.Range(-10, 30).Select(i => new WifiSample(T0.AddSeconds(i), default, null, i is >= 0 and < 3 ? null : 5, i is >= 0 and < 3, null, null, null)).ToList();
        Assert.Equal((16, 3), RoamingTracker.GatewayImpact(ev, samples, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10)));
    }

    [Fact]
    public void Event_history_is_bounded()
    {
        var t = new RoamingTracker(capacity: 10);
        for (var i = 0; i < 100; i++) t.Observe(T0.AddSeconds(i), i % 2 == 0 ? WifiFixtures.Connection("Net", "02:00:00:00:00:01") : null);
        Assert.Equal(10, t.Events.Count);
    }
}

public class WifiMonitorTests
{
    private static Observation<WifiConnection> Connected() => Observation<WifiConnection>.Ok(WifiFixtures.Connection("Net", "02:00:00:00:00:01"), DateTimeOffset.UtcNow);

    [Fact]
    public async Task Samples_connection_gateway_and_dns_with_measured_intervals()
    {
        var wifi = new FakeWifi { Connection = Connected };
        var icmp = new FakeIcmp();
        icmp.Alive.Add("192.0.2.1");
        var monitor = new WifiMonitor(wifi, icmp, TimeProvider.System, capacity: 100) { DnsProbe = _ => Task.FromResult<(double?, string)>((12.5, "ok")) };
        var three = new TaskCompletionSource();
        monitor.Sampled += _ =>
        {
            if (monitor.History.Count >= 3) three.TrySetResult();
        };
        monitor.Start(WifiFixtures.Adapter, TimeSpan.FromMilliseconds(250));
        await three.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await monitor.StopAsync();
        var h = monitor.History.Snapshot();
        Assert.Null(h[0].Interval);
        Assert.All(h.Skip(1), s => Assert.InRange(s.Interval!.Value.TotalMilliseconds, 100, 2000));
        Assert.All(h, s => Assert.Equal(12.5, s.DnsMs));
        Assert.All(h, s => Assert.NotNull(s.GatewayRttMs));
        Assert.False(monitor.Running);
    }

    [Fact]
    public async Task Access_denied_and_disconnected_are_kept_typed_and_never_ping()
    {
        var wifi = new FakeWifi { Connection = () => Observation<WifiConnection>.Of(ObservationState.AccessDenied, DateTimeOffset.UtcNow, WlanLayout.LocationHint) };
        var icmp = new FakeIcmp();
        var monitor = new WifiMonitor(wifi, icmp, TimeProvider.System);
        var s = await monitor.SampleAsync(WifiFixtures.Adapter, TimeSpan.FromSeconds(1), null, TestContext.Current.CancellationToken);
        Assert.Equal(ObservationState.AccessDenied, s.Connection.State);
        Assert.Contains("location", s.Connection.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.Null(s.Connected);
        Assert.False(s.GatewayLost);
        Assert.Equal(0, icmp.Calls);
    }

    [Fact]
    public async Task A_local_probe_failure_is_not_a_lost_ping()
    {
        var wifi = new FakeWifi { Connection = Connected };
        var icmp = new FakeIcmp { Override = _ => throw new InvalidOperationException("socket") };
        var monitor = new WifiMonitor(wifi, icmp, TimeProvider.System) { DnsProbe = _ => throw new InvalidOperationException("no server") };
        var s = await monitor.SampleAsync(WifiFixtures.Adapter, TimeSpan.FromSeconds(1), null, TestContext.Current.CancellationToken);
        Assert.False(s.GatewayLost);
        Assert.Null(s.GatewayRttMs);
        Assert.Null(s.DnsMs);
        Assert.Equal("no server", s.DnsDetail);
    }

    [Fact]
    public async Task Repeated_start_and_stop_is_safe_and_history_stays_bounded()
    {
        var wifi = new FakeWifi { Connection = Connected };
        var icmp = new FakeIcmp();
        icmp.Alive.Add("192.0.2.1");
        var monitor = new WifiMonitor(wifi, icmp, TimeProvider.System, capacity: 5);
        for (var i = 0; i < 5; i++)
        {
            monitor.Start(WifiFixtures.Adapter, TimeSpan.FromMilliseconds(250));
            Assert.Throws<InvalidOperationException>(() => monitor.Start(WifiFixtures.Adapter, TimeSpan.FromSeconds(1)));
            await monitor.StopAsync();
            await monitor.StopAsync(); // idempotent
        }

        var calls = wifi.ConnectionCalls;
        await Task.Delay(600, TestContext.Current.CancellationToken);
        Assert.Equal(calls, wifi.ConnectionCalls); // nothing runs after Stop

        monitor.Start(WifiFixtures.Adapter, TimeSpan.FromMilliseconds(250));
        await Task.Delay(2200, TestContext.Current.CancellationToken);
        await monitor.StopAsync();
        Assert.Equal(5, monitor.History.Count);
        Assert.Throws<ArgumentOutOfRangeException>(() => monitor.Start(WifiFixtures.Adapter, TimeSpan.FromMilliseconds(10)));
    }

    [Fact]
    public async Task Unsupported_provider_reports_why()
    {
        var p = new UnsupportedWifiProvider("not on this platform");
        Assert.False(p.Capability.Available);
        var a = await p.AdaptersAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ObservationState.Unsupported, a.State);
        Assert.Equal("not on this platform", a.Detail);
    }

    [Fact]
    public void Scan_book_merges_scans_ages_out_and_stays_bounded()
    {
        var book = new WifiScanBook(capacity: 3);
        var t0 = DateTimeOffset.UtcNow;
        WifiBss At(string mac, int rssi, DateTimeOffset at) => WifiFixtures.Bss("N", mac, rssi, 2412) with { SeenAt = at };
        book.Add([At("02:00:00:00:00:01", -50, t0), At("02:00:00:00:00:02", -60, t0)]);
        book.Add([At("02:00:00:00:00:01", -55, t0.AddMinutes(3))]); // 02 not heard this time
        Assert.Equal(2, book.Scans);
        var now = t0.AddMinutes(3);
        Assert.Equal(2, book.Current(now, TimeSpan.FromMinutes(5)).Count);
        Assert.Equal(-55, book.Current(now, TimeSpan.FromMinutes(5))[0].RssiDbm);
        Assert.Single(book.Current(now, TimeSpan.FromMinutes(1)));
        book.Add([At("02:00:00:00:00:03", -70, now), At("02:00:00:00:00:04", -70, now)]);
        Assert.Equal(3, book.Count); // the least recently seen (02) was dropped
        Assert.DoesNotContain(book.Current(now, TimeSpan.FromHours(1)), b => WifiFormat.Bssid(b.Bssid) == "02:00:00:00:00:02");
    }

    [Fact]
    public void Bounded_history_drops_the_oldest()
    {
        var h = new BoundedHistory<int>(3);
        for (var i = 0; i < 10; i++) h.Add(i);
        Assert.Equal([7, 8, 9], h.Snapshot());
    }
}

public class WifiAdvisorTests
{
    private static readonly RegulatoryDomain Domain = RegulatoryDomain.For("TR");

    private static WifiAdvisorInput Input(WifiConnection? c, IReadOnlyList<WifiBss> visible, int scans = 3) => new(visible, scans, c, [], [], Domain);

    [Fact]
    public void Weak_signal_is_a_warning_with_its_observations()
    {
        var c = WifiFixtures.Connection("Net", "02:00:00:00:00:01", -80);
        var r = WifiAdvisor.Advise(Input(c, [])).Single(x => x.Topic == "Weak signal");
        Assert.Equal(AdviceSeverity.Warning, r.Severity);
        Assert.Contains(r.Observations, o => o.Contains("-80", StringComparison.Ordinal) || o.Contains("−80", StringComparison.Ordinal));
        Assert.Equal(AdviceConfidence.Low, r.Confidence); // one reading
    }

    [Fact]
    public void Forty_mhz_on_24_ghz_gets_a_20_mhz_recommendation()
    {
        var own = WifiFixtures.Bss("Net", "02:00:00:00:00:01", -50, 2412, WifiFixtures.HtOperation(1, 1));
        var c = WifiFixtures.Connection("Net", "02:00:00:00:00:01", -50, 2412);
        var r = WifiAdvisor.Advise(Input(c, [own, WifiFixtures.Bss("X", "02:00:00:00:00:09", -60, 2437)]));
        var width = r.Single(x => x.Topic == "Channel width");
        Assert.Equal(AdviceConfidence.High, width.Confidence);
        Assert.Contains(r, x => x.Topic == "Channel");
    }

    [Fact]
    public void Same_network_on_a_higher_band_is_suggested()
    {
        var c = WifiFixtures.Connection("Net", "02:00:00:00:00:01", -55, 2437);
        var r = WifiAdvisor.Advise(Input(c, [WifiFixtures.Bss("Net", "02:00:00:00:00:02", -60, 5180)]));
        Assert.Contains(r, x => x.Topic == "Band" && x.Severity == AdviceSeverity.Suggestion);
    }

    [Fact]
    public void A_sticky_client_is_reported_and_channel_advice_never_exceeds_medium()
    {
        var own = WifiFixtures.Bss("Net", "02:00:00:00:00:01", -78, 5180);
        var c = WifiFixtures.Connection("Net", "02:00:00:00:00:01", -78, 5180);
        var r = WifiAdvisor.Advise(Input(c, [own, WifiFixtures.Bss("Net", "02:00:00:00:00:02", -55, 5500)], scans: 50));
        Assert.Contains(r, x => x.Topic == "Roaming");
        Assert.All(r.Where(x => x.Topic == "Channel"), x => Assert.NotEqual(AdviceConfidence.High, x.Confidence));
        Assert.All(r, x => Assert.NotEmpty(x.Observations));
    }

    [Fact]
    public void Not_connected_gives_one_informational_entry()
    {
        var r = WifiAdvisor.Advise(Input(null, []));
        Assert.Equal(AdviceSeverity.Info, Assert.Single(r).Severity);
    }
}

public class SiteSurveyTests
{
    [Fact]
    public void Interpolation_honours_measured_points_and_leaves_far_cells_empty()
    {
        var samples = new[] { (0.05, 0.05, -40.0), (0.35, 0.05, -80.0) };
        var grid = SiteSurvey.Interpolate(samples, 10, 10, maxDistance: 0.15);
        Assert.Equal(-40, grid[0, 0]); // a cell centred on a measured point shows the measurement
        Assert.Equal(-80, grid[0, 3]);
        Assert.InRange(grid[0, 1]!.Value, -80, -40); // between the points: an estimate
        Assert.Null(grid[9, 9]); // far from every point: no estimate
    }

    [Fact]
    public void Distances_follow_the_plan_proportions()
    {
        var samples = new[] { (0.5, 0.5, -50.0) };
        // a plan half as tall as wide: 0.4 of its height is 0.2 plan widths, inside a 0.25 radius
        var wide = SiteSurvey.Interpolate(samples, 10, 10, maxDistance: 0.25, aspect: 0.5);
        Assert.NotNull(wide[9, 5]);
        Assert.Null(SiteSurvey.Interpolate(samples, 10, 10, maxDistance: 0.25)[9, 5]);
    }

    [Fact]
    public void Not_heard_counts_as_the_floor_and_coverage_is_compared()
    {
        var project = new SiteSurveyProject
        {
            Points =
            [
                new SurveyPoint { X = 0.1, Y = 0.1, Readings = [new SurveyReading { Ssid = "Net", Bssid = "aa", RssiDbm = -50 }, new SurveyReading { Ssid = "Net", Bssid = "bb", RssiDbm = -65 }] },
                new SurveyPoint { X = 0.9, Y = 0.9, Readings = [new SurveyReading { Ssid = "Net", Bssid = "bb", RssiDbm = -60 }] },
            ],
        };
        var values = SiteSurvey.Values(project, r => r.Bssid == "aa");
        Assert.Equal(SiteSurvey.NotHeardDbm, values[1].Value);
        var cov = SiteSurvey.Coverage(project);
        Assert.Equal("bb", cov[0].Bssid); // heard at both points
        Assert.Equal(2, cov[0].PointsHeard);
        Assert.Equal(50, cov.Single(c => c.Bssid == "aa").PercentAtLeast67);
    }

    [Fact]
    public void Csv_export_quotes_and_neutralises_formulas()
    {
        var project = new SiteSurveyProject { Points = [new SurveyPoint { Note = "=cmd()", Readings = [new SurveyReading { Ssid = "a,b", Bssid = "aa", RssiDbm = -50, FrequencyMhz = 2412 }] }, new SurveyPoint()] };
        var csv = SiteSurvey.Csv(project);
        Assert.Contains("'=cmd()", csv, StringComparison.Ordinal);
        Assert.Contains("\"a,b\"", csv, StringComparison.Ordinal);
        Assert.Contains(",aa,-50,2412,1", csv, StringComparison.Ordinal);
        Assert.Equal(3, csv.Trim().Split('\n').Length); // header + reading + empty point
    }
}
