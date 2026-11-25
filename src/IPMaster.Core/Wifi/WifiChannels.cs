namespace IPMaster.Core.Wifi;

/// <summary>
/// 802.11 channel arithmetic (D-097). 2.4 GHz: channel n at 2407 + 5n MHz (14 at 2484); 5 GHz: 5000 + 5n; 6 GHz:
/// 5950 + 5n (channel 2 at 5935). A 20 MHz 2.4 GHz channel is treated as 22 MHz wide (the DSSS/OFDM spectral mask),
/// which is why only channels five apart (1/6/11) do not overlap. Bonded channels on 5/6 GHz use the standard blocks.
/// </summary>
public static class WifiChannels
{
    public static WifiBand BandOf(int mhz) => mhz switch
    {
        >= 2400 and <= 2500 => WifiBand.Band24,
        >= 5150 and <= 5895 => WifiBand.Band5,
        >= 5925 and <= 7125 => WifiBand.Band6,
        _ => WifiBand.Unknown,
    };

    public static int? ChannelOf(int mhz) => mhz switch
    {
        2484 => 14,
        >= 2412 and <= 2472 when (mhz - 2407) % 5 == 0 => (mhz - 2407) / 5,
        >= 5150 and <= 5895 when mhz % 5 == 0 => (mhz - 5000) / 5,
        5935 => 2,
        >= 5955 and <= 7115 when (mhz - 5950) % 5 == 0 => (mhz - 5950) / 5,
        _ => null,
    };

    public static int? FrequencyOf(WifiBand band, int channel) => band switch
    {
        WifiBand.Band24 when channel == 14 => 2484,
        WifiBand.Band24 when channel is >= 1 and <= 13 => 2407 + (5 * channel),
        WifiBand.Band5 when channel is >= 32 and <= 177 => 5000 + (5 * channel),
        WifiBand.Band6 when channel == 2 => 5935,
        WifiBand.Band6 when channel is >= 1 and <= 233 => 5950 + (5 * channel),
        _ => null,
    };

    public static string BandName(WifiBand band) => band switch
    {
        WifiBand.Band24 => "2.4 GHz",
        WifiBand.Band5 => "5 GHz",
        WifiBand.Band6 => "6 GHz",
        _ => "unknown",
    };

    /// <summary>Occupied spectrum (MHz) of a BSS on <paramref name="primary"/> at <paramref name="widthMhz"/>.</summary>
    public static (double Low, double High) Span(WifiBand band, int primary, int widthMhz, int? centerChannel = null, int secondaryOffset = 0)
    {
        var p = FrequencyOf(band, primary) ?? 0;
        if (band == WifiBand.Band24)
        {
            if (widthMhz >= 40 && secondaryOffset != 0)
            {
                var s = p + (20 * secondaryOffset);
                return (Math.Min(p, s) - 10, Math.Max(p, s) + 10);
            }

            return (p - 11, p + 11);
        }

        if (widthMhz <= 20) return (p - 10, p + 10);
        var center = centerChannel is { } c && FrequencyOf(band, c) is { } cf ? cf : FrequencyOf(band, AlignedCenter(band, primary, widthMhz)) ?? p;
        return (center - (widthMhz / 2.0), center + (widthMhz / 2.0));
    }

    /// <summary>Centre channel of the standard 40/80/160/320 MHz block that contains <paramref name="primary"/>.</summary>
    public static int AlignedCenter(WifiBand band, int primary, int widthMhz)
    {
        var n = Math.Max(1, widthMhz / 20);
        var b = band == WifiBand.Band6 ? 1 : primary >= 149 ? 149 : 36;
        var index = Math.Max(0, (primary - b) / 4);
        var start = index / n * n;
        return b + (start * 4) + ((n - 1) * 2);
    }

    /// <summary>The 20 MHz channels inside a block, for DFS and regulatory checks.</summary>
    public static IEnumerable<int> SubChannels(WifiBand band, int center, int widthMhz)
    {
        var n = Math.Max(1, widthMhz / 20);
        var first = center - ((n - 1) * 2);
        for (var k = 0; k < n; k++) yield return first + (4 * k);
    }

    /// <summary>Fraction (0–1) of <paramref name="b"/>'s spectrum that falls inside <paramref name="a"/>.</summary>
    public static double Overlap((double Low, double High) a, (double Low, double High) b)
    {
        var width = b.High - b.Low;
        if (width <= 0) return 0;
        var shared = Math.Min(a.High, b.High) - Math.Max(a.Low, b.Low);
        return shared <= 0 ? 0 : Math.Min(1, shared / width);
    }

    /// <summary>5 GHz channels 52–144 need radar detection (DFS): a minute of listening before use, and a forced move on radar.</summary>
    public static bool IsDfs(WifiBand band, int channel) => band == WifiBand.Band5 && channel is >= 52 and <= 144;

    /// <summary>6 GHz Preferred Scanning Channels (5, 21, 37, …): clients that scan only these find the AP faster.</summary>
    public static bool IsPsc(int channel6) => channel6 >= 5 && (channel6 - 5) % 16 == 0;
}

/// <summary>
/// Channels allowed for access points in a regulatory domain (D-097). Only a few common domains are listed; any other
/// or unknown country gets a conservative subset and the recommendation says so. Always confirm with local rules.
/// </summary>
public sealed record RegulatoryDomain(string Name, string? Country, bool Known, IReadOnlySet<int> Channels24, IReadOnlySet<int> Channels5, IReadOnlySet<int> Channels6)
{
    private static readonly HashSet<string> Etsi = new(StringComparer.OrdinalIgnoreCase)
    {
        "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LI",
        "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK", "TR", "EU",
    };

    private static IReadOnlySet<int> Range(params (int From, int To)[] ranges)
    {
        var set = new HashSet<int>();
        foreach (var (from, to) in ranges)
        {
            for (var c = from; c <= to; c++) set.Add(c);
        }

        return set;
    }

    private static IReadOnlySet<int> Fives(params (int From, int To)[] ranges)
    {
        var set = new HashSet<int>();
        foreach (var (from, to) in ranges)
        {
            for (var c = from; c <= to; c += 4) set.Add(c);
        }

        return set;
    }

    private static IReadOnlySet<int> Six(int last)
    {
        var set = new HashSet<int>();
        for (var c = 1; c <= last; c += 4) set.Add(c);
        return set;
    }

    public static RegulatoryDomain For(string? country)
    {
        var cc = country?.Trim().ToUpperInvariant();
        if (cc is "US" or "CA")
            return new("FCC (" + cc + ")", cc, true, Range((1, 11)), Fives((36, 64), (100, 144), (149, 165)), Six(233));
        if (cc is not null && Etsi.Contains(cc))
            return new("ETSI (" + cc + ")", cc, true, Range((1, 13)), Fives((36, 64), (100, 140)), Six(93));
        if (cc == "JP")
            return new("Japan", cc, true, Range((1, 13)), Fives((36, 64), (100, 144)), Six(93));
        if (cc == "CN")
            return new("China", cc, true, Range((1, 13)), Fives((36, 64), (149, 165)), new HashSet<int>());
        return new(cc is null ? "unknown (conservative subset)" : cc + " (not listed; conservative subset)", cc, false,
            Range((1, 11)), Fives((36, 64), (100, 140)), Six(93));
    }

    /// <summary>The country most visible access points announce (Country element); null when none does.</summary>
    public static string? Observed(IEnumerable<WifiBss> visible) => visible
        .Select(b => b.Ies.Country).Where(c => c is not null)
        .GroupBy(c => c).OrderByDescending(g => g.Count()).Select(g => g.Key).FirstOrDefault();

    public IReadOnlySet<int> ChannelsFor(WifiBand band) => band switch
    {
        WifiBand.Band24 => Channels24,
        WifiBand.Band5 => Channels5,
        WifiBand.Band6 => Channels6,
        _ => new HashSet<int>(),
    };
}
