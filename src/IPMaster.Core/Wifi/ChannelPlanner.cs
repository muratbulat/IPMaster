using System.Globalization;
using System.Net.NetworkInformation;

namespace IPMaster.Core.Wifi;

public sealed record ChannelCandidate(
    WifiBand Band,
    int Primary,
    int Center,
    int WidthMhz,
    double Low,
    double High,
    bool Allowed,
    bool Dfs,
    bool Preferred,
    double Score,
    int CoChannel,
    int Overlapping,
    double? MeasuredUtilizationPercent,
    IReadOnlyList<string> Evidence)
{
    public string Label => WidthMhz <= 20 ? Primary.ToString(CultureInfo.InvariantCulture)
        : string.Create(CultureInfo.InvariantCulture, $"{Primary} ({WidthMhz} MHz, centre {Center})");
}

public sealed record ChannelPlan(WifiBand Band, int WidthMhz, RegulatoryDomain Domain, IReadOnlyList<ChannelCandidate> Candidates, ChannelCandidate? Best, int Excluded);

/// <summary>
/// Evidence-based channel scoring (D-097). For each candidate block, every other visible BSS at or above −90 dBm adds
/// <c>overlap × weight(RSSI)</c>, where weight rises linearly from 0 at −95 dBm to 1 at −50 dBm and stronger. A BSS whose
/// primary channel lies inside the block shares airtime (co-channel contention: radios decode each other's preambles down
/// to about −82 dBm and take turns); a BSS that only partly overlaps counts 1.5× because the radios cannot coordinate
/// (adjacent-channel interference). Channel busy time an AP measured and announced (BSS Load element) adds
/// <c>2 × utilisation</c>; everything else is inferred from beacons heard at this computer, which is not the AP's position.
/// DFS blocks get a small penalty (radar can force a move). Fewer networks is not automatically better: three networks at
/// −90 dBm weigh less than one at −50 dBm.
/// </summary>
public static class ChannelPlanner
{
    public const int Floor = -90;

    public static double Weight(int rssiDbm) => Math.Clamp((rssiDbm + 95) / 45.0, 0, 1);

    /// <summary>Same radio as <paramref name="b"/>: same frequency and a BSSID that differs only in the first or last octet (virtual BSSIDs).</summary>
    public static bool SameRadio(WifiBss a, PhysicalAddress b, int frequencyMhz)
    {
        ArgumentNullException.ThrowIfNull(a);
        ArgumentNullException.ThrowIfNull(b);
        if (a.FrequencyMhz != frequencyMhz) return false;
        var x = a.Bssid.GetAddressBytes();
        var y = b.GetAddressBytes();
        if (x.Length != 6 || y.Length != 6) return false;
        for (var i = 1; i < 5; i++)
        {
            if (x[i] != y[i]) return false;
        }

        return x[0] == y[0] || x[5] == y[5];
    }

    public static ChannelPlan Plan(IReadOnlyList<WifiBss> visible, WifiBand band, int widthMhz, RegulatoryDomain domain, PhysicalAddress? ownBssid = null, int ownFrequencyMhz = 0)
    {
        ArgumentNullException.ThrowIfNull(visible);
        ArgumentNullException.ThrowIfNull(domain);
        if (band == WifiBand.Band24) widthMhz = 20; // 40 MHz in 2.4 GHz is not planned (see the advisor)
        var others = visible.Where(b => b.Band == band && b.Channel is not null && b.RssiDbm >= Floor).ToList();
        var excluded = 0;
        if (ownBssid is not null)
        {
            excluded = others.RemoveAll(b => SameRadio(b, ownBssid, ownFrequencyMhz));
        }

        var allowed = domain.ChannelsFor(band);
        var candidates = new List<ChannelCandidate>();
        foreach (var (primary, center) in Blocks(band, widthMhz))
        {
            var span = WifiChannels.Span(band, primary, widthMhz, center);
            List<int> subs = band == WifiBand.Band24 ? [primary] : [.. WifiChannels.SubChannels(band, center, widthMhz)];
            var isAllowed = subs.All(allowed.Contains);
            var dfs = subs.Any(c => WifiChannels.IsDfs(band, c));
            var preferred = band switch
            {
                WifiBand.Band24 => primary is 1 or 6 or 11,
                WifiBand.Band6 => subs.Any(WifiChannels.IsPsc),
                _ => true,
            };
            double score = 0;
            int co = 0, partial = 0;
            double? measured = null;
            string? measuredBy = null;
            var evidence = new List<string>();
            foreach (var b in others)
            {
                var o = WifiChannels.Overlap(span, b.Span);
                if (o <= 0) continue;
                var inside = b.Channel is { } bc && subs.Contains(bc);
                var w = o * Weight(b.RssiDbm) * (inside ? 1 : 1.5);
                score += w;
                if (inside)
                {
                    co++;
                    if (b.Ies.ChannelUtilizationPercent is { } u && (measured is null || u > measured))
                    {
                        measured = u;
                        measuredBy = Name(b);
                    }
                }
                else
                {
                    partial++;
                }
            }

            if (measured is { } m) score += 2 * m / 100;
            if (dfs) score += 0.25;
            if (co > 0) evidence.Add(string.Create(CultureInfo.InvariantCulture, $"{co} network(s) with their primary channel here (shared airtime), strongest {others.Where(b => b.Channel is { } x && subs.Contains(x) && WifiChannels.Overlap(span, b.Span) > 0).Max(b => b.RssiDbm)} dBm (inferred from beacons)"));
            if (partial > 0) evidence.Add(string.Create(CultureInfo.InvariantCulture, $"{partial} network(s) partly overlapping (adjacent-channel interference, inferred)"));
            if (measured is { } mu) evidence.Add(string.Create(CultureInfo.InvariantCulture, $"channel busy {mu:0} % as measured and announced by {measuredBy} (BSS Load element)"));
            if (co == 0 && partial == 0) evidence.Add("no network heard at or above −90 dBm in this spectrum");
            if (dfs) evidence.Add("DFS channel: radar detection can force the AP to move; clients may take longer to find it");
            if (!isAllowed) evidence.Add("not allowed in " + domain.Name);
            if (!preferred) evidence.Add(band == WifiBand.Band24 ? "not one of 1/6/11: overlaps two of the usual channels" : "contains no 6 GHz preferred scanning channel");
            candidates.Add(new ChannelCandidate(band, primary, center, widthMhz, span.Low, span.High, isAllowed, dfs, preferred, Math.Round(score, 3), co, partial, measured, evidence));
        }

        var best = candidates.Where(c => c.Allowed && c.Preferred).OrderBy(c => c.Score).ThenBy(c => c.Dfs).ThenBy(c => c.Primary).FirstOrDefault();
        return new ChannelPlan(band, widthMhz, domain, candidates, best, excluded);
    }

    private static string Name(WifiBss b) => (b.Hidden ? "(hidden)" : b.Ssid) + " " + WifiFormat.Bssid(b.Bssid);

    /// <summary>Candidate (primary, centre) pairs: every channel on 2.4 GHz, standard blocks on 5/6 GHz.</summary>
    public static IEnumerable<(int Primary, int Center)> Blocks(WifiBand band, int widthMhz)
    {
        switch (band)
        {
            case WifiBand.Band24:
                for (var c = 1; c <= 13; c++) yield return (c, c);
                break;
            case WifiBand.Band5:
                foreach (var start in new[] { 36, 149 })
                {
                    var end = start == 36 ? 144 : 177;
                    var n = Math.Max(1, widthMhz / 20);
                    for (var c = start; c + ((n - 1) * 4) <= end; c += 4 * n)
                    {
                        if (start == 36 && c is > 64 and < 100) continue; // 68–96 are not Wi-Fi channels
                        yield return (c, c + ((n - 1) * 2));
                    }
                }

                break;
            case WifiBand.Band6:
            {
                var n = Math.Max(1, widthMhz / 20);
                for (var c = 1; c + ((n - 1) * 4) <= 233; c += 4 * n) yield return (c, c + ((n - 1) * 2));
                break;
            }
        }
    }
}

public static class WifiFormat
{
    public static string Bssid(PhysicalAddress mac)
    {
        ArgumentNullException.ThrowIfNull(mac);
        return string.Join(':', mac.GetAddressBytes().Select(b => b.ToString("x2", CultureInfo.InvariantCulture)));
    }
}
