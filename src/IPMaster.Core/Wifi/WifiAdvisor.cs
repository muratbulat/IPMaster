using System.Globalization;
using IPMaster.Core.Monitoring;

namespace IPMaster.Core.Wifi;

public enum AdviceConfidence
{
    Low,
    Medium,
    High,
}

public enum AdviceSeverity
{
    Info,
    Suggestion,
    Warning,
}

/// <summary>One recommendation with the observations it rests on. IPMaster never applies it: AP settings are the user's to change.</summary>
public sealed record WifiRecommendation(string Topic, AdviceSeverity Severity, string Advice, IReadOnlyList<string> Observations, AdviceConfidence Confidence, string ConfidenceReason);

public sealed record WifiAdvisorInput(
    IReadOnlyList<WifiBss> Visible,
    int Scans,
    WifiConnection? Connection,
    IReadOnlyList<WifiSample> Samples,
    IReadOnlyList<WifiEvent> Events,
    RegulatoryDomain Domain);

/// <summary>
/// Explainable rules over what was observed (D-097). Thresholds: −67 dBm (the usual minimum for voice/video), −75 dBm
/// (weak), −82 dBm (preamble detection, so co-channel radios share airtime), 8 dB (a clearly stronger AP of the same
/// network). Channel advice is capped at Medium confidence: beacons are heard at this computer, not at the AP.
/// </summary>
public static class WifiAdvisor
{
    public static IReadOnlyList<WifiRecommendation> Advise(WifiAdvisorInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var list = new List<WifiRecommendation>();
        var c = input.Connection;
        var scanBasis = input.Scans switch
        {
            <= 1 => (AdviceConfidence.Low, "one scan only; scan again over a few minutes"),
            < 5 => (AdviceConfidence.Medium, $"{input.Scans} scans"),
            _ => (AdviceConfidence.Medium, $"{input.Scans} scans, from this computer's position only"),
        };
        if (c is null)
        {
            list.Add(new("Connection", AdviceSeverity.Info, "Not connected: recommendations about the current connection need an active Wi-Fi connection.",
                [$"{input.Visible.Count} network(s) visible"], AdviceConfidence.High, "reported by the operating system"));
            return list;
        }

        var own = input.Visible.FirstOrDefault(b => b.Bssid.Equals(c.Bssid));
        var rssiSamples = input.Samples.Select(s => s.Connected?.RssiDbm).OfType<int>().ToList();
        var rssi = rssiSamples.Count > 0 ? Median(rssiSamples) : c.RssiDbm ?? own?.RssiDbm;
        var rssiBasis = rssiSamples.Count switch
        {
            >= 30 => (AdviceConfidence.High, $"median of {rssiSamples.Count} samples"),
            > 1 => (AdviceConfidence.Medium, $"median of {rssiSamples.Count} samples; monitor longer for High"),
            _ => (AdviceConfidence.Low, "a single reading; start Live Monitoring for more"),
        };

        // signal
        if (rssi is { } r)
        {
            if (r < -75)
            {
                list.Add(new("Weak signal", AdviceSeverity.Warning,
                    "The signal is weak here. Move the access point (or this computer) closer, reduce walls and obstacles between them, or add an access point covering this area.",
                    [$"signal {r} dBm (below −75 dBm)", $"connected to {c.Ssid} {WifiFormat.Bssid(c.Bssid)} on channel {c.Channel?.ToString(CultureInfo.InvariantCulture) ?? "?"}"],
                    rssiBasis.Item1, rssiBasis.Item2));
            }
            else if (r < -67)
            {
                list.Add(new("Marginal signal", AdviceSeverity.Suggestion,
                    "The signal is usable but below the −67 dBm usually needed for calls and video. Consider AP placement or an additional AP.",
                    [$"signal {r} dBm"], rssiBasis.Item1, rssiBasis.Item2));
            }
        }

        // band
        if (c.Band == WifiBand.Band24)
        {
            var better = input.Visible.Where(b => b.Ssid == c.Ssid && b.Band is WifiBand.Band5 or WifiBand.Band6 && b.RssiDbm >= -70).OrderByDescending(b => b.RssiDbm).FirstOrDefault();
            if (better is not null)
            {
                list.Add(new("Band", AdviceSeverity.Suggestion,
                    $"This computer uses 2.4 GHz although {c.Ssid} is also heard on {WifiChannels.BandName(better.Band)} at a good level. The higher band usually has more capacity and less interference; check band steering or prefer the higher band on the client.",
                    [$"connected on 2.4 GHz, channel {c.Channel}", $"{better.Ssid} {WifiFormat.Bssid(better.Bssid)} on {WifiChannels.BandName(better.Band)} channel {better.Channel} at {better.RssiDbm} dBm"],
                    scanBasis.Item1, scanBasis.Item2));
            }
        }
        else if (c.Band == WifiBand.Band5)
        {
            var six = input.Visible.Where(b => b.Ssid == c.Ssid && b.Band == WifiBand.Band6 && b.RssiDbm >= -65).OrderByDescending(b => b.RssiDbm).FirstOrDefault();
            if (six is not null)
            {
                list.Add(new("Band", AdviceSeverity.Info,
                    $"{c.Ssid} is also heard on 6 GHz at {six.RssiDbm} dBm; this adapter receives 6 GHz beacons, so a 6 GHz connection may be possible (WPA3 is required there).",
                    [$"connected on 5 GHz channel {c.Channel}", $"6 GHz BSS {WifiFormat.Bssid(six.Bssid)} channel {six.Channel}"], scanBasis.Item1, scanBasis.Item2));
            }
        }

        // width and channel
        if (own is not null && own.Channel is { } ch)
        {
            if (own.Band == WifiBand.Band24 && own.WidthMhz >= 40)
            {
                var neighbours = input.Visible.Count(b => b.Band == WifiBand.Band24 && !b.Bssid.Equals(own.Bssid) && b.RssiDbm >= -82);
                list.Add(new("Channel width", AdviceSeverity.Suggestion,
                    "Use 20 MHz on 2.4 GHz: a 40 MHz channel there covers most of the band and overlaps the other networks.",
                    [$"the access point uses 40 MHz on channel {ch}", $"{neighbours} other 2.4 GHz network(s) at or above −82 dBm"],
                    AdviceConfidence.High, "established practice; the width is read from the AP's beacon"));
            }

            var width = own.WidthMhz ?? 20;
            var plan = ChannelPlanner.Plan(input.Visible, own.Band, width, input.Domain, own.Bssid, own.FrequencyMhz);
            var current = plan.Candidates.FirstOrDefault(x => ch >= x.Primary && WifiChannels.SubChannels(own.Band, x.Center, plan.WidthMhz).Contains(ch));
            if (own.Band == WifiBand.Band5 && width >= 160 && current is not null && current.CoChannel + current.Overlapping >= 2)
            {
                list.Add(new("Channel width", AdviceSeverity.Suggestion,
                    "Consider 80 MHz: the 160 MHz channel overlaps other networks, so they contend for the same airtime.",
                    [$"{current.CoChannel + current.Overlapping} other network(s) inside channel {current.Label}"], scanBasis.Item1, scanBasis.Item2));
            }

            if (plan.Best is { } best && current is not null)
            {
                var obs = new List<string> { $"current {current.Label}: score {current.Score:0.##} — {string.Join("; ", current.Evidence)}" };
                obs.Add($"best {best.Label}: score {best.Score:0.##} — {string.Join("; ", best.Evidence)}");
                if (!input.Domain.Known) obs.Add("regulatory domain " + input.Domain.Name + ": confirm the channel is allowed locally");
                if (plan.Excluded > 0) obs.Add($"{plan.Excluded} BSS(s) of the connected access point itself were left out");
                if (best.Primary != current.Primary && current.Score - best.Score >= 0.5)
                {
                    list.Add(new("Channel", AdviceSeverity.Suggestion,
                        $"Channel {best.Label} looks less busy than the current {current.Label}. Change it on the access point if interference near the AP is similar.",
                        obs, scanBasis.Item1, scanBasis.Item2 + "; heard here, not at the AP"));
                }
                else
                {
                    list.Add(new("Channel", AdviceSeverity.Info, $"The current channel {current.Label} is among the least busy that were observed.", obs,
                        scanBasis.Item1, scanBasis.Item2 + "; heard here, not at the AP"));
                }

                if (current.CoChannel >= 3)
                {
                    list.Add(new("Co-channel contention", AdviceSeverity.Warning,
                        "Several networks share this channel and take turns with the connected AP. Fewer, well-placed APs or a different channel reduce contention.",
                        [$"{current.CoChannel} other network(s) with their primary channel inside {current.Label}"], scanBasis.Item1, scanBasis.Item2));
                }

                if (own.Band == WifiBand.Band24 && current.Overlapping > 0)
                {
                    list.Add(new("Adjacent-channel interference", AdviceSeverity.Warning,
                        "Networks on channels between 1, 6 and 11 partly overlap this one and cannot coordinate with it. Keep 2.4 GHz networks on 1, 6 or 11.",
                        [$"{current.Overlapping} partly overlapping network(s)"], scanBasis.Item1, scanBasis.Item2));
                }
            }

            if (own.Ies.ChannelUtilizationPercent is { } u && u >= 50)
            {
                list.Add(new("Channel utilisation", AdviceSeverity.Warning, "The access point reports its channel busy for much of the time; expect lower throughput.",
                    [$"channel busy {u:0} % and {own.Ies.StationCount} station(s), as announced by the AP (BSS Load element: measured by the AP)"],
                    AdviceConfidence.High, "measured by the access point"));
            }
        }

        // roaming
        if (rssi is { } cur && cur < -72)
        {
            var stronger = input.Visible.Where(b => b.Ssid == c.Ssid && !b.Bssid.Equals(c.Bssid) && b.RssiDbm >= cur + 8).OrderByDescending(b => b.RssiDbm).FirstOrDefault();
            if (stronger is not null)
            {
                list.Add(new("Roaming", AdviceSeverity.Suggestion,
                    "The client stays on a weak access point while a clearly stronger one of the same network is heard (a \"sticky\" client). Check the adapter's roaming aggressiveness, and 802.11k/v support or a minimum-RSSI setting on the APs.",
                    [$"connected at {cur} dBm", $"{WifiFormat.Bssid(stronger.Bssid)} heard at {stronger.RssiDbm} dBm on channel {stronger.Channel}"],
                    scanBasis.Item1, scanBasis.Item2));
            }
        }

        var roams = input.Events.Count(e => e.Kind == WifiEventKind.Roamed);
        if (input.Samples.Count >= 2)
        {
            var span = input.Samples[^1].At - input.Samples[0].At;
            var perHour = span.TotalMinutes >= 5 ? roams / span.TotalHours : (double?)null;
            var tracker = new RoamingTracker();
            foreach (var s in input.Samples) tracker.Observe(s.At, s.Connected);
            var pingPong = tracker.PingPongs(TimeSpan.FromMinutes(2));
            if (pingPong >= 3 || perHour > 20)
            {
                list.Add(new("Roaming", AdviceSeverity.Warning,
                    "The client roams often between access points. Cells with similar signal overlap here; reduce AP transmit power or adjust roaming thresholds.",
                    [$"{roams} roam(s) in {span.TotalMinutes:0} min", $"{pingPong} back-and-forth roam(s) within 2 minutes"],
                    span.TotalMinutes >= 30 ? AdviceConfidence.High : AdviceConfidence.Medium, $"monitored for {span.TotalMinutes:0} min"));
            }

            var disconnects = input.Events.Count(e => e.Kind == WifiEventKind.Disconnected);
            var gw = WifiMonitor.GatewayStats(input.Samples, new MonitoringSettings { WindowSamples = input.Samples.Count });
            var basis = span.TotalMinutes >= 30 ? AdviceConfidence.High : span.TotalMinutes >= 5 ? AdviceConfidence.Medium : AdviceConfidence.Low;
            if (disconnects >= 2)
            {
                list.Add(new("Connection stability", AdviceSeverity.Warning, "The connection dropped repeatedly. Check signal at this position, driver updates and the AP's event log.",
                    [$"{disconnects} disconnect(s) in {span.TotalMinutes:0} min"], basis, $"monitored for {span.TotalMinutes:0} min"));
            }

            if (gw.Samples >= 10 && gw.LossPercent >= 2)
            {
                var weak = rssi is { } x && x < -70;
                list.Add(new("Packet loss", AdviceSeverity.Warning,
                    weak ? "Pings to the gateway are lost; the weak signal is a likely cause."
                         : "Pings to the gateway are lost although the signal is good: interference, a busy channel or the AP/backhaul are more likely than coverage.",
                    [$"gateway loss {gw.LossPercent:0.#} % of {gw.Samples} pings", $"jitter {gw.JitterMs?.ToString("0.#", CultureInfo.InvariantCulture) ?? "—"} ms", $"signal {rssi?.ToString(CultureInfo.InvariantCulture) ?? "?"} dBm"],
                    basis, $"{gw.Samples} gateway pings"));
            }
        }

        return list;
    }

    private static int Median(List<int> values)
    {
        var sorted = values.OrderBy(v => v).ToList();
        return sorted[sorted.Count / 2];
    }
}
