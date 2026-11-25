using System.Globalization;
using System.Text;

namespace IPMaster.Core.Wifi;

/// <summary>One BSS heard at a survey point.</summary>
public sealed class SurveyReading
{
    public string Ssid { get; set; } = "";

    public string Bssid { get; set; } = "";

    public int RssiDbm { get; set; }

    public int FrequencyMhz { get; set; }
}

/// <summary>A measurement location; X and Y are fractions (0–1) of the floor-plan image, so they survive resizing.</summary>
public sealed class SurveyPoint
{
    public double X { get; set; }

    public double Y { get; set; }

    public DateTimeOffset At { get; set; }

    public string Note { get; set; } = "";

    public List<SurveyReading> Readings { get; set; } = [];
}

/// <summary>A saved survey (JSON; persisted models use set accessors, D-016).</summary>
public sealed class SiteSurveyProject
{
    public string FloorPlanPath { get; set; } = "";

    public List<SurveyPoint> Points { get; set; } = [];
}

public sealed record CoverageSummary(string Bssid, string Ssid, int PointsHeard, int Points, int? MedianRssiDbm, int? BestRssiDbm, double PercentAtLeast67);

/// <summary>
/// Heatmaps and coverage comparison (D-097). The heatmap is an inverse-distance-weighted estimate between the measured
/// points, never a measurement: cells farther than <c>maxDistance</c> from every point stay empty. A point where the
/// selected AP was not heard counts as <see cref="NotHeardDbm"/> (it was measured: below what the adapter reports).
/// </summary>
public static class SiteSurvey
{
    public const int NotHeardDbm = -100;

    /// <summary>Per point, the strongest reading that matches <paramref name="match"/>.</summary>
    public static IReadOnlyList<(double X, double Y, double Value)> Values(SiteSurveyProject project, Func<SurveyReading, bool> match)
    {
        ArgumentNullException.ThrowIfNull(project);
        ArgumentNullException.ThrowIfNull(match);
        return project.Points.Select(p => (p.X, p.Y, (double)(p.Readings.Where(match).Select(r => (int?)r.RssiDbm).Max() ?? NotHeardDbm))).ToList();
    }

    /// <summary>
    /// Grid of estimates (rows × cols, row-major), null where no point is within <paramref name="maxDistance"/>. Distances
    /// are in plan widths: <paramref name="aspect"/> (height ÷ width of the plan) keeps them true on a non-square plan.
    /// </summary>
    public static double?[,] Interpolate(IReadOnlyList<(double X, double Y, double Value)> samples, int cols, int rows, double maxDistance = 0.25, double power = 2, double aspect = 1)
    {
        ArgumentNullException.ThrowIfNull(samples);
        var grid = new double?[rows, cols];
        if (samples.Count == 0 || cols <= 0 || rows <= 0) return grid;
        for (var r = 0; r < rows; r++)
        {
            for (var c = 0; c < cols; c++)
            {
                double x = (c + 0.5) / cols, y = (r + 0.5) / rows;
                double num = 0, den = 0;
                var near = false;
                double? exact = null;
                foreach (var s in samples)
                {
                    var d = Math.Sqrt(((s.X - x) * (s.X - x)) + ((s.Y - y) * (s.Y - y) * aspect * aspect));
                    if (d < 1e-9)
                    {
                        exact = s.Value;
                        break;
                    }

                    if (d <= maxDistance) near = true;
                    var w = 1 / Math.Pow(d, power);
                    num += w * s.Value;
                    den += w;
                }

                grid[r, c] = exact ?? (near ? num / den : null);
            }
        }

        return grid;
    }

    public static IReadOnlyList<CoverageSummary> Coverage(SiteSurveyProject project)
    {
        ArgumentNullException.ThrowIfNull(project);
        var total = project.Points.Count;
        return project.Points.SelectMany(p => p.Readings).GroupBy(r => r.Bssid, StringComparer.OrdinalIgnoreCase).Select(g =>
        {
            var perPoint = project.Points.Select(p => p.Readings.Where(r => string.Equals(r.Bssid, g.Key, StringComparison.OrdinalIgnoreCase)).Select(r => (int?)r.RssiDbm).Max()).ToList();
            var heard = perPoint.OfType<int>().OrderBy(v => v).ToList();
            return new CoverageSummary(g.Key, g.First().Ssid, heard.Count, total, heard.Count > 0 ? heard[heard.Count / 2] : null, heard.Count > 0 ? heard[^1] : null,
                total == 0 ? 0 : 100.0 * heard.Count(v => v >= -67) / total);
        }).OrderByDescending(c => c.PercentAtLeast67).ThenByDescending(c => c.MedianRssiDbm).ToList();
    }

    public static string Csv(SiteSurveyProject project)
    {
        ArgumentNullException.ThrowIfNull(project);
        var sb = new StringBuilder("point,x,y,time,note,ssid,bssid,rssi_dbm,frequency_mhz,channel\n");
        for (var i = 0; i < project.Points.Count; i++)
        {
            var p = project.Points[i];
            foreach (var r in p.Readings.DefaultIfEmpty(new SurveyReading { RssiDbm = NotHeardDbm }))
            {
                sb.AppendLine(string.Join(',', (i + 1).ToString(CultureInfo.InvariantCulture), p.X.ToString("0.####", CultureInfo.InvariantCulture),
                    p.Y.ToString("0.####", CultureInfo.InvariantCulture), p.At.ToString("O", CultureInfo.InvariantCulture), Quote(p.Note), Quote(r.Ssid), r.Bssid,
                    r.Bssid.Length == 0 ? "" : r.RssiDbm.ToString(CultureInfo.InvariantCulture), r.FrequencyMhz == 0 ? "" : r.FrequencyMhz.ToString(CultureInfo.InvariantCulture),
                    WifiChannels.ChannelOf(r.FrequencyMhz)?.ToString(CultureInfo.InvariantCulture) ?? ""));
            }
        }

        return sb.ToString();
    }

    // CSV-injection safe: a leading = + - @ is prefixed with an apostrophe (spreadsheets would evaluate it)
    private static string Quote(string s)
    {
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? "\"" + s.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : s;
    }
}
