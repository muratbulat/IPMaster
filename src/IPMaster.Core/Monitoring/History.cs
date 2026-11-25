using System.Globalization;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Monitoring;

/// <summary>History tab (HIS-03).</summary>
public sealed record HistorySettings
{
    public bool Enabled { get; set; }

    public int RetentionDays { get; set; } = 90;

    public bool ShowFirstSeen { get; set; } = true;

    public bool ShowLastSeen { get; set; } = true;

    public bool ShowAvailability { get; set; } = true;
}

/// <summary>A LAN recognised by its gateway (HIS-01).</summary>
public sealed record NetworkIdentity(string Fingerprint, string Name)
{
    /// <summary>"gateway:&lt;address&gt;" when the network has a default gateway, also when <see cref="Fingerprint"/> is its MAC:
    /// lets history keep one network when the gateway MAC is missing for a session (D-088).</summary>
    public string? Gateway { get; init; }
}

public sealed record HistoryDevice(string Mac, DateTimeOffset FirstSeen, DateTimeOffset LastSeen, string LastIp, string LastHost, int Eligible, int Online,
    IReadOnlyList<double?> RecentRtt)
{
    /// <summary>Percent of eligible (complete, covering) sessions since first sighting in which the device answered.</summary>
    public double? Availability => Eligible == 0 ? null : 100.0 * Online / Eligible;
}

public sealed record Sighting(DateTimeOffset At, string Ip, string Host, double? RttMs, bool Online);

public enum InventoryPeriod
{
    Day,
    Week,
    Month,
    Quarter,
    All,
}

public enum InventoryShow
{
    All,
    NewInPeriod,
    Disappeared,
}

/// <summary>Device history storage (SQLite in Infrastructure). Devices without a MAC are never recorded (HIS-06).</summary>
public interface IHistoryStore
{
    /// <summary>Records one finished scan session; returns MACs seen for the first time on this network (empty for the network's first session).</summary>
    IReadOnlySet<string> RecordSession(NetworkIdentity network, DateTimeOffset started, DateTimeOffset finished, bool complete,
        IReadOnlyCollection<DeviceResult> results, Func<string, bool> eligibleIp);

    IReadOnlyDictionary<string, HistoryDevice> Devices(NetworkIdentity network);

    IReadOnlyList<Sighting> Timeline(NetworkIdentity network, string mac, DateTimeOffset? from, int max = 5000);

    int Cleanup(int retentionDays, DateTimeOffset now);
}

public static class HistoryText
{
    public static string Relative(DateTimeOffset at, DateTimeOffset now)
    {
        var d = now - at;
        if (d < TimeSpan.FromMinutes(1)) return "just now";
        if (d < TimeSpan.FromHours(1)) return $"{(int)d.TotalMinutes} min ago";
        if (d < TimeSpan.FromDays(1)) return $"{(int)d.TotalHours} h ago";
        if (d < TimeSpan.FromDays(60)) return $"{(int)d.TotalDays} days ago";
        return at.ToLocalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
    }

    public static string MacKey(System.Net.NetworkInformation.PhysicalAddress mac) => Formats.Mac(mac, ":").ToUpperInvariant();

    public static DateTimeOffset? From(InventoryPeriod p, DateTimeOffset now) => p switch
    {
        InventoryPeriod.Day => now.AddDays(-1),
        InventoryPeriod.Week => now.AddDays(-7),
        InventoryPeriod.Month => now.AddDays(-30),
        InventoryPeriod.Quarter => now.AddDays(-90),
        _ => null,
    };

    /// <summary>
    /// Inventory filter (HIS-05): All = seen during the period (everything for all time); New = first seen inside the
    /// period; Disappeared = present before the period but not seen during it.
    /// </summary>
    public static IEnumerable<HistoryDevice> Filter(IEnumerable<HistoryDevice> devices, DateTimeOffset? from, InventoryShow show)
    {
        ArgumentNullException.ThrowIfNull(devices);
        if (from is not { } f) return devices;
        return show switch
        {
            InventoryShow.NewInPeriod => devices.Where(d => d.FirstSeen >= f),
            InventoryShow.Disappeared => devices.Where(d => d.FirstSeen < f && d.LastSeen < f),
            _ => devices.Where(d => d.LastSeen >= f),
        };
    }

    /// <summary>"▁▃▅▇" equaliser of recent response times (lost = space).</summary>
    public static string Sparkline(IReadOnlyList<double?> rtts)
    {
        ArgumentNullException.ThrowIfNull(rtts);
        const string bars = "▁▂▃▄▅▆▇█";
        var values = rtts.Where(r => r is not null).Select(r => r!.Value).ToList();
        if (values.Count == 0) return "";
        var max = Math.Max(1, values.Max());
        return new string(rtts.Select(r => r is { } v ? bars[Math.Clamp((int)Math.Round(v / max * (bars.Length - 1)), 0, bars.Length - 1)] : ' ').ToArray());
    }
}

/// <summary>History columns (HIS-02). <see cref="HistoryView"/> is refreshed after each recorded session.</summary>
public sealed class HistoryView
{
    public IReadOnlyDictionary<string, HistoryDevice> Devices { get; set; } = new Dictionary<string, HistoryDevice>();

    /// <summary>MACs first seen in the latest session (shown bold), except on a network's first session.</summary>
    public IReadOnlySet<string> Newcomers { get; set; } = new HashSet<string>();

    public NetworkIdentity? Network { get; set; }

    public HistoryDevice? For(DeviceResult d) =>
        d.Mac.HasValue && Devices.TryGetValue(HistoryText.MacKey(d.Mac.Value!), out var h) ? h : null;

    public bool IsNewcomer(DeviceResult d) => d.Mac.HasValue && Newcomers.Contains(HistoryText.MacKey(d.Mac.Value!));

    public IEnumerable<ResultColumn> Columns(HistorySettings s, Func<DateTimeOffset> now)
    {
        ArgumentNullException.ThrowIfNull(s);
        if (!s.Enabled) yield break;
        if (s.ShowFirstSeen) yield return new ResultColumn("h:first", "First Seen", ColumnKind.DateTime, (d, _) => For(d) is { } h ? HistoryText.Relative(h.FirstSeen, now()) : "", d => For(d)?.FirstSeen);
        if (s.ShowLastSeen) yield return new ResultColumn("h:last", "Last Seen (History)", ColumnKind.DateTime, (d, _) => For(d) is { } h ? HistoryText.Relative(h.LastSeen, now()) : "", d => For(d)?.LastSeen);
        if (s.ShowAvailability)
        {
            yield return new ResultColumn("h:avail", "Availability", ColumnKind.Number,
                (d, _) => For(d) is { Availability: { } a } h ? $"{a:0.#} % ({h.Online}/{h.Eligible})" : "", d => For(d)?.Availability);
        }
    }
}
