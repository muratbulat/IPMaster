using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace IPMaster.Core.Results;

/// <summary>
/// Type-aware order for displayed table values (sorting by column header). Each value is classified by its own form, so
/// the order is total and transitive: IP addresses (by address, IPv4 before IPv6), then numbers (with units normalised:
/// ms/s, bit and byte rates, sizes, %; durations such as "13 min 20 sec" in seconds), then dates and times, then text in
/// natural order ("host2" before "host10", case-insensitive by default). Empty values and "—" sort last.
/// </summary>
public static partial class ValueOrder
{
    private enum Kind
    {
        Address,
        Number,
        Date,
        Text,
        Empty,
    }

    private static readonly Dictionary<string, double> Units = new(StringComparer.Ordinal)
    {
        // time → seconds
        ["µs"] = 1e-6, ["us"] = 1e-6, ["ms"] = 1e-3, ["s"] = 1, ["sec"] = 1, ["min"] = 60, ["h"] = 3600,
        // rates → bits per second
        ["bps"] = 1, ["bit/s"] = 1, ["kbps"] = 1e3, ["kbit/s"] = 1e3, ["Mbps"] = 1e6, ["Mbit/s"] = 1e6, ["Gbps"] = 1e9, ["Gbit/s"] = 1e9, ["Tbps"] = 1e12,
        ["B/s"] = 8, ["kB/s"] = 8e3, ["KB/s"] = 8e3, ["MB/s"] = 8e6, ["GB/s"] = 8e9, ["TB/s"] = 8e12, ["KiB/s"] = 8 * 1024.0, ["MiB/s"] = 8 * 1048576.0, ["GiB/s"] = 8 * 1073741824.0,
        // sizes → bytes
        ["B"] = 1, ["bytes"] = 1, ["kB"] = 1e3, ["KB"] = 1e3, ["MB"] = 1e6, ["GB"] = 1e9, ["TB"] = 1e12, ["PB"] = 1e15,
        ["KiB"] = 1024, ["MiB"] = 1048576, ["GiB"] = 1073741824, ["TiB"] = 1099511627776,
        // plain measures
        ["%"] = 1, ["dBm"] = 1, ["dB"] = 1, ["MHz"] = 1, ["GHz"] = 1e3, ["°"] = 1, ["ppm"] = 1,
    };

    [GeneratedRegex(@"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")]
    private static partial Regex Ipv4();

    [GeneratedRegex(@"^(?<n>[-+−]?\d[\d.,  ]*)\s*(?<u>[A-Za-zµ%°/]+)?$")]
    private static partial Regex NumberWithUnit();

    [GeneratedRegex(@"^(?:(?<n>\d+(?:[.,]\d+)?)\s*(?<u>days?|h|min|sec|s|ms)\s*)+$")]
    private static partial Regex Duration();

    public static int Compare(string? a, string? b, bool ignoreCase = true, CultureInfo? culture = null)
    {
        culture ??= CultureInfo.CurrentCulture;
        var (ka, va) = Classify(a, culture);
        var (kb, vb) = Classify(b, culture);
        if (ka != kb) return ka.CompareTo(kb);
        return ka switch
        {
            Kind.Address => CompareBytes((byte[])va!, (byte[])vb!),
            Kind.Number => ((double)va!).CompareTo((double)vb!),
            Kind.Date => ((DateTime)va!).CompareTo((DateTime)vb!),
            Kind.Text => Natural((string)va!, (string)vb!, ignoreCase, culture),
            _ => 0,
        };
    }

    /// <summary>No value: empty, whitespace or a placeholder dash. Such values sort last.</summary>
    public static bool IsEmpty(string? text) => text?.Trim() is null or "" or "—" or "-" or "–" or "n/a";

    /// <summary>An <see cref="IComparer{T}"/> for strings with this order.</summary>
    public static IComparer<string?> Comparer(bool ignoreCase = true) => Comparer<string?>.Create((x, y) => Compare(x, y, ignoreCase));

    private static (Kind, object?) Classify(string? text, CultureInfo culture)
    {
        if (IsEmpty(text)) return (Kind.Empty, null);
        var s = text!.Trim();
        if (Address(s) is { } bytes) return (Kind.Address, bytes);
        if (Number(s, culture) is { } n) return (Kind.Number, n);
        if (s.Any(char.IsDigit) && (s.Contains(':', StringComparison.Ordinal) || s.Contains('-', StringComparison.Ordinal) || s.Contains('/', StringComparison.Ordinal))
            && DateTime.TryParse(s, culture, DateTimeStyles.AllowWhiteSpaces, out var d)) return (Kind.Date, d);
        return (Kind.Text, s);
    }

    /// <summary>IPv4 (dotted quad, optional /prefix) or IPv6; 18 bytes: family, 16 address bytes (IPv4 mapped), prefix last.</summary>
    private static byte[]? Address(string s)
    {
        var prefix = 255;
        var host = s;
        var slash = s.IndexOf('/', StringComparison.Ordinal);
        if (slash > 0 && int.TryParse(s[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out var p))
        {
            host = s[..slash];
            prefix = p;
        }

        var v4 = Ipv4().IsMatch(s);
        if (!v4 && !host.Contains(':', StringComparison.Ordinal)) return null;
        if (!IPAddress.TryParse(host, out var ip)) return null;
        if (!v4 && ip.AddressFamily != AddressFamily.InterNetworkV6) return null;
        var bytes = new byte[18];
        bytes[0] = (byte)(ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1);
        (ip.AddressFamily == AddressFamily.InterNetwork ? ip.MapToIPv6() : ip).GetAddressBytes().CopyTo(bytes, 1);
        bytes[17] = (byte)Math.Min(prefix, 255);
        return bytes;
    }

    private static double? Number(string s, CultureInfo culture)
    {
        var duration = Duration().Match(s);
        if (duration.Success && duration.Groups["u"].Captures.Count > 1)
        {
            double total = 0;
            for (var i = 0; i < duration.Groups["n"].Captures.Count; i++)
            {
                var unit = duration.Groups["u"].Captures[i].Value;
                var factor = unit.StartsWith("day", StringComparison.Ordinal) ? 86_400 : Units[unit];
                total += ParseNumber(duration.Groups["n"].Captures[i].Value, culture) * factor;
            }

            return total;
        }

        var m = NumberWithUnit().Match(s);
        if (!m.Success) return null;
        var multiplier = 1.0;
        if (m.Groups["u"].Success)
        {
            var u = m.Groups["u"].Value;
            if (u.StartsWith("day", StringComparison.Ordinal)) multiplier = 86_400;
            else if (!Units.TryGetValue(u, out multiplier)) return null; // an unknown word after a number is text ("3 items" stays text)
        }

        var value = ParseNumber(m.Groups["n"].Value, culture);
        return double.IsNaN(value) ? null : value * multiplier;
    }

    private static double ParseNumber(string text, CultureInfo culture)
    {
        var t = text.Replace('−', '-').Replace(" ", "", StringComparison.Ordinal).Replace(" ", "", StringComparison.Ordinal);
        const NumberStyles styles = NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint | NumberStyles.AllowThousands;
        return double.TryParse(t, styles, culture, out var v) || double.TryParse(t, styles, CultureInfo.InvariantCulture, out v) ? v : double.NaN;
    }

    private static int CompareBytes(byte[] a, byte[] b)
    {
        for (var i = 0; i < a.Length; i++)
        {
            var c = a[i].CompareTo(b[i]);
            if (c != 0) return c;
        }

        return 0;
    }

    /// <summary>Digit runs compare as numbers, the rest as text.</summary>
    private static int Natural(string a, string b, bool ignoreCase, CultureInfo culture)
    {
        var options = ignoreCase ? CompareOptions.IgnoreCase : CompareOptions.None;
        int i = 0, j = 0;
        while (i < a.Length && j < b.Length)
        {
            if (char.IsDigit(a[i]) && char.IsDigit(b[j]))
            {
                int si = i, sj = j;
                while (i < a.Length && char.IsDigit(a[i])) i++;
                while (j < b.Length && char.IsDigit(b[j])) j++;
                var da = a[si..i].TrimStart('0');
                var db = b[sj..j].TrimStart('0');
                var c = da.Length != db.Length ? da.Length.CompareTo(db.Length) : string.CompareOrdinal(da, db);
                if (c != 0) return c;
            }
            else
            {
                int si = i, sj = j;
                while (i < a.Length && !char.IsDigit(a[i])) i++;
                while (j < b.Length && !char.IsDigit(b[j])) j++;
                var c = culture.CompareInfo.Compare(a[si..i], b[sj..j], options);
                if (c != 0) return c;
            }
        }

        var rest = (a.Length - i).CompareTo(b.Length - j);
        return rest != 0 ? rest : culture.CompareInfo.Compare(a, b, options); // equal ignoring case and zeros: stable tie-break
    }
}
