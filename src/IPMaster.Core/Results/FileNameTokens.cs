using System.Globalization;
using System.Text;

namespace IPMaster.Core.Results;

/// <summary>
/// Expands manual date/time tokens enclosed in percent signs (<c>%yyyy%%mm%%dd%</c>).
/// Tokens: y yy yyyy m mm mmm mmmm d dd ddd dddd h hh n nn s ss. Names use invariant (English) culture
/// for reproducible file names (D-014). <c>y</c> is the two-digit year. Unknown tokens are left unchanged.
/// </summary>
public static class FileNameTokens
{
    public static string Expand(string pattern, DateTime now)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        var inv = CultureInfo.InvariantCulture;
        var sb = new StringBuilder(pattern.Length + 16);
        var i = 0;
        while (i < pattern.Length)
        {
            if (pattern[i] == '%')
            {
                var close = pattern.IndexOf('%', i + 1);
                if (close > i + 1)
                {
                    var token = pattern[(i + 1)..close];
                    var value = Token(token, now, inv);
                    if (value is not null)
                    {
                        sb.Append(value);
                        i = close + 1;
                        continue;
                    }
                }
            }

            sb.Append(pattern[i]);
            i++;
        }

        return sb.ToString();
    }

    private static string? Token(string t, DateTime d, CultureInfo c) => t.ToLowerInvariant() switch
    {
        "y" or "yy" => (d.Year % 100).ToString("00", c),
        "yyyy" => d.Year.ToString("0000", c),
        "m" => d.Month.ToString(c),
        "mm" => d.Month.ToString("00", c),
        "mmm" => c.DateTimeFormat.GetAbbreviatedMonthName(d.Month),
        "mmmm" => c.DateTimeFormat.GetMonthName(d.Month),
        "d" => d.Day.ToString(c),
        "dd" => d.Day.ToString("00", c),
        "ddd" => c.DateTimeFormat.GetAbbreviatedDayName(d.DayOfWeek),
        "dddd" => c.DateTimeFormat.GetDayName(d.DayOfWeek),
        "h" => d.Hour.ToString(c),
        "hh" => d.Hour.ToString("00", c),
        "n" => d.Minute.ToString(c),
        "nn" => d.Minute.ToString("00", c),
        "s" => d.Second.ToString(c),
        "ss" => d.Second.ToString("00", c),
        _ => null,
    };
}
