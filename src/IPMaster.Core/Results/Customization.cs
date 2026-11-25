using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Results;

/// <summary>Manual "Virtual columns": <c>[Column Name]</c> references combined into one value, optionally transformed
/// by a regular expression and replacement.</summary>
public sealed record VirtualColumnDefinition
{
    public string Name { get; set; } = "";

    /// <summary>Source expression, e.g. <c>[Host Name] ([MAC Address])</c>.</summary>
    public string Source { get; set; } = "";

    public string Regex { get; set; } = "";

    public string Replacement { get; set; } = "";
}

public enum StyleCondition
{
    None,
    Equal,
    NotEqual,
    Contains,
    NotContains,
    LessThan,
    GreaterThan,
    Regex,
}

/// <summary>Manual "Change Column View": colours, font styles, display transform and highlighting condition.</summary>
public sealed record ColumnStyle
{
    public string ColumnId { get; set; } = "";

    public string Background { get; set; } = "";

    public string Foreground { get; set; } = "";

    public bool Bold { get; set; }

    public bool Italic { get; set; }

    public bool Underline { get; set; }

    public bool Strikethrough { get; set; }

    public string Regex { get; set; } = "";

    public string Replacement { get; set; } = "";

    public StyleCondition Condition { get; set; }

    public string ConditionValue { get; set; } = "";

    public bool HasFormatting => Background.Length > 0 || Foreground.Length > 0 || Bold || Italic || Underline || Strikethrough;
}

public sealed record FriendlyEntry
{
    /// <summary>Identifying value(s) joined with " | " in the order of <see cref="FriendlyNameSettings.IdentifyBy"/>.</summary>
    public string Key { get; set; } = "";

    public string Name { get; set; } = "";

    public Dictionary<string, string> Data { get; set; } = [];
}

/// <summary>Manual "Friendly names and comments": labels and associated data keyed by one or more columns.</summary>
public sealed record FriendlyNameSettings
{
    /// <summary>Identifying column ids; empty = "No mapping" (friendly names disabled).</summary>
    public IReadOnlyList<string> IdentifyBy { get; set; } = ["mac"];

    /// <summary>Associated data parameter names (e.g. Asset tag, Location, Owner).</summary>
    public IReadOnlyList<string> Parameters { get; set; } = [];

    public IReadOnlyList<FriendlyEntry> Entries { get; set; } = [];

    public bool Enabled => IdentifyBy.Count > 0;
}

public enum ImportMode
{
    /// <summary>Only entries whose key is not present yet are added.</summary>
    Append,

    /// <summary>New entries are added and existing keys are updated.</summary>
    Merge,

    /// <summary>The list is replaced.</summary>
    Replace,
}

/// <summary>Bounded regular expressions for user-supplied display transforms (regex execution is bounded).</summary>
public static class SafeRegex
{
    public static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(100);

    public static string? Validate(string pattern)
    {
        if (string.IsNullOrEmpty(pattern)) return null;
        try
        {
            _ = new Regex(pattern, RegexOptions.CultureInvariant, Timeout);
            return null;
        }
        catch (ArgumentException ex)
        {
            return ex.Message;
        }
    }

    public static string Replace(string input, string pattern, string replacement)
    {
        if (string.IsNullOrEmpty(pattern)) return input;
        try
        {
            return System.Text.RegularExpressions.Regex.Replace(input, pattern, replacement, RegexOptions.CultureInvariant, Timeout);
        }
        catch (RegexMatchTimeoutException)
        {
            return "[regex timeout]";
        }
        catch (ArgumentException)
        {
            return "[invalid regex]";
        }
    }

    public static bool IsMatch(string input, string pattern)
    {
        try
        {
            return System.Text.RegularExpressions.Regex.IsMatch(input, pattern, RegexOptions.CultureInvariant | RegexOptions.IgnoreCase, Timeout);
        }
        catch (Exception ex) when (ex is RegexMatchTimeoutException or ArgumentException)
        {
            return false;
        }
    }
}

public static class ColumnStyles
{
    /// <summary>Display text after the column's regex transform.</summary>
    public static string Transform(ColumnStyle? style, string text) =>
        style is null || style.Regex.Length == 0 ? text : SafeRegex.Replace(text, style.Regex, style.Replacement);

    /// <summary>Whether the formatting applies to a cell (always when no condition is set). Evaluated on the original value.</summary>
    public static bool Applies(ColumnStyle style, string text)
    {
        ArgumentNullException.ThrowIfNull(style);
        ArgumentNullException.ThrowIfNull(text);
        var v = style.ConditionValue;
        const StringComparison ci = StringComparison.OrdinalIgnoreCase;
        return style.Condition switch
        {
            StyleCondition.None => true,
            StyleCondition.Equal => string.Equals(text, v, ci),
            StyleCondition.NotEqual => !string.Equals(text, v, ci),
            StyleCondition.Contains => text.Contains(v, ci),
            StyleCondition.NotContains => !text.Contains(v, ci),
            StyleCondition.LessThan => Compare(text, v) is < 0,
            StyleCondition.GreaterThan => Compare(text, v) is > 0,
            StyleCondition.Regex => SafeRegex.IsMatch(text, v),
            _ => false,
        };
    }

    private static int? Compare(string a, string b)
    {
        if (LeadingNumber(a) is { } x && LeadingNumber(b) is { } y) return x.CompareTo(y);
        return a.Length == 0 ? null : string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    private static double? LeadingNumber(string s)
    {
        var t = new string(s.Trim().TakeWhile(c => char.IsAsciiDigit(c) || c is '.' or '-' or '<').Where(c => c != '<').ToArray());
        return double.TryParse(t, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
    }
}

/// <summary>Builds the full column set: enabled built-in columns, friendly-name columns and virtual columns.</summary>
public static class ColumnSet
{
    public const string FriendlyNameId = "friendly";
    public const string FriendlyDataPrefix = "fd:";
    public const string VirtualPrefix = "v:";

    public static IReadOnlyList<ResultColumn> Build(ScanSettings scan, FriendlyNameSettings friendly, IReadOnlyList<VirtualColumnDefinition> virtualColumns,
        Queries.QuerySettings? queries = null)
    {
        ArgumentNullException.ThrowIfNull(scan);
        ArgumentNullException.ThrowIfNull(friendly);
        ArgumentNullException.ThrowIfNull(virtualColumns);
        var list = new List<ResultColumn>(ColumnCatalog.EnabledFor(scan));
        if (friendly.Enabled && (friendly.Entries.Count > 0 || friendly.Parameters.Count > 0))
        {
            var map = new FriendlyNameMap(friendly);
            list.Insert(Math.Min(1, list.Count), new ResultColumn(FriendlyNameId, "Friendly Name", ColumnKind.Text, (d, _) => map.Find(d)?.Name ?? ""));
            foreach (var p in friendly.Parameters)
            {
                var param = p;
                list.Add(new ResultColumn(FriendlyDataPrefix + param, param, ColumnKind.Text, (d, _) => map.Find(d)?.Data.GetValueOrDefault(param) ?? ""));
            }
        }

        if (queries is not null) list.AddRange(Queries.QueryColumns.For(queries));

        foreach (var v in virtualColumns.Where(v => v.Name.Length > 0))
        {
            var def = v;
            var available = list.ToList(); // only columns defined before this one: no forward references, so no cycles
            list.Add(new ResultColumn(VirtualPrefix + def.Name, def.Name, ColumnKind.Text, (d, f) => Evaluate(def, available, d, f)));
        }

        return list;
    }

    /// <summary>Replaces <c>[Header]</c> or <c>[id]</c> references with the referenced column text, then applies the regex.</summary>
    public static string Evaluate(VirtualColumnDefinition def, IReadOnlyList<ResultColumn> available, DeviceResult device, ColumnFormat format)
    {
        ArgumentNullException.ThrowIfNull(def);
        ArgumentNullException.ThrowIfNull(available);
        var sb = new StringBuilder();
        var s = def.Source;
        for (var i = 0; i < s.Length; i++)
        {
            if (s[i] == '[')
            {
                var close = s.IndexOf(']', i + 1);
                if (close > i)
                {
                    var name = s[(i + 1)..close];
                    var col = available.FirstOrDefault(c => string.Equals(c.Header, name, StringComparison.OrdinalIgnoreCase)
                                                            || string.Equals(c.Id, name, StringComparison.OrdinalIgnoreCase));
                    sb.Append(col is null ? $"[unknown column {name}]" : col.Text(device, format));
                    i = close;
                    continue;
                }
            }

            sb.Append(s[i]);
        }

        return SafeRegex.Replace(sb.ToString(), def.Regex, def.Replacement);
    }

    /// <summary>Validates a virtual column against the columns defined before it.</summary>
    public static string? Validate(VirtualColumnDefinition def, IReadOnlyList<ResultColumn> available)
    {
        ArgumentNullException.ThrowIfNull(def);
        if (string.IsNullOrWhiteSpace(def.Name)) return "Name is required.";
        if (SafeRegex.Validate(def.Regex) is { } e) return "Regular expression: " + e;
        var refs = System.Text.RegularExpressions.Regex.Matches(def.Source, @"\[([^\]]+)\]").Select(m => m.Groups[1].Value);
        foreach (var r in refs)
        {
            if (string.Equals(r, def.Name, StringComparison.OrdinalIgnoreCase)) return $"The column cannot refer to itself ([{r}]).";
            if (!available.Any(c => string.Equals(c.Header, r, StringComparison.OrdinalIgnoreCase) || string.Equals(c.Id, r, StringComparison.OrdinalIgnoreCase)))
            {
                return $"Unknown column [{r}] (only built-in columns and virtual columns defined earlier can be used).";
            }
        }
        return null;
    }
}

/// <summary>Key computation and lookup for friendly names (manual: "Identify by").</summary>
public sealed class FriendlyNameMap
{
    private static readonly string[] HeaderStart = ["Key", "Friendly Name"];
    private static readonly char[] Delimiters = [',', ';', '	'];

    private readonly FriendlyNameSettings _settings;
    private readonly Dictionary<string, FriendlyEntry> _byKey;

    public FriendlyNameMap(FriendlyNameSettings settings)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _byKey = new Dictionary<string, FriendlyEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in settings.Entries) _byKey.TryAdd(NormalizeKey(e.Key), e);
    }

    /// <summary>Key of a device; null when any identifying value is missing. MAC keys are format-independent.</summary>
    public static string? KeyOf(DeviceResult device, IReadOnlyList<string> identifyBy)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(identifyBy);
        var parts = new List<string>();
        foreach (var id in identifyBy)
        {
            string text;
            if (id == "mac") text = device.Mac.HasValue ? Formats.Mac(device.Mac.Value!, "-") : "";
            else text = ColumnCatalog.Find(id)?.Text(device) ?? "";
            if (text.Length == 0 || text.StartsWith('[')) return null;
            parts.Add(text);
        }

        return parts.Count == 0 ? null : string.Join(" | ", parts);
    }

    public static string NormalizeKey(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        // Accept any MAC spelling in imported/typed keys.
        return string.Join(" | ", key.Split('|').Select(p => p.Trim()).Select(p => Formats.ParseMac(p) is { } m ? Formats.Mac(m, "-") : p));
    }

    public FriendlyEntry? Find(DeviceResult device)
    {
        var key = KeyOf(device, _settings.IdentifyBy);
        return key is null ? null : _byKey.GetValueOrDefault(NormalizeKey(key));
    }

    public static IReadOnlyList<FriendlyEntry> Upsert(IReadOnlyList<FriendlyEntry> entries, FriendlyEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(entry);
        var key = NormalizeKey(entry.Key);
        var list = entries.Where(e => !string.Equals(NormalizeKey(e.Key), key, StringComparison.OrdinalIgnoreCase)).ToList();
        if (entry.Name.Length > 0 || entry.Data.Values.Any(v => v.Length > 0)) list.Add(entry with { Key = key });
        return list;
    }

    // ---- CSV import / export (manual: Export and Import with append, merge or replace) ----
    public static string ExportCsv(FriendlyNameSettings settings, char delimiter = ',')
    {
        ArgumentNullException.ThrowIfNull(settings);
        using var w = new StringWriter(CultureInfo.InvariantCulture);
        CsvExporter.WriteRow(w, HeaderStart.Concat(settings.Parameters), delimiter, protectFormulas: true);
        foreach (var e in settings.Entries)
        {
            CsvExporter.WriteRow(w, new[] { e.Key, e.Name }.Concat(settings.Parameters.Select(p => e.Data.GetValueOrDefault(p) ?? "")), delimiter, protectFormulas: true);
        }

        return w.ToString();
    }

    /// <summary>Imports CSV (header: Key, Friendly Name, parameters…). Unknown parameter columns are added to the parameter list.</summary>
    public static FriendlyNameSettings ImportCsv(FriendlyNameSettings settings, string csv, ImportMode mode, out int imported)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(csv);
        var rows = ParseCsv(csv);
        imported = 0;
        if (rows.Count == 0) return settings;
        var header = rows[0];
        var start = header.Count >= 2 && header[0].Equals("Key", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        var paramNames = start == 1 ? header.Skip(2).ToList() : settings.Parameters.ToList();
        var parameters = settings.Parameters.Concat(paramNames.Where(p => !settings.Parameters.Contains(p))).ToList();
        var entries = mode == ImportMode.Replace ? new List<FriendlyEntry>() : settings.Entries.ToList();
        foreach (var r in rows.Skip(start))
        {
            if (r.Count == 0 || string.IsNullOrWhiteSpace(r[0])) continue;
            var key = NormalizeKey(UnprotectCell(r[0]));
            var existing = entries.FindIndex(e => string.Equals(NormalizeKey(e.Key), key, StringComparison.OrdinalIgnoreCase));
            if (existing >= 0 && mode == ImportMode.Append) continue;
            var data = new Dictionary<string, string>();
            for (var i = 0; i < paramNames.Count && i + 2 < r.Count; i++) data[paramNames[i]] = UnprotectCell(r[i + 2]);
            var entry = new FriendlyEntry { Key = key, Name = r.Count > 1 ? UnprotectCell(r[1]) : "", Data = data };
            if (existing >= 0) entries[existing] = entry;
            else entries.Add(entry);
            imported++;
        }

        return settings with { Parameters = parameters, Entries = entries };
    }

    private static string UnprotectCell(string s) => s.Length > 1 && s[0] == '\'' && s[1] is '=' or '+' or '-' or '@' ? s[1..] : s;

    /// <summary>RFC 4180 parsing with automatic delimiter detection (comma, semicolon or tab).</summary>
    public static List<List<string>> ParseCsv(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var firstLine = text.Split('\n')[0];
        var delimiter = Delimiters.OrderByDescending(d => firstLine.Count(c => c == d)).First();
        var rows = new List<List<string>>();
        var row = new List<string>();
        var cell = new StringBuilder();
        var quoted = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (quoted)
            {
                if (c == '"' && i + 1 < text.Length && text[i + 1] == '"')
                {
                    cell.Append('"');
                    i++;
                }
                else if (c == '"')
                {
                    quoted = false;
                }
                else
                {
                    cell.Append(c);
                }

                continue;
            }

            if (c == '"') quoted = true;
            else if (c == delimiter)
            {
                row.Add(cell.ToString());
                cell.Clear();
            }
            else if (c == '\n' || c == '\r')
            {
                if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                row.Add(cell.ToString());
                cell.Clear();
                if (row.Any(x => x.Length > 0)) rows.Add(row);
                row = [];
            }
            else if (c != '﻿')
            {
                cell.Append(c);
            }
        }

        row.Add(cell.ToString());
        if (row.Any(x => x.Length > 0)) rows.Add(row);
        return rows;
    }
}
