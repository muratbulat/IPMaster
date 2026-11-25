using System.Globalization;
using System.Text.RegularExpressions;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Results;

public enum FilterOperation
{
    Contains,
    NotContains,
    EqualTo,
    NotEqualTo,
    StartsWith,
    EndsWith,
    LessThan,
    GreaterThan,
    Regex,
    IsEmpty,
    IsNotEmpty,
}

public sealed record FilterCondition
{
    public string ColumnId { get; set; } = "ip";

    public FilterOperation Operation { get; set; } = FilterOperation.Contains;

    public string Value { get; set; } = "";
}

public enum FilterMode
{
    /// <summary>Matching rows are highlighted; all rows stay visible.</summary>
    Highlight,

    /// <summary>Only matching rows are shown.</summary>
    ShowOnlyMatching,
}

/// <summary>A compound filter (manual: advanced filter panel; saved filters = quick host filters).</summary>
public sealed record FilterDefinition
{
    public string Name { get; set; } = "";

    public IReadOnlyList<FilterCondition> Conditions { get; set; } = [];

    /// <summary>True: all conditions must match (AND); false: any (OR).</summary>
    public bool MatchAll { get; set; } = true;

    public FilterMode Mode { get; set; } = FilterMode.Highlight;
}

public enum ShareCategory
{
    Standard,
    Writable,
    Restricted,
    Administrative,
    Printer,
}

/// <summary>Compiled filter. Text comparisons are case-insensitive; LessThan/GreaterThan compare typed values
/// (IP addresses numerically, numbers, dates) when both sides parse, otherwise text ordinally.</summary>
public sealed class CompiledFilter
{
    private readonly List<(ResultColumn Column, FilterCondition Condition, Regex? Regex, IComparable? Typed)> _conditions = [];
    private readonly bool _matchAll;

    private CompiledFilter(bool matchAll) => _matchAll = matchAll;

    public static CompiledFilter Compile(FilterDefinition definition, out IReadOnlyList<string> errors, IReadOnlyList<ResultColumn>? columns = null)
    {
        ArgumentNullException.ThrowIfNull(definition);
        var errs = new List<string>();
        var f = new CompiledFilter(definition.MatchAll);
        foreach (var c in definition.Conditions)
        {
            var col = columns?.FirstOrDefault(x => x.Id == c.ColumnId) ?? ColumnCatalog.Find(c.ColumnId);
            if (col is null)
            {
                errs.Add($"Unknown column '{c.ColumnId}'.");
                continue;
            }

            Regex? regex = null;
            if (c.Operation == FilterOperation.Regex)
            {
                try
                {
                    regex = new Regex(c.Value, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
                }
                catch (ArgumentException ex)
                {
                    errs.Add($"Invalid regular expression '{c.Value}': {ex.Message}");
                    continue;
                }
            }

            f._conditions.Add((col, c, regex, ParseTyped(col.Kind, c.Value)));
        }

        errors = errs;
        return f;
    }

    public bool IsEmpty => _conditions.Count == 0;

    public bool Matches(DeviceResult device, ColumnFormat format)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (_conditions.Count == 0) return true;
        foreach (var c in _conditions)
        {
            var m = Evaluate(c, device, format);
            if (_matchAll && !m) return false;
            if (!_matchAll && m) return true;
        }

        return _matchAll;
    }

    private static bool Evaluate((ResultColumn Column, FilterCondition Condition, Regex? Regex, IComparable? Typed) c, DeviceResult d, ColumnFormat format)
    {
        var text = c.Column.Text(d, format);
        var v = c.Condition.Value;
        const StringComparison ci = StringComparison.OrdinalIgnoreCase;
        switch (c.Condition.Operation)
        {
            case FilterOperation.Contains: return text.Contains(v, ci);
            case FilterOperation.NotContains: return !text.Contains(v, ci);
            case FilterOperation.EqualTo: return string.Equals(text, v, ci);
            case FilterOperation.NotEqualTo: return !string.Equals(text, v, ci);
            case FilterOperation.StartsWith: return text.StartsWith(v, ci);
            case FilterOperation.EndsWith: return text.EndsWith(v, ci);
            case FilterOperation.IsEmpty: return text.Length == 0;
            case FilterOperation.IsNotEmpty: return text.Length > 0;
            case FilterOperation.Regex:
                try
                {
                    return c.Regex!.IsMatch(text);
                }
                catch (RegexMatchTimeoutException)
                {
                    return false;
                }

            case FilterOperation.LessThan:
            case FilterOperation.GreaterThan:
            {
                int cmp;
                var typed = c.Column.Value?.Invoke(d);
                if (c.Typed is not null && typed is not null && typed.GetType() == c.Typed.GetType()) cmp = typed.CompareTo(c.Typed);
                else if (typed is null && c.Typed is not null) return false; // no value: neither less nor greater
                else cmp = string.Compare(text, v, StringComparison.OrdinalIgnoreCase);
                return c.Condition.Operation == FilterOperation.LessThan ? cmp < 0 : cmp > 0;
            }

            default: return false;
        }
    }

    private static IComparable? ParseTyped(ColumnKind kind, string value) => kind switch
    {
        ColumnKind.IpAddress => TargetParser.TryParseAddress(value.Trim(), out var a) ? a : null,
        ColumnKind.Number => double.TryParse(value.Trim().TrimEnd('%', 's', 'm', ' '), NumberStyles.Float, CultureInfo.InvariantCulture, out var n)
            ? (IComparable)n
            : null,
        ColumnKind.DateTime => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out var t) ? t : null,
        _ => null,
    };
}

/// <summary>Built-in quick host filters and share-type filtering (manual: Shares filter panel).</summary>
public static class ShareFilters
{
    public static bool HasSharedFolders(DeviceResult d) =>
        d.Shares.HasValue && d.Shares.Value!.Any(s => s.Kind == ShareKind.Folder && !s.IsAdministrative);

    public static bool Matches(ShareInfo s, ShareCategory category) => category switch
    {
        ShareCategory.Standard => s.Kind == ShareKind.Folder && !s.IsAdministrative && s.TypeLetters.Contains('C', StringComparison.Ordinal),
        ShareCategory.Writable => s.TypeLetters.Contains('W', StringComparison.Ordinal),
        ShareCategory.Restricted => s.TypeLetters.Contains('R', StringComparison.Ordinal),
        ShareCategory.Administrative => s.IsAdministrative,
        ShareCategory.Printer => s.Kind == ShareKind.Printer,
        _ => false,
    };

    public static bool MatchesAny(ShareInfo s, IReadOnlyCollection<ShareCategory> categories) =>
        categories.Count == 0 || categories.Any(c => Matches(s, c));
}

public enum CompareKey
{
    IpAddress,
    MacAddress,
}

public enum ChangeKind
{
    Added,
    Removed,
    Changed,
    Unchanged,
}

public sealed record ColumnChange(string Column, string Before, string After);

public sealed record CompareRow(ChangeKind Change, string Key, DeviceResult? Before, DeviceResult? After, IReadOnlyList<ColumnChange> Changes);

public sealed record CompareResult(IReadOnlyList<CompareRow> Rows, int SkippedWithoutKey)
{
    public int Count(ChangeKind kind) => Rows.Count(r => r.Change == kind);
}

/// <summary>Compares two saved scans (manual: Reports → Compare Scans).</summary>
public static class ScanComparer
{
    public static CompareResult Compare(IReadOnlyList<DeviceResult> before, IReadOnlyList<DeviceResult> after, CompareKey key,
        IReadOnlyList<ResultColumn> columns, ColumnFormat? format = null)
    {
        ArgumentNullException.ThrowIfNull(before);
        ArgumentNullException.ThrowIfNull(after);
        ArgumentNullException.ThrowIfNull(columns);
        format ??= ColumnFormat.Default;
        var skipped = 0;

        Dictionary<string, DeviceResult> Index(IReadOnlyList<DeviceResult> list)
        {
            var map = new Dictionary<string, DeviceResult>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in list)
            {
                var k = KeyOf(d, key);
                if (k is null)
                {
                    skipped++;
                    continue;
                }

                map.TryAdd(k, d);
            }

            return map;
        }

        var a = Index(before);
        var b = Index(after);
        var rows = new List<CompareRow>();
        foreach (var (k, old) in a)
        {
            if (!b.TryGetValue(k, out var cur))
            {
                rows.Add(new CompareRow(ChangeKind.Removed, k, old, null, []));
                continue;
            }

            var changes = columns.Where(c => !string.Equals(c.Text(old, format), c.Text(cur, format), StringComparison.Ordinal)
                                             && c.Id is not ("lastScanned" or "lastSeen" or "rtt"))
                .Select(c => new ColumnChange(c.Header, c.Text(old, format), c.Text(cur, format)))
                .ToList();
            rows.Add(new CompareRow(changes.Count > 0 ? ChangeKind.Changed : ChangeKind.Unchanged, k, old, cur, changes));
        }

        foreach (var (k, cur) in b)
        {
            if (!a.ContainsKey(k)) rows.Add(new CompareRow(ChangeKind.Added, k, null, cur, []));
        }

        return new CompareResult(rows.OrderBy(r => r.Change).ThenBy(r => r.After?.Key ?? r.Before!.Key).ToList(), skipped);
    }

    private static string? KeyOf(DeviceResult d, CompareKey key) => key switch
    {
        CompareKey.MacAddress => d.Mac.HasValue ? Formats.Mac(d.Mac.Value!) : null,
        _ => d.Key.ToString(),
    };
}
