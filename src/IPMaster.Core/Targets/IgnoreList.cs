using System.Globalization;
using System.Text.RegularExpressions;

namespace IPMaster.Core.Targets;

/// <summary>
/// Addresses that are never scanned. Each line is an address, range, CIDR block, or a wildcard pattern.
/// IPv4 wildcards apply per octet (<c>10.0.0.*</c>, <c>10.?.1.1</c>, <c>192.168.1*.*</c>);
/// IPv6 wildcards match the compressed lower-case text form. See D-012.
/// </summary>
public sealed class IgnoreList
{
    private readonly List<(AddressKey Start, AddressKey End)> _ranges = [];
    private readonly List<bool[][]> _v4Patterns = [];
    private readonly List<Regex> _v6Patterns = [];

    public static IgnoreList Empty { get; } = new([]);

    public IReadOnlyList<RejectedLine> Rejected { get; }

    public bool IsEmpty => _ranges.Count == 0 && _v4Patterns.Count == 0 && _v6Patterns.Count == 0;

    public IgnoreList(IEnumerable<string> lines)
    {
        ArgumentNullException.ThrowIfNull(lines);
        var rejected = new List<RejectedLine>();
        var n = 0;
        foreach (var raw in lines)
        {
            n++;
            var line = raw?.Trim() ?? "";
            if (line.Length == 0 || line[0] == '#') continue;
            if (line.Contains('*', StringComparison.Ordinal) || line.Contains('?', StringComparison.Ordinal))
            {
                if (line.Contains(':', StringComparison.Ordinal))
                {
                    var pattern = "^" + Regex.Escape(line.ToLowerInvariant()).Replace(@"\*", ".*", StringComparison.Ordinal)
                        .Replace(@"\?", ".", StringComparison.Ordinal) + "$";
                    _v6Patterns.Add(new Regex(pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50)));
                }
                else if (TryBuildV4Pattern(line, out var table))
                {
                    _v4Patterns.Add(table);
                }
                else
                {
                    rejected.Add(new RejectedLine(n, line, "Invalid IPv4 wildcard pattern."));
                }

                continue;
            }

            if (TargetParser.TryParse(line, out var spec, out var error) && spec.Kind != TargetKind.HostName)
            {
                _ranges.Add((spec.Start, spec.End));
            }
            else
            {
                rejected.Add(new RejectedLine(n, line, spec?.Kind == TargetKind.HostName
                    ? "Host names cannot be ignored; use an address or pattern."
                    : error));
            }
        }

        Rejected = rejected;
    }

    public bool IsIgnored(AddressKey a)
    {
        foreach (var (s, e) in _ranges)
        {
            if (s.IsV6 != a.IsV6) continue;
            if (a.IsV6 && s.ScopeId != 0 && s.ScopeId != a.ScopeId) continue;
            if (a.Value >= s.Value && a.Value <= e.Value) return true;
        }

        if (!a.IsV6)
        {
            var v = a.V4;
            foreach (var t in _v4Patterns)
            {
                if (t[0][(byte)(v >> 24)] && t[1][(byte)(v >> 16)] && t[2][(byte)(v >> 8)] && t[3][(byte)v]) return true;
            }
        }
        else if (_v6Patterns.Count > 0)
        {
            var text = a.ToIPAddress().ToString().ToLowerInvariant();
            foreach (var r in _v6Patterns)
            {
                if (r.IsMatch(text)) return true;
            }
        }

        return false;
    }

    private static bool TryBuildV4Pattern(string line, out bool[][] table)
    {
        table = null!;
        var parts = line.Split('.');
        if (parts.Length != 4) return false;
        table = new bool[4][];
        for (var i = 0; i < 4; i++)
        {
            var p = parts[i];
            if (p.Length == 0 || p.Any(c => !(char.IsAsciiDigit(c) || c == '*' || c == '?'))) return false;
            table[i] = new bool[256];
            var any = false;
            for (var o = 0; o < 256; o++)
            {
                if (GlobMatch(p, o.ToString(CultureInfo.InvariantCulture)))
                {
                    table[i][o] = true;
                    any = true;
                }
            }

            if (!any) return false;
        }

        return true;
    }

    internal static bool GlobMatch(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text)
    {
        // iterative glob with single backtrack point for '*'
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == text[t]))
            {
                p++;
                t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
