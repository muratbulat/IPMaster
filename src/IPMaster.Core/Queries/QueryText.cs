using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using System.Xml.XPath;
using IPMaster.Core.Discovery;

namespace IPMaster.Core.Queries;

/// <summary>Manual path syntax shared by Remote Registry and Remote Files: <c>[a|b]</c> alternatives and <c>*</c>/<c>?</c> wildcards.</summary>
public static class PathPattern
{
    public const int MaxAlternatives = 64;

    /// <summary>Expands bracketed alternatives in order: <c>SOFTWARE\[A|B]\X</c> → <c>SOFTWARE\A\X</c>, <c>SOFTWARE\B\X</c>.</summary>
    public static IReadOnlyList<string> Alternatives(string pattern)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        var results = new List<string> { "" };
        var i = 0;
        while (i < pattern.Length)
        {
            var open = pattern.IndexOf('[', i);
            var close = open < 0 ? -1 : pattern.IndexOf(']', open + 1);
            if (open < 0 || close < 0)
            {
                Append(results, pattern[i..]);
                break;
            }

            Append(results, pattern[i..open]);
            var options = pattern[(open + 1)..close].Split('|');
            if (options.Length == 1)
            {
                // a bracket without alternatives is literal text (e.g. a folder named "[old]")
                Append(results, pattern[open..(close + 1)]);
            }
            else
            {
                var next = new List<string>(results.Count * options.Length);
                foreach (var prefix in results)
                {
                    foreach (var o in options) next.Add(prefix + o);
                }

                if (next.Count > MaxAlternatives) throw new ArgumentException($"More than {MaxAlternatives} alternative paths.", nameof(pattern));
                results = next;
            }

            i = close + 1;
        }

        return results;

        static void Append(List<string> list, string s)
        {
            for (var k = 0; k < list.Count; k++) list[k] += s;
        }
    }

    public static bool HasWildcards(string segment) => segment.AsSpan().IndexOfAny('*', '?') >= 0;

    /// <summary>Case-insensitive <c>*</c>/<c>?</c> match of a whole name.</summary>
    public static bool Match(string name, string pattern)
    {
        ArgumentNullException.ThrowIfNull(name);
        ArgumentNullException.ThrowIfNull(pattern);
        int n = 0, p = 0, star = -1, mark = 0;
        while (n < name.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || char.ToUpperInvariant(pattern[p]) == char.ToUpperInvariant(name[n])))
            {
                n++;
                p++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = n;
            }
            else if (star >= 0)
            {
                p = star + 1;
                n = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }

    public static string[] Segments(string path) => path.Split(['\\', '/'], StringSplitOptions.RemoveEmptyEntries);
}

/// <summary>Result of resolving a wildcard path against a tree (registry keys, folders).</summary>
public sealed record PathResolution(IReadOnlyList<string> Matches, IReadOnlyList<string> Errors, bool Truncated);

/// <summary>
/// Expands wildcard segments recursively against a tree. <paramref name="children"/> lists child names of a node and
/// returns null when it cannot be read (access denied); those failures are reported, not hidden (FIL-03).
/// </summary>
public static class PathResolver
{
    public const int DefaultMaxMatches = 1000;

    public static PathResolution Resolve(string root, string relativePattern, Func<string, IReadOnlyList<string>?> children,
        Func<string, bool> exists, int maxMatches = DefaultMaxMatches, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(children);
        ArgumentNullException.ThrowIfNull(exists);
        var segments = PathPattern.Segments(relativePattern);
        var errors = new List<string>();
        var current = new List<string> { root };
        var truncated = false;
        for (var i = 0; i < segments.Length && current.Count > 0; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var seg = segments[i];
            var last = i == segments.Length - 1;
            var next = new List<string>();
            foreach (var node in current)
            {
                if (!PathPattern.HasWildcards(seg))
                {
                    var candidate = Join(node, seg);
                    if (!last || exists(candidate)) next.Add(candidate);
                    continue;
                }

                var names = children(node);
                if (names is null)
                {
                    errors.Add($"{node}: access denied");
                    continue;
                }

                foreach (var n in names)
                {
                    if (!PathPattern.Match(n, seg)) continue;
                    if (next.Count >= maxMatches)
                    {
                        truncated = true;
                        break;
                    }

                    next.Add(Join(node, n));
                }
            }

            // intermediate literal segments are checked lazily: drop nodes that do not exist before listing their children
            current = last ? next : next.Where(exists).ToList();
        }

        return new PathResolution(current, errors, truncated);
    }

    private static string Join(string a, string b) => a.Length == 0 ? b : a.EndsWith('\\') ? a + b : a + "\\" + b;
}

/// <summary>Manual Remote Groups "Additional options": strip domain names, disregard accounts by wildcard.</summary>
public static class AccountFilter
{
    public static IReadOnlyList<string> Apply(IEnumerable<string> accounts, bool stripDomain, IReadOnlyList<string> exclusions)
    {
        ArgumentNullException.ThrowIfNull(accounts);
        ArgumentNullException.ThrowIfNull(exclusions);
        var patterns = exclusions.Select(e => e.Trim()).Where(e => e.Length > 0).ToList();
        var result = new List<string>();
        foreach (var a in accounts)
        {
            var shortName = a.Contains('\\', StringComparison.Ordinal) ? a[(a.LastIndexOf('\\') + 1)..] : a;
            if (patterns.Any(p => PathPattern.Match(a, p) || PathPattern.Match(shortName, p))) continue;
            var shown = stripDomain ? shortName : a;
            if (!result.Contains(shown, StringComparer.OrdinalIgnoreCase)) result.Add(shown);
        }

        return result;
    }
}

/// <summary>Removes ANSI/VT escape sequences from command output (SSH-01).</summary>
public static partial class AnsiText
{
    public static string Strip(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var s = Escape().Replace(text, "");
        s = s.Replace("\r\n", "\n", StringComparison.Ordinal).Replace('\r', '\n');
        return new string(s.Where(c => c is '\n' or '\t' || !char.IsControl(c)).ToArray()).TrimEnd('\n', ' ');
    }

    // CSI, OSC (BEL or ST terminated), and two-character escapes
    [GeneratedRegex(@"\x1B\[[0-?]*[ -/]*[@-~]|\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)|\x1B[@-Z\\-_]", RegexOptions.CultureInvariant, 200)]
    private static partial Regex Escape();
}

/// <summary>SNMP OID variables (SNM-06) and value rendering (SNM-04).</summary>
public static partial class SnmpText
{
    /// <summary>Replaces <c>%0</c> with the address octets and <c>%1</c> with the MAC octets, then validates the OID.</summary>
    public static string ExpandOid(string oid, IPAddress address, PhysicalAddress? mac)
    {
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentNullException.ThrowIfNull(address);
        var s = oid.Trim().TrimStart('.');
        if (s.Contains("%0", StringComparison.Ordinal))
        {
            s = s.Replace("%0", string.Join('.', address.GetAddressBytes()), StringComparison.Ordinal);
        }

        if (s.Contains("%1", StringComparison.Ordinal))
        {
            if (mac is null) throw new InvalidOperationException("The OID uses %1 but the device has no MAC address.");
            s = s.Replace("%1", string.Join('.', mac.GetAddressBytes()), StringComparison.Ordinal);
        }

        if (!IsOid(s)) throw new FormatException($"'{oid}' is not a numeric OID.");
        return s;
    }

    public static bool IsOid(string s) => OidPattern().IsMatch(s);

    [GeneratedRegex(@"^[0-2](\.(0|[1-9][0-9]{0,9}))+$", RegexOptions.CultureInvariant)]
    private static partial Regex OidPattern();

    /// <summary>Automatic: text when every byte is printable ASCII (trailing NULs ignored), else hex.</summary>
    public static string RenderOctets(ReadOnlySpan<byte> bytes, SnmpDisplay mode)
    {
        var trimmed = bytes;
        while (trimmed.Length > 0 && trimmed[^1] == 0) trimmed = trimmed[..^1];
        var printable = trimmed.Length > 0;
        foreach (var b in trimmed)
        {
            if (b is < 0x20 and not (0x09 or 0x0A or 0x0D) or > 0x7E)
            {
                printable = false;
                break;
            }
        }

        return mode switch
        {
            SnmpDisplay.Hex => Convert.ToHexString(bytes).Chunk(2).Aggregate(new StringBuilder(), (sb, c) => sb.Append(sb.Length > 0 ? " " : "").Append(c)).ToString(),
            SnmpDisplay.Ascii => Encoding.ASCII.GetString(trimmed).Replace('\0', '.'),
            _ => printable || trimmed.Length == 0 ? Encoding.ASCII.GetString(trimmed) : RenderOctets(bytes, SnmpDisplay.Hex),
        };
    }
}

/// <summary>Response extraction for Remote XML / JSON / Nmap (HTP-01/02, NMP-01). Multiple matches are returned one per line.</summary>
public static class Extraction
{
    public const int MaxResults = 1000;

    /// <summary>XPath over a DTD-free document. Namespaces are removed first so plain paths like <c>/root/item</c> work (D-052).</summary>
    public static IReadOnlyList<string> XPath(string xml, string expression)
    {
        var doc = SafeXml.Parse(xml);
        StripNamespaces(doc);
        object result;
        try
        {
            result = doc.XPathEvaluate(expression);
        }
        catch (XPathException ex)
        {
            throw new FormatException("Invalid XPath: " + ex.Message, ex);
        }

        return result switch
        {
            IEnumerable<object> items => items.Take(MaxResults).Select(NodeText).ToList(),
            bool b => [b ? "true" : "false"],
            double d => [d.ToString(CultureInfo.InvariantCulture)],
            string s => [s],
            _ => [],
        };

        static string NodeText(object o) => o switch
        {
            XAttribute a => a.Value,
            XElement e => e.HasElements ? e.ToString(SaveOptions.DisableFormatting) : e.Value,
            XText t => t.Value,
            _ => o.ToString() ?? "",
        };
    }

    private static void StripNamespaces(XDocument doc)
    {
        foreach (var e in doc.Descendants())
        {
            e.Name = e.Name.LocalName;
            var attrs = e.Attributes().Where(a => !a.IsNamespaceDeclaration).Select(a => new XAttribute(a.Name.LocalName, a.Value)).ToList();
            e.ReplaceAttributes(attrs);
        }
    }

    /// <summary>All matches; group 1 when the pattern has a capturing group, the whole match otherwise.</summary>
    public static IReadOnlyList<string> Regex(string text, string pattern)
    {
        System.Text.RegularExpressions.Regex re;
        try
        {
            re = new System.Text.RegularExpressions.Regex(pattern, RegexOptions.CultureInvariant | RegexOptions.Multiline, TimeSpan.FromMilliseconds(250));
        }
        catch (ArgumentException ex)
        {
            throw new FormatException("Invalid regular expression: " + ex.Message, ex);
        }

        var list = new List<string>();
        foreach (Match m in re.Matches(text))
        {
            list.Add((m.Groups.Count > 1 && m.Groups[1].Success ? m.Groups[1].Value : m.Value).Trim());
            if (list.Count >= MaxResults) break;
        }

        return list;
    }

    public static IReadOnlyList<string> JsonPath(string json, string path)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(json, documentOptions: new JsonDocumentOptions { MaxDepth = 128 });
        }
        catch (JsonException ex)
        {
            throw new FormatException("Invalid JSON: " + ex.Message, ex);
        }

        return Queries.JsonPath.Evaluate(root, path).Take(MaxResults).Select(Queries.JsonPath.Text).ToList();
    }
}

/// <summary>
/// JSONPath subset (D-053): <c>$</c>, <c>.name</c>, <c>['name']</c>, <c>[n]</c> (negative from the end), <c>[*]</c>,
/// <c>.*</c>, <c>..name</c> (recursive), <c>[a,b]</c> unions and filters <c>[?(@.key op value)]</c> with
/// <c>== != &lt; &lt;= &gt; &gt;=</c> and existence <c>[?(@.key)]</c>.
/// </summary>
public static class JsonPath
{
    public static IEnumerable<JsonNode?> Evaluate(JsonNode? root, string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        var p = path.Trim();
        if (p.Length == 0 || p[0] != '$') throw new FormatException("JSONPath must start with $.");
        IEnumerable<JsonNode?> current = [root];
        var i = 1;
        while (i < p.Length)
        {
            if (p[i] == '.')
            {
                var recursive = i + 1 < p.Length && p[i + 1] == '.';
                i += recursive ? 2 : 1;
                if (i < p.Length && p[i] == '[')
                {
                    var (sel, end) = ParseBracket(p, i);
                    current = (recursive ? current.SelectMany(Descendants) : current).SelectMany(sel).ToList();
                    i = end;
                    continue;
                }

                var start = i;
                while (i < p.Length && p[i] is not ('.' or '[')) i++;
                var name = p[start..i];
                if (name.Length == 0) throw new FormatException($"Empty member name at position {start}.");
                current = (recursive ? current.SelectMany(Descendants) : current).SelectMany(n => Child(n, name)).ToList();
            }
            else if (p[i] == '[')
            {
                var (sel, end) = ParseBracket(p, i);
                current = current.SelectMany(sel).ToList();
                i = end;
            }
            else
            {
                throw new FormatException($"Unexpected '{p[i]}' at position {i}.");
            }
        }

        return current;
    }

    public static string Text(JsonNode? n) => n switch
    {
        null => "null",
        JsonValue v when v.TryGetValue<string>(out var s) => s,
        JsonValue v => v.ToJsonString(),
        _ => n.ToJsonString(),
    };

    private static IEnumerable<JsonNode?> Child(JsonNode? n, string name) => name == "*"
        ? All(n)
        : n is JsonObject o && o.TryGetPropertyValue(name, out var v) ? [v] : [];

    private static IEnumerable<JsonNode?> All(JsonNode? n) => n switch
    {
        JsonObject o => o.Select(kv => kv.Value),
        JsonArray a => a,
        _ => [],
    };

    private static IEnumerable<JsonNode?> Descendants(JsonNode? n)
    {
        yield return n;
        foreach (var c in All(n))
        {
            foreach (var d in Descendants(c)) yield return d;
        }
    }

    private static (Func<JsonNode?, IEnumerable<JsonNode?>> Selector, int End) ParseBracket(string p, int open)
    {
        // find the matching ']' outside quotes
        var depth = 0;
        char? quote = null;
        var close = -1;
        for (var k = open; k < p.Length; k++)
        {
            var c = p[k];
            if (quote is { } q)
            {
                if (c == q) quote = null;
                continue;
            }

            if (c is '\'' or '"') quote = c;
            else if (c == '[') depth++;
            else if (c == ']' && --depth == 0)
            {
                close = k;
                break;
            }
        }

        if (close < 0) throw new FormatException("Unclosed '['.");
        var body = p[(open + 1)..close].Trim();
        if (body == "*") return (All, close + 1);
        if (body.StartsWith("?(", StringComparison.Ordinal) && body.EndsWith(')'))
        {
            var filter = ParseFilter(body[2..^1]);
            return (n => All(n).Where(filter), close + 1);
        }

        var parts = SplitUnion(body);
        return (n => parts.SelectMany(part => Select(n, part)), close + 1);
    }

    private static IEnumerable<JsonNode?> Select(JsonNode? n, string part)
    {
        if (part.Length >= 2 && part[0] is '\'' or '"' && part[^1] == part[0]) return Child(n, part[1..^1]);
        if (int.TryParse(part, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var index))
        {
            if (n is not JsonArray a) return [];
            var k = index < 0 ? a.Count + index : index;
            return k >= 0 && k < a.Count ? [a[k]] : [];
        }

        throw new FormatException($"Unsupported selector '[{part}]'.");
    }

    private static List<string> SplitUnion(string body)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        char? quote = null;
        foreach (var c in body)
        {
            if (quote is { } q)
            {
                sb.Append(c);
                if (c == q) quote = null;
            }
            else if (c is '\'' or '"')
            {
                quote = c;
                sb.Append(c);
            }
            else if (c == ',')
            {
                parts.Add(sb.ToString().Trim());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }

        parts.Add(sb.ToString().Trim());
        return parts;
    }

    private static Func<JsonNode?, bool> ParseFilter(string expr)
    {
        string[] ops = ["==", "!=", "<=", ">=", "<", ">"];
        foreach (var op in ops)
        {
            var at = expr.IndexOf(op, StringComparison.Ordinal);
            if (at < 0) continue;
            var left = expr[..at].Trim();
            var right = expr[(at + op.Length)..].Trim();
            var path = LeftPath(left);
            var literal = Literal(right);
            return n => Evaluate(n, path).Any(v => Compare(v, op, literal));
        }

        var existsPath = LeftPath(expr.Trim());
        return n => Evaluate(n, existsPath).Any();

        static string LeftPath(string left)
        {
            if (!left.StartsWith('@')) throw new FormatException("Filters must compare @.member with a value.");
            return "$" + left[1..];
        }
    }

    private static JsonNode? Literal(string s)
    {
        if (s.Length >= 2 && s[0] is '\'' or '"' && s[^1] == s[0]) return JsonValue.Create(s[1..^1]);
        try
        {
            return JsonNode.Parse(s);
        }
        catch (JsonException ex)
        {
            throw new FormatException($"Invalid filter value '{s}'.", ex);
        }
    }

    private static bool Compare(JsonNode? value, string op, JsonNode? literal)
    {
        if (value is JsonValue a && literal is JsonValue b && a.TryGetValue<double>(out var x) && b.TryGetValue<double>(out var y))
        {
            return op switch { "==" => x == y, "!=" => x != y, "<" => x < y, "<=" => x <= y, ">" => x > y, _ => x >= y };
        }

        var l = Text(value);
        var r = Text(literal);
        var c = string.CompareOrdinal(l, r);
        return op switch { "==" => c == 0, "!=" => c != 0, "<" => c < 0, "<=" => c <= 0, ">" => c > 0, _ => c >= 0 };
    }
}
