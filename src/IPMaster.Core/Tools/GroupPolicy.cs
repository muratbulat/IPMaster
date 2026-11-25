using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace IPMaster.Core.Tools;

public enum GpoScope
{
    Computer,
    User,
}

public enum GpoState
{
    Unknown,
    Applied,
    Filtered,
}

/// <summary>One GPO as the RSoP report lists it for one scope. Fields the report does not give stay empty / null.</summary>
public sealed record GpoEntry
{
    public GpoScope Scope { get; init; }

    public string Name { get; init; } = "";

    /// <summary>GUID ({…}) or "LocalGPO"; empty when not reported.</summary>
    public string Id { get; init; } = "";

    public string Domain { get; init; } = "";

    public GpoState State { get; init; }

    /// <summary>gpresult-style reason for a filtered GPO ("Denied (Security)", "Not Applied (Empty)"…); empty when applied.</summary>
    public string Reason { get; init; } = "";

    public IReadOnlyList<string> Links { get; init; } = [];

    public string Version { get; init; } = "";

    public IReadOnlyList<string> Extensions { get; init; } = [];

    public string StateText => State switch
    {
        GpoState.Applied => "Applied",
        GpoState.Filtered => "Filtered",
        _ => "Unknown",
    };
}

/// <summary>One effective (winning, precedence 1) setting from the report's extension data.</summary>
public sealed record GpoSetting(GpoScope Scope, string Name, string Value, string Category, string WinningGpo, string Extension);

public sealed record GpoScopeInfo
{
    public GpoScope Scope { get; init; }

    public bool Available { get; init; }

    /// <summary>Why the scope has no data (access denied, no RSoP data…).</summary>
    public string Message { get; init; } = "";

    public string Account { get; init; } = "";

    public string Domain { get; init; } = "";

    public string Site { get; init; } = "";

    public bool? SlowLink { get; init; }

    /// <summary>End of the last Group Policy processing (Group Policy Infrastructure extension), UTC; null = not reported.</summary>
    public DateTimeOffset? LastProcessing { get; init; }

    /// <summary>Error code of the Group Policy Infrastructure extension; 0 = success; null = not reported.</summary>
    public long? ProcessingError { get; init; }
}

public sealed record GpoReport(DateTimeOffset Collected, DateTimeOffset? ReportTime, IReadOnlyList<GpoScopeInfo> Scopes, IReadOnlyList<GpoEntry> Gpos, IReadOnlyList<GpoSetting> Settings);

public sealed class GpoReportException(string message, Exception? inner = null) : Exception(message, inner);

/// <summary>
/// Parser of <c>gpresult /x</c> RSoP XML (D-107). Read-only and namespace-agnostic (element local names); DTDs are
/// prohibited and no external resource is resolved. Missing data stays missing: nothing is inferred from absent elements.
/// </summary>
public static class GroupPolicy
{
    private const string InfrastructureId = "{00000000-0000-0000-0000-000000000000}";

    private static readonly XmlReaderSettings Safe = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 64 * 1024 * 1024 };

    /// <summary>Parses one report; it may hold ComputerResults, UserResults or both.</summary>
    public static (DateTimeOffset? ReportTime, IReadOnlyList<GpoScopeInfo> Scopes, IReadOnlyList<GpoEntry> Gpos, IReadOnlyList<GpoSetting> Settings) Parse(string xml)
    {
        XDocument doc;
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml ?? ""), Safe);
            doc = XDocument.Load(reader);
        }
        catch (XmlException ex)
        {
            throw new GpoReportException("Report failed: the RSoP XML is not valid.", ex);
        }

        var root = doc.Root ?? throw new GpoReportException("Report failed: empty RSoP XML.");
        if (root.Name.LocalName != "Rsop") throw new GpoReportException("Report failed: this is not an RSoP report.");
        var readTime = Date(Value(root, "ReadTime"));
        var scopes = new List<GpoScopeInfo>();
        var gpos = new List<GpoEntry>();
        var settings = new List<GpoSetting>();
        foreach (var (name, scope) in new[] { ("ComputerResults", GpoScope.Computer), ("UserResults", GpoScope.User) })
        {
            if (Child(root, name) is not { } results) continue;
            var infra = Children(results, "ExtensionStatus").FirstOrDefault(e => string.Equals(Value(e, "Identifier"), InfrastructureId, StringComparison.OrdinalIgnoreCase));
            scopes.Add(new GpoScopeInfo
            {
                Scope = scope, Available = true, Account = Value(results, "Name"), Domain = Value(results, "Domain"), Site = Value(results, "Site"),
                SlowLink = Bool(Value(results, "SlowLink")), LastProcessing = infra is null ? null : Date(Value(infra, "EndTime")) ?? Date(Value(infra, "BeginTime")),
                ProcessingError = infra is not null && long.TryParse(Value(infra, "Error"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var err) ? err : null,
            });
            var scopeGpos = Children(results, "GPO").Select(g => Gpo(g, scope)).ToList();
            gpos.AddRange(scopeGpos);
            var names = scopeGpos.Where(g => g.Id.Length > 0).GroupBy(g => g.Id, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Name, StringComparer.OrdinalIgnoreCase);
            foreach (var ext in Children(results, "ExtensionData")) settings.AddRange(Settings(ext, scope, names));
        }

        return (readTime, scopes, gpos, settings);
    }

    /// <summary>
    /// Applied only when the report confirms it: enabled, valid, allowed by WMI and security filtering and linked with an
    /// applied order. Otherwise the gpresult reason; Unknown when the deciding elements are missing.
    /// </summary>
    internal static GpoEntry Gpo(XElement g, GpoScope scope)
    {
        var enabled = Bool(Value(g, "Enabled"));
        var valid = Bool(Value(g, "IsValid"));
        var filter = Bool(Value(g, "FilterAllowed"));
        var denied = Bool(Value(g, "AccessDenied"));
        var links = Children(g, "Link").ToList();
        var applied = links.Select(l => int.TryParse(Value(l, "AppliedOrder"), NumberStyles.Integer, CultureInfo.InvariantCulture, out var o) ? o : (int?)null).ToList();
        var extensions = Children(g, "ExtensionName").Select(e => e.Value.Trim()).Where(v => v.Length > 0).ToList();
        var path = Child(g, "Path");
        GpoState state;
        string reason;
        if (enabled is null || valid is null || filter is null || denied is null || applied.Count == 0 || applied.Any(a => a is null))
        {
            (state, reason) = (GpoState.Unknown, "The report does not give the filtering state.");
        }
        else if (denied == true) (state, reason) = (GpoState.Filtered, "Denied (Security)");
        else if (filter == false) (state, reason) = (GpoState.Filtered, "Denied (WMI Filter)" + (Value(g, "FilterName") is { Length: > 0 } wf ? $": {wf}" : ""));
        else if (enabled == false) (state, reason) = (GpoState.Filtered, "Disabled (GPO)");
        else if (valid == false) (state, reason) = (GpoState.Filtered, "Not valid");
        else if (applied.Any(a => a > 0)) (state, reason) = (GpoState.Applied, "");
        else if (links.All(l => Bool(Value(l, "Enabled")) == false)) (state, reason) = (GpoState.Filtered, "Disabled (Link)");
        else if (extensions.Count == 0) (state, reason) = (GpoState.Filtered, "Not Applied (Empty)");
        else (state, reason) = (GpoState.Filtered, "Not Applied (reason not reported)");

        return new GpoEntry
        {
            Scope = scope, Name = Value(g, "Name"), Id = path is null ? "" : Value(path, "Identifier"), Domain = path is null ? "" : Value(path, "Domain"),
            State = state, Reason = reason, Links = links.Select(l => Value(l, "SOMPath")).Where(s => s.Length > 0).ToList(),
            Version = Value(g, "VersionDirectory") is { Length: > 0 } vd ? $"AD {vd}, SYSVOL {Value(g, "VersionSysvol")}" : "", Extensions = extensions,
        };
    }

    /// <summary>Winning settings of one extension: items that name their GPO and have precedence 1 (or none reported).</summary>
    internal static IEnumerable<GpoSetting> Settings(XElement extensionData, GpoScope scope, IReadOnlyDictionary<string, string> gpoNames)
    {
        var extName = Value(extensionData, "Name");
        foreach (var ext in Children(extensionData, "Extension"))
        {
            foreach (var item in ext.Elements())
            {
                if (Child(item, "GPO") is not { } gpo) continue;
                if (Value(item, "Precedence") is { Length: > 0 } p && p != "1") continue; // a losing setting
                var id = Value(gpo, "Identifier");
                var name = First(item, "Name", "KeyName", "PolicyTarget", "SystemAccessPolicyName", "Path");
                if (Value(item, "KeyPath") is { Length: > 0 } key) name = name.Length > 0 ? $"{key}\\{name}" : key;
                if (name.Length == 0) continue;
                var value = First(item, "State", "SettingString", "SettingNumber", "SettingBoolean", "Value");
                if (value.Length == 0 && Child(item, "Display") is { } display) value = First(display, "DisplayString", "DisplayNumber", "DisplayBoolean");
                if (value.Length == 0 && Children(item, "Member").Any()) value = string.Join(", ", Children(item, "Member").Select(m => Value(m, "Name")).Where(v => v.Length > 0));
                var category = Value(item, "Category") is { Length: > 0 } c ? c : extName;
                var winner = gpoNames.TryGetValue(id, out var n) ? n : id;
                yield return new GpoSetting(scope, name, value.Length > 0 ? value : "(not reported)", category, winner, extName);
            }
        }
    }

    public static GpoReport Combine(DateTimeOffset collected, params (DateTimeOffset? ReportTime, IReadOnlyList<GpoScopeInfo> Scopes, IReadOnlyList<GpoEntry> Gpos, IReadOnlyList<GpoSetting> Settings)[] parts) =>
        new(collected, parts.Select(p => p.ReportTime).Where(t => t is not null).DefaultIfEmpty(null).Max(), parts.SelectMany(p => p.Scopes).ToList(),
            parts.SelectMany(p => p.Gpos).ToList(), parts.SelectMany(p => p.Settings).ToList());

    // ---------------- filters and text ----------------
    public static bool Matches(GpoEntry g, GpoScope? scope, string search) =>
        (scope is null || g.Scope == scope) && (search.Trim().Length == 0 || g.Name.Contains(search.Trim(), StringComparison.CurrentCultureIgnoreCase));

    public static bool Matches(GpoSetting s, string search)
    {
        search = search.Trim();
        return search.Length == 0 || s.Name.Contains(search, StringComparison.CurrentCultureIgnoreCase) || s.Value.Contains(search, StringComparison.CurrentCultureIgnoreCase)
               || s.Category.Contains(search, StringComparison.CurrentCultureIgnoreCase) || s.WinningGpo.Contains(search, StringComparison.CurrentCultureIgnoreCase);
    }

    public static string? StateClass(GpoState s) => s switch
    {
        GpoState.Applied => "success",
        GpoState.Filtered => "warning",
        _ => null,
    };

    public static string Time(DateTimeOffset? t) => t is { } v ? v.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) : "Unavailable";

    /// <summary>Short TXT summary from the parsed data (the full reports come from gpresult itself).</summary>
    public static string Summary(GpoReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Group Policy Summary").AppendLine(new string('-', 40));
        sb.Append(CultureInfo.InvariantCulture, $"Report refreshed:   {Time(r.Collected)}").AppendLine();
        foreach (var s in r.Scopes)
        {
            sb.AppendLine().Append(CultureInfo.InvariantCulture, $"{s.Scope}").AppendLine();
            if (!s.Available)
            {
                sb.Append(CultureInfo.InvariantCulture, $"  {s.Message}").AppendLine();
                continue;
            }

            sb.Append(CultureInfo.InvariantCulture, $"  Name:            {Or(s.Account)}").AppendLine();
            sb.Append(CultureInfo.InvariantCulture, $"  Domain:          {Or(s.Domain)}").AppendLine();
            sb.Append(CultureInfo.InvariantCulture, $"  Last processing: {Time(s.LastProcessing)}{(s.ProcessingError is { } e and not 0 ? $" (error {e})" : "")}").AppendLine();
            foreach (var g in r.Gpos.Where(g => g.Scope == s.Scope).OrderBy(g => g.State).ThenBy(g => g.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                sb.Append(CultureInfo.InvariantCulture, $"  {g.StateText,-9} {g.Name}{(g.Reason.Length > 0 ? $" — {g.Reason}" : "")}").AppendLine();
            }
        }

        sb.AppendLine().Append(CultureInfo.InvariantCulture, $"Applied: {r.Gpos.Count(g => g.State == GpoState.Applied)}   Filtered: {r.Gpos.Count(g => g.State == GpoState.Filtered)}   Settings reported: {r.Settings.Count}").AppendLine();
        return sb.ToString();
    }

    private static string Or(string s) => s.Length > 0 ? s : "Unavailable";

    // ---------------- XML helpers (local names) ----------------
    private static XElement? Child(XElement e, string name) => e.Elements().FirstOrDefault(c => c.Name.LocalName == name);

    private static IEnumerable<XElement> Children(XElement e, string name) => e.Elements().Where(c => c.Name.LocalName == name);

    private static string Value(XElement e, string name) => Child(e, name)?.Value.Trim() ?? "";

    private static string First(XElement e, params string[] names) => names.Select(n => Value(e, n)).FirstOrDefault(v => v.Length > 0) ?? "";

    private static bool? Bool(string v) => v.Length == 0 ? null : string.Equals(v, "true", StringComparison.OrdinalIgnoreCase) || v == "1" ? true : string.Equals(v, "false", StringComparison.OrdinalIgnoreCase) || v == "0" ? false : null;

    /// <summary>RSoP times are UTC (with or without a "Z").</summary>
    private static DateTimeOffset? Date(string v) =>
        DateTimeOffset.TryParse(v, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}
