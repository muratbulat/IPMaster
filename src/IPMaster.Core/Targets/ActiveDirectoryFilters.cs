using System.Text;

namespace IPMaster.Core.Targets;

public sealed record AdFilterPreset(string Name, string Template, bool NeedsText);

public sealed record AdComputer(string Name, string DnsHostName, string OperatingSystem)
{
    /// <summary>Scan target: the DNS host name when present, else the computer name.</summary>
    public string Target => DnsHostName.Length > 0 ? DnsHostName : Name;
}

/// <summary>LDAP filters for the Active Directory import (TGT-13). User text is escaped per RFC 4515.</summary>
public static class ActiveDirectoryFilters
{
    public static readonly IReadOnlyList<AdFilterPreset> Presets =
    [
        new("All computers", "(objectCategory=computer)", false),
        new("Enabled computers", "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", false),
        new("Name contains string", "(&(objectCategory=computer)(name=*{0}*))", true),
        new("Name starts with", "(&(objectCategory=computer)(name={0}*))", true),
        new("Windows 10 machines", "(&(objectCategory=computer)(operatingSystem=Windows 10*))", false),
        new("Windows 11 machines", "(&(objectCategory=computer)(operatingSystem=Windows 11*))", false),
        new("Windows servers", "(&(objectCategory=computer)(operatingSystem=*Server*))", false),
        new("Operating system contains", "(&(objectCategory=computer)(operatingSystem=*{0}*))", true),
        new("Domain controllers", "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", false),
    ];

    public static string Escape(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            sb.Append(c switch
            {
                '\\' => @"\5c",
                '*' => @"\2a",
                '(' => @"\28",
                ')' => @"\29",
                '\0' => @"\00",
                _ => c.ToString(),
            });
        }

        return sb.ToString();
    }

    public static string Build(AdFilterPreset preset, string text)
    {
        ArgumentNullException.ThrowIfNull(preset);
        return preset.NeedsText ? preset.Template.Replace("{0}", Escape(text ?? ""), StringComparison.Ordinal) : preset.Template;
    }

    /// <summary>Basic syntax check of a hand-written filter: balanced parentheses, starts with '('.</summary>
    public static string? Validate(string filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return "Enter a filter.";
        var f = filter.Trim();
        if (f[0] != '(') return "LDAP filters start with '('.";
        var depth = 0;
        foreach (var c in f)
        {
            if (c == '(') depth++;
            else if (c == ')' && --depth < 0) return "Unbalanced parentheses.";
        }

        return depth == 0 ? null : "Unbalanced parentheses.";
    }

    /// <summary>"corp.example.com" → "DC=corp,DC=example,DC=com".</summary>
    public static string BaseFromDomain(string domain) =>
        string.Join(",", (domain ?? "").Trim('.').Split('.', StringSplitOptions.RemoveEmptyEntries).Select(p => "DC=" + p));
}
