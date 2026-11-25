using System.Net;

namespace IPMaster.Core.Tools;

/// <summary>One answer of one server (D-094). Status is the RCODE text ("NOERROR", "NXDOMAIN", "NOERROR (no data)") or the transport outcome ("TIMEOUT", …).</summary>
public sealed record DnsLookup(string Server, string Name, string Type, string Status, IReadOnlyList<string> Values, string Chain = "")
{
    public bool Answered => Status is "NOERROR" or "NXDOMAIN" or "NOERROR (no data)";

    public bool HasData => Status == "NOERROR" && Values.Count > 0;
}

/// <summary>An audited name or address with every lookup made for it.</summary>
public sealed record DnsAuditEntry(string Input, bool IsAddress, IReadOnlyList<DnsLookup> Lookups);

public enum AuditLevel
{
    Ok,
    Info,
    Warning,
    Error,
}

public sealed record DnsFinding(AuditLevel Level, string Text);

/// <summary>
/// Bulk DNS consistency rules (D-094). Several names for one address and several addresses for one name are normal and
/// reported as information, not errors; a PTR that does not resolve back (not forward-confirmed), a missing PTR, servers
/// that disagree (may be intended: round robin, split DNS) and failing servers are flagged. Read-only: nothing is changed.
/// </summary>
public static class DnsAudit
{
    public static IReadOnlyList<DnsFinding> Analyze(DnsAuditEntry e)
    {
        ArgumentNullException.ThrowIfNull(e);
        var f = new List<DnsFinding>();
        foreach (var l in e.Lookups.Where(l => !l.Answered))
        {
            f.Add(new(AuditLevel.Error, $"{l.Server}: {l.Status} for {l.Type} {l.Name}."));
        }

        IReadOnlyList<string> addresses;
        if (e.IsAddress)
        {
            addresses = [e.Input];
        }
        else
        {
            var forward = e.Lookups.Where(l => l.Type is "A" or "AAAA" && Same(l.Name, e.Input)).ToList();
            var answered = forward.Where(l => l.Answered).ToList();
            if (answered.Count > 0 && answered.All(l => l.Status == "NXDOMAIN"))
            {
                f.Add(new(AuditLevel.Error, $"{e.Input} does not exist (NXDOMAIN on every server that answered)."));
                return f;
            }

            foreach (var chain in forward.Select(l => l.Chain).Where(c => c.Length > 0).Distinct()) f.Add(new(AuditLevel.Info, $"Alias: {chain}."));
            var perServer = answered.GroupBy(l => l.Server).ToDictionary(g => g.Key, g => g.Where(l => l.HasData).SelectMany(l => l.Values).ToHashSet(StringComparer.OrdinalIgnoreCase));
            if (perServer.Values.All(s => s.Count == 0))
            {
                f.Add(new(AuditLevel.Warning, $"{e.Input} exists but has no A or AAAA record."));
                return f;
            }

            if (perServer.Count > 1 && perServer.Values.Select(s => string.Join(",", s.Order(StringComparer.OrdinalIgnoreCase))).Distinct().Count() > 1)
            {
                f.Add(new(AuditLevel.Warning, "Servers disagree: " + string.Join("; ", perServer.Select(kv => $"{kv.Key}: {(kv.Value.Count == 0 ? "none" : string.Join(", ", kv.Value.Order()))}"))
                                              + " (may be intended: round robin, geo or split DNS)."));
            }

            addresses = perServer.Values.SelectMany(s => s).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
            if (addresses.Count > 1) f.Add(new(AuditLevel.Info, $"{e.Input} has {addresses.Count} addresses: {string.Join(", ", addresses)}."));
        }

        foreach (var address in addresses)
        {
            var ptr = e.Lookups.Where(l => l.Type == "PTR" && Same(l.Name, address) && l.Answered).ToList();
            if (ptr.Count == 0) continue; // only failing servers: already reported
            var names = ptr.Where(l => l.HasData).SelectMany(l => l.Values).Select(n => n.TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (names.Count == 0)
            {
                f.Add(new(AuditLevel.Warning, $"No PTR record for {address}."));
                continue;
            }

            var withoutPtr = ptr.Where(l => !l.HasData).Select(l => l.Server).Distinct().ToList();
            if (withoutPtr.Count > 0) f.Add(new(AuditLevel.Warning, $"Servers disagree on the PTR of {address}: none on {string.Join(", ", withoutPtr)}."));
            if (names.Count > 1) f.Add(new(AuditLevel.Info, $"{address} has {names.Count} PTR names: {string.Join(", ", names)} (several names may legitimately share an address)."));
            foreach (var name in names)
            {
                var back = e.Lookups.Where(l => l.Type is "A" or "AAAA" && Same(l.Name, name) && l.HasData).SelectMany(l => l.Values).ToHashSet(StringComparer.OrdinalIgnoreCase);
                if (back.Contains(address))
                {
                    f.Add(new(AuditLevel.Ok, $"{address} ↔ {name} (forward-confirmed reverse DNS)."));
                }
                else
                {
                    f.Add(new(AuditLevel.Warning, $"PTR {name} for {address} does not resolve back to {address} (not forward-confirmed"
                                                  + (back.Count > 0 ? $"; it resolves to {string.Join(", ", back.Order())})." : ").")));
                }

                if (!e.IsAddress && !Same(name, e.Input) && !e.Lookups.Any(l => l.Chain.Contains(name, StringComparison.OrdinalIgnoreCase)))
                {
                    f.Add(new(AuditLevel.Info, $"The PTR name of {address} is {name}, not {e.Input} (normal when several names share the address)."));
                }
            }
        }

        if (f.Count == 0) f.Add(new(AuditLevel.Ok, "Consistent."));
        return f;
    }

    /// <summary>Entries from text: one name or address per line or comma-separated; # comments; duplicates removed.</summary>
    public static IReadOnlyList<string> ParseInput(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        return text.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.Split('#')[0]) // a comment runs to the end of its line
            .SelectMany(line => line.Split([',', ';', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Select(x => x.TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static bool IsAddress(string input) => IPAddress.TryParse(input, out _);

    private static bool Same(string a, string b) => string.Equals(a.TrimEnd('.'), b.TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
}
