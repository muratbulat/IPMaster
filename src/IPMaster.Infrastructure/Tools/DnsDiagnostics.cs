using System.Globalization;
using System.Net;
using System.Text;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

/// <summary>DNS Diagnostics operations (D-073): each returns a plain-text report and a one-line summary.</summary>
public static class DnsDiagnostics
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>"Auto" type: PTR for an address (name generated), A otherwise.</summary>
    public static (string Name, ushort Type) Normalize(string input, DnsType? type)
    {
        var t = input.Trim();
        if (IPAddress.TryParse(t, out var ip) && (type is null or DnsType.PTR)) return (DnsWire.PtrName(ip), (ushort)DnsType.PTR);
        return (t, (ushort)(type ?? DnsType.A));
    }

    public static async Task<(string Report, string Summary)> QueryAsync(string input, DnsType? type, IReadOnlyList<IPEndPoint> servers, DnsQueryOptions options,
        bool alsoOsResolver, CancellationToken ct)
    {
        var (name, qtype) = Normalize(input, type);
        var sb = new StringBuilder();
        var summary = new List<string>();
        foreach (var server in servers)
        {
            ct.ThrowIfCancellationRequested();
            var (steps, problem) = await DnsClient.ResolveAsync(server, name, qtype, options, ct).ConfigureAwait(false);
            foreach (var r in steps) Append(sb, r);
            if (problem is not null) sb.AppendLine("  ⚠ " + problem);
            var last = steps[^1];
            summary.Add($"{server}: {last.Status}{(last.Records.Count > 0 ? $", {last.Records.Count} record(s)" : "")}");
            sb.AppendLine();
        }

        if (alsoOsResolver && qtype is (ushort)DnsType.A or (ushort)DnsType.AAAA)
        {
            var (addrs, detail, dur) = await DnsClient.OsResolveAsync(name, options.Timeout, ct).ConfigureAwait(false);
            sb.AppendLine(Inv, $";; OS resolver (cache, hosts file, suffix search; not a direct DNS query) — {dur.TotalMilliseconds:0} ms");
            foreach (var a in addrs) sb.AppendLine("   " + a);
            if (detail.Length > 0) sb.AppendLine("   " + detail);
            sb.AppendLine();
        }

        return (sb.ToString(), string.Join(" · ", summary));
    }

    public static void Append(StringBuilder sb, DnsQueryResult r)
    {
        ArgumentNullException.ThrowIfNull(sb);
        ArgumentNullException.ThrowIfNull(r);
        sb.AppendLine(Inv, $";; {r.Name} {DnsWire.TypeName(r.Type)} @ {r.Server} via {(r.Transport.Length > 0 ? r.Transport : "—")} — {r.Duration.TotalMilliseconds:0} ms");
        sb.AppendLine(";; status: " + r.Status + (r.Message is { } m ? $", flags: {m.Flags}, id {m.Id}" : "") + (r.Detail.Length > 0 ? " — " + r.Detail : ""));
        if (r.Message is not { } msg) return;
        void Section(string title, IReadOnlyList<DnsRecord> records)
        {
            if (records.Count == 0) return;
            sb.AppendLine(";; " + title);
            foreach (var rec in records) sb.AppendLine(Inv, $"{rec.Name,-40} {rec.Ttl,7} {rec.TypeName,-6} {rec.Data}");
        }

        Section("ANSWER", msg.Answers);
        Section("AUTHORITY", msg.Authority);
        Section("ADDITIONAL", msg.Additional.Where(a => a.Type != (ushort)DnsType.OPT).ToList());
    }

    /// <summary>Same question to every server; record sets compared without regard to order, TTLs reported separately.</summary>
    public static async Task<(string Report, string Summary)> CompareAsync(string input, DnsType? type, IReadOnlyList<IPEndPoint> servers, DnsQueryOptions options, CancellationToken ct)
    {
        if (servers.Count < 2) return ("Enter at least two DNS servers to compare.", "Compare needs two or more servers.");
        var (name, qtype) = Normalize(input, type);
        var results = new List<(IPEndPoint Server, DnsQueryResult Last)>();
        var sb = new StringBuilder();
        foreach (var s in servers)
        {
            ct.ThrowIfCancellationRequested();
            var (steps, _) = await DnsClient.ResolveAsync(s, name, qtype, options, ct).ConfigureAwait(false);
            results.Add((s, steps[^1]));
            Append(sb, steps[^1]);
            sb.AppendLine();
        }

        var baseline = results[0];
        var differences = 0;
        sb.AppendLine(Inv, $";; Comparison against {baseline.Server}");
        foreach (var (server, last) in results.Skip(1))
        {
            if (baseline.Last.Outcome != DnsOutcome.Reply || last.Outcome != DnsOutcome.Reply || baseline.Last.Message!.Rcode != last.Message!.Rcode)
            {
                sb.AppendLine(Inv, $"{server}: status differs or unavailable ({baseline.Last.Status} vs {last.Status}).");
                differences++;
                continue;
            }

            var c = DnsCompare.Compare(baseline.Last.Records, last.Records);
            sb.AppendLine(Inv, $"{server}: {c.Result switch { RecordSetComparison.Identical => "identical records", RecordSetComparison.SameRecordsDifferentTtl => "same records, different TTLs", _ => "different records" }}");
            foreach (var x in c.OnlyInFirst) sb.AppendLine("   only on " + baseline.Server + ": " + x);
            foreach (var x in c.OnlyInSecond) sb.AppendLine("   only on " + server + ": " + x);
            foreach (var x in c.TtlDifferences) sb.AppendLine("   " + x);
            if (c.Result == RecordSetComparison.Different) differences++;
        }

        return (sb.ToString(), differences == 0 ? $"All {servers.Count} servers agree on the records." : $"{differences} server(s) differ from {baseline.Server}.");
    }

    /// <summary>Forward → PTR → forward again for every address of the name (or the address entered).</summary>
    public static async Task<(string Report, string Summary)> ForwardReverseAsync(string input, IPEndPoint server, DnsQueryOptions options, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var addresses = new List<string>();
        if (IPAddress.TryParse(input.Trim(), out var ip))
        {
            addresses.Add(ip.ToString());
        }
        else
        {
            foreach (var t in new[] { DnsType.A, DnsType.AAAA })
            {
                var (steps, _) = await DnsClient.ResolveAsync(server, input.Trim(), (ushort)t, options, ct).ConfigureAwait(false);
                Append(sb, steps[^1]);
                addresses.AddRange(steps[^1].Records.Select(r => r.Data));
            }

            sb.AppendLine();
        }

        if (addresses.Count == 0) return (sb + "No addresses to check.", "No addresses found for " + input.Trim() + ".");
        var results = new List<ReverseCheckResult>();
        foreach (var a in addresses.Distinct())
        {
            ct.ThrowIfCancellationRequested();
            var ptr = await DnsClient.QueryAsync(server, DnsWire.PtrName(IPAddress.Parse(a)), (ushort)DnsType.PTR, options, ct).ConfigureAwait(false);
            Append(sb, ptr);
            var names = ptr.Records.Select(r => r.Data).ToList();
            var forward = new Dictionary<string, (int?, IReadOnlyList<string>)>(StringComparer.OrdinalIgnoreCase);
            foreach (var n in names.Take(8))
            {
                var all = new List<string>();
                int? rcode = null;
                foreach (var t in new[] { DnsType.A, DnsType.AAAA })
                {
                    var (steps, _) = await DnsClient.ResolveAsync(server, n.TrimEnd('.'), (ushort)t, options, ct).ConfigureAwait(false);
                    var last = steps[^1];
                    if (last.Outcome == DnsOutcome.Reply) rcode = rcode is null or 3 ? last.Message!.Rcode : rcode;
                    all.AddRange(last.Records.Select(r => r.Data));
                }

                forward[n] = (rcode, all);
            }

            var r = DnsForwardReverse.Classify(a, ptr.Outcome == DnsOutcome.Reply ? ptr.Message!.Rcode : null, names, forward);
            results.Add(r);
            sb.AppendLine(Inv, $";; {a}: {r.Result} — {r.Detail}");
            sb.AppendLine();
        }

        var summary = string.Join(" · ", results.GroupBy(r => r.Result).Select(g => $"{g.Count()} {g.Key}"));
        return (sb.ToString(), summary);
    }

    /// <summary>Parses "192.0.2.53, [2001:db8::53]:5353" into endpoints (default port applied).</summary>
    public static bool TryParseServers(string text, int defaultPort, out List<IPEndPoint> servers, out string error)
    {
        servers = [];
        error = "";
        foreach (var raw in (text ?? "").Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
        {
            IPEndPoint? ep = null;
            if (raw.StartsWith('['))
            {
                // [v6] or [v6]:port
                var close = raw.IndexOf(']', StringComparison.Ordinal);
                if (close > 0 && IPAddress.TryParse(raw[1..close], out var a6))
                {
                    var rest = raw[(close + 1)..];
                    if (rest.Length == 0) ep = new IPEndPoint(a6, defaultPort);
                    else if (rest.StartsWith(':') && int.TryParse(rest[1..], NumberStyles.None, Inv, out var p6) && p6 is > 0 and <= 65535) ep = new IPEndPoint(a6, p6);
                }
            }
            else if (raw.Count(c => c == ':') == 1)
            {
                // v4:port
                var parts = raw.Split(':');
                if (IPAddress.TryParse(parts[0], out var a4) && int.TryParse(parts[1], NumberStyles.None, Inv, out var p4) && p4 is > 0 and <= 65535) ep = new IPEndPoint(a4, p4);
            }
            else if (IPAddress.TryParse(raw, out var a))
            {
                ep = new IPEndPoint(a, defaultPort);
            }

            if (ep is null)
            {
                error = $"'{raw}' is not a DNS server address (use an IP address, address:port or [IPv6]:port).";
                return false;
            }

            servers.Add(ep);
        }

        if (servers.Count == 0) error = "Enter at least one DNS server address.";
        return servers.Count > 0;
    }
}
