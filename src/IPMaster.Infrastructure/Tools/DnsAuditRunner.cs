using System.Net;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

/// <summary>
/// Runs the Bulk DNS Audit lookups (D-094) with <see cref="DnsClient"/> against each chosen server: A and AAAA (CNAME
/// chains followed), PTR of every address found, and A/AAAA of every PTR name (forward confirmation). Read-only queries
/// only. Bounded: at most <see cref="MaxEntries"/> entries, <see cref="Parallel"/> entries at a time, 8 PTR names per address.
/// </summary>
public static class DnsAuditRunner
{
    public const int MaxEntries = 5000;
    public const int Parallel = 8;

    public static async Task<IReadOnlyList<DnsAuditEntry>> RunAsync(IReadOnlyList<string> inputs, IReadOnlyList<IPEndPoint> servers, DnsQueryOptions options,
        Action<DnsAuditEntry>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(servers);
        if (inputs.Count > MaxEntries) throw new ArgumentException($"At most {MaxEntries} entries per audit.", nameof(inputs));
        if (servers.Count == 0) throw new ArgumentException("Choose at least one DNS server.", nameof(servers));
        var results = new DnsAuditEntry[inputs.Count];
        using var slots = new SemaphoreSlim(Parallel);
        await Task.WhenAll(inputs.Select(async (input, i) =>
        {
            await slots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                results[i] = await AuditAsync(input, servers, options, ct).ConfigureAwait(false);
                progress?.Invoke(results[i]);
            }
            finally
            {
                slots.Release();
            }
        })).ConfigureAwait(false);
        return results;
    }

    private static async Task<DnsAuditEntry> AuditAsync(string input, IReadOnlyList<IPEndPoint> servers, DnsQueryOptions options, CancellationToken ct)
    {
        var lookups = new List<DnsLookup>();
        var isAddress = IPAddress.TryParse(input, out var address);
        foreach (var server in servers)
        {
            var s = server.ToString();
            var addresses = new List<string>();
            if (isAddress)
            {
                addresses.Add(address!.ToString());
            }
            else
            {
                foreach (var type in new[] { DnsType.A, DnsType.AAAA })
                {
                    var l = await LookupAsync(server, input, type, options, ct).ConfigureAwait(false);
                    lookups.Add(l);
                    addresses.AddRange(l.HasData ? l.Values : []);
                }
            }

            foreach (var a in addresses.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var ptr = await LookupAsync(server, a, DnsType.PTR, options, ct).ConfigureAwait(false);
                lookups.Add(ptr);
                foreach (var name in ptr.HasData ? ptr.Values.Take(8) : [])
                {
                    var ip = IPAddress.Parse(a);
                    var type = ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? DnsType.A : DnsType.AAAA;
                    if (!lookups.Any(x => x.Server == s && x.Type == type.ToString() && string.Equals(x.Name, name.TrimEnd('.'), StringComparison.OrdinalIgnoreCase)))
                    {
                        lookups.Add(await LookupAsync(server, name.TrimEnd('.'), type, options, ct).ConfigureAwait(false));
                    }
                }
            }
        }

        return new DnsAuditEntry(input, isAddress, lookups);
    }

    private static async Task<DnsLookup> LookupAsync(IPEndPoint server, string name, DnsType type, DnsQueryOptions options, CancellationToken ct)
    {
        var query = type == DnsType.PTR ? DnsWire.PtrName(IPAddress.Parse(name)) : name;
        var (steps, chainProblem) = await DnsClient.ResolveAsync(server, query, (ushort)type, options, ct).ConfigureAwait(false);
        var last = steps[^1];
        var chain = steps.Count > 1 ? string.Join(" → ", steps.Select(st => st.Name.TrimEnd('.'))) + (chainProblem is null ? "" : $" ({chainProblem})") : chainProblem ?? "";
        var values = last.Records.Select(r => r.Data.TrimEnd('.')).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var status = last.Outcome == DnsOutcome.Reply && last.Message!.Rcode == 0 && values.Count == 0 ? "NOERROR (no data)" : last.Status;
        return new DnsLookup(server.ToString(), name, type.ToString(), status, values, chain);
    }
}
