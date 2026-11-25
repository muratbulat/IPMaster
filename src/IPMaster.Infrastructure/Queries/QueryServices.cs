using System.Net;
using IPMaster.Core.Configuration;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Security;
using Microsoft.Extensions.Logging;

namespace IPMaster.Infrastructure.Queries;

/// <summary>Builds query providers and plans from the current settings (used by the GUI and the CLI alike).</summary>
public sealed class QueryServices(CredentialVault vault, KnownHostStore knownHosts, ILoggerFactory? loggers = null)
{
    public CredentialVault Vault { get; } = vault;

    public KnownHostStore KnownHosts { get; } = knownHosts;

    public IReadOnlyList<IRemoteQueryProvider> Providers(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return
        [
            new WmiQueryProvider(),
            new RegistryQueryProvider(),
            new FileQueryProvider(),
            new ServiceQueryProvider(),
            new GroupQueryProvider(),
            new PerformanceQueryProvider(),
            new PowerShellQueryProvider(),
            new WshScriptProvider(),
            new SnmpQueryProvider(),
            new SshQueryProvider(KnownHosts),
            new HttpQueryProvider(QueryKind.Xml),
            new HttpQueryProvider(QueryKind.Json),
            new NmapQueryProvider(() => settings.Queries.Nmap),
            new PythonQueryProvider(() => settings.Queries.PythonPath),
        ];
    }

    /// <summary>Plan for a scan; null when no query is enabled.</summary>
    public QueryPlan? Plan(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (!settings.Queries.Enabled.Any()) return null;
        KnownHosts.Load(settings.Queries.KnownHosts);
        return new QueryPlan(settings.Queries, settings.VirtualColumns, settings.AvailableColumns, Providers(settings), Vault, TimeProvider.System,
            loggers?.CreateLogger<QueryPlan>());
    }

    /// <summary>Editor "Test": runs one query (enabled or not) against one address with every other enabled item available to Remote.*.</summary>
    public async Task<Observation<string>> TestAsync(AppSettings settings, QueryDefinition query, IPAddress target, CancellationToken ct,
        DeviceResult? device = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentNullException.ThrowIfNull(target);
        var items = settings.Queries.Items.Where(q => q.Id != query.Id).Append(query with { Enabled = true }).ToList();
        var s = settings with { Queries = settings.Queries with { Items = items } };
        using var plan = new QueryPlan(s.Queries, s.VirtualColumns, s.AvailableColumns, Providers(s), Vault, TimeProvider.System);
        if (!TargetParser.TryParseAddress(target.ToString(), out var key)) throw new ArgumentException("Invalid address.", nameof(target));
        var d = device ?? new DeviceResult { Key = key, Status = DeviceStatus.Online, LastScanned = DateTimeOffset.UtcNow };
        var results = await plan.RunAsync(d, ct, [query.Id]).ConfigureAwait(false);
        return results.TryGetValue(query.ColumnId, out var o) ? o : Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, "No result.");
    }

    /// <summary>Single-column rescan (SCN-04): reruns the given query for one device and returns the device with the new value.</summary>
    public async Task<DeviceResult> RescanColumnAsync(AppSettings settings, DeviceResult device, Guid queryId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(device);
        using var plan = Plan(settings) ?? throw new InvalidOperationException("No query is enabled.");
        var fresh = await plan.RunAsync(device, ct, [queryId]).ConfigureAwait(false);
        var merged = device.Queries.ToDictionary(kv => kv.Key, kv => kv.Value);
        foreach (var (k, v) in fresh) merged[k] = v;
        return device with
        {
            Queries = System.Collections.Immutable.ImmutableSortedDictionary.ToImmutableSortedDictionary(merged, StringComparer.Ordinal),
        };
    }
}
