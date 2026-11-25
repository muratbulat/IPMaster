using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Text.RegularExpressions;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace IPMaster.Core.Queries;

/// <summary>Implements one query family. Providers never fabricate values: unavailable runtimes report Unsupported.</summary>
public interface IRemoteQueryProvider
{
    QueryKind Kind { get; }

    /// <summary>Whether this scanner can run the family at all (OS, runtime, tool installed).</summary>
    CapabilityStatus Capability { get; }

    Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken);
}

/// <summary>What a script can ask the host while it runs (Input.Column, Remote.*).</summary>
public interface IQueryContext
{
    /// <summary>Display text of another column of the same device.</summary>
    string Column(string name);

    /// <summary>Runs another configured query (by Remote.* family name and item name) and returns its text.</summary>
    Task<string> RemoteAsync(string family, string name, CancellationToken cancellationToken);
}

public sealed record QueryCall(
    QueryDefinition Query,
    DeviceResult Device,
    ResolvedCredential? Credential,
    QuerySettings Settings,
    ISecretSource Secrets,
    IQueryContext Context);

public static class QueryColumns
{
    public const string Prefix = "q:";

    /// <summary>Family names of the manual's <c>Remote</c> namespace.</summary>
    public static readonly IReadOnlyDictionary<string, QueryKind> RemoteFamilies = new Dictionary<string, QueryKind>(StringComparer.OrdinalIgnoreCase)
    {
        ["Files"] = QueryKind.Files,
        ["Groups"] = QueryKind.Groups,
        ["JSON"] = QueryKind.Json,
        ["Nmap"] = QueryKind.Nmap,
        ["Performance"] = QueryKind.Performance,
        ["PowerShell"] = QueryKind.PowerShell,
        ["Registry"] = QueryKind.Registry,
        ["SNMP"] = QueryKind.Snmp,
        ["SSH"] = QueryKind.Ssh,
        ["Services"] = QueryKind.Services,
        ["WMI"] = QueryKind.Wmi,
        ["XML"] = QueryKind.Xml,
    };

    public static string DisplayName(QueryKind kind) => kind switch
    {
        QueryKind.Wmi => "WMI",
        QueryKind.Snmp => "SNMP",
        QueryKind.Ssh => "SSH",
        QueryKind.Xml => "XML",
        QueryKind.Json => "JSON",
        QueryKind.Script => "Scripting",
        _ => kind.ToString(),
    };

    public static IEnumerable<ResultColumn> For(QuerySettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        foreach (var q in settings.Enabled)
        {
            var id = q.ColumnId;
            yield return new ResultColumn(id, q.Name, ColumnKind.Text,
                (d, _) => d.Queries.TryGetValue(id, out var o) ? ObservationText.Render(o, v => v) : "");
        }
    }
}

/// <summary>Static dependency graph of the enabled queries (QRY-02).</summary>
public sealed record QueryGraph(
    IReadOnlyList<QueryDefinition> Order,
    IReadOnlyDictionary<Guid, int> Levels,
    IReadOnlyDictionary<Guid, IReadOnlyList<Guid>> Dependencies,
    IReadOnlyDictionary<Guid, string> Errors);

public static partial class QueryDependencies
{
    [GeneratedRegex("""Input\s*\.\s*Column\s*\(\s*(?:"([^"]*)"|'([^']*)')\s*\)""", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex ColumnCall();

    [GeneratedRegex("""Remote\s*\.\s*([A-Za-z]+)\s*\(\s*(?:"([^"]*)"|'([^']*)')\s*\)""", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)]
    private static partial Regex RemoteCall();

    public static IReadOnlyList<string> ColumnReads(string script) =>
        ColumnCall().Matches(script ?? "").Select(m => m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value).ToList();

    public static IReadOnlyList<(string Family, string Name)> RemoteCalls(string script) =>
        RemoteCall().Matches(script ?? "").Select(m => (m.Groups[1].Value, m.Groups[2].Success ? m.Groups[2].Value : m.Groups[3].Value)).ToList();

    public static string? ScriptText(QueryDefinition q) => q.Kind switch
    {
        QueryKind.Script => q.Script?.Script,
        QueryKind.Python => q.Python?.Script,
        _ => null,
    };

    public static QueryGraph Build(IReadOnlyList<QueryDefinition> enabled, IReadOnlyList<VirtualColumnDefinition> virtualColumns)
    {
        ArgumentNullException.ThrowIfNull(enabled);
        ArgumentNullException.ThrowIfNull(virtualColumns);
        var byId = enabled.ToDictionary(q => q.Id);
        var deps = new Dictionary<Guid, IReadOnlyList<Guid>>();
        var errors = new Dictionary<Guid, string>();
        foreach (var q in enabled)
        {
            var set = new HashSet<Guid>();
            if (ScriptText(q) is { } script)
            {
                foreach (var col in ColumnReads(script)) AddColumn(col, set, enabled, virtualColumns, 0);
                foreach (var (family, name) in RemoteCalls(script))
                {
                    if (!QueryColumns.RemoteFamilies.TryGetValue(family, out var kind))
                    {
                        errors[q.Id] = $"Unknown Remote family '{family}'.";
                        continue;
                    }

                    var target = enabled.FirstOrDefault(t => t.Kind == kind && string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));
                    if (target is not null) set.Add(target.Id);
                }
            }

            deps[q.Id] = set.ToList();
        }

        // Cycles: Tarjan's strongly connected components.
        foreach (var scc in StronglyConnected(enabled.Select(q => q.Id).ToList(), id => deps[id]))
        {
            if (scc.Count > 1 || deps[scc[0]].Contains(scc[0]))
            {
                var names = string.Join(" → ", scc.Append(scc[0]).Select(id => byId[id].Name));
                foreach (var id in scc) errors[id] = "Dependency cycle: " + names;
            }
        }

        // Levels and order; anything depending on a failed item fails too.
        var levels = new Dictionary<Guid, int>();
        int Level(Guid id, int guard)
        {
            if (levels.TryGetValue(id, out var l)) return l;
            if (guard > enabled.Count) return 0;
            var lvl = deps[id].Count == 0 ? 0 : deps[id].Max(d => Level(d, guard + 1)) + 1;
            levels[id] = lvl;
            return lvl;
        }

        foreach (var q in enabled.Where(q => !errors.ContainsKey(q.Id))) Level(q.Id, 0);
        bool changed;
        do
        {
            changed = false;
            foreach (var q in enabled.Where(q => !errors.ContainsKey(q.Id)))
            {
                if (deps[q.Id].FirstOrDefault(errors.ContainsKey) is var bad && bad != Guid.Empty && byId.TryGetValue(bad, out var badQuery))
                {
                    errors[q.Id] = $"Depends on '{badQuery.Name}', which cannot run.";
                    changed = true;
                }
            }
        }
        while (changed);

        var order = enabled.Where(q => !errors.ContainsKey(q.Id)).OrderBy(q => levels.GetValueOrDefault(q.Id)).ToList();
        return new QueryGraph(order, levels, deps, errors);
    }

    private static void AddColumn(string name, HashSet<Guid> set, IReadOnlyList<QueryDefinition> enabled, IReadOnlyList<VirtualColumnDefinition> virtualColumns, int depth)
    {
        if (depth > 32) return;
        foreach (var q in enabled.Where(q => string.Equals(q.Name, name, StringComparison.OrdinalIgnoreCase) || string.Equals(q.ColumnId, name, StringComparison.OrdinalIgnoreCase)))
        {
            set.Add(q.Id);
        }

        var v = virtualColumns.FirstOrDefault(v => string.Equals(v.Name, name, StringComparison.OrdinalIgnoreCase));
        if (v is null) return;
        foreach (Match m in VirtualRef().Matches(v.Source)) AddColumn(m.Groups[1].Value, set, enabled, virtualColumns, depth + 1);
    }

    [GeneratedRegex(@"\[([^\]]+)\]", RegexOptions.CultureInvariant)]
    private static partial Regex VirtualRef();

    private static List<List<Guid>> StronglyConnected(List<Guid> nodes, Func<Guid, IReadOnlyList<Guid>> edges)
    {
        var index = 0;
        var stack = new Stack<Guid>();
        var onStack = new HashSet<Guid>();
        var idx = new Dictionary<Guid, int>();
        var low = new Dictionary<Guid, int>();
        var result = new List<List<Guid>>();
        var known = nodes.ToHashSet();

        void Visit(Guid v)
        {
            idx[v] = low[v] = index++;
            stack.Push(v);
            onStack.Add(v);
            foreach (var w in edges(v).Where(known.Contains))
            {
                if (!idx.TryGetValue(w, out var wIndex))
                {
                    Visit(w);
                    low[v] = Math.Min(low[v], low[w]);
                }
                else if (onStack.Contains(w))
                {
                    low[v] = Math.Min(low[v], wIndex);
                }
            }

            if (low[v] != idx[v]) return;
            var scc = new List<Guid>();
            Guid x;
            do
            {
                x = stack.Pop();
                onStack.Remove(x);
                scc.Add(x);
            }
            while (x != v);
            scc.Reverse();
            result.Add(scc);
        }

        foreach (var n in nodes.Where(n => !idx.ContainsKey(n))) Visit(n);
        return result;
    }
}

/// <summary>
/// Runs the enabled queries for devices of one scan (or for a single-column rescan). Levels run in dependency order;
/// queries of one level run concurrently under the plan's own budget. <c>Remote.*</c> calls run nested under the
/// caller's slot, are memoised per device and can never wait on an item that is still running elsewhere, so dynamic
/// call graphs cannot deadlock; a call that re-enters its own chain is reported as a cycle (QRY-02).
/// </summary>
public sealed class QueryPlan : IDisposable
{
    public const int MaxNesting = 8;

    private readonly IReadOnlyDictionary<QueryKind, IRemoteQueryProvider> _providers;
    private readonly ISecretSource _secrets;
    private readonly QuerySettings _settings;
    private readonly IReadOnlyList<ResultColumn> _columns;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;
    private readonly SemaphoreSlim _slots;

    public QueryPlan(QuerySettings settings, IReadOnlyList<VirtualColumnDefinition> virtualColumns, IReadOnlyList<ResultColumn> columns,
        IEnumerable<IRemoteQueryProvider> providers, ISecretSource secrets, TimeProvider? time = null, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(providers);
        _settings = settings;
        _columns = columns ?? [];
        _providers = providers.GroupBy(p => p.Kind).ToDictionary(g => g.Key, g => g.First());
        _secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
        _time = time ?? TimeProvider.System;
        _logger = logger ?? NullLogger.Instance;
        All = settings.Enabled.ToList();
        Graph = QueryDependencies.Build(All, virtualColumns ?? []);
        var concurrency = Math.Clamp(settings.Concurrency, 1, 256);
        _slots = new SemaphoreSlim(concurrency, concurrency);
    }

    /// <summary>Enabled queries, including those that cannot run (cycles).</summary>
    public IReadOnlyList<QueryDefinition> All { get; }

    public QueryGraph Graph { get; }

    public bool IsEmpty => All.Count == 0;

    public void Dispose() => _slots.Dispose();

    public ImmutableSortedDictionary<string, Observation<string>> Pending(IReadOnlyCollection<Guid>? only = null) =>
        All.Where(q => only is null || only.Contains(q.Id))
            .ToImmutableSortedDictionary(q => q.ColumnId, _ => Observation<string>.Pending, StringComparer.Ordinal);

    /// <summary>Runs every query (or <paramref name="only"/>) for one device; results keyed by column id.</summary>
    public async Task<ImmutableSortedDictionary<string, Observation<string>>> RunAsync(DeviceResult device, CancellationToken cancellationToken,
        IReadOnlyCollection<Guid>? only = null)
    {
        ArgumentNullException.ThrowIfNull(device);
        var run = new DeviceRun(this, device);
        var now = _time.GetUtcNow();
        foreach (var q in All.Where(q => only is null || only.Contains(q.Id)))
        {
            if (Graph.Errors.TryGetValue(q.Id, out var err)) run.Set(q, Observation<string>.Of(ObservationState.Failed, now, err));
        }

        // A single-column rescan still evaluates that column's dependencies (they feed Input.Column).
        var wanted = only is null ? Graph.Order : Graph.Order.Where(q => only.Contains(q.Id) || IsDependencyOf(q.Id, only)).ToList();
        foreach (var level in wanted.GroupBy(q => Graph.Levels.GetValueOrDefault(q.Id)).OrderBy(g => g.Key))
        {
            await Task.WhenAll(level.Select(q => run.TopLevelAsync(q, cancellationToken))).ConfigureAwait(false);
        }

        return run.Results(only);
    }

    private bool IsDependencyOf(Guid id, IReadOnlyCollection<Guid> roots)
    {
        var seen = new HashSet<Guid>();
        var stack = new Stack<Guid>(roots);
        while (stack.Count > 0)
        {
            var r = stack.Pop();
            if (!seen.Add(r) || !Graph.Dependencies.TryGetValue(r, out var deps)) continue;
            foreach (var d in deps)
            {
                if (d == id) return true;
                stack.Push(d);
            }
        }

        return false;
    }

    private async Task<Observation<string>> ExecuteAsync(QueryDefinition q, DeviceResult device, IQueryContext context, CancellationToken ct)
    {
        var now = _time.GetUtcNow();
        if (!_providers.TryGetValue(q.Kind, out var provider))
        {
            return Observation<string>.Of(ObservationState.Unsupported, now, $"{QueryColumns.DisplayName(q.Kind)} queries are not available in this build.");
        }

        if (!provider.Capability.Available) return Observation<string>.Of(ObservationState.Unsupported, now, provider.Capability.Description);
        ResolvedCredential? credential = null;
        if (q.CredentialId is { } cid)
        {
            if (!_secrets.CanReveal) return Observation<string>.Of(ObservationState.Failed, now, "Credentials are locked (master password or OS key unavailable).");
            credential = _secrets.Credential(cid);
            if (credential is null) return Observation<string>.Of(ObservationState.Failed, now, "The selected credential no longer exists.");
        }

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Clamp(q.TimeoutSeconds, 1, 3600)), _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        try
        {
            var result = await provider.ExecuteAsync(new QueryCall(q, device, credential, _settings, _secrets, context), linked.Token).ConfigureAwait(false);
            if (result.State == ObservationState.Success && string.IsNullOrWhiteSpace(result.Value))
            {
                return Observation<string>.Of(ObservationState.Empty, result.ObservedAt ?? _time.GetUtcNow(), result.Detail);
            }

            return result;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return Observation<string>.Of(ObservationState.Timeout, _time.GetUtcNow(), $"No result within {q.TimeoutSeconds} s.");
        }
        catch (UnauthorizedAccessException ex)
        {
            return Observation<string>.Of(ObservationState.AccessDenied, _time.GetUtcNow(), ex.Message);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (_logger.IsEnabled(LogLevel.Debug)) _logger.LogDebug(ex, "Query {Name} failed", q.Name);
            return Observation<string>.Of(ObservationState.Failed, _time.GetUtcNow(), ex.Message);
        }
    }

    private sealed class DeviceRun(QueryPlan owner, DeviceResult device)
    {
        public QueryPlan Plan { get; } = owner;

        private readonly ConcurrentDictionary<Guid, Task<Observation<string>>> _tasks = new();
        private readonly object _lock = new();
        private ImmutableSortedDictionary<string, Observation<string>> _results =
            device.Queries.ToImmutableSortedDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);

        public void Set(QueryDefinition q, Observation<string> o)
        {
            lock (_lock) _results = _results.SetItem(q.ColumnId, o);
        }

        public ImmutableSortedDictionary<string, Observation<string>> Results(IReadOnlyCollection<Guid>? only)
        {
            lock (_lock)
            {
                if (only is null) return _results;
                var keep = Plan.All.Where(q => only.Contains(q.Id)).Select(q => q.ColumnId).ToHashSet();
                return _results.Where(kv => keep.Contains(kv.Key)).ToImmutableSortedDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            }
        }

        private DeviceResult Snapshot()
        {
            lock (_lock) return device with { Queries = _results };
        }

        public async Task TopLevelAsync(QueryDefinition q, CancellationToken ct)
        {
            if (_tasks.TryGetValue(q.Id, out var done))
            {
                await done.ConfigureAwait(false);
                return;
            }

            await Plan._slots.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await GetOrRun(q, [], ct).ConfigureAwait(false);
            }
            finally
            {
                Plan._slots.Release();
            }
        }

        private Task<Observation<string>> GetOrRun(QueryDefinition q, ImmutableList<Guid> chain, CancellationToken ct)
        {
            var mine = new TaskCompletionSource<Observation<string>>(TaskCreationOptions.RunContinuationsAsynchronously);
            var existing = _tasks.GetOrAdd(q.Id, mine.Task);
            if (existing != mine.Task)
            {
                // Completed elsewhere: reuse. Still running elsewhere: run an independent copy (never wait → no deadlock).
                return existing.IsCompleted ? existing : RunCore(q, chain, ct);
            }

            _ = CompleteAsync();
            return mine.Task;

            async Task CompleteAsync()
            {
                try
                {
                    mine.SetResult(await RunCore(q, chain, ct).ConfigureAwait(false));
                }
                catch (Exception ex)
                {
                    mine.SetException(ex);
                }
            }
        }

        private async Task<Observation<string>> RunCore(QueryDefinition q, ImmutableList<Guid> chain, CancellationToken ct)
        {
            var context = new Context(this, chain.Add(q.Id), q);
            var result = await Plan.ExecuteAsync(q, Snapshot(), context, ct).ConfigureAwait(false);
            Set(q, result);
            return result;
        }

        private sealed class Context(DeviceRun run, ImmutableList<Guid> chain, QueryDefinition self) : IQueryContext
        {
            public string Column(string name)
            {
                var snapshot = run.Snapshot();
                var col = run.Plan._columns.FirstOrDefault(c => string.Equals(c.Header, name, StringComparison.OrdinalIgnoreCase))
                          ?? run.Plan._columns.FirstOrDefault(c => string.Equals(c.Id, name, StringComparison.OrdinalIgnoreCase));
                if (col is null) return "";
                if (col.Id == self.ColumnId) return "";
                return col.Text(snapshot);
            }

            public async Task<string> RemoteAsync(string family, string name, CancellationToken cancellationToken)
            {
                if (!QueryColumns.RemoteFamilies.TryGetValue(family, out var kind)) throw new ArgumentException($"Unknown Remote family '{family}'.", nameof(family));
                var target = run.Plan.All.FirstOrDefault(q => q.Kind == kind && string.Equals(q.Name, name, StringComparison.OrdinalIgnoreCase));
                if (target is null) return $"[no {QueryColumns.DisplayName(kind)} item named '{name}']";
                if (chain.Contains(target.Id)) return "[dependency cycle]";
                if (chain.Count >= MaxNesting) return "[nesting limit reached]";
                if (run.Plan.Graph.Errors.TryGetValue(target.Id, out var err)) return $"[{err}]";
                var o = await run.GetOrRun(target, chain, cancellationToken).ConfigureAwait(false);
                return ObservationText.Render(o, v => v);
            }
        }
    }
}
