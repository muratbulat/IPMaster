using System.Net;

namespace IPMaster.Core.Targets;

/// <summary>An IPv4 subnet configured on a local adapter; used to derive network/broadcast addresses.</summary>
public sealed record LocalSubnet(AddressKey Network, int PrefixLength);

public sealed record PlanLimits
{
    /// <summary>Plans larger than this are rejected outright (default: one /8).</summary>
    public ulong MaxTargets { get; init; } = 1UL << 24;

    /// <summary>Plans larger than this need explicit confirmation (GUI dialog, CLI <c>/yes</c>).</summary>
    public ulong ConfirmationThreshold { get; init; } = 65_536;
}

public sealed record PlanOptions
{
    public bool PingNetworkAndBroadcast { get; init; }

    public IReadOnlyList<LocalSubnet> LocalSubnets { get; init; } = [];

    public IgnoreList Ignore { get; init; } = IgnoreList.Empty;

    public PlanLimits Limits { get; init; } = new();

    public bool Confirmed { get; init; }

    /// <summary>Performs IPv6 neighbour discovery on an interface scope; returns responders (with scope IDs).</summary>
    public Func<long, CancellationToken, Task<IReadOnlyList<IPAddress>>>? Discover { get; init; }

    /// <summary>Addresses never produced by the plan (rescan of previously undiscovered addresses).</summary>
    public IReadOnlySet<AddressKey>? Exclude { get; init; }
}

public enum PlanStatus
{
    Ready,
    NeedsConfirmation,
    TooLarge,
    Empty,
}

public sealed record PlanBuildResult(
    PlanStatus Status,
    TargetPlan Plan,
    UInt128 RawCount,
    IReadOnlyList<string> Errors,
    IReadOnlyList<string> Warnings)
{
    public bool CanStart => Status == PlanStatus.Ready;
}

/// <summary>Resolves host-name targets to an address. Returns null when unresolvable.</summary>
public delegate Task<IPAddress?> HostTargetResolver(string hostName, CancellationToken cancellationToken);

public static class TargetPlanBuilder
{
    /// <summary>Host-name targets resolved at the same time while a plan is built.</summary>
    public const int MaxConcurrentHostLookups = 16;

    public static async Task<PlanBuildResult> BuildAsync(
        IEnumerable<TargetSpec> specs,
        PlanOptions options,
        HostTargetResolver? resolver,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(specs);
        ArgumentNullException.ThrowIfNull(options);
        var list = specs.ToList();
        var errors = new List<string>();
        var warnings = new List<string>();

        UInt128 raw = 0;
        foreach (var s in list) raw += s.RawCount;

        if (list.Count == 0)
        {
            return new PlanBuildResult(PlanStatus.Empty, TargetPlan.Empty, 0, ["No enabled targets."], warnings);
        }

        if (raw > options.Limits.MaxTargets)
        {
            return new PlanBuildResult(PlanStatus.TooLarge, TargetPlan.Empty, raw,
                [$"The targets describe {raw:N0} addresses, above the limit of {options.Limits.MaxTargets:N0}. Narrow the ranges (IPv6 ranges in particular) or raise the limit in options."],
                warnings);
        }

        var v4Intervals = new List<(UInt128, UInt128)>();
        var v6Intervals = new Dictionary<long, List<(UInt128, UInt128)>>();
        var octet = new List<OctetRangeSource>();
        var singles = new AddressListSource();
        var excluded = new HashSet<AddressKey>();

        // Host names are resolved up front, concurrently but bounded (review C-19); the plan is then built in the original order.
        var resolved = new Dictionary<int, (IPAddress? Address, string? Error)>();
        if (resolver is not null)
        {
            var hostIndexes = Enumerable.Range(0, list.Count).Where(i => list[i].Kind == TargetKind.HostName).ToList();
            await Parallel.ForEachAsync(hostIndexes, new ParallelOptions { MaxDegreeOfParallelism = MaxConcurrentHostLookups, CancellationToken = cancellationToken },
                async (i, ct) =>
                {
                    (IPAddress?, string?) r;
                    try
                    {
                        r = (await resolver(list[i].HostName!, ct).ConfigureAwait(false), null);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        r = (null, ex.Message);
                    }

                    lock (resolved) resolved[i] = r;
                }).ConfigureAwait(false);
        }

        for (var index = 0; index < list.Count; index++)
        {
            var spec = list[index];
            switch (spec.Kind)
            {
                case TargetKind.HostName:
                {
                    var (addr, error) = resolved.TryGetValue(index, out var r) ? r : (null, null);
                    if (error is not null)
                    {
                        errors.Add($"Host name '{spec.HostName}' could not be resolved: {error}");
                        continue;
                    }

                    if (addr is null) errors.Add($"Host name '{spec.HostName}' could not be resolved.");
                    else singles.Add(AddressKey.From(addr));
                    break;
                }

                case TargetKind.NeighborDiscovery:
                {
                    if (options.Discover is null)
                    {
                        errors.Add($"Neighbour discovery on {spec.Original} is not available here.");
                        break;
                    }

                    var found = await options.Discover(spec.Start.ScopeId, cancellationToken).ConfigureAwait(false);
                    if (found.Count == 0) errors.Add($"Neighbour discovery on {spec.Original} found no responders.");
                    foreach (var a in found) singles.Add(AddressKey.From(a));
                    break;
                }

                case TargetKind.SingleAddress:
                    singles.Add(spec.Start);
                    break;

                default:
                    if (spec.OctetMode && !spec.IsV6)
                    {
                        octet.Add(new OctetRangeSource(spec.Start.V4, spec.End.V4));
                    }
                    else if (spec.IsV6)
                    {
                        if (!v6Intervals.TryGetValue(spec.Start.ScopeId, out var l)) v6Intervals[spec.Start.ScopeId] = l = [];
                        l.Add((spec.Start.Value, spec.End.Value));
                    }
                    else
                    {
                        v4Intervals.Add((spec.Start.Value, spec.End.Value));
                    }

                    if (!options.PingNetworkAndBroadcast && !spec.IsV6 && spec.Kind == TargetKind.Cidr && spec.PrefixLength <= 30)
                    {
                        excluded.Add(spec.Start);
                        excluded.Add(spec.End);
                    }

                    break;
            }
        }

        if (!options.PingNetworkAndBroadcast)
        {
            foreach (var subnet in options.LocalSubnets)
            {
                if (subnet.Network.IsV6 || subnet.PrefixLength > 30) continue;
                var mask = AddressKey.MaskFor(subnet.PrefixLength, false);
                var net = subnet.Network.Value & mask;
                excluded.Add(AddressKey.FromIPv4((uint)net));
                excluded.Add(AddressKey.FromIPv4((uint)(net | (uint.MaxValue & ~mask))));
            }
        }

        var sources = new List<ITargetSource>();
        if (v4Intervals.Count > 0) sources.Add(new IntervalSetSource(v4Intervals, false, 0));
        sources.AddRange(octet);
        if (singles.Count > 0) sources.Add(singles);
        foreach (var (scope, intervals) in v6Intervals.OrderBy(k => k.Key)) sources.Add(new IntervalSetSource(intervals, true, scope));

        foreach (var r in options.Ignore.Rejected) warnings.Add($"Ignored-address line {r.LineNumber} skipped: {r.Reason}");

        var plan = new TargetPlan(sources, options.Ignore, excluded, warnings, options.Exclude);
        if (plan.RawCount == 0)
        {
            return new PlanBuildResult(PlanStatus.Empty, plan, 0, errors.Count > 0 ? errors : ["Nothing to scan."], warnings);
        }

        var status = plan.RawCount > options.Limits.ConfirmationThreshold && !options.Confirmed
            ? PlanStatus.NeedsConfirmation
            : PlanStatus.Ready;
        return new PlanBuildResult(status, plan, plan.RawCount, errors, warnings);
    }
}
