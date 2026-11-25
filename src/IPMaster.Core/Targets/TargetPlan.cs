namespace IPMaster.Core.Targets;

/// <summary>
/// An immutable, lazily enumerated scan plan. Addresses are deduplicated across sources (an address
/// is produced by the first source that contains it) and filtered by the ignore list and
/// network/broadcast exclusions, without materialising the address set.
/// </summary>
public sealed class TargetPlan
{
    private readonly IReadOnlyList<ITargetSource> _sources;
    private readonly ulong[] _offsets;
    private readonly IgnoreList _ignore;
    private readonly HashSet<AddressKey> _excludedEndpoints;
    private readonly IReadOnlySet<AddressKey>? _exclude;

    internal TargetPlan(IReadOnlyList<ITargetSource> sources, IgnoreList ignore, HashSet<AddressKey> excludedEndpoints,
        IReadOnlyList<string> warnings, IReadOnlySet<AddressKey>? exclude = null)
    {
        _exclude = exclude is { Count: > 0 } ? exclude : null;
        _sources = sources;
        _ignore = ignore;
        _excludedEndpoints = excludedEndpoints;
        Warnings = warnings;
        _offsets = new ulong[sources.Count];
        ulong total = 0;
        for (var i = 0; i < sources.Count; i++)
        {
            _offsets[i] = total;
            total = checked(total + sources[i].Count);
        }

        RawCount = total;
    }

    public static TargetPlan Empty { get; } = new([], IgnoreList.Empty, [], []);

    /// <summary>Upper bound: sum of all source sizes before deduplication and exclusions.</summary>
    public ulong RawCount { get; }

    public IReadOnlyList<string> Warnings { get; }

    /// <summary>Exact number of addresses that will be scanned. Computed by a counting pass (no allocation per address).</summary>
    public ulong CountExact(CancellationToken cancellationToken = default)
    {
        ulong n = 0;
        for (ulong i = 0; i < RawCount; i++)
        {
            if ((i & 0xFFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            if (TryGet(i, out _)) n++;
        }

        return n;
    }

    public IEnumerable<AddressKey> Enumerate(bool randomOrder = false, ulong seed = 0)
    {
        if (RawCount == 0) yield break;
        var perm = randomOrder ? new IndexPermutation(RawCount, seed == 0 ? (ulong)Random.Shared.NextInt64() : seed) : null;
        for (ulong i = 0; i < RawCount; i++)
        {
            var raw = perm?.Map(i) ?? i;
            if (TryGet(raw, out var key)) yield return key;
        }
    }

    public bool Contains(AddressKey key)
    {
        for (var s = 0; s < _sources.Count; s++)
        {
            if (_sources[s].Contains(key) && !IsExcludedEndpoint(key, _sources[s])) return (_exclude is null || !_exclude.Contains(key)) && (_ignore.IsEmpty || !_ignore.IsIgnored(key));
        }

        return false;
    }

    private bool TryGet(ulong rawIndex, out AddressKey key)
    {
        var s = FindSource(rawIndex);
        var source = _sources[s];
        key = source.ElementAt(rawIndex - _offsets[s]);
        for (var earlier = 0; earlier < s; earlier++)
        {
            // an earlier source wins only if it would actually emit the address (not an excluded endpoint)
            if (_sources[earlier].Contains(key) && !IsExcludedEndpoint(key, _sources[earlier])) return false;
        }

        return !IsExcluded(key, source);
    }

    private bool IsExcludedEndpoint(AddressKey key, ITargetSource source)
        => !source.IsExplicitList && _excludedEndpoints.Count > 0 && _excludedEndpoints.Contains(key);

    private bool IsExcluded(AddressKey key, ITargetSource source)
    {
        if (IsExcludedEndpoint(key, source)) return true;
        if (_exclude is not null && _exclude.Contains(key)) return true;
        return !_ignore.IsEmpty && _ignore.IsIgnored(key);
    }

    private int FindSource(ulong rawIndex)
    {
        var lo = 0;
        var hi = _offsets.Length - 1;
        while (lo < hi)
        {
            var mid = (lo + hi + 1) / 2;
            if (_offsets[mid] <= rawIndex) lo = mid;
            else hi = mid - 1;
        }

        // skip empty sources sharing the same offset
        while (lo < _sources.Count - 1 && _sources[lo].Count == 0) lo++;
        return lo;
    }
}
