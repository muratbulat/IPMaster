namespace IPMaster.Core.Targets;

/// <summary>
/// A lazily indexable set of addresses. Sources never materialise their contents; plans compose
/// them and enumerate by index, which also enables random-order permutation.
/// </summary>
public interface ITargetSource
{
    ulong Count { get; }

    AddressKey ElementAt(ulong index);

    bool Contains(AddressKey address);

    /// <summary>True for sources built from explicitly listed single addresses (never subject to
    /// network/broadcast exclusion).</summary>
    bool IsExplicitList { get; }
}

/// <summary>Union of sequential ranges of one address family and scope, merged and sorted.</summary>
public sealed class IntervalSetSource : ITargetSource
{
    private readonly (UInt128 Start, UInt128 End)[] _intervals;
    private readonly ulong[] _prefixCounts; // cumulative counts before interval i
    private readonly bool _isV6;
    private readonly long _scope;

    public IntervalSetSource(IEnumerable<(UInt128 Start, UInt128 End)> intervals, bool isV6, long scopeId)
    {
        ArgumentNullException.ThrowIfNull(intervals);
        _isV6 = isV6;
        _scope = scopeId;
        var sorted = intervals.OrderBy(i => i.Start).ToList();
        var merged = new List<(UInt128 Start, UInt128 End)>();
        foreach (var iv in sorted)
        {
            if (merged.Count > 0)
            {
                var last = merged[^1];
                // merge overlapping or adjacent intervals
                if (iv.Start <= last.End || (last.End != UInt128.MaxValue && iv.Start == last.End + 1))
                {
                    merged[^1] = (last.Start, iv.End > last.End ? iv.End : last.End);
                    continue;
                }
            }

            merged.Add(iv);
        }

        _intervals = merged.ToArray();
        _prefixCounts = new ulong[_intervals.Length];
        UInt128 total = 0;
        for (var i = 0; i < _intervals.Length; i++)
        {
            _prefixCounts[i] = checked((ulong)total);
            total += _intervals[i].End - _intervals[i].Start + 1;
        }

        Count = checked((ulong)total);
    }

    public ulong Count { get; }

    public bool IsExplicitList => false;

    public AddressKey ElementAt(ulong index)
    {
        if (index >= Count) throw new ArgumentOutOfRangeException(nameof(index));
        var lo = 0;
        var hi = _intervals.Length - 1;
        while (lo < hi)
        {
            var mid = (lo + hi + 1) / 2;
            if (_prefixCounts[mid] <= index) lo = mid;
            else hi = mid - 1;
        }

        return new AddressKey(_intervals[lo].Start + (index - _prefixCounts[lo]), _isV6, _scope);
    }

    public bool Contains(AddressKey address)
    {
        if (address.IsV6 != _isV6 || (_isV6 && address.ScopeId != _scope)) return false;
        var lo = 0;
        var hi = _intervals.Length - 1;
        while (lo <= hi)
        {
            var mid = (lo + hi) / 2;
            var (s, e) = _intervals[mid];
            if (address.Value < s) hi = mid - 1;
            else if (address.Value > e) lo = mid + 1;
            else return true;
        }

        return false;
    }
}

/// <summary>
/// IPv4 octet range mode: every octet varies independently between the start and end octet.
/// For 10.1.254.1–10.9.254.5 this yields 1×9×1×5 = 45 addresses.
/// </summary>
public sealed class OctetRangeSource : ITargetSource
{
    private readonly byte[] _lo = new byte[4];
    private readonly byte[] _hi = new byte[4];

    public OctetRangeSource(uint start, uint end)
    {
        if (!IsValid(start, end)) throw new ArgumentException("Each start octet must be <= the matching end octet.");
        for (var i = 0; i < 4; i++)
        {
            _lo[i] = (byte)(start >> (24 - (8 * i)));
            _hi[i] = (byte)(end >> (24 - (8 * i)));
        }

        Count = (ulong)CountFor(start, end);
    }

    public static bool IsValid(uint start, uint end)
    {
        for (var i = 0; i < 4; i++)
        {
            if ((byte)(start >> (24 - (8 * i))) > (byte)(end >> (24 - (8 * i)))) return false;
        }

        return true;
    }

    public static UInt128 CountFor(uint start, uint end)
    {
        if (!IsValid(start, end)) return 0;
        UInt128 n = 1;
        for (var i = 0; i < 4; i++)
        {
            n *= (uint)((byte)(end >> (24 - (8 * i))) - (byte)(start >> (24 - (8 * i))) + 1);
        }

        return n;
    }

    public ulong Count { get; }

    public bool IsExplicitList => false;

    public AddressKey ElementAt(ulong index)
    {
        if (index >= Count) throw new ArgumentOutOfRangeException(nameof(index));
        uint value = 0;
        // last octet varies fastest
        Span<uint> digits = stackalloc uint[4];
        for (var i = 3; i >= 0; i--)
        {
            var radix = (ulong)(_hi[i] - _lo[i] + 1);
            digits[i] = (uint)(index % radix) + _lo[i];
            index /= radix;
        }

        for (var i = 0; i < 4; i++) value = (value << 8) | digits[i];
        return AddressKey.FromIPv4(value);
    }

    public bool Contains(AddressKey address)
    {
        if (address.IsV6) return false;
        var v = address.V4;
        for (var i = 0; i < 4; i++)
        {
            var o = (byte)(v >> (24 - (8 * i)));
            if (o < _lo[i] || o > _hi[i]) return false;
        }

        return true;
    }
}

/// <summary>Explicit list of single addresses (typed singles and resolved host names), de-duplicated.</summary>
public sealed class AddressListSource : ITargetSource
{
    private readonly List<AddressKey> _items = [];
    private readonly HashSet<AddressKey> _set = [];

    public void Add(AddressKey key)
    {
        if (_set.Add(key)) _items.Add(key);
    }

    public ulong Count => (ulong)_items.Count;

    public bool IsExplicitList => true;

    public AddressKey ElementAt(ulong index) => _items[checked((int)index)];

    public bool Contains(AddressKey address) => _set.Contains(address);
}
