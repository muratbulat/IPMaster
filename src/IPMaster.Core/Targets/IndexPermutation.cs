namespace IPMaster.Core.Targets;

/// <summary>
/// Pseudo-random bijection on [0, n) using a balanced Feistel network with cycle walking, so random
/// scan order needs O(1) memory regardless of plan size. Not cryptographic; it only spreads load.
/// </summary>
public sealed class IndexPermutation
{
    private readonly ulong _n;
    private readonly int _halfBits;
    private readonly ulong _halfMask;
    private readonly ulong[] _keys;

    public IndexPermutation(ulong n, ulong seed)
    {
        if (n == 0) throw new ArgumentOutOfRangeException(nameof(n));
        _n = n;
        var bits = 64 - (int)ulong.LeadingZeroCount(Math.Max(n - 1, 1));
        if (bits % 2 == 1) bits++;
        if (bits < 2) bits = 2;
        _halfBits = bits / 2;
        _halfMask = (1UL << _halfBits) - 1;
        _keys = new ulong[4];
        var s = seed;
        for (var i = 0; i < _keys.Length; i++) _keys[i] = SplitMix(ref s);
    }

    public ulong Map(ulong index)
    {
        if (index >= _n) throw new ArgumentOutOfRangeException(nameof(index));
        var x = index;
        do
        {
            x = Encrypt(x);
        }
        while (x >= _n);

        return x;
    }

    private ulong Encrypt(ulong x)
    {
        var l = (x >> _halfBits) & _halfMask;
        var r = x & _halfMask;
        foreach (var k in _keys)
        {
            var f = Mix(r ^ k) & _halfMask;
            (l, r) = (r, l ^ f);
        }

        return (l << _halfBits) | r;
    }

    private static ulong Mix(ulong z)
    {
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }

    private static ulong SplitMix(ref ulong s)
    {
        s += 0x9E3779B97F4A7C15UL;
        return Mix(s);
    }
}
