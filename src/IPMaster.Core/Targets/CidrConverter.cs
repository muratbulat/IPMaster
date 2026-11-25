namespace IPMaster.Core.Targets;

/// <summary>Range ⇄ CIDR conversion for the address bar's CIDR button.</summary>
public static class CidrConverter
{
    /// <summary>Converts a range to the minimal list of CIDR blocks that exactly covers it.</summary>
    public static IReadOnlyList<string> RangeToCidrs(AddressKey start, AddressKey end, int maxBlocks = 256)
        => RangeToBlocks(start, end, maxBlocks).Select(b => $"{start.WithValue(b.Network)}/{b.Prefix}").ToList();

    /// <summary>
    /// Minimal exact CIDR cover of an inclusive range, computed per block (never per address). At most 2·bits−2 blocks are
    /// ever needed (62 for IPv4, 254 for IPv6), so the default bound only matters for callers that pass a smaller one.
    /// </summary>
    public static IReadOnlyList<(UInt128 Network, int Prefix)> RangeToBlocks(AddressKey start, AddressKey end, int maxBlocks = 256)
    {
        if (start.IsV6 != end.IsV6) throw new ArgumentException("Address families differ.");
        if (start.Value > end.Value) throw new ArgumentException("Start is greater than end.");
        var bits = start.IsV6 ? 128 : 32;
        var result = new List<(UInt128, int)>();
        var cur = start.Value;
        while (true)
        {
            // largest block aligned at cur that does not exceed end
            var size = bits;
            while (size > 0)
            {
                var hostBits = bits - size + 1;
                if (hostBits == 128)
                {
                    // the whole IPv6 space (::/0) cannot be expressed as cur + (2^128 − 1) without overflow
                    if (cur == 0 && end.Value == UInt128.MaxValue) size = 0;
                    break;
                }

                var blockMask = (UInt128.One << hostBits) - 1;
                if ((cur & blockMask) != 0) break;
                var last = cur + blockMask;
                if (last < cur || last > end.Value) break;
                size--;
            }

            result.Add((cur, size));
            if (result.Count > maxBlocks) throw new InvalidOperationException($"Range needs more than {maxBlocks} CIDR blocks.");
            if (size == 0) break;
            var next = cur + ((UInt128.One << (bits - size)) - 1);
            if (next >= end.Value) break;
            cur = next + 1;
        }

        return result;
    }

    /// <summary>Converts a target expression: CIDR → "start-end"; range → CIDR (or several, comma-separated).</summary>
    public static bool TryConvert(string text, out string converted, out string error)
    {
        converted = "";
        if (!TargetParser.TryParse(text, out var spec, out error)) return false;
        switch (spec.Kind)
        {
            case TargetKind.Cidr:
                converted = $"{spec.Start}-{spec.End}";
                return true;
            case TargetKind.Range:
            case TargetKind.SingleAddress:
                try
                {
                    converted = string.Join(", ", RangeToCidrs(spec.Start, spec.End));
                    return true;
                }
                catch (InvalidOperationException ex)
                {
                    error = ex.Message;
                    return false;
                }

            default:
                error = "Host names cannot be converted.";
                return false;
        }
    }
}
