using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Tools;

public enum IpFamily
{
    IPv4,
    IPv6,
}

/// <summary>A parsed address: numeric value (no IPv4-mapped folding) plus an IPv6 zone kept apart from the arithmetic.</summary>
public readonly record struct IpAddressValue(UInt128 Value, bool IsV6, string Zone = "", bool UsedEmbeddedIPv4Notation = false)
{
    public int Bits => IsV6 ? 128 : 32;

    public override string ToString() => IpText.Format(Value, IsV6);
}

/// <summary>An aligned CIDR block. All sizes are exact: <see cref="Count"/> is a <see cref="BigInteger"/> because ::/0 holds 2^128 addresses.</summary>
public readonly record struct IpBlock(UInt128 Network, int Prefix, bool IsV6)
{
    public int Bits => IsV6 ? 128 : 32;

    public int HostBits => Bits - Prefix;

    public UInt128 HostMask => IpMath.LowMask(HostBits);

    public UInt128 Mask => IpMath.Full(IsV6) & ~HostMask;

    public UInt128 Last => Network | HostMask;

    public BigInteger Count => BigInteger.One << HostBits;

    public bool Contains(UInt128 value) => (value & Mask) == Network;

    public bool Contains(IpBlock other) => other.IsV6 == IsV6 && other.Prefix >= Prefix && Contains(other.Network);

    public static IpBlock Containing(UInt128 value, int prefix, bool isV6)
    {
        var bits = isV6 ? 128 : 32;
        if (prefix < 0 || prefix > bits) throw new ArgumentOutOfRangeException(nameof(prefix));
        return new IpBlock(value & (IpMath.Full(isV6) & ~IpMath.LowMask(bits - prefix)), prefix, isV6);
    }

    public override string ToString() => $"{IpText.Format(Network, IsV6)}/{Prefix}";
}

/// <summary>A labelled value: <see cref="Display"/> is for reading, <see cref="Copy"/> is the plain exact value for the clipboard.</summary>
public sealed record IpField(string Label, string Display, string Copy, string Hint = "");

public static class IpMath
{
    public static UInt128 Full(bool isV6) => isV6 ? UInt128.MaxValue : uint.MaxValue;

    /// <summary>The low <paramref name="bits"/> bits set (UInt128 shifts are taken modulo 128, so 128 is special-cased).</summary>
    public static UInt128 LowMask(int bits) => bits <= 0 ? UInt128.Zero : bits >= 128 ? UInt128.MaxValue : (UInt128.One << bits) - 1;

    public static UInt128 ToUInt128(BigInteger value) => (UInt128)value;
}

/// <summary>Text forms: RFC 5952 compressed IPv6, expanded IPv6, binary, reverse-DNS names and readable counts.</summary>
public static class IpText
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Format(UInt128 value, bool isV6)
    {
        if (!isV6)
        {
            var v = (uint)value;
            return string.Create(Inv, $"{v >> 24}.{(v >> 16) & 0xFF}.{(v >> 8) & 0xFF}.{v & 0xFF}");
        }

        var h = Hextets(value);
        // RFC 5952 §5: IPv4-mapped addresses keep the dotted quad.
        if (h[0] == 0 && h[1] == 0 && h[2] == 0 && h[3] == 0 && h[4] == 0 && h[5] == 0xFFFF)
        {
            return "::ffff:" + Format((uint)value, false);
        }

        // RFC 5952 §4.2: compress the longest run (first on a tie) of two or more zero hextets.
        int bestStart = -1, bestLen = 0;
        for (var i = 0; i < 8;)
        {
            if (h[i] != 0)
            {
                i++;
                continue;
            }

            var j = i;
            while (j < 8 && h[j] == 0) j++;
            if (j - i > bestLen)
            {
                bestStart = i;
                bestLen = j - i;
            }

            i = j;
        }

        if (bestLen < 2) bestStart = -1;
        var sb = new StringBuilder(39);
        for (var i = 0; i < 8; i++)
        {
            if (i == bestStart)
            {
                sb.Append("::");
                i += bestLen - 1;
                continue;
            }

            if (sb.Length > 0 && sb[^1] != ':') sb.Append(':');
            sb.Append(h[i].ToString("x", Inv));
        }

        return sb.ToString();
    }

    public static string Expanded(UInt128 value) => string.Join(":", Hextets(value).Select(x => x.ToString("x4", Inv)));

    public static ushort[] Hextets(UInt128 value)
    {
        var h = new ushort[8];
        for (var i = 0; i < 8; i++) h[i] = (ushort)(value >> (112 - (16 * i)));
        return h;
    }

    /// <summary>Bits most-significant first ('0'/'1'), <paramref name="bits"/> long.</summary>
    public static string Binary(UInt128 value, int bits)
    {
        var c = new char[bits];
        for (var i = 0; i < bits; i++) c[i] = ((value >> (bits - 1 - i)) & UInt128.One) == UInt128.One ? '1' : '0';
        return new string(c);
    }

    /// <summary>Dotted binary for IPv4 (octets), colon-separated 16-bit groups for IPv6.</summary>
    public static string GroupedBinary(UInt128 value, bool isV6)
    {
        var b = Binary(value, isV6 ? 128 : 32);
        var size = isV6 ? 16 : 8;
        return string.Join(isV6 ? ":" : ".", Enumerable.Range(0, b.Length / size).Select(i => b.Substring(i * size, size)));
    }

    public static string ReverseName(UInt128 value, bool isV6)
    {
        if (!isV6)
        {
            var v = (uint)value;
            return string.Create(Inv, $"{v & 0xFF}.{(v >> 8) & 0xFF}.{(v >> 16) & 0xFF}.{v >> 24}.in-addr.arpa");
        }

        var sb = new StringBuilder(73);
        for (var i = 0; i < 32; i++) sb.Append(((int)((value >> (4 * i)) & 0xF)).ToString("x", Inv)).Append('.');
        return sb.Append("ip6.arpa").ToString();
    }

    /// <summary>Reverse zone that exactly holds <paramref name="block"/>, or an explanation when the prefix is not on a label boundary.</summary>
    public static string ReverseZone(IpBlock block)
    {
        var unit = block.IsV6 ? 4 : 8;
        var labels = block.Prefix / unit;
        var full = ReverseName(block.Network, block.IsV6).Split('.');
        var total = block.IsV6 ? 32 : 4;
        if (block.Prefix % unit == 0)
        {
            return string.Join('.', full.Skip(total - labels)); // keep only the network labels + suffix
        }

        var next = (labels + 1) * unit;
        var zones = 1 << (next - block.Prefix);
        return block.IsV6
            ? string.Create(Inv, $"Not on a nibble boundary: delegate as {zones} zones of /{next}")
            : string.Create(Inv, $"Not on an octet boundary: needs {zones} zones of /{next}, or classless delegation (RFC 2317)");
    }

    public static string Exact(BigInteger n) => n.ToString(Inv);

    public static string Grouped(BigInteger n) => n.ToString("N0", Inv);

    /// <summary>Exact with digit grouping below 10^12; larger counts as a power of two with an approximation.</summary>
    public static string Readable(BigInteger n)
    {
        if (n < 1_000_000_000_000) return Grouped(n);
        var power = n.IsPowerOfTwo ? (int)(n.GetBitLength() - 1) : -1;
        // exponent from the digit count (Log10 can land just below an integer), then renormalise after rounding: never "10 × 10^n"
        var exp = n.ToString(Inv).Length - 1;
        var mantissa = Math.Round((double)n / Math.Pow(10, exp), 2);
        if (mantissa >= 10)
        {
            mantissa /= 10;
            exp++;
        }

        var approx = string.Create(Inv, $"≈ {mantissa:0.##} × 10^{exp}");
        return power >= 0 ? string.Create(Inv, $"2^{power}  ({approx})") : approx;
    }

    public static string Hex(UInt128 value, bool isV6) => "0x" + (isV6 ? value.ToString("X32", Inv) : ((uint)value).ToString("X8", Inv));
}

/// <summary>
/// UI-independent IP calculator. Everything is computed arithmetically on <see cref="UInt128"/> / <see cref="BigInteger"/>;
/// nothing enumerates addresses, so ::/0 and 0.0.0.0/0 cost the same as a /32. Parsing reuses the scanner's strict IPv4
/// parser (<see cref="TargetParser"/>) and range conversion reuses <see cref="CidrConverter"/>.
/// </summary>
public static class IpCalculator
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static readonly IReadOnlyList<string> Examples = ["192.168.10.25/24", "10.20.30.40/22", "192.0.2.10/31", "2001:db8:1234::25/64"];

    // ---------------------------------------------------------------- parsing

    public static bool TryParseAddress(string? text, out IpAddressValue address, out string error)
    {
        address = default;
        error = "";
        var t = (text ?? "").Trim();
        if (t.Length == 0)
        {
            error = "Enter an IP address.";
            return false;
        }

        if (t.Length > 100)
        {
            error = "The address is too long.";
            return false;
        }

        var bracketed = t.StartsWith('[') && t.EndsWith(']');
        if (bracketed) t = t[1..^1];
        if (t.Contains('[', StringComparison.Ordinal) || t.Contains(']', StringComparison.Ordinal))
        {
            // "[::1]:80" is a socket address (host + port), not an IP address
            error = "Enter the address without brackets or a port, e.g. 2001:db8::1.";
            return false;
        }

        if (bracketed && !t.Contains(':', StringComparison.Ordinal))
        {
            error = "Brackets are used only around IPv6 addresses.";
            return false;
        }

        var zone = "";
        var pct = t.IndexOf('%', StringComparison.Ordinal);
        if (pct >= 0)
        {
            zone = t[(pct + 1)..];
            t = t[..pct];
            if (!t.Contains(':', StringComparison.Ordinal))
            {
                error = "Zone IDs (%…) apply to IPv6 addresses only.";
                return false;
            }

            if (zone.Length is 0 or > 64 || !zone.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-' or '~'))
            {
                error = "The zone ID after % must be an interface name or index, e.g. fe80::1%12 or fe80::1%eth0.";
                return false;
            }
        }

        if (t.Contains(':', StringComparison.Ordinal))
        {
            if (!IPAddress.TryParse(t, out var ip) || ip.AddressFamily != AddressFamily.InterNetworkV6 || ip.ScopeId != 0)
            {
                error = $"'{t}' is not a valid IPv6 address. Use up to eight hex groups separated by ':', with '::' at most once.";
                return false;
            }

            Span<byte> b = stackalloc byte[16];
            ip.TryWriteBytes(b, out _);
            address = new IpAddressValue(BinaryPrimitives.ReadUInt128BigEndian(b), true, zone, t.Contains('.', StringComparison.Ordinal));
            return true;
        }

        if (!TryParseIPv4(t, out var v4, out error)) return false;
        address = new IpAddressValue(v4, false);
        return true;
    }

    private static bool TryParseIPv4(string t, out uint value, out string error)
    {
        value = 0;
        error = "";
        var parts = t.Split('.');
        if (parts.Length != 4 || parts.Any(p => p.Length == 0))
        {
            error = $"'{t}' is not a valid IPv4 address: it needs four numbers (0–255) separated by dots, e.g. 192.168.1.10.";
            return false;
        }

        foreach (var p in parts)
        {
            if (!p.All(char.IsAsciiDigit))
            {
                error = $"'{t}' is not a valid IPv4 address: '{p}' is not a decimal number.";
                return false;
            }

            if (p.Length > 1 && p[0] == '0')
            {
                error = $"'{t}' has a leading zero in '{p}'. Some tools read that as octal, so it is rejected; write {p.TrimStart('0').PadLeft(1, '0')}.";
                return false;
            }

            if (p.Length > 3 || int.Parse(p, Inv) > 255)
            {
                error = $"'{t}' is not a valid IPv4 address: {p} is above 255.";
                return false;
            }
        }

        return TargetParser.TryParseStrictIPv4(t, out value);
    }

    /// <summary>Parses a dotted-decimal subnet mask. Non-contiguous masks are rejected with the reason.</summary>
    public static bool TryParseMask(string? text, out int prefix, out string error)
    {
        prefix = 0;
        var t = (text ?? "").Trim();
        if (!TryParseIPv4(t, out var mask, out _))
        {
            error = $"'{t}' is not a dotted-decimal subnet mask such as 255.255.255.0.";
            return false;
        }

        if (TargetParser.TryMaskToPrefix(mask, out prefix))
        {
            error = "";
            return true;
        }

        if (TargetParser.TryMaskToPrefix(~mask, out var inverse))
        {
            error = $"{t} looks like a wildcard (inverse) mask. The matching subnet mask is {IpText.Format(~mask, false)} (/{inverse}).";
            return false;
        }

        error = $"{t} is not a valid subnet mask: the 1-bits must be contiguous from the left ({IpText.GroupedBinary(mask, false)}). "
                + "Non-contiguous masks cannot be expressed as a CIDR prefix.";
        return false;
    }

    public static bool TryParsePrefix(string? text, bool isV6, out int prefix, out string error)
    {
        prefix = 0;
        var t = (text ?? "").Trim().TrimStart('/');
        var bits = isV6 ? 128 : 32;
        if (t.Length > 1 && t[0] == '0' && t.All(char.IsAsciiDigit))
        {
            // same rule as IPv4 octets (review R-16)
            error = $"Write /{t.TrimStart('0').PadLeft(1, '0')}: prefix lengths are written without a leading zero.";
            return false;
        }

        if (t.Length is 0 or > 3 || !t.All(char.IsAsciiDigit) || (prefix = int.Parse(t, Inv)) > bits)
        {
            error = isV6 ? "The IPv6 prefix length must be a whole number from 0 to 128." : "The IPv4 prefix length must be a whole number from 0 to 32.";
            return false;
        }

        error = "";
        return true;
    }

    /// <summary>
    /// Parses "address", "address/prefix", "address/mask", "address mask" or "address/prefix mask". A prefix and a mask that
    /// disagree are rejected rather than one silently winning. <paramref name="family"/> null accepts either family.
    /// </summary>
    public static bool TryParseInput(string? text, IpFamily? family, out IpAddressValue address, out int? prefix, out string error)
    {
        address = default;
        prefix = null;
        var t = (text ?? "").Trim();
        if (t.Length == 0)
        {
            error = "Enter an address, for example 192.168.10.25/24.";
            return false;
        }

        var parts = t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).ToList();
        // "10.0.0.1 /24" and "10.0.0.1/ 24": glue a detached prefix back onto the address
        for (var i = parts.Count - 1; i > 0; i--)
        {
            if (parts[i].StartsWith('/') || parts[i - 1].EndsWith('/'))
            {
                parts[i - 1] += parts[i];
                parts.RemoveAt(i);
            }
        }

        if (parts.Count > 2)
        {
            error = "Enter one address, optionally followed by /prefix or a subnet mask.";
            return false;
        }

        var first = parts[0];
        string? suffix = null;
        var slash = first.LastIndexOf('/');
        if (slash >= 0)
        {
            suffix = first[(slash + 1)..];
            first = first[..slash];
        }

        if (!TryParseAddress(first, out address, out error)) return false;
        if (family is { } f && address.IsV6 != (f == IpFamily.IPv6))
        {
            error = address.IsV6
                ? $"'{first}' is an IPv6 address, but IPv4 is selected. Choose IPv6 above."
                : $"'{first}' is an IPv4 address, but IPv6 is selected. Choose IPv4 above, or write it as ::ffff:{first} for an IPv4-mapped IPv6 address.";
            return false;
        }

        if (suffix is not null)
        {
            if (suffix.Length == 0)
            {
                error = "Enter a prefix length after '/'.";
                return false;
            }

            if (suffix.Contains('.', StringComparison.Ordinal))
            {
                if (address.IsV6)
                {
                    error = "IPv6 has no dotted subnet masks; use a prefix length such as /64.";
                    return false;
                }

                if (!TryParseMask(suffix, out var mp, out error)) return false;
                prefix = mp;
            }
            else
            {
                if (!TryParsePrefix(suffix, address.IsV6, out var p, out error)) return false;
                prefix = p;
            }
        }

        if (parts.Count == 2)
        {
            if (address.IsV6)
            {
                error = "IPv6 has no subnet masks; use a prefix length such as /64.";
                return false;
            }

            if (!TryParseMask(parts[1], out var mp, out error)) return false;
            if (prefix is { } p && p != mp)
            {
                error = $"The prefix /{p} and the mask {parts[1]} (/{mp}) disagree. Remove one, or make them match.";
                prefix = null;
                return false;
            }

            prefix = mp;
        }

        error = "";
        return true;
    }

    /// <summary>Parses a network for planning/membership: "address/prefix" (mask accepted for IPv4); host bits are cleared and reported.</summary>
    public static bool TryParseNetwork(string? text, IpFamily? family, out IpBlock block, out bool normalized, out string error)
    {
        block = default;
        normalized = false;
        if (!TryParseInput(text, family, out var a, out var p, out error)) return false;
        if (p is null)
        {
            error = a.IsV6 ? "Add a prefix length, for example 2001:db8::/48." : "Add a prefix length or mask, for example 10.0.0.0/16.";
            return false;
        }

        block = IpBlock.Containing(a.Value, p.Value, a.IsV6);
        normalized = block.Network != a.Value;
        return true;
    }

    // ---------------------------------------------------------------- calculation

    /// <param name="original">The address as typed (without prefix or zone), shown as "Original Address" for IPv6.</param>
    public static IpCalcResult Calculate(IpAddressValue address, int prefix, string? original = null)
    {
        var block = IpBlock.Containing(address.Value, prefix, address.IsV6);
        return new IpCalcResult(address, block, IpSpecialRanges.Classify(address.Value, address.IsV6), original);
    }

    /// <summary>Smallest IPv4 subnet whose usable count fits <paramref name="hosts"/>. /31 is used for two hosts only when allowed.</summary>
    public static bool TryPrefixForHosts(BigInteger hosts, bool allowPointToPoint, out int prefix, out string note)
    {
        prefix = 0;
        if (hosts < 1)
        {
            note = "Enter at least one host.";
            return false;
        }

        if (hosts == 1)
        {
            prefix = 32;
            note = "One host fits a /32 (single-host route, no network or broadcast address).";
            return true;
        }

        if (hosts == 2)
        {
            prefix = allowPointToPoint ? 31 : 30;
            note = allowPointToPoint
                ? "Two hosts use a /31 point-to-point link (RFC 3021): both addresses are usable, there is no broadcast. Clear the /31 option to use a /30."
                : "Two hosts need a /30 (4 addresses, 2 usable). For a point-to-point link a /31 (RFC 3021) also fits; tick the /31 option to use it.";
            return true;
        }

        for (var p = 30; p >= 0; p--)
        {
            if ((BigInteger.One << (32 - p)) - 2 >= hosts)
            {
                prefix = p;
                note = string.Create(Inv, $"{IpText.Grouped(hosts)} hosts need a /{p}: {IpText.Grouped((BigInteger.One << (32 - p)) - 2)} usable addresses per subnet (network and broadcast excluded).");
                return true;
            }
        }

        note = "More hosts than an IPv4 subnet can hold (4,294,967,294 usable at most).";
        return false;
    }

    public static bool TryContains(string? networkText, string? addressText, out ContainsResult result, out string error)
    {
        result = default!;
        if (!TryParseNetwork(networkText, null, out var block, out var normalized, out error)) return false;
        if (!TryParseAddress(addressText, out var a, out error)) return false;
        if (a.IsV6 != block.IsV6)
        {
            error = "The subnet and the address are different address families (IPv4 vs IPv6).";
            return false;
        }

        result = new ContainsResult(block, a, block.Contains(a.Value), normalized);
        return true;
    }

    /// <summary>Parses a CIDR block, an inclusive "start - end" range, or a single address into an interval.</summary>
    public static bool TryParseInterval(string? text, out IpInterval interval, out string error)
    {
        interval = default;
        var t = (text ?? "").Trim().Replace('–', '-').Replace('—', '-');
        // Try every '-' as the range separator: a zone ID may itself contain '-' (fe80::1%eth-0).
        string? rangeError = null;
        for (var dash = t.IndexOf('-', StringComparison.Ordinal); dash >= 0; dash = t.IndexOf('-', dash + 1))
        {
            var okStart = TryParseAddress(t[..dash], out var s, out var e1);
            var okEnd = TryParseAddress(t[(dash + 1)..], out var e, out var e2);
            if (okStart && okEnd) return TryInterval(s, e, out interval, out error);
            rangeError ??= okStart ? e2 : e1;
        }

        if (rangeError is not null && !t.Contains('%', StringComparison.Ordinal))
        {
            error = rangeError;
            return false;
        }

        if (t.Contains('/', StringComparison.Ordinal) || t.Contains(' ', StringComparison.Ordinal))
        {
            if (!TryParseNetwork(t, null, out var b, out _, out error)) return false;
            interval = new IpInterval(b.Network, b.Last, b.IsV6, b.ToString());
            return true;
        }

        if (!TryParseAddress(t, out var a, out error)) return false;
        interval = new IpInterval(a.Value, a.Value, a.IsV6, a.ToString());
        return true;
    }

    private static bool TryInterval(IpAddressValue s, IpAddressValue e, out IpInterval interval, out string error)
    {
        interval = default;
        if (s.IsV6 != e.IsV6)
        {
            error = "The start and end addresses are different address families (IPv4 vs IPv6).";
            return false;
        }

        if (s.Value > e.Value)
        {
            error = $"The start address {s} is after the end address {e}.";
            return false;
        }

        error = "";
        interval = new IpInterval(s.Value, e.Value, s.IsV6, $"{s} – {e}");
        return true;
    }

    public static bool TryCompare(string? a, string? b, out CompareResult result, out string error)
    {
        result = default!;
        if (!TryParseInterval(a, out var x, out error))
        {
            error = "A: " + error;
            return false;
        }

        if (!TryParseInterval(b, out var y, out error))
        {
            error = "B: " + error;
            return false;
        }

        if (x.IsV6 != y.IsV6)
        {
            error = "A and B are different address families (IPv4 vs IPv6); they cannot overlap.";
            return false;
        }

        result = CompareResult.Of(x, y);
        return true;
    }

    public static bool TryRangeToCidr(string? start, string? end, out IReadOnlyList<IpBlock> blocks, out BigInteger total, out string error)
    {
        blocks = [];
        total = 0;
        if (!TryParseAddress(start, out var s, out error))
        {
            error = "Start: " + error;
            return false;
        }

        if (!TryParseAddress(end, out var e, out error))
        {
            error = "End: " + error;
            return false;
        }

        if (!TryInterval(s, e, out var iv, out error)) return false;
        blocks = CidrConverter.RangeToBlocks(new AddressKey(iv.Start, iv.IsV6), new AddressKey(iv.End, iv.IsV6))
            .Select(x => new IpBlock(x.Network, x.Prefix, iv.IsV6)).ToList();
        total = iv.Count;
        return true;
    }
}

public sealed record ContainsResult(IpBlock Network, IpAddressValue Address, bool Contains, bool Normalized)
{
    public string Text => Contains
        ? $"Yes: {Address} is inside {Network} (offset {IpText.Grouped((BigInteger)(Address.Value - Network.Network))} of {IpText.Readable(Network.Count)})."
        : $"No: {Address} is outside {Network} ({IpText.Format(Network.Network, Network.IsV6)} – {IpText.Format(Network.Last, Network.IsV6)}).";
}

public readonly record struct IpInterval(UInt128 Start, UInt128 End, bool IsV6, string Label)
{
    public BigInteger Count => (BigInteger)(End - Start) + 1;
}

public enum SubnetRelation
{
    Equal,
    Disjoint,
    AContainsB,
    BContainsA,
    Overlapping,
}

public sealed record CompareResult(IpInterval A, IpInterval B, SubnetRelation Relation, string Text)
{
    public static CompareResult Of(IpInterval a, IpInterval b)
    {
        string F(UInt128 v) => IpText.Format(v, a.IsV6);
        if (a.Start == b.Start && a.End == b.End) return new(a, b, SubnetRelation.Equal, $"Equal: both cover {F(a.Start)} – {F(a.End)} ({IpText.Readable(a.Count)} addresses).");
        if (a.End < b.Start || b.End < a.Start)
        {
            var adjacent = (a.End < b.Start && a.End + 1 == b.Start) || (b.End < a.Start && b.End + 1 == a.Start);
            var text = "Disjoint: no addresses in common.";
            if (adjacent)
            {
                var lo = UInt128.Min(a.Start, b.Start);
                var hi = UInt128.Max(a.End, b.End);
                var union = CidrConverter.RangeToBlocks(new AddressKey(lo, a.IsV6), new AddressKey(hi, a.IsV6));
                text += union.Count == 1
                    ? $" They are adjacent and aggregate exactly into {F(union[0].Network)}/{union[0].Prefix}."
                    : " They are adjacent, but together they do not form a single CIDR block.";
            }

            return new(a, b, SubnetRelation.Disjoint, text);
        }

        if (a.Start <= b.Start && b.End <= a.End) return new(a, b, SubnetRelation.AContainsB, $"A contains B: every address of B is inside A ({IpText.Readable(b.Count)} of {IpText.Readable(a.Count)}).");
        if (b.Start <= a.Start && a.End <= b.End) return new(a, b, SubnetRelation.BContainsA, $"A is contained in B: every address of A is inside B ({IpText.Readable(a.Count)} of {IpText.Readable(b.Count)}).");
        var s = UInt128.Max(a.Start, b.Start);
        var e = UInt128.Min(a.End, b.End);
        return new(a, b, SubnetRelation.Overlapping,
            $"Overlapping: they share {F(s)} – {F(e)} ({IpText.Readable((BigInteger)(e - s) + 1)} addresses) but neither contains the other. (Two CIDR blocks can never partially overlap; this happens only with ranges.)");
    }
}

/// <summary>The calculator's result for one address and prefix, plus the field lists the window and the summary export share.</summary>
public sealed class IpCalcResult
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public IpCalcResult(IpAddressValue address, IpBlock block, IpClassification classification, string? original = null)
    {
        Address = address;
        OriginalText = string.IsNullOrWhiteSpace(original) ? IpText.Format(address.Value, address.IsV6) : original.Trim();
        Block = block;
        Classification = classification;
        if (!block.IsV6)
        {
            Mask = block.Mask;
            Wildcard = block.HostMask;
            switch (block.Prefix)
            {
                case 32:
                    FirstUsable = LastUsable = block.Network;
                    Usable = 1;
                    break;
                case 31:
                    FirstUsable = block.Network;
                    LastUsable = block.Last;
                    Usable = 2;
                    break;
                default:
                    Broadcast = block.Last;
                    FirstUsable = block.Network + 1;
                    LastUsable = block.Last - 1;
                    Usable = block.Count - 2;
                    break;
            }
        }

        Primary = BuildPrimary();
        Advanced = BuildAdvanced();
        Notes = BuildNotes();
    }

    public IpAddressValue Address { get; }

    public IpBlock Block { get; }

    public IpClassification Classification { get; }

    public bool IsV6 => Block.IsV6;

    /// <summary>The entered address had host bits set, so the network differs from it.</summary>
    public bool Normalized => Address.Value != Block.Network;

    public UInt128 Mask { get; }

    public UInt128 Wildcard { get; }

    /// <summary>IPv4 only, and only for prefixes up to /30 (/31 and /32 have none).</summary>
    public UInt128? Broadcast { get; }

    public UInt128 FirstUsable { get; }

    public UInt128 LastUsable { get; }

    public BigInteger Total => Block.Count;

    /// <summary>IPv4 host-assignable count by subnet arithmetic; IPv6 has no such deduction and leaves this 0.</summary>
    public BigInteger Usable { get; }

    public IReadOnlyList<IpField> Primary { get; }

    public IReadOnlyList<IpField> Advanced { get; }

    public IReadOnlyList<string> Notes { get; }

    private string F(UInt128 v) => IpText.Format(v, IsV6);

    private static IpField Plain(string label, string value, string hint = "") => new(label, value, value, hint);

    private static IpField Count(string label, BigInteger n, string hint = "") => new(label, IpText.Readable(n), IpText.Exact(n), hint);

    private List<IpField> BuildPrimary()
    {
        var b = Block;
        if (!IsV6)
        {
            var none = b.Prefix == 31 ? "None (/31 point-to-point)" : "None (/32 host route)";
            return
            [
                Plain("Entered IP Address", F(Address.Value)),
                Plain("Network Address", F(b.Network)),
                Plain("CIDR Prefix", string.Create(Inv, $"/{b.Prefix}")),
                Plain("Subnet Mask", F(Mask)),
                Plain("Wildcard Mask", F(Wildcard), "Inverse mask, as used in ACLs and OSPF network statements."),
                Broadcast is { } bc ? Plain("Broadcast Address", F(bc)) : new IpField("Broadcast Address", none, ""),
                Plain("First Usable Address", F(FirstUsable)),
                Plain("Last Usable Address", F(LastUsable)),
                Count("Total Addresses", Total),
                Count("Usable Addresses", Usable, b.Prefix switch
                {
                    32 => "A /32 is a single address; nothing is subtracted.",
                    31 => "RFC 3021: on a point-to-point /31 both addresses are usable.",
                    _ => "Total minus the network and broadcast addresses.",
                }),
                new("Address Classification", Classification.Display, Classification.Name, Classification.Description),
            ];
        }

        return
        [
            Plain("Original Address", Address.Zone.Length > 0 ? $"{OriginalText}%{Address.Zone}" : OriginalText),
            Plain("Compressed Address", F(Address.Value), "RFC 5952 canonical form."),
            Plain("Expanded Address", IpText.Expanded(Address.Value)),
            Plain("Network Prefix", b.ToString()),
            Plain("Prefix Length", string.Create(Inv, $"/{b.Prefix}")),
            Plain("First Address", F(b.Network)),
            Plain("Last Address", F(b.Last)),
            Count("Total Addresses", Total, "Exact count; IPv6 has no broadcast and no network/broadcast deduction."),
            new("Address Classification", Classification.Display, Classification.Name, Classification.Description),
            Plain("Reverse DNS Name", IpText.ReverseName(Address.Value, true)),
        ];
    }

    /// <summary>The address exactly as typed (IPv6 "Original Address").</summary>
    public string OriginalText { get; }

    private List<IpField> BuildAdvanced()
    {
        var b = Block;
        var list = new List<IpField>
        {
            Plain("Network (CIDR)", b.ToString()),
            Plain("Address Range", $"{F(b.Network)} – {F(b.Last)}"),
            new("Total Addresses (exact)", IpText.Grouped(Total), IpText.Exact(Total)),
        };
        if (!IsV6)
        {
            var v = (uint)Address.Value;
            list.Add(Plain("Reverse DNS Name", IpText.ReverseName(Address.Value, false)));
            list.Add(Plain("Reverse DNS Zone", IpText.ReverseZone(b)));
            list.Add(Plain("Address (binary)", IpText.GroupedBinary(Address.Value, false)));
            list.Add(Plain("Subnet Mask (binary)", IpText.GroupedBinary(Mask, false)));
            list.Add(Plain("Address (hex)", IpText.Hex(Address.Value, false)));
            list.Add(Plain("Address (decimal)", v.ToString(Inv)));
            list.Add(Plain("Subnet Mask (hex)", IpText.Hex(Mask, false)));
            list.Add(Plain("Historical Class", (v >> 24) switch
            {
                < 128 => "A (classful default /8)",
                < 192 => "B (classful default /16)",
                < 224 => "C (classful default /24)",
                < 240 => "D (multicast)",
                _ => "E (reserved)",
            }, "Classful addressing is obsolete since CIDR (RFC 4632); shown for reference only."));
        }
        else
        {
            list.Add(Plain("Reverse DNS Zone", IpText.ReverseZone(b)));
            list.Add(Plain("Address (hex)", IpText.Hex(Address.Value, true)));
            list.Add(Plain("Interface Identifier (low 64 bits)", IpText.Expanded(Address.Value)[20..]));
            if (Eui64Mac(Address.Value) is { } mac)
            {
                list.Add(Plain("Modified EUI-64 MAC", mac, "The interface identifier embeds this MAC address (U/L bit inverted, ff:fe inserted)."));
            }

            if (Address.Zone.Length > 0) list.Add(Plain("Zone ID", Address.Zone, "Selects the interface; not part of the address arithmetic."));
            foreach (var e in EmbeddedIPv4(Address.Value)) list.Add(e);
        }

        return list;
    }

    private List<string> BuildNotes()
    {
        var b = Block;
        var notes = new List<string>();
        if (Normalized) notes.Add($"The entered address has host bits set; its network is {b}.");
        if (!IsV6)
        {
            if (b.Prefix == 31) notes.Add("/31 point-to-point (RFC 3021): both addresses are usable on the link; there is no network or broadcast address.");
            if (b.Prefix == 32) notes.Add("/32 single-host route: one address; no network or broadcast address is subtracted.");
            if (b.Prefix == 0) notes.Add("0.0.0.0/0 is the whole IPv4 space (the default route).");
        }
        else
        {
            if (b.Prefix == 0) notes.Add("::/0 is the whole IPv6 space (the default route).");
            if (b.Prefix == 127) notes.Add("/127 point-to-point (RFC 6164): both addresses are used on inter-router links.");
            if (b.Prefix == 128) notes.Add("/128 single address (host route or loopback).");
            if (b.Prefix < 127)
            {
                notes.Add("IPv6 has no broadcast address. Not every address is for hosts: the all-zeros interface identifier is the Subnet-Router anycast address (RFC 4291)"
                          + (b.Prefix <= 64 ? ", the highest 128 identifiers of each /64 are reserved subnet anycast addresses (RFC 2526), and SLAAC needs a /64." : "."));
            }

            if (Address.Zone.Length > 0 && !Classification.Name.Contains("Link", StringComparison.OrdinalIgnoreCase) && !Classification.Name.Contains("Multicast", StringComparison.Ordinal))
            {
                notes.Add("A zone ID is normally used only with link-local or other scoped addresses.");
            }
        }

        if (Classification.Block is { } cb && cb.Prefix > b.Prefix) notes.Add($"The {b} network is larger than the {Classification.Name} range {cb}; it also contains addresses of other kinds.");
        var inside = IpSpecialRanges.Within(b).Where(r => r.Block.Prefix > b.Prefix && !(Classification.Block is { } c && r.Block.Contains(c))).Take(4).ToList();
        if (inside.Count > 0 && b.Prefix > 0) notes.Add("This network also contains special-purpose ranges: " + string.Join(", ", inside.Select(r => $"{r.Block} ({r.Name})")) + ".");
        return notes;
    }

    private static string? Eui64Mac(UInt128 v)
    {
        var iid = (ulong)v;
        if (((iid >> 24) & 0xFFFF) != 0xFFFE) return null;
        var mac = new[] { (byte)((iid >> 56) ^ 0x02), (byte)(iid >> 48), (byte)(iid >> 40), (byte)(iid >> 16), (byte)(iid >> 8), (byte)iid };
        return string.Join("-", mac.Select(x => x.ToString("X2", Inv)));
    }

    private static IEnumerable<IpField> EmbeddedIPv4(UInt128 v)
    {
        string V4(uint x) => IpText.Format(x, false);
        if (v >> 32 == 0xFFFF) yield return Plain("Embedded IPv4 (IPv4-mapped)", V4((uint)v));
        if (v >> 32 == new UInt128(0x0064_FF9B_0000_0000UL, 0) >> 32) yield return Plain("Embedded IPv4 (NAT64 64:ff9b::/96)", V4((uint)v));
        if (v >> 112 == 0x2002) yield return Plain("Embedded IPv4 (6to4)", V4((uint)(v >> 80)));
        if (v >> 96 == 0x2001_0000) yield return Plain("Embedded IPv4 (Teredo client)", V4(~(uint)v));
    }

    /// <summary>Machine-readable export: every field's plain (exact) value, counts as strings.</summary>
    public void WriteJson(Stream stream)
    {
        using var j = new System.Text.Json.Utf8JsonWriter(stream, new System.Text.Json.JsonWriterOptions { Indented = true });
        j.WriteStartObject();
        j.WriteString("generator", "IPMaster IP Calculator");
        j.WriteString("family", IsV6 ? "IPv6" : "IPv4");
        j.WriteString("network", Block.ToString());
        foreach (var group in new[] { ("results", Primary), ("details", Advanced) })
        {
            j.WriteStartObject(group.Item1);
            foreach (var f in group.Item2) j.WriteString(f.Label, f.Copy);
            j.WriteEndObject();
        }

        j.WriteString("classification", Classification.Description);
        j.WriteStartArray("notes");
        foreach (var n in Notes) j.WriteStringValue(n);
        j.WriteEndArray();
        j.WriteString("classificationSource", IpSpecialRanges.Source);
        j.WriteEndObject();
    }

    /// <summary>Plain-text summary for Copy Summary and the summary export.</summary>
    public string Summary()
    {
        var sb = new StringBuilder();
        sb.AppendLine(IsV6 ? "IPv6 calculation" : "IPv4 calculation");
        foreach (var f in Primary) sb.Append(f.Label).Append(": ").AppendLine(f.Display);
        sb.AppendLine();
        foreach (var f in Advanced) sb.Append(f.Label).Append(": ").AppendLine(f.Display);
        if (Notes.Count > 0)
        {
            sb.AppendLine();
            foreach (var n in Notes) sb.Append("Note: ").AppendLine(n);
        }

        sb.AppendLine();
        sb.Append("Classification: ").AppendLine(Classification.Description);
        sb.AppendLine(IpSpecialRanges.Source);
        return sb.ToString();
    }
}
