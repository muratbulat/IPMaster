using System.Globalization;
using System.Net;
using System.Net.Sockets;

namespace IPMaster.Core.Targets;

public sealed record RejectedLine(int LineNumber, string Text, string Reason);

public sealed record TargetListParseResult(IReadOnlyList<TargetSpec> Targets, IReadOnlyList<RejectedLine> Rejected);

/// <summary>
/// Parses target expressions: single IPv4/IPv6 addresses (with optional IPv6 scope), start–end ranges,
/// CIDR (prefix length or dotted mask) and host names. IPv4 parsing is strict (four decimal octets),
/// unlike <see cref="IPAddress.TryParse(string, out IPAddress)"/>, which accepts "10.1" as 10.0.0.1.
/// </summary>
public static class TargetParser
{
    /// <summary>Maximum characters accepted in one target line (defensive bound for imports).</summary>
    public const int MaxLineLength = 1024;

    /// <summary>ff02::1, the IPv6 all-nodes link-local multicast group.</summary>
    public static readonly UInt128 AllNodesMulticast = new(0xFF02_0000_0000_0000UL, 1UL);

    public static bool TryParse(string? text, out TargetSpec spec, out string error)
        => TryParse(text, octetMode: false, out spec, out error);

    public static bool TryParse(string? text, bool octetMode, out TargetSpec spec, out string error)
    {
        spec = null!;
        error = "";
        if (string.IsNullOrWhiteSpace(text))
        {
            error = "Empty target.";
            return false;
        }

        if (text.Length > MaxLineLength)
        {
            error = "Target expression is too long.";
            return false;
        }

        var original = text.Trim();
        var s = original.Replace('–', '-').Replace('—', '-');

        // CIDR or address/mask
        var slash = s.IndexOf('/', StringComparison.Ordinal);
        if (slash >= 0)
        {
            return TryParseCidr(s[..slash].Trim(), s[(slash + 1)..].Trim(), original, octetMode, out spec, out error);
        }

        // Range: try every '-' split point where both sides are addresses (host names may contain '-').
        for (var i = s.IndexOf('-', StringComparison.Ordinal); i >= 0; i = s.IndexOf('-', i + 1))
        {
            var left = s[..i].Trim();
            var right = s[(i + 1)..].Trim();
            if (TryParseAddress(left, out var a) && TryParseAddress(right, out var b))
            {
                return TryBuildRange(a, b, original, octetMode, out spec, out error);
            }
        }

        if (TryParseAddress(s, out var single))
        {
            if (single.IsV6 && single.Value == AllNodesMulticast)
            {
                if (single.ScopeId == 0)
                {
                    error = "Neighbour discovery (ff02::1) needs an interface scope, e.g. ff02::1%12.";
                    return false;
                }

                spec = new TargetSpec { Kind = TargetKind.NeighborDiscovery, Start = single, End = single, Original = original };
                return true;
            }

            spec = new TargetSpec { Kind = TargetKind.SingleAddress, Start = single, End = single, Original = original };
            return true;
        }

        if (IsValidHostName(s))
        {
            spec = new TargetSpec { Kind = TargetKind.HostName, HostName = s, Original = original };
            return true;
        }

        error = $"'{original}' is not an IP address, range, CIDR block or host name.";
        return false;
    }

    /// <summary>
    /// Parses a multi-line list (import dialog, <c>/file</c>). Blank lines and lines starting with
    /// <c>#</c> or <c>;</c> are skipped; unrecognised lines are returned in <see cref="TargetListParseResult.Rejected"/>.
    /// </summary>
    public static TargetListParseResult ParseList(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var targets = new List<TargetSpec>();
        var rejected = new List<RejectedLine>();
        var lineNumber = 0;
        foreach (var raw in text.AsSpan().EnumerateLines())
        {
            lineNumber++;
            var line = raw.Trim().ToString();
            if (line.Length == 0 || line[0] == '#' || line[0] == ';') continue;
            if (TryParse(line, out var spec, out var error)) targets.Add(spec);
            else rejected.Add(new RejectedLine(lineNumber, line.Length > 200 ? line[..200] : line, error));
        }

        return new TargetListParseResult(targets, rejected);
    }

    public static bool TryParseAddress(string text, out AddressKey key)
    {
        key = default;
        if (string.IsNullOrEmpty(text)) return false;

        if (text.Contains(':', StringComparison.Ordinal))
        {
            var t = text;
            if (t.StartsWith('[') && t.EndsWith(']')) t = t[1..^1];
            if (IPAddress.TryParse(t, out var v6) && v6.AddressFamily == AddressFamily.InterNetworkV6)
            {
                key = AddressKey.From(v6);
                return true;
            }

            return false;
        }

        if (TryParseStrictIPv4(text, out var v4))
        {
            key = AddressKey.FromIPv4(v4);
            return true;
        }

        return false;
    }

    public static bool TryParseStrictIPv4(ReadOnlySpan<char> text, out uint value)
    {
        value = 0;
        var octets = 0;
        while (true)
        {
            var dot = text.IndexOf('.');
            var part = dot < 0 ? text : text[..dot];
            if (part.Length is 0 or > 3) return false;
            foreach (var c in part)
            {
                if (c is < '0' or > '9') return false;
            }

            var n = int.Parse(part, NumberStyles.None, CultureInfo.InvariantCulture);
            if (n > 255) return false;
            value = (value << 8) | (uint)n;
            octets++;
            if (dot < 0) break;
            if (octets == 4) return false;
            text = text[(dot + 1)..];
        }

        return octets == 4;
    }

    public static bool IsValidHostName(string s)
    {
        if (s.Length is 0 or > 253) return false;
        var name = s.EndsWith('.') ? s[..^1] : s;
        var hasLetter = false;
        foreach (var label in name.Split('.'))
        {
            if (label.Length is 0 or > 63) return false;
            if (label[0] == '-' || label[^1] == '-') return false;
            foreach (var c in label)
            {
                if (char.IsAsciiLetter(c) || c == '_') hasLetter = true;
                else if (!char.IsAsciiDigit(c) && c != '-') return false;
            }
        }

        return hasLetter;
    }

    private static bool TryParseCidr(string addressText, string prefixText, string original, bool octetMode,
        out TargetSpec spec, out string error)
    {
        spec = null!;
        if (!TryParseAddress(addressText, out var address))
        {
            error = $"'{addressText}' is not a valid IP address.";
            return false;
        }

        var bits = address.IsV6 ? 128 : 32;
        int prefix;
        if (int.TryParse(prefixText, NumberStyles.None, CultureInfo.InvariantCulture, out var p))
        {
            prefix = p;
        }
        else if (!address.IsV6 && TryParseStrictIPv4(prefixText, out var mask) && TryMaskToPrefix(mask, out var mp))
        {
            prefix = mp;
        }
        else
        {
            error = $"'{prefixText}' is not a valid prefix length or subnet mask.";
            return false;
        }

        if (prefix < 0 || prefix > bits)
        {
            error = $"Prefix length must be between 0 and {bits}.";
            return false;
        }

        var maskValue = AddressKey.MaskFor(prefix, address.IsV6);
        var hostBits = (address.IsV6 ? UInt128.MaxValue : uint.MaxValue) & ~maskValue;
        var start = address.WithValue(address.Value & maskValue);
        var end = address.WithValue((address.Value & maskValue) | hostBits);
        spec = new TargetSpec
        {
            Kind = TargetKind.Cidr,
            Start = start,
            End = end,
            PrefixLength = prefix,
            Original = original,
            OctetMode = octetMode && !address.IsV6,
        };
        error = "";
        return true;
    }

    public static bool TryMaskToPrefix(uint mask, out int prefix)
    {
        prefix = 0;
        var m = mask;
        while ((m & 0x8000_0000u) != 0)
        {
            prefix++;
            m <<= 1;
        }

        return m == 0;
    }

    private static bool TryBuildRange(AddressKey a, AddressKey b, string original, bool octetMode,
        out TargetSpec spec, out string error)
    {
        spec = null!;
        if (a.IsV6 != b.IsV6)
        {
            error = "Range start and end must be the same address family.";
            return false;
        }

        if (a.IsV6 && a.ScopeId != b.ScopeId)
        {
            if (a.ScopeId != 0 && b.ScopeId != 0)
            {
                error = "Range start and end have different IPv6 scope IDs.";
                return false;
            }

            var scope = a.ScopeId != 0 ? a.ScopeId : b.ScopeId;
            a = a with { ScopeId = scope };
            b = b with { ScopeId = scope };
        }

        if (a.Value > b.Value)
        {
            error = "Range start is greater than range end.";
            return false;
        }

        if (octetMode && a.IsV6)
        {
            error = "Octet range mode applies to IPv4 ranges only.";
            return false;
        }

        if (octetMode && !OctetRangeSource.IsValid(a.V4, b.V4))
        {
            error = "In octet range mode every start octet must be less than or equal to the matching end octet.";
            return false;
        }

        spec = new TargetSpec
        {
            Kind = a == b ? TargetKind.SingleAddress : TargetKind.Range,
            Start = a,
            End = b,
            Original = original,
            OctetMode = octetMode,
        };
        error = "";
        return true;
    }
}
