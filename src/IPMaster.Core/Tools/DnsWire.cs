using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace IPMaster.Core.Tools;

#pragma warning disable CA1720 // standard DNS record-type mnemonics (RFC 1035)
public enum DnsType : ushort
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    OPT = 41,
    CAA = 257,
}
#pragma warning restore CA1720

public enum DnsRcode
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
}

public sealed record DnsQuestion(string Name, ushort Type, ushort Class);

/// <summary>One resource record. <see cref="Data"/> is the readable form; <see cref="Normalized"/> is used for comparisons.</summary>
public sealed record DnsRecord(string Name, ushort Type, ushort Class, uint Ttl, string Data)
{
    public string TypeName => DnsWire.TypeName(Type);

    /// <summary>Case-insensitive owner, type and data (TTL excluded): equal records compare equal across servers.</summary>
    public string Normalized => $"{Name.TrimEnd('.').ToLowerInvariant()} {TypeName} {(Type is (ushort)DnsType.TXT or (ushort)DnsType.CAA ? Data : Data.ToLowerInvariant())}";
}

public sealed record DnsMessage(
    ushort Id,
    bool IsResponse,
    int Opcode,
    bool Authoritative,
    bool Truncated,
    bool RecursionDesired,
    bool RecursionAvailable,
    bool AuthenticData,
    bool CheckingDisabled,
    int Rcode,
    IReadOnlyList<DnsQuestion> Questions,
    IReadOnlyList<DnsRecord> Answers,
    IReadOnlyList<DnsRecord> Authority,
    IReadOnlyList<DnsRecord> Additional)
{
    public string RcodeName => DnsWire.RcodeName(Rcode);

    public string Flags => string.Join(" ", new[] { IsResponse ? "qr" : null, Authoritative ? "aa" : null, Truncated ? "tc" : null,
        RecursionDesired ? "rd" : null, RecursionAvailable ? "ra" : null, AuthenticData ? "ad" : null, CheckingDisabled ? "cd" : null }.Where(f => f is not null));
}

/// <summary>
/// DNS wire format (RFC 1035, 3596, 2782, 6844) for the DNS Diagnostics tool (D-073). Parsing is defensive: every read is
/// bounds-checked and compression pointers may only point backwards, at most 64 hops, so a hostile reply cannot loop.
/// </summary>
public static class DnsWire
{
    private const int MaxPointerHops = 64;
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static readonly IReadOnlyList<DnsType> QueryTypes =
        [DnsType.A, DnsType.AAAA, DnsType.PTR, DnsType.MX, DnsType.TXT, DnsType.SRV, DnsType.CNAME, DnsType.NS, DnsType.SOA, DnsType.CAA];

    public static string TypeName(ushort t) => Enum.IsDefined(typeof(DnsType), t) ? ((DnsType)t).ToString() : "TYPE" + t.ToString(Inv);

    public static string RcodeName(int r) => r switch
    {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "RCODE" + r.ToString(Inv),
    };

    public static byte[] BuildQuery(ushort id, string name, ushort type, bool recursionDesired)
    {
        ArgumentNullException.ThrowIfNull(name);
        var buf = new List<byte>(64);
        void U16(int v)
        {
            buf.Add((byte)(v >> 8));
            buf.Add((byte)v);
        }

        U16(id);
        U16(recursionDesired ? 0x0100 : 0);
        U16(1);
        U16(0);
        U16(0);
        U16(0);
        WriteName(buf, name);
        U16(type);
        U16(1);
        return [.. buf];
    }

    public static void WriteName(List<byte> buf, string name)
    {
        ArgumentNullException.ThrowIfNull(buf);
        var n = name.Trim().TrimEnd('.');
        if (n.Length > 253) throw new ArgumentException("A DNS name is at most 253 characters.", nameof(name));
        if (n.Length > 0)
        {
            foreach (var label in n.Split('.'))
            {
                var bytes = Encoding.ASCII.GetBytes(IdnLabel(label));
                if (bytes.Length is 0 or > 63) throw new ArgumentException($"Invalid label '{label}': 1 to 63 characters.", nameof(name));
                buf.Add((byte)bytes.Length);
                buf.AddRange(bytes);
            }
        }

        buf.Add(0);
    }

    private static string IdnLabel(string label) => label.All(char.IsAscii) ? label : new IdnMapping().GetAscii(label);

    public static bool TryParse(ReadOnlySpan<byte> data, out DnsMessage message, out string error)
    {
        message = null!;
        try
        {
            message = Parse(data.ToArray());
            error = "";
            return true;
        }
        catch (FormatException ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static DnsMessage Parse(byte[] d)
    {
        ArgumentNullException.ThrowIfNull(d);
        if (d.Length < 12) throw new FormatException("Reply shorter than a DNS header.");
        var id = BinaryPrimitives.ReadUInt16BigEndian(d);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(2));
        int qd = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(4)), an = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(6));
        int ns = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(8)), ar = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(10));
        var pos = 12;
        var questions = new List<DnsQuestion>();
        for (var i = 0; i < qd; i++)
        {
            var name = ReadName(d, ref pos);
            Need(d, pos, 4);
            questions.Add(new DnsQuestion(name, BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(pos)), BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(pos + 2))));
            pos += 4;
        }

        List<DnsRecord> Section(int count)
        {
            var list = new List<DnsRecord>(Math.Min(count, 256));
            for (var i = 0; i < count; i++) list.Add(ReadRecord(d, ref pos));
            return list;
        }

        var answers = Section(an);
        var authority = Section(ns);
        var additional = Section(ar);
        return new DnsMessage(id, (flags & 0x8000) != 0, (flags >> 11) & 0xF, (flags & 0x0400) != 0, (flags & 0x0200) != 0, (flags & 0x0100) != 0,
            (flags & 0x0080) != 0, (flags & 0x0020) != 0, (flags & 0x0010) != 0, flags & 0xF, questions, answers, authority, additional);
    }

    private static void Need(byte[] d, int pos, int n)
    {
        if (pos < 0 || pos + n > d.Length) throw new FormatException("Reply is truncated or malformed.");
    }

    public static string ReadName(byte[] d, ref int pos)
    {
        var sb = new StringBuilder();
        var p = pos;
        var jumped = false;
        var hops = 0;
        while (true)
        {
            Need(d, p, 1);
            var len = d[p];
            if (len == 0)
            {
                p++;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                Need(d, p, 2);
                var target = ((len & 0x3F) << 8) | d[p + 1];
                if (target >= p || ++hops > MaxPointerHops) throw new FormatException("Invalid name compression pointer.");
                if (!jumped) pos = p + 2;
                jumped = true;
                p = target;
                continue;
            }

            if ((len & 0xC0) != 0) throw new FormatException("Unsupported label type.");
            Need(d, p + 1, len);
            if (sb.Length > 0) sb.Append('.');
            foreach (var b in d.AsSpan(p + 1, len))
            {
                // escape non-printable and separator bytes (RFC 4343 presentation)
                if (b is (byte)'.' or (byte)'\\') sb.Append('\\').Append((char)b);
                else if (b is < 0x21 or > 0x7E) sb.Append('\\').Append(b.ToString("D3", Inv));
                else sb.Append((char)b);
            }

            if (sb.Length > 1024) throw new FormatException("Name too long.");
            p += len + 1;
        }

        if (!jumped) pos = p;
        return sb.Length == 0 ? "." : sb.Append('.').ToString();
    }

    private static DnsRecord ReadRecord(byte[] d, ref int pos)
    {
        var name = ReadName(d, ref pos);
        Need(d, pos, 10);
        var type = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(pos));
        var cls = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(pos + 2));
        var ttl = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(pos + 4));
        int rdlen = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(pos + 8));
        pos += 10;
        Need(d, pos, rdlen);
        var start = pos;
        var end = pos + rdlen;
        string data;
        var p = start;
        switch ((DnsType)type)
        {
            case DnsType.A when rdlen == 4:
                data = new IPAddress(d.AsSpan(start, 4)).ToString();
                break;
            case DnsType.AAAA when rdlen == 16:
                data = IpText.Format(BinaryPrimitives.ReadUInt128BigEndian(d.AsSpan(start, 16)), true);
                break;
            case DnsType.CNAME or DnsType.NS or DnsType.PTR:
                data = ReadName(d, ref p);
                break;
            case DnsType.MX:
                Need(d, p, 2);
                var pref = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(p));
                p += 2;
                data = pref.ToString(Inv) + " " + ReadName(d, ref p);
                break;
            case DnsType.SRV:
                Need(d, p, 6);
                var prio = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(p));
                var weight = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(p + 2));
                var port = BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(p + 4));
                p += 6;
                data = string.Create(Inv, $"{prio} {weight} {port} ") + ReadName(d, ref p);
                break;
            case DnsType.SOA:
                var mname = ReadName(d, ref p);
                var rname = ReadName(d, ref p);
                Need(d, p, 20);
                var v = Enumerable.Range(0, 5).Select(i => BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(p + (4 * i)))).ToArray();
                data = string.Create(Inv, $"{mname} {rname} {v[0]} {v[1]} {v[2]} {v[3]} {v[4]}");
                break;
            case DnsType.TXT:
                var parts = new List<string>();
                while (p < end)
                {
                    var len = d[p];
                    Need(d, p + 1, len);
                    parts.Add("\"" + Encoding.UTF8.GetString(d, p + 1, len).Replace("\"", "\\\"", StringComparison.Ordinal) + "\"");
                    p += len + 1;
                }

                data = string.Join(" ", parts);
                break;
            case DnsType.CAA when rdlen >= 2:
                var flags = d[start];
                var tagLen = d[start + 1];
                Need(d, start + 2, tagLen);
                var tag = Encoding.ASCII.GetString(d, start + 2, tagLen);
                var value = Encoding.UTF8.GetString(d, start + 2 + tagLen, end - (start + 2 + tagLen));
                data = string.Create(Inv, $"{flags} {tag} \"{value}\"");
                break;
            default:
                data = "\\# " + rdlen.ToString(Inv) + (rdlen > 0 ? " " + Convert.ToHexString(d, start, rdlen) : ""); // RFC 3597 form
                break;
        }

        pos = end;
        return new DnsRecord(name, type, cls, ttl, data);
    }

    /// <summary>in-addr.arpa / ip6.arpa name for an address (shared with the IP Calculator).</summary>
    public static string PtrName(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        Span<byte> b = stackalloc byte[16];
        address.TryWriteBytes(b, out var n);
        return n == 4
            ? IpText.ReverseName(BinaryPrimitives.ReadUInt32BigEndian(b), false) + "."
            : IpText.ReverseName(BinaryPrimitives.ReadUInt128BigEndian(b), true) + ".";
    }
}

public enum RecordSetComparison
{
    Identical,
    SameRecordsDifferentTtl,
    Different,
}

public sealed record ServerComparison(RecordSetComparison Result, IReadOnlyList<string> OnlyInFirst, IReadOnlyList<string> OnlyInSecond, IReadOnlyList<string> TtlDifferences);

public static class DnsCompare
{
    /// <summary>Compares two answer sets independent of order; TTL differences are reported separately.</summary>
    public static ServerComparison Compare(IEnumerable<DnsRecord> first, IEnumerable<DnsRecord> second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);
        var a = first.GroupBy(r => r.Normalized).ToDictionary(g => g.Key, g => g.First().Ttl, StringComparer.Ordinal);
        var b = second.GroupBy(r => r.Normalized).ToDictionary(g => g.Key, g => g.First().Ttl, StringComparer.Ordinal);
        var onlyA = a.Keys.Except(b.Keys).Order(StringComparer.Ordinal).ToList();
        var onlyB = b.Keys.Except(a.Keys).Order(StringComparer.Ordinal).ToList();
        var ttl = a.Keys.Intersect(b.Keys).Where(k => a[k] != b[k]).Order(StringComparer.Ordinal)
            .Select(k => string.Create(CultureInfo.InvariantCulture, $"{k}: TTL {a[k]} vs {b[k]}")).ToList();
        var result = onlyA.Count + onlyB.Count > 0 ? RecordSetComparison.Different : ttl.Count > 0 ? RecordSetComparison.SameRecordsDifferentTtl : RecordSetComparison.Identical;
        return new ServerComparison(result, onlyA, onlyB, ttl);
    }
}

public enum ReverseCheck
{
    Confirmed,
    MissingPtr,
    Mismatch,
    Inconclusive,
}

public sealed record ReverseCheckResult(string Address, ReverseCheck Result, IReadOnlyList<string> PtrNames, string Detail);

public static class DnsForwardReverse
{
    /// <summary>
    /// Classifies one address: Confirmed when one of its PTR names resolves forward to the address again; MissingPtr when the
    /// PTR query answered authoritatively with no name (NXDOMAIN or empty); Mismatch when PTR names exist but none points back;
    /// Inconclusive when a query failed (timeout, SERVFAIL, REFUSED…).
    /// </summary>
    public static ReverseCheckResult Classify(string address, int? ptrRcode, IReadOnlyList<string> ptrNames, IReadOnlyDictionary<string, (int? Rcode, IReadOnlyList<string> Addresses)> forwardOfPtr)
    {
        ArgumentNullException.ThrowIfNull(ptrNames);
        ArgumentNullException.ThrowIfNull(forwardOfPtr);
        if (ptrRcode is null || (ptrRcode != 0 && ptrRcode != 3)) return new(address, ReverseCheck.Inconclusive, ptrNames, $"PTR query failed ({(ptrRcode is null ? "no answer" : DnsWire.RcodeName(ptrRcode.Value))}).");
        if (ptrNames.Count == 0) return new(address, ReverseCheck.MissingPtr, ptrNames, ptrRcode == 3 ? "No PTR record (NXDOMAIN)." : "No PTR record (empty NOERROR).");
        var normalized = Normalize(address);
        var anyFailed = false;
        foreach (var name in ptrNames)
        {
            if (!forwardOfPtr.TryGetValue(name, out var f) || f.Rcode is null || (f.Rcode != 0 && f.Rcode != 3))
            {
                anyFailed = true;
                continue;
            }

            if (f.Addresses.Any(a => Normalize(a) == normalized)) return new(address, ReverseCheck.Confirmed, ptrNames, $"{name} resolves back to {address}.");
        }

        return anyFailed
            ? new(address, ReverseCheck.Inconclusive, ptrNames, "The forward lookup of a PTR name failed.")
            : new(address, ReverseCheck.Mismatch, ptrNames, $"No PTR name ({string.Join(", ", ptrNames)}) resolves back to {address}.");
    }

    private static string Normalize(string a) => IPAddress.TryParse(a, out var ip) ? ip.ToString() : a.ToLowerInvariant();
}
