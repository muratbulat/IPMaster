using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace IPMaster.Core.Tools;

/// <summary>NTP timestamp conversion (RFC 5905 §6): 32.32 fixed point seconds since 1900, era chosen nearest a pivot time.</summary>
public static class NtpTime
{
    private static readonly DateTime Era0 = new(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    private const long TicksPerEra = (1L << 32) * TimeSpan.TicksPerSecond;

    public static ulong FromDateTime(DateTime utc)
    {
        var ticks = (utc.ToUniversalTime() - Era0).Ticks;
        var era = Math.Floor((double)ticks / TicksPerEra);
        ticks -= (long)era * TicksPerEra;
        var seconds = (ulong)(ticks / TimeSpan.TicksPerSecond);
        var fraction = (ulong)((ticks % TimeSpan.TicksPerSecond) * (double)(1UL << 32) / TimeSpan.TicksPerSecond);
        return (seconds << 32) | fraction;
    }

    /// <summary>Converts to UTC in the 136-year era closest to <paramref name="pivotUtc"/> (handles the 2036 rollover).</summary>
    public static DateTime ToDateTime(ulong timestamp, DateTime pivotUtc)
    {
        var seconds = (long)(timestamp >> 32);
        var fractionTicks = (long)Math.Round((timestamp & 0xFFFF_FFFF) * (double)TimeSpan.TicksPerSecond / (1UL << 32));
        var inEra = (seconds * TimeSpan.TicksPerSecond) + fractionTicks;
        var pivot = (pivotUtc.ToUniversalTime() - Era0).Ticks;
        var era = (long)Math.Round((double)(pivot - inEra) / TicksPerEra);
        return Era0.AddTicks(inEra + (era * TicksPerEra));
    }

    /// <summary>NTP short format (16.16 seconds), used for root delay/dispersion.</summary>
    public static TimeSpan FromShort(uint value) => TimeSpan.FromTicks((long)(value * (double)TimeSpan.TicksPerSecond / 65536));
}

public enum NtpLeap
{
    NoWarning = 0,
    LastMinuteHas61Seconds = 1,
    LastMinuteHas59Seconds = 2,
    Unsynchronized = 3,
}

public sealed record NtpPacket(
    NtpLeap Leap,
    int Version,
    int Mode,
    int Stratum,
    int Poll,
    int Precision,
    TimeSpan RootDelay,
    TimeSpan RootDispersion,
    uint ReferenceIdRaw,
    ulong Reference,
    ulong Origin,
    ulong Receive,
    ulong Transmit)
{
    public const int Size = 48;

    /// <summary>Kiss-o'-Death: stratum 0 with an ASCII kiss code in the reference ID (RFC 5905 §7.4).</summary>
    public bool IsKissOfDeath => Stratum == 0;

    public string KissCode => Ascii(ReferenceIdRaw);

    /// <summary>Stratum 1: a 4-character source (GPS, PPS…); higher strata: the upstream server's IPv4 address (or an IPv6 hash).</summary>
    public string ReferenceId => Stratum <= 1
        ? Ascii(ReferenceIdRaw)
        : string.Create(CultureInfo.InvariantCulture, $"{ReferenceIdRaw >> 24}.{(ReferenceIdRaw >> 16) & 0xFF}.{(ReferenceIdRaw >> 8) & 0xFF}.{ReferenceIdRaw & 0xFF}");

    public double PrecisionSeconds => Math.Pow(2, Precision);

    private static string Ascii(uint v)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(b, v);
        return Encoding.ASCII.GetString(b).TrimEnd('\0').Trim();
    }

    /// <summary>Client request (mode 3, version 4). The transmit field carries a random nonce, which a valid reply echoes as its origin.</summary>
    public static byte[] Request(ulong nonce)
    {
        var b = new byte[Size];
        b[0] = (0 << 6) | (4 << 3) | 3;
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(40), nonce);
        return b;
    }

    public static byte[] Encode(NtpPacket p)
    {
        ArgumentNullException.ThrowIfNull(p);
        var b = new byte[Size];
        b[0] = (byte)(((int)p.Leap << 6) | (p.Version << 3) | p.Mode);
        b[1] = (byte)p.Stratum;
        b[2] = (byte)(sbyte)p.Poll;
        b[3] = (byte)(sbyte)p.Precision;
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(4), (uint)(p.RootDelay.TotalSeconds * 65536));
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(8), (uint)(p.RootDispersion.TotalSeconds * 65536));
        BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(12), p.ReferenceIdRaw);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(16), p.Reference);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(24), p.Origin);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(32), p.Receive);
        BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(40), p.Transmit);
        return b;
    }

    public static NtpPacket? TryParse(ReadOnlySpan<byte> b)
    {
        if (b.Length < Size) return null;
        return new NtpPacket((NtpLeap)(b[0] >> 6), (b[0] >> 3) & 7, b[0] & 7, b[1], (sbyte)b[2], (sbyte)b[3],
            NtpTime.FromShort(BinaryPrimitives.ReadUInt32BigEndian(b[4..])), NtpTime.FromShort(BinaryPrimitives.ReadUInt32BigEndian(b[8..])),
            BinaryPrimitives.ReadUInt32BigEndian(b[12..]), BinaryPrimitives.ReadUInt64BigEndian(b[16..]), BinaryPrimitives.ReadUInt64BigEndian(b[24..]),
            BinaryPrimitives.ReadUInt64BigEndian(b[32..]), BinaryPrimitives.ReadUInt64BigEndian(b[40..]));
    }

    /// <summary>Reason a reply to <paramref name="nonce"/> is unusable, or null when it is a valid server reply (KoD is reported separately).</summary>
    public string? Problem(ulong nonce)
    {
        if (Origin != nonce) return "the origin timestamp does not match the request (stale or spoofed reply)";
        if (Mode != 4) return string.Create(CultureInfo.InvariantCulture, $"mode {Mode} is not a server reply");
        if (Version is < 1 or > 4) return string.Create(CultureInfo.InvariantCulture, $"unsupported version {Version}");
        if (IsKissOfDeath) return null;
        if (Stratum > 15) return string.Create(CultureInfo.InvariantCulture, $"stratum {Stratum} means the server is unsynchronized");
        if (Transmit == 0) return "the transmit timestamp is zero";
        return null;
    }
}

/// <summary>On-wire offset/delay calculation (RFC 5905 §8).</summary>
public static class NtpMath
{
    /// <summary>offset θ = ((T2 − T1) + (T3 − T4)) / 2: positive when the local clock is behind the server.</summary>
    public static TimeSpan Offset(DateTime t1, DateTime t2, DateTime t3, DateTime t4) => TimeSpan.FromTicks(((t2 - t1).Ticks + (t3 - t4).Ticks) / 2);

    /// <summary>round-trip delay δ = (T4 − T1) − (T3 − T2).</summary>
    public static TimeSpan Delay(DateTime t1, DateTime t2, DateTime t3, DateTime t4) => (t4 - t1) - (t3 - t2);

    public static string Describe(TimeSpan offset)
    {
        var ms = offset.TotalMilliseconds;
        var size = Math.Abs(ms) >= 1000 ? string.Create(CultureInfo.InvariantCulture, $"{Math.Abs(offset.TotalSeconds):0.000} s") : string.Create(CultureInfo.InvariantCulture, $"{Math.Abs(ms):0.000} ms");
        return ms switch
        {
            > 0 => $"local clock is {size} behind the server",
            < 0 => $"local clock is {size} ahead of the server",
            _ => "local clock matches the server",
        };
    }
}
