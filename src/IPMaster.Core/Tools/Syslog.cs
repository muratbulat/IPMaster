using System.Globalization;
using System.Text;

namespace IPMaster.Core.Tools;

public enum SyslogFormat
{
    Rfc5424,
    Rfc3164,
    Unknown,
}

public sealed record SyslogMessage(
    DateTime ReceivedUtc,
    string Source,
    string Transport,
    int Facility,
    int Severity,
    SyslogFormat Format,
    DateTimeOffset? Timestamp,
    string Host,
    string AppName,
    string ProcId,
    string MsgId,
    string StructuredData,
    string Message,
    bool PriorityMissing)
{
    public static readonly IReadOnlyList<string> SeverityNames = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"];

    public static readonly IReadOnlyList<string> FacilityNames =
    [
        "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
        "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
    ];

    public string SeverityName => SeverityNames[Severity];

    public string FacilityName => Facility < FacilityNames.Count ? FacilityNames[Facility] : Facility.ToString(CultureInfo.InvariantCulture);
}

/// <summary>Syslog message parsing (D-079): RFC 5424 when VERSION "1" follows the PRI, else BSD syslog (RFC 3164), else unknown (raw kept).</summary>
public static class SyslogParser
{
    public const int MaxMessageChars = 64 * 1024;

    private static readonly string[] Months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

    public static SyslogMessage Parse(ReadOnlySpan<byte> raw, DateTime receivedUtc, string source, string transport)
    {
        var text = raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF ? raw[3..] : raw;
        var s = Encoding.UTF8.GetString(text).TrimEnd('\r', '\n', '\0');
        if (s.Length > MaxMessageChars) s = s[..MaxMessageChars];
        var (pri, rest, missing) = Priority(s);
        var facility = pri / 8;
        var severity = pri % 8;
        if (rest.StartsWith("1 ", StringComparison.Ordinal) && TryRfc5424(rest[2..], receivedUtc, source, transport, facility, severity) is { } m) return m;
        if (TryRfc3164(rest, receivedUtc, source, transport, facility, severity, missing) is { } b) return b;
        return new SyslogMessage(receivedUtc, source, transport, facility, severity, SyslogFormat.Unknown, null, "", "", "", "", "", rest, missing);
    }

    /// <summary>"&lt;PRI&gt;" with 1–3 digits and a value ≤ 191; missing/invalid → user.notice (13), as RFC 3164 §4.3.3 suggests.</summary>
    private static (int Pri, string Remainder, bool Missing) Priority(string s)
    {
        if (s.Length >= 3 && s[0] == '<')
        {
            var close = s.IndexOf('>', 1);
            if (close is >= 2 and <= 4 && int.TryParse(s.AsSpan(1, close - 1), NumberStyles.None, CultureInfo.InvariantCulture, out var pri) && pri <= 191
                && (close == 2 || s[1] != '0'))
            {
                return (pri, s[(close + 1)..], false);
            }
        }

        return (13, s, true);
    }

    private static SyslogMessage? TryRfc5424(string s, DateTime received, string source, string transport, int facility, int severity)
    {
        var pos = 0;
        string? Field()
        {
            if (pos >= s.Length) return null;
            var sp = s.IndexOf(' ', pos);
            var v = sp < 0 ? s[pos..] : s[pos..sp];
            pos = sp < 0 ? s.Length : sp + 1;
            return v;
        }

        var ts = Field();
        var host = Field();
        var app = Field();
        var proc = Field();
        var msgId = Field();
        if (ts is null || host is null || app is null || proc is null || msgId is null) return null;
        DateTimeOffset? timestamp = null;
        if (ts != "-")
        {
            if (!DateTimeOffset.TryParse(ts, CultureInfo.InvariantCulture, DateTimeStyles.None, out var t) || !ts.Contains('T', StringComparison.Ordinal)) return null;
            timestamp = t;
        }

        string sd;
        if (pos < s.Length && s[pos] == '-')
        {
            sd = "";
            pos++;
        }
        else if (pos < s.Length && s[pos] == '[')
        {
            var start = pos;
            while (pos < s.Length && s[pos] == '[')
            {
                pos++;
                var inQuote = false;
                for (; pos < s.Length; pos++)
                {
                    if (s[pos] == '\\' && inQuote)
                    {
                        pos++; // escaped \" \] \\
                        continue;
                    }

                    if (s[pos] == '"') inQuote = !inQuote;
                    else if (s[pos] == ']' && !inQuote) break;
                }

                if (pos >= s.Length) return null; // unterminated element
                pos++;
            }

            sd = s[start..pos];
        }
        else
        {
            return null;
        }

        var msg = pos < s.Length && s[pos] == ' ' ? s[(pos + 1)..] : pos < s.Length ? s[pos..] : "";
        if (msg.StartsWith('﻿')) msg = msg[1..];
        static string Nil(string v) => v == "-" ? "" : v;
        return new SyslogMessage(received, source, transport, facility, severity, SyslogFormat.Rfc5424, timestamp, Nil(host), Nil(app), Nil(proc), Nil(msgId), sd, msg, false);
    }

    /// <summary>"Mmm dd hh:mm:ss HOST TAG[PID]: MSG". The year is not sent: the nearest year that does not put the time more than a month after receipt is used.</summary>
    private static SyslogMessage? TryRfc3164(string s, DateTime received, string source, string transport, int facility, int severity, bool missing)
    {
        if (s.Length < 16) return null;
        var month = Array.IndexOf(Months, s[..3]);
        if (month < 0 || s[3] != ' ' || s[6] != ' ' || s[9] != ':' || s[12] != ':') return null;
        if (!int.TryParse(s.AsSpan(4, 2).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var day) || day is < 1 or > 31) return null;
        if (!TimeSpan.TryParseExact(s.AsSpan(7, 8), "hh\\:mm\\:ss", CultureInfo.InvariantCulture, out var time)) return null;
        DateTimeOffset? timestamp = null;
        foreach (var year in new[] { received.Year, received.Year - 1, received.Year + 1 })
        {
            if (day > DateTime.DaysInMonth(year, month + 1)) continue;
            var local = new DateTime(year, month + 1, day, 0, 0, 0, DateTimeKind.Unspecified) + time;
            if ((local - received).TotalDays > 31) continue; // a timestamp more than a month ahead belongs to an earlier year
            if (timestamp is null || Math.Abs((local - received).TotalDays) < Math.Abs((timestamp.Value.DateTime - received).TotalDays)) timestamp = new DateTimeOffset(local, TimeSpan.Zero);
        }

        var rest = s.Length > 16 ? s[16..] : "";
        var sp = rest.IndexOf(' ', StringComparison.Ordinal);
        var host = "";
        if (sp > 0 && !rest[..sp].EndsWith(':') && !rest[..sp].Contains('[', StringComparison.Ordinal))
        {
            host = rest[..sp];
            rest = rest[(sp + 1)..];
        }

        var app = "";
        var proc = "";
        var tagEnd = 0;
        while (tagEnd < rest.Length && tagEnd < 48 && (char.IsLetterOrDigit(rest[tagEnd]) || rest[tagEnd] is '-' or '_' or '.' or '/')) tagEnd++;
        if (tagEnd > 0 && tagEnd < rest.Length && rest[tagEnd] is '[' or ':')
        {
            app = rest[..tagEnd];
            var after = tagEnd;
            if (rest[after] == '[' && rest.IndexOf(']', after) is var close and > 0)
            {
                proc = rest[(after + 1)..close];
                after = close + 1;
            }

            if (after < rest.Length && rest[after] == ':') after++;
            rest = rest[after..].TrimStart(' ');
        }

        // local time of the sender is unknown: shown as received (no zone conversion)
        return new SyslogMessage(received, source, transport, facility, severity, SyslogFormat.Rfc3164, timestamp, host, app, proc, "", "", rest, missing);
    }
}

/// <summary>
/// TCP syslog stream framing (RFC 6587): octet counting ("LEN SP MSG") when a frame starts with a digit, otherwise
/// non-transparent framing ending in LF (CR LF and NUL also end a frame). Frames longer than the limit are skipped and counted.
/// </summary>
public sealed class SyslogStreamDecoder(int maxFrameBytes = 64 * 1024)
{
    private enum State
    {
        Start,
        Length,
        Body,
        Line,
        SkipOctets,
        SkipLine,
    }

    private readonly List<byte> _buffer = [];
    private State _state;
    private long _count;

    public int MaxFrameBytes { get; } = maxFrameBytes;

    /// <summary>Frames skipped because they exceeded <see cref="MaxFrameBytes"/>.</summary>
    public int Oversized { get; private set; }

    /// <summary>Bytes held for an incomplete frame (bounded by <see cref="MaxFrameBytes"/>).</summary>
    public int Pending => _buffer.Count;

    public List<byte[]> Push(ReadOnlySpan<byte> data)
    {
        var frames = new List<byte[]>();
        foreach (var b in data)
        {
            switch (_state)
            {
                case State.Start:
                    if (b is (byte)'\n' or (byte)'\r' or 0) break; // empty frames, stray terminators
                    _buffer.Add(b);
                    if (b is >= (byte)'1' and <= (byte)'9')
                    {
                        _state = State.Length;
                        _count = b - '0';
                    }
                    else
                    {
                        _state = State.Line;
                    }

                    break;
                case State.Length:
                    if (b is >= (byte)'0' and <= (byte)'9' && _buffer.Count < 10)
                    {
                        _buffer.Add(b);
                        _count = (_count * 10) + (b - '0');
                    }
                    else if (b == ' ')
                    {
                        _buffer.Clear();
                        if (_count > MaxFrameBytes)
                        {
                            Oversized++;
                            _state = State.SkipOctets;
                        }
                        else
                        {
                            _state = State.Body;
                        }
                    }
                    else
                    {
                        _state = State.Line; // a newline-framed message that starts with a digit
                        Line(b, frames);
                    }

                    break;
                case State.Body:
                    _buffer.Add(b);
                    if (_buffer.Count == _count) Emit(frames, _buffer.Count);
                    break;
                case State.Line:
                    Line(b, frames);
                    break;
                case State.SkipOctets:
                    if (--_count == 0) _state = State.Start;
                    break;
                case State.SkipLine:
                    if (b is (byte)'\n' or 0) _state = State.Start;
                    break;
            }
        }

        return frames;
    }

    private void Line(byte b, List<byte[]> frames)
    {
        if (b is (byte)'\n' or 0)
        {
            var end = _buffer.Count;
            if (end > 0 && _buffer[end - 1] == '\r') end--;
            Emit(frames, end);
            return;
        }

        _buffer.Add(b);
        if (_buffer.Count > MaxFrameBytes)
        {
            Oversized++;
            _buffer.Clear();
            _state = State.SkipLine;
        }
    }

    private void Emit(List<byte[]> frames, int length)
    {
        if (length > 0) frames.Add(_buffer.GetRange(0, length).ToArray());
        _buffer.Clear();
        _state = State.Start;
    }
}
