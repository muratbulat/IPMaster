using System.Text;
using IPMaster.Core.Tools;
using MailKit;

namespace IPMaster.Infrastructure.Tools;

/// <summary>
/// MailKit protocol logger for the SMTP tester. Secrets are removed here, before anything is stored: MailKit's
/// <see cref="IAuthenticationSecretDetector"/> marks AUTH payload bytes, and <see cref="SmtpText.RedactClientLine"/> also
/// hides any AUTH initial response and every line answering a 334 challenge. Message content (DATA) is counted, not
/// logged. Bounded: at most <see cref="MaxEntries"/> entries per session.
/// </summary>
public sealed class SmtpSessionLogger : IProtocolLogger
{
    public const int MaxEntries = 20_000;
    private readonly Action<SmtpLogEntry> _sink;
    private readonly TimeProvider _time;
    private readonly StringBuilder _clientPartial = new();
    private readonly StringBuilder _serverPartial = new();
    private readonly object _lock = new();
    private int _count;
    private bool _authChallenge;
    private bool _dataRequested;
    private bool _inData;
    private long _dataBytes;
    private string _dataTail = "";

    public SmtpSessionLogger(Action<SmtpLogEntry> sink, TimeProvider? time = null)
    {
        _sink = sink;
        _time = time ?? TimeProvider.System;
    }

    public IAuthenticationSecretDetector? AuthenticationSecretDetector { get; set; }

    /// <summary>True once the client sent the DATA command (or BDAT).</summary>
    public bool DataCommandSent { get; private set; }

    /// <summary>Time of the first server bytes (greeting) and of the last completed server reply.</summary>
    public DateTimeOffset? FirstServerAt { get; private set; }

    public string? LastServerReply { get; private set; }

    public int LastServerCode { get; private set; }

    /// <summary>The server sent bytes that are not SMTP text (e.g. a TLS record): drives the implicit-TLS hint (review S-09).</summary>
    public bool ReceivedBinary { get; private set; }

    /// <summary>Last SMTP command verb sent (known verbs only, never an AUTH continuation line).</summary>
    public string? LastClientVerb { get; private set; }

    private static readonly HashSet<string> Verbs = new(StringComparer.OrdinalIgnoreCase) { "EHLO", "HELO", "STARTTLS", "AUTH", "MAIL", "RCPT", "DATA", "BDAT", "RSET", "NOOP", "QUIT", "VRFY" };

    // stateful decoders: a UTF-8 character can be split across two buffers (review S-09)
    private readonly Decoder _clientDecoder = Encoding.UTF8.GetDecoder();
    private readonly Decoder _serverDecoder = Encoding.UTF8.GetDecoder();

    private static string Decode(Decoder d, byte[] bytes, int offset, int count)
    {
        var chars = new char[d.GetCharCount(bytes, offset, count)];
        d.GetChars(bytes, offset, count, chars, 0);
        return new string(chars);
    }

    public void Info(string text) => Emit(SmtpLogKind.Info, text);

    public void Tls(string text) => Emit(SmtpLogKind.Tls, text);

    public void Error(string text) => Emit(SmtpLogKind.Error, text);

    public void LogConnect(Uri uri) => Emit(SmtpLogKind.Info, $"MailKit session on {uri.Host}:{uri.Port}");

    public void LogClient(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        lock (_lock)
        {
            if (_inData)
            {
                _dataBytes += count;
                // the terminator may be split across writes: keep the last five bytes seen
                _dataTail += Encoding.ASCII.GetString(buffer, offset + Math.Max(0, count - 5), Math.Min(count, 5));
                if (_dataTail.Length > 5) _dataTail = _dataTail[^5..];
                if (_dataTail.EndsWith("\r\n.\r\n", StringComparison.Ordinal))
                {
                    _inData = false;
                    Emit(SmtpLogKind.Client, $"[message content: {_dataBytes:N0} bytes, not logged] .");
                    _dataBytes = 0;
                    _dataTail = "";
                }

                return;
            }

            var copy = new byte[count];
            Buffer.BlockCopy(buffer, offset, copy, 0, count);
            if (AuthenticationSecretDetector?.DetectSecrets(buffer, offset, count) is { Count: > 0 } secrets)
            {
                foreach (var s in secrets)
                {
                    for (var i = 0; i < s.Length && s.StartIndex - offset + i < copy.Length; i++) copy[s.StartIndex - offset + i] = (byte)'*';
                }
            }

            _clientPartial.Append(Decode(_clientDecoder, copy, 0, copy.Length));
            foreach (var line in TakeLines(_clientPartial))
            {
                var verb = line.Split(' ', 2)[0];
                if (!_authChallenge && Verbs.Contains(verb)) LastClientVerb = verb.ToUpperInvariant();
                var safe = SmtpText.RedactClientLine(line, _authChallenge);
                _authChallenge = false;
                if (line.Equals("DATA", StringComparison.OrdinalIgnoreCase))
                {
                    _dataRequested = true;
                    DataCommandSent = true;
                }

                if (line.StartsWith("BDAT ", StringComparison.OrdinalIgnoreCase)) DataCommandSent = true;
                Emit(SmtpLogKind.Client, safe);
            }
        }
    }

    public void LogServer(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        lock (_lock)
        {
            FirstServerAt ??= _time.GetUtcNow();
            for (var i = offset; i < offset + count; i++)
            {
                var b = buffer[i];
                if (b < 0x09 || b is >= 0x0E and < 0x20) ReceivedBinary = true;
            }

            _serverPartial.Append(Decode(_serverDecoder, buffer, offset, count));
            foreach (var line in TakeLines(_serverPartial))
            {
                Emit(SmtpLogKind.Server, line);
                if (line.Length >= 3 && int.TryParse(line.AsSpan(0, 3), out var code))
                {
                    var final = line.Length == 3 || line[3] == ' ';
                    if (!final) continue;
                    LastServerCode = code;
                    LastServerReply = line;
                    _authChallenge = code == 334;
                    if (code == 354 && _dataRequested)
                    {
                        _inData = true;
                        _dataRequested = false;
                    }
                }
            }
        }
    }

    private static IEnumerable<string> TakeLines(StringBuilder sb)
    {
        var text = sb.ToString();
        var start = 0;
        int nl;
        var lines = new List<string>();
        while ((nl = text.IndexOf('\n', start)) >= 0)
        {
            lines.Add(text[start..nl].TrimEnd('\r'));
            start = nl + 1;
        }

        sb.Clear();
        if (start < text.Length) sb.Append(text, start, text.Length - start);
        return lines;
    }

    private void Emit(SmtpLogKind kind, string text)
    {
        if (Interlocked.Increment(ref _count) > MaxEntries)
        {
            if (_count == MaxEntries + 1) _sink(new SmtpLogEntry(_time.GetUtcNow(), SmtpLogKind.Info, "Log limit reached; further lines are not recorded."));
            return;
        }

        _sink(new SmtpLogEntry(_time.GetUtcNow(), kind, text));
    }

    public void Dispose()
    {
        // nothing to release: entries go to the sink as they arrive
    }
}
