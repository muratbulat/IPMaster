using System.Globalization;
using System.Text.RegularExpressions;

namespace IPMaster.Core.Tools;

public enum SmtpConnectionSecurity
{
    None,

    /// <summary>STARTTLS must succeed; never falls back to plaintext.</summary>
    StartTlsRequired,

    ImplicitTls,
}

public enum SmtpAuthMode
{
    None,
    UsernamePassword,
}

public enum SmtpBodyFormat
{
    PlainText,
    Html,
}

/// <summary>Message fields of a profile (optional template) and of the tester window.</summary>
public sealed record SmtpMessageTemplate
{
    /// <summary>Empty = the From address.</summary>
    public string EnvelopeSender { get; set; } = "";

    /// <summary>Empty = To + Cc + Bcc.</summary>
    public string EnvelopeRecipients { get; set; } = "";

    public string From { get; set; } = "";

    public string To { get; set; } = "";

    public string Cc { get; set; } = "";

    public string Bcc { get; set; } = "";

    public string Subject { get; set; } = "";

    public string Body { get; set; } = "";

    public SmtpBodyFormat BodyFormat { get; set; }

    public IReadOnlyList<string> Attachments { get; set; } = [];
}

/// <summary>A named SMTP tester profile (Tools → SMTP Client Tester). Never contains a password (D-068).</summary>
public sealed record SmtpProfile
{
    public string Name { get; set; } = "";

    public string Server { get; set; } = "";

    public int Port { get; set; } = 587;

    public SmtpConnectionSecurity Security { get; set; } = SmtpConnectionSecurity.StartTlsRequired;

    public int ConnectTimeoutSeconds { get; set; } = 15;

    public int OperationTimeoutSeconds { get; set; } = 30;

    /// <summary>Empty = the local computer's fully qualified name.</summary>
    public string EhloName { get; set; } = "";

    public SmtpAuthMode AuthMode { get; set; }

    public string UserName { get; set; } = "";

    /// <summary>Password from the Credential Manager; null = typed per session, never saved.</summary>
    public Guid? CredentialId { get; set; }

    /// <summary>"Auto" or a SASL mechanism name.</summary>
    public string Mechanism { get; set; } = "Auto";

    /// <summary>Profile-specific; false is shown as a warning in the window. Never changes global TLS behaviour.</summary>
    public bool ValidateCertificate { get; set; } = true;

    /// <summary>Lab override: allow credentials over an unencrypted connection.</summary>
    public bool AllowPlaintextAuth { get; set; }

    /// <summary>Null = the profile keeps no message template.</summary>
    public SmtpMessageTemplate? Message { get; set; }
}

public sealed record ToolSettings
{
    public IReadOnlyList<SmtpProfile> SmtpProfiles { get; set; } = [];

    public IReadOnlyList<KmsProfile> KmsProfiles { get; set; } = [];

    /// <summary>iPerf executable chosen by the user (Tools → iPerf Network Performance); empty = search PATH.</summary>
    public string IperfExecutable { get; set; } = "";
}

public enum SmtpOperation
{
    /// <summary>DNS, TCP, greeting/EHLO, TLS, AUTH. No MAIL/RCPT/DATA.</summary>
    Connection,

    /// <summary>Connection + MAIL FROM + RCPT TO per recipient + RSET. Never DATA.</summary>
    Recipients,

    /// <summary>Connection + full submission.</summary>
    Send,
}

public enum SmtpStage
{
    Dns,
    Tcp,
    Greeting,
    Tls,
    Authentication,
    Recipients,
    Submission,
}

public enum StageOutcome
{
    NotRun,
    Skipped,
    Success,

    /// <summary>Passed with a caveat (e.g. certificate errors ignored by the profile).</summary>
    Warning,
    Failed,
    Cancelled,
}

public sealed record StageResult(SmtpStage Stage, StageOutcome Outcome, TimeSpan? Duration, string Summary, string? Explanation = null, string? ServerResponse = null);

public enum SmtpLogKind
{
    Info,
    Client,
    Server,
    Tls,
    Error,
}

public sealed record SmtpLogEntry(DateTimeOffset At, SmtpLogKind Kind, string Text)
{
    public string Format() => $"{At.ToLocalTime():HH:mm:ss.fff} {Kind switch
    {
        SmtpLogKind.Client => "C:",
        SmtpLogKind.Server => "S:",
        SmtpLogKind.Tls => "TLS",
        SmtpLogKind.Error => "ERR",
        _ => "  *",
    }} {Text}";
}

public sealed record RecipientResult(string Address, bool Accepted, int Code, string? EnhancedCode, string Response, string? Explanation);

public sealed record SmtpTestReport(
    SmtpOperation Operation,
    IReadOnlyList<StageResult> Stages,
    IReadOnlyList<RecipientResult> Recipients,
    TimeSpan Elapsed,
    string? FinalResponse,
    string? QueueId,
    bool DataSent)
{
    public bool Succeeded => Stages.All(s => s.Outcome is StageOutcome.Success or StageOutcome.Warning or StageOutcome.Skipped or StageOutcome.NotRun)
                             && Stages.Any(s => s.Outcome is StageOutcome.Success or StageOutcome.Warning);
}

/// <summary>Pure helpers: reply parsing, explanations, redaction, presets, test messages.</summary>
public static partial class SmtpText
{
    /// <summary>First line of a window log whose oldest lines were dropped to stay within the bound.</summary>
    public const string LogTrimmedMarker = "[… earlier log lines removed to keep the window log bounded …]";

    /// <summary>Default bound for the window's session log (all runs together), in characters.</summary>
    public const int MaxWindowLogChars = 2_000_000;

    /// <summary>
    /// Appends one log line and, when the log would exceed <paramref name="maxChars"/>, drops whole lines from the start
    /// (to about three quarters of the bound, so trimming is not repeated for every line) and marks the cut.
    /// </summary>
    public static void AppendBounded(System.Text.StringBuilder log, string line, int maxChars = MaxWindowLogChars)
    {
        ArgumentNullException.ThrowIfNull(log);
        log.AppendLine(line);
        if (log.Length <= maxChars) return;
        var text = log.ToString();
        var keepFrom = text.Length - (maxChars * 3 / 4) + LogTrimmedMarker.Length + 1;
        var cut = text.IndexOf('\n', Math.Clamp(keepFrom, 0, text.Length - 1));
        log.Clear().AppendLine(LogTrimmedMarker).Append(cut < 0 ? "" : text.AsSpan(cut + 1));
    }

    public static readonly IReadOnlyList<string> Mechanisms = ["Auto", "PLAIN", "LOGIN", "CRAM-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256", "SCRAM-SHA-512", "NTLM"];

    public static string StageName(SmtpStage s) => s switch
    {
        SmtpStage.Dns => "DNS resolution",
        SmtpStage.Tcp => "TCP connection",
        SmtpStage.Greeting => "Greeting and EHLO",
        SmtpStage.Tls => "TLS negotiation",
        SmtpStage.Authentication => "Authentication",
        SmtpStage.Recipients => "Envelope (MAIL FROM / RCPT TO)",
        _ => "Message submission",
    };

    /// <summary>Port presets: 25 relay/MX, 587 submission (STARTTLS), 465 submission (implicit TLS).</summary>
    public static SmtpConnectionSecurity SuggestedSecurity(int port) => port switch
    {
        465 => SmtpConnectionSecurity.ImplicitTls,
        587 => SmtpConnectionSecurity.StartTlsRequired,
        _ => SmtpConnectionSecurity.StartTlsRequired,
    };

    [GeneratedRegex(@"^(?<c>[245]\.\d{1,3}\.\d{1,3})\b")]
    private static partial Regex EnhancedRegex();

    [GeneratedRegex(@"(?:queued as|queue id|id=|ok\s*:?\s*queued as)\s*<?(?<id>[A-Za-z0-9._\-@]{4,})>?", RegexOptions.IgnoreCase)]
    private static partial Regex QueueRegex();

    [GeneratedRegex(@"^(?<cmd>AUTH\s+\S+)\s+\S.*$", RegexOptions.IgnoreCase)]
    private static partial Regex AuthInitialRegex();

    /// <summary>RFC 3463 enhanced status code at the start of the reply text ("5.7.1 Relaying denied").</summary>
    public static string? EnhancedCode(string? text) => text is null ? null : EnhancedRegex().Match(text.TrimStart()) is { Success: true } m ? m.Groups["c"].Value : null;

    /// <summary>Queue identifier from a final DATA reply ("250 2.0.0 Ok: queued as 4Xk2"), when the server supplies one.</summary>
    public static string? QueueId(string? response)
    {
        if (string.IsNullOrWhiteSpace(response)) return null;
        var m = QueueRegex().Match(response);
        if (m.Success) return m.Groups["id"].Value.TrimEnd('.');
        // Exchange/Microsoft 365: "2.6.0 <message-id> [InternalId=...] Queued mail for delivery"
        var i = response.IndexOf("InternalId=", StringComparison.OrdinalIgnoreCase);
        if (i >= 0)
        {
            var end = response.IndexOfAny([',', ']', ' '], i);
            return response[(i + 11)..(end < 0 ? response.Length : end)];
        }

        return null;
    }

    /// <summary>
    /// Safety net applied to every client line before it is stored (MailKit's secret detector runs first): an AUTH
    /// command's initial response, and any line answering a 334 challenge, are replaced.
    /// </summary>
    public static string RedactClientLine(string line, bool answeringAuthChallenge)
    {
        ArgumentNullException.ThrowIfNull(line);
        if (answeringAuthChallenge) return line.Length == 0 || line == "*" ? line : "******** (authentication data hidden)";
        var m = AuthInitialRegex().Match(line);
        return m.Success ? m.Groups["cmd"].Value + " ******** (authentication data hidden)" : line;
    }

    /// <summary>Administrator-facing explanation of a negative reply at a stage; the original reply is kept separately.</summary>
    public static string? ExplainReply(SmtpStage stage, int code, string? text)
    {
        var t = text ?? "";
        var enhanced = EnhancedCode(t) ?? "";
        bool Has(string s) => t.Contains(s, StringComparison.OrdinalIgnoreCase);
        if (enhanced is "5.2.2" or "4.2.2" || (Has("mailbox") && (Has("full") || Has("quota"))))
        {
            return "The recipient's mailbox is full or over its storage quota. This is a problem at the recipient's side, not with this message or server.";
        }

        if (code == 552 || enhanced is "5.3.4" or "5.2.3" or "4.3.4" || (Has("size") && Has("exceed")))
        {
            return "Message size limit: the server refuses messages this large (compare with the SIZE value it advertised in EHLO).";
        }

        switch (stage)
        {
            case SmtpStage.Authentication:
                if (code == 535 || enhanced == "5.7.8") return "Authentication failed: the server rejected the user name or password (or the account is not allowed to submit mail).";
                if (code == 534 || enhanced == "5.7.9") return "The server requires a stronger authentication mechanism, or an app password / modern authentication for this account.";
                if (code == 538) return "The server only allows this authentication mechanism over an encrypted connection.";
                if (code == 454) return "Temporary authentication failure on the server; try again later.";
                return code >= 400 ? "The server rejected authentication." : null;
            case SmtpStage.Recipients when code is >= 400:
                if (Has("relay") || enhanced == "5.7.1" || code == 554 && Has("access denied"))
                {
                    return "Relay denied: the server will not accept mail for this recipient from this client. Authenticate, send from an allowed address/IP, or use the recipient's own MX server.";
                }

                if (code is 550 or 551 or 553 && (enhanced.StartsWith("5.1.", StringComparison.Ordinal) || Has("unknown") || Has("no such") || Has("does not exist")))
                {
                    return "Recipient rejected: the server does not know this mailbox.";
                }

                if (code is >= 450 and < 500) return "Temporary rejection (greylisting, rate limit or a busy server); a real sender would retry later.";
                return "Recipient rejected by the server.";
            case SmtpStage.Submission when code is >= 400:
                if (Has("spam") || Has("policy") || enhanced.StartsWith("5.7.", StringComparison.Ordinal)) return "The message was refused by server policy (content, authentication of the sender domain, or anti-spam).";
                return "The server refused the message.";
            case SmtpStage.Greeting when code is >= 400:
                return code == 554 ? "The server refuses connections from this client (554 at greeting: blocked IP or no service)." : "The server greeting or EHLO was rejected.";
        }

        return null;
    }

    /// <summary>Explanation for MAIL FROM rejections (sender stage is reported under Recipients/Submission).</summary>
    public static string ExplainSender(int code, string? text)
    {
        var size = ExplainReply(SmtpStage.Submission, code, text);
        if (size is not null && size.StartsWith("Message size", StringComparison.Ordinal)) return size;
        var t = text ?? "";
        if (t.Contains("auth", StringComparison.OrdinalIgnoreCase) || code == 530) return "Sender rejected: the server requires authentication before MAIL FROM.";
        return "Sender rejected: the server does not accept this envelope sender (not owned by the account, unknown domain, or policy).";
    }

    /// <summary>Diagnostic subject and body with a timestamp and a unique id.</summary>
    public static (string Subject, string Body, string Id) GenerateTestMessage(DateTimeOffset now, Guid id, string server, SmtpBodyFormat format)
    {
        var shortId = id.ToString("N")[..12].ToUpperInvariant();
        var stamp = now.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture);
        var subject = $"[IPMaster SMTP test] {stamp} id {shortId}";
        var lines = new[]
        {
            "This is a diagnostic message sent by IPMaster's SMTP Client Tester.",
            "",
            $"Test id:  {shortId}",
            $"Created:  {stamp}",
            $"Server:   {server}",
            "",
            "Acceptance by the SMTP server does not prove delivery to an inbox. If this message arrived, compare",
            "its Received headers with the session log to follow its path. It can be deleted.",
        };
        var body = format == SmtpBodyFormat.Html
            ? "<html><body><pre style=\"font-family:monospace\">" + string.Join("\n", lines.Select(System.Net.WebUtility.HtmlEncode)) + "</pre></body></html>"
            : string.Join("\r\n", lines);
        return (subject, body, shortId);
    }
}
