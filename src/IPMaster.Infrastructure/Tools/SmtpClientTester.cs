using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using IPMaster.Core.Tools;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace IPMaster.Infrastructure.Tools;

/// <summary>What the tester window asks for. The password is only held for this run and never logged.</summary>
public sealed record SmtpTestRequest
{
    public required SmtpOperation Operation { get; init; }

    public required SmtpProfile Connection { get; init; }

    public string? Password { get; init; }

    public SmtpMessageTemplate Message { get; init; } = new();

    /// <summary>Generated record ToString() would print the password; it is redacted here (review S-07).</summary>
    private bool PrintMembers(System.Text.StringBuilder builder)
    {
        builder.Append(System.Globalization.CultureInfo.InvariantCulture, $"Operation = {Operation}, Connection = {Connection.Name}, Password = {(Password is null ? "(none)" : "(redacted)")}, SendToAcceptedOnly = {SendToAcceptedOnly}");
        return true;
    }

    /// <summary>Send: deliver to the accepted recipients when some are rejected (default: abort before DATA).</summary>
    public bool SendToAcceptedOnly { get; init; }
}

public interface ISmtpTester
{
    /// <summary>Runs one operation stage by stage. Never throws for network/protocol failures: they are stage results.</summary>
    Task<SmtpTestReport> RunAsync(SmtpTestRequest request, Action<SmtpLogEntry> log, CancellationToken cancellationToken);
}

/// <summary>Envelope and MIME message built from the window's fields (validation included).</summary>
public sealed record SmtpEnvelope(MailboxAddress Sender, IReadOnlyList<MailboxAddress> Recipients, MimeMessage? Message);

public static class SmtpMessages
{
    public const long MaxAttachmentBytes = 50L * 1024 * 1024;

    /// <summary>Parses "a@x, B &lt;b@y&gt;; c@z" (commas, semicolons or new lines). Errors name the bad entry.</summary>
    public static IReadOnlyList<MailboxAddress> ParseList(string? text, string field, List<string> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);
        var result = new List<MailboxAddress>();
        if (string.IsNullOrWhiteSpace(text)) return result;
        foreach (var part in text.Replace(';', ',').Replace('\n', ',').Replace('\r', ',').Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!MailboxAddress.TryParse(ParserOptions.Default, part, out var mb) || !IsAddress(mb.Address))
            {
                errors.Add($"{field}: '{part}' is not a valid e-mail address.");
                continue;
            }

            result.Add(mb);
        }

        return result;
    }

    private static bool IsAddress(string a)
    {
        var at = a.LastIndexOf('@');
        return at > 0 && at < a.Length - 1 && !a.Any(char.IsWhiteSpace) && a[(at + 1)..].Contains('.', StringComparison.Ordinal) || a.EndsWith("@localhost", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Envelope defaults: sender = From, recipients = To + Cc + Bcc; explicit envelope fields override them.</summary>
    /// <param name="createMessage">False validates only (sizes, existence) without reading attachments: the UI uses that, so
    /// files are never loaded on the UI thread; the MIME message is built once, on the worker, when sending.</param>
    public static SmtpEnvelope Build(SmtpMessageTemplate m, bool withMessage, out IReadOnlyList<string> errors, bool createMessage = true)
    {
        ArgumentNullException.ThrowIfNull(m);
        var e = new List<string>();
        var from = ParseList(m.From, "From", e);
        var to = ParseList(m.To, "To", e);
        var cc = ParseList(m.Cc, "Cc", e);
        var bcc = ParseList(m.Bcc, "Bcc", e);
        var envSender = ParseList(m.EnvelopeSender, "Envelope Sender", e);
        var envRcpts = ParseList(m.EnvelopeRecipients, "Envelope Recipients", e);
        if (envSender.Count > 1) e.Add("Envelope Sender: enter a single address.");
        if (from.Count > 1 && withMessage) e.Add("From: enter a single address.");
        var sender = envSender.FirstOrDefault() ?? from.FirstOrDefault();
        if (sender is null) e.Add("Enter an Envelope Sender or a From address.");
        // De-duplicated case-insensitively, exactly as MailKit does before sending RCPT: the per-recipient bookkeeping that
        // decides "abort before DATA" must count the same recipients the server is asked about (review S-01).
        var recipients = (envRcpts.Count > 0 ? envRcpts : to.Concat(cc).Concat(bcc)).DistinctBy(x => x.Address, StringComparer.OrdinalIgnoreCase).ToList();
        if (recipients.Count == 0) e.Add("Enter at least one recipient (To, Cc, Bcc or Envelope Recipients).");
        MimeMessage? message = null;
        if (withMessage)
        {
            if (from.Count == 0) e.Add("From is required to send a message.");
            if (to.Count + cc.Count == 0 && bcc.Count == 0 && envRcpts.Count == 0) e.Add("Enter at least one To, Cc or Bcc address.");
            long total = 0;
            foreach (var a in m.Attachments)
            {
                if (!File.Exists(a))
                {
                    e.Add($"Attachment not found: {a}");
                    continue;
                }

                total += new FileInfo(a).Length;
            }

            if (total > MaxAttachmentBytes) e.Add($"Attachments total {total / 1024 / 1024} MB; the limit is {MaxAttachmentBytes / 1024 / 1024} MB.");
            if (e.Count == 0 && createMessage)
            {
                message = new MimeMessage();
                message.From.AddRange(from);
                message.To.AddRange(to);
                message.Cc.AddRange(cc);
                // Bcc recipients are envelope-only: no Bcc header is ever written.
                message.Subject = m.Subject;
                message.Date = DateTimeOffset.Now;
                message.MessageId = MimeKit.Utils.MimeUtils.GenerateMessageId(sender!.Domain.Length > 0 ? sender.Domain : "ipmaster.invalid");
                var builder = new BodyBuilder();
                if (m.BodyFormat == SmtpBodyFormat.Html) builder.HtmlBody = m.Body;
                else builder.TextBody = m.Body;
                foreach (var a in m.Attachments) builder.Attachments.Add(a);
                message.Body = builder.ToMessageBody();
            }
        }

        errors = e;
        return new SmtpEnvelope(sender ?? new MailboxAddress("", "invalid@invalid"), recipients, message);
    }

    /// <summary>Things the user should know about the envelope that are not errors (review S-09).</summary>
    public static IReadOnlyList<string> EnvelopeNotes(SmtpMessageTemplate m)
    {
        ArgumentNullException.ThrowIfNull(m);
        var notes = new List<string>();
        if (m.EnvelopeRecipients.Trim().Length > 0 && m.Bcc.Trim().Length > 0)
        {
            notes.Add("Envelope Recipients is set, so the Bcc addresses receive nothing (Bcc is only used when the envelope recipients come from the message fields).");
        }

        return notes;
    }

    /// <summary>Local computer name with its DNS domain (default EHLO name).</summary>
    public static string DefaultEhloName()
    {
        try
        {
            var p = IPGlobalProperties.GetIPGlobalProperties();
            var host = string.IsNullOrEmpty(p.HostName) ? Environment.MachineName : p.HostName;
            return string.IsNullOrEmpty(p.DomainName) ? host : $"{host}.{p.DomainName}";
        }
        catch (NetworkInformationException)
        {
            return Environment.MachineName;
        }
    }
}

/// <summary>MailKit client with the hooks the tester needs: raw envelope commands and per-recipient decisions.</summary>
internal sealed class DiagnosticSmtpClient(IProtocolLogger logger) : SmtpClient(logger)
{
    public List<RecipientResult> RecipientResults { get; } = [];

    public int ExpectedRecipients { get; set; }

    public bool AbortOnRejection { get; set; } = true;

    public SmtpResponse? SenderResponse { get; private set; }

    public Task<SmtpResponse> CommandAsync(string command, CancellationToken ct) => SendCommandAsync(command, ct);

    protected override void OnSenderAccepted(MimeMessage message, MailboxAddress mailbox, SmtpResponse response)
    {
        SenderResponse = response;
        base.OnSenderAccepted(message, mailbox, response);
    }

    protected override void OnSenderNotAccepted(MimeMessage message, MailboxAddress mailbox, SmtpResponse response)
    {
        SenderResponse = response;
        base.OnSenderNotAccepted(message, mailbox, response);
    }

    protected override void OnRecipientAccepted(MimeMessage message, MailboxAddress mailbox, SmtpResponse response)
    {
        RecipientResults.Add(SmtpClientTester.Recipient(mailbox.Address, response));
        Check();
    }

    protected override void OnRecipientNotAccepted(MimeMessage message, MailboxAddress mailbox, SmtpResponse response)
    {
        // base would throw at the first rejection; collect every answer first
        RecipientResults.Add(SmtpClientTester.Recipient(mailbox.Address, response));
        Check();
    }

    private void Check()
    {
        if (RecipientResults.Count == ExpectedRecipients && AbortOnRejection && RecipientResults.Any(r => !r.Accepted) && RecipientResults.Any(r => r.Accepted))
        {
            throw new RecipientsRejectedException();
        }
    }
}

/// <summary>Raised before DATA when some recipients were rejected and the user did not choose to send to the others.</summary>
internal sealed class RecipientsRejectedException : Exception
{
    public RecipientsRejectedException()
        : base("Some recipients were rejected; submission aborted before DATA.")
    {
    }

    public RecipientsRejectedException(string message)
        : base(message)
    {
    }

    public RecipientsRejectedException(string message, Exception inner)
        : base(message, inner)
    {
    }
}

/// <summary>
/// Stage-by-stage SMTP diagnostics (D-068). DNS and TCP are done here so they are reported separately; the connected socket
/// is then handed to MailKit, which reads the greeting, sends EHLO, negotiates TLS (STARTTLS or implicit, never falling back)
/// and re-sends EHLO after STARTTLS. Pipelining and chunking are switched off for the session so every reply is attributable.
/// </summary>
public sealed class SmtpClientTester : ISmtpTester
{
    private sealed class Run(SmtpTestRequest request, SmtpSessionLogger log, CancellationToken user)
    {
        public SmtpTestRequest Request { get; } = request;

        public SmtpSessionLogger Log { get; } = log;

        public CancellationToken User { get; } = user;

        public Dictionary<SmtpStage, StageResult> Stages { get; } = Enum.GetValues<SmtpStage>().ToDictionary(s => s, s => new StageResult(s, StageOutcome.NotRun, null, "Not run"));

        public List<RecipientResult> Recipients { get; } = [];

        public X509Certificate2? Certificate { get; set; }

        public SslPolicyErrors CertificateErrors { get; set; }

        public List<string> ChainProblems { get; } = [];

        public string? FinalResponse { get; set; }

        public SmtpProfile C => Request.Connection;

        public void Set(SmtpStage s, StageOutcome o, TimeSpan? d, string summary, string? explanation = null, string? response = null)
        {
            Stages[s] = new StageResult(s, o, d, summary, explanation, response);
            var text = $"{SmtpText.StageName(s)}: {o}{(d is { } t ? $" in {t.TotalMilliseconds:0} ms" : "")} — {summary}";
            if (o == StageOutcome.Failed) Log.Error(text);
            else Log.Info(text);
            if (explanation is not null) Log.Info("  → " + explanation);
        }

        public void Skip(SmtpStage s, string why) => Stages[s] = new StageResult(s, StageOutcome.Skipped, null, why);
    }

    public async Task<SmtpTestReport> RunAsync(SmtpTestRequest request, Action<SmtpLogEntry> log, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(log);
        var logger = new SmtpSessionLogger(log);
        var run = new Run(request, logger, cancellationToken);
        var total = Stopwatch.StartNew();
        var c = request.Connection;
        logger.Info($"{request.Operation switch { SmtpOperation.Connection => "Test Connection", SmtpOperation.Recipients => "Test Recipient Acceptance", _ => "Send Test Email" }} — {c.Server}:{c.Port}, {c.Security}, " +
                    $"authentication {(c.AuthMode == SmtpAuthMode.None ? "none" : c.Mechanism)}, certificate validation {(c.ValidateCertificate ? "on" : "OFF (profile exception)")}");
        Socket? socket = null;
        DiagnosticSmtpClient? client = null;
        try
        {
            var addresses = await ResolveAsync(run).ConfigureAwait(false);
            if (addresses is null) return Report(run, total, logger);
            socket = await ConnectTcpAsync(run, addresses).ConfigureAwait(false);
            if (socket is null) return Report(run, total, logger);
            client = new DiagnosticSmtpClient(logger)
            {
                Timeout = Math.Clamp(c.OperationTimeoutSeconds, 1, 600) * 1000,
                LocalDomain = string.IsNullOrWhiteSpace(c.EhloName) ? SmtpMessages.DefaultEhloName() : c.EhloName.Trim(),
                CheckCertificateRevocation = c.ValidateCertificate,
                ServerCertificateValidationCallback = (_, cert, chain, errors) => OnCertificate(run, cert, chain, errors),
            };
            if (!await HandshakeAsync(run, client, socket).ConfigureAwait(false)) return Report(run, total, logger);
            socket = null; // owned by the client now
            if (!await AuthenticateAsync(run, client).ConfigureAwait(false)) return Report(run, total, logger);
            switch (request.Operation)
            {
                case SmtpOperation.Connection:
                    run.Skip(SmtpStage.Recipients, "Not part of Test Connection (no MAIL FROM / RCPT TO sent).");
                    run.Skip(SmtpStage.Submission, "Not part of Test Connection (no DATA sent).");
                    break;
                case SmtpOperation.Recipients:
                    await EnvelopeAsync(run, client).ConfigureAwait(false);
                    run.Skip(SmtpStage.Submission, "Envelope check only: RSET was sent instead of DATA.");
                    break;
                default:
                    await SubmitAsync(run, client).ConfigureAwait(false);
                    break;
            }

            await QuitAsync(client, logger).ConfigureAwait(false);
        }
        catch (Exception ex) when (cancellationToken.IsCancellationRequested && ex is not OutOfMemoryException)
        {
            // Any failure after the user pressed Cancel (OCE, or the I/O error of the aborted socket) is a cancellation.
            if (logger.DataCommandSent && request.Operation == SmtpOperation.Send)
            {
                run.Set(SmtpStage.Submission, StageOutcome.Cancelled, null, "Cancelled after DATA was sent.",
                    "The message content was already being transmitted. The server may or may not have accepted it: check the recipient mailbox or the server's logs before sending again.");
            }
            else
            {
                foreach (var s in run.Stages.Values.Where(s => s.Outcome == StageOutcome.NotRun).Take(1)) run.Set(s.Stage, StageOutcome.Cancelled, null, "Cancelled by the user.");
            }

            logger.Info("Cancelled; the connection was closed.");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Stage handlers catch the expected network/protocol errors; anything else must still end as a report, never
            // escape into the window's async-void handler (review S-02). Exception messages carry no credentials.
            var stage = run.Stages.Values.FirstOrDefault(s => s.Outcome == StageOutcome.NotRun)?.Stage ?? SmtpStage.Submission;
            run.Set(stage, StageOutcome.Failed, null, $"Unexpected error: {Inner(ex)}",
                "The test stopped on an error it does not classify. The session log shows the last command and reply.");
            logger.Error($"Unexpected {ex.GetType().Name}: {Inner(ex)}");
        }
        finally
        {
            client?.Dispose();
            run.Certificate?.Dispose();
            socket?.Dispose();
        }

        return Report(run, total, logger);
    }

    private static SmtpTestReport Report(Run run, Stopwatch total, SmtpSessionLogger logger)
    {
        total.Stop();
        logger.Info($"Total elapsed {total.Elapsed.TotalMilliseconds:0} ms. Server acceptance does not prove delivery to the recipient's inbox.");
        return new SmtpTestReport(run.Request.Operation, run.Stages.Values.OrderBy(s => s.Stage).ToList(), run.Recipients, total.Elapsed, run.FinalResponse,
            SmtpText.QueueId(run.FinalResponse), logger.DataCommandSent);
    }

    // ---------------- 1 DNS ----------------
    private static async Task<IPAddress[]?> ResolveAsync(Run run)
    {
        var host = run.C.Server.Trim().Trim('[', ']');
        if (IPAddress.TryParse(host, out var literal))
        {
            run.Set(SmtpStage.Dns, StageOutcome.Success, TimeSpan.Zero, $"{literal} is an IP address; no lookup needed.");
            return [literal];
        }

        var sw = Stopwatch.StartNew();
        using var cts = Linked(run, run.C.ConnectTimeoutSeconds);
        try
        {
            var all = await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            if (all.Length == 0)
            {
                run.Set(SmtpStage.Dns, StageOutcome.Failed, sw.Elapsed, $"{host} has no A/AAAA records.", "DNS failure: the name exists but has no address records. Check the host name (not the domain's MX name unless it has A/AAAA records).");
                return null;
            }

            run.Set(SmtpStage.Dns, StageOutcome.Success, sw.Elapsed, $"{host} → {string.Join(", ", all.Select(a => a.ToString()))}");
            return all;
        }
        catch (SocketException ex)
        {
            run.Set(SmtpStage.Dns, StageOutcome.Failed, sw.Elapsed, $"{host}: {ex.SocketErrorCode} ({ex.Message})",
                ex.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData
                    ? "DNS failure: the name does not resolve. Check spelling and the DNS servers of this computer (internal names may need the internal DNS or VPN)."
                    : "DNS failure: the resolver did not answer; check this computer's DNS configuration.");
            return null;
        }
        catch (OperationCanceledException) when (!run.User.IsCancellationRequested)
        {
            run.Set(SmtpStage.Dns, StageOutcome.Failed, sw.Elapsed, $"No answer within {run.C.ConnectTimeoutSeconds} s.", "DNS timeout: the DNS server did not answer in time.");
            return null;
        }
    }

    // ---------------- 2 TCP ----------------
    private static async Task<Socket?> ConnectTcpAsync(Run run, IPAddress[] addresses)
    {
        var sw = Stopwatch.StartNew();
        var errors = new List<string>();
        var anyTimeout = false;
        var anyRefused = false;
        foreach (var a in addresses)
        {
            var socket = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            using var cts = Linked(run, run.C.ConnectTimeoutSeconds);
            try
            {
                run.Log.Info($"Connecting to {Endpoint(a, run.C.Port)}…");
                await socket.ConnectAsync(new IPEndPoint(a, run.C.Port), cts.Token).ConfigureAwait(false);
                run.Set(SmtpStage.Tcp, StageOutcome.Success, sw.Elapsed, $"Connected to {Endpoint(a, run.C.Port)} from {socket.LocalEndPoint}.");
                return socket;
            }
            catch (SocketException ex)
            {
                socket.Dispose();
                anyRefused |= ex.SocketErrorCode == SocketError.ConnectionRefused;
                errors.Add($"{Endpoint(a, run.C.Port)}: {ex.SocketErrorCode}");
                run.Log.Error($"{Endpoint(a, run.C.Port)}: {ex.Message}");
            }
            catch (OperationCanceledException) when (!run.User.IsCancellationRequested)
            {
                socket.Dispose();
                anyTimeout = true;
                errors.Add($"{Endpoint(a, run.C.Port)}: no answer within {run.C.ConnectTimeoutSeconds} s");
                run.Log.Error(errors[^1]);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        run.Set(SmtpStage.Tcp, StageOutcome.Failed, sw.Elapsed, string.Join("; ", errors),
            anyRefused
                ? $"Connection refused: nothing listens on port {run.C.Port} at that address, or a firewall actively rejects it. Check the port (25, 587, 465) and the server's service."
                : anyTimeout
                    ? $"Connection timeout: no answer on port {run.C.Port}. A firewall may drop the traffic (many networks block outbound port 25), or the server is down."
                    : "The TCP connection failed (network unreachable or reset).");
        return null;
    }

    private static string Endpoint(IPAddress a, int port) => a.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{a}]:{port}" : $"{a}:{port}";

    // ---------------- 3 + 4 greeting, EHLO, TLS ----------------
    private static bool OnCertificate(Run run, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        run.CertificateErrors = errors;
        if (cert is not null)
        {
            run.Certificate?.Dispose();
            run.Certificate = new X509Certificate2(cert);
        }
        if (chain is not null)
        {
            foreach (var st in chain.ChainStatus.Where(s => s.Status != X509ChainStatusFlags.NoError))
            {
                run.ChainProblems.Add($"{st.Status}: {st.StatusInformation.Trim()}");
            }
        }

        return !run.C.ValidateCertificate || errors == SslPolicyErrors.None;
    }

    private static async Task<bool> HandshakeAsync(Run run, DiagnosticSmtpClient client, Socket socket)
    {
        var c = run.C;
        var host = c.Server.Trim().Trim('[', ']');
        var options = c.Security switch
        {
            SmtpConnectionSecurity.ImplicitTls => SecureSocketOptions.SslOnConnect,
            SmtpConnectionSecurity.StartTlsRequired => SecureSocketOptions.StartTls, // fails if STARTTLS is not offered
            _ => SecureSocketOptions.None,
        };
        var start = DateTimeOffset.UtcNow;
        using var cts = Linked(run, c.OperationTimeoutSeconds);
        try
        {
            await client.ConnectAsync(socket, host, c.Port, options, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !run.User.IsCancellationRequested)
        {
            HandshakeFailed(run, ex, start);
            return false;
        }

        var end = DateTimeOffset.UtcNow;
        var greetAt = run.Log.FirstServerAt ?? end;
        var caps = client.Capabilities;
        var extras = new List<string>();
        if (client.MaxSize > 0) extras.Add($"SIZE {client.MaxSize:N0} bytes");
        if (client.AuthenticationMechanisms.Count > 0) extras.Add("AUTH " + string.Join(" ", client.AuthenticationMechanisms));
        run.Log.Info($"Capabilities: {caps}{(extras.Count > 0 ? "; " + string.Join("; ", extras) : "")}");
        if (c.Security == SmtpConnectionSecurity.ImplicitTls)
        {
            run.Set(SmtpStage.Tls, TlsOutcome(run), greetAt - start, TlsSummary(client, run), TlsExplanation(run));
            run.Set(SmtpStage.Greeting, StageOutcome.Success, end - greetAt, $"Greeting and EHLO over TLS ({caps}).");
        }
        else if (c.Security == SmtpConnectionSecurity.StartTlsRequired)
        {
            run.Set(SmtpStage.Greeting, StageOutcome.Success, null, "Greeting received, EHLO answered, STARTTLS offered.");
            run.Set(SmtpStage.Tls, TlsOutcome(run), end - greetAt, TlsSummary(client, run) + " EHLO repeated after STARTTLS.", TlsExplanation(run));
        }
        else
        {
            run.Set(SmtpStage.Greeting, StageOutcome.Success, end - start, $"Greeting received and EHLO answered ({caps}).");
            run.Set(SmtpStage.Tls, StageOutcome.Skipped, null, caps.HasFlag(SmtpCapabilities.StartTLS)
                ? "Connection Security is None; the server offers STARTTLS but it was not used."
                : "Connection Security is None; the session is unencrypted.");
        }

        LogCertificate(run);
        // one reply per command: easier to attribute, and DATA is never pipelined behind a rejected RCPT
        client.Capabilities &= ~(SmtpCapabilities.Pipelining | SmtpCapabilities.Chunking | SmtpCapabilities.BinaryMime);
        return true;
    }

    private static StageOutcome TlsOutcome(Run run) => run.CertificateErrors == SslPolicyErrors.None ? StageOutcome.Success : StageOutcome.Warning;

    private static string TlsSummary(DiagnosticSmtpClient client, Run run)
    {
        var suite = client.SslCipherSuite is { } cs ? cs.ToString() : "cipher suite not reported by this platform";
        var cert = run.Certificate is { } x ? $" Certificate {x.GetNameInfo(X509NameType.SimpleName, false)}." : "";
        var warn = run.CertificateErrors == SslPolicyErrors.None ? "" : $" Certificate problems ignored by this profile: {run.CertificateErrors}.";
        return $"{client.SslProtocol}, {suite}.{cert}{warn}";
    }

    private static string? TlsExplanation(Run run) => run.CertificateErrors == SslPolicyErrors.None ? null : CertificateExplanation(run);

    /// <summary>Extra advice for chain problems that are not about trust (review S-09).</summary>
    internal static string ChainHint(IEnumerable<string> chainProblems)
    {
        var all = string.Join(" ", chainProblems);
        return all.Contains("Revocation", StringComparison.OrdinalIgnoreCase) || all.Contains("OfflineRevocation", StringComparison.OrdinalIgnoreCase)
            ? " Revocation could not be checked: this computer could not reach the CRL/OCSP addresses in the certificate (offline or isolated network, proxy, firewall). The certificate itself may be fine."
            : "";
    }

    private static string CertificateExplanation(Run run)
    {
        var parts = new List<string>();
        var host = run.C.Server.Trim().Trim('[', ']');
        if (run.CertificateErrors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            var names = Names(run.Certificate);
            parts.Add(IPAddress.TryParse(host, out _)
                ? $"Name mismatch: you connected by IP address ({host}), but the certificate is issued to {names}. Certificates rarely contain IP addresses: enter the server's host name instead (TLS validates and sends SNI for the name you enter)."
                : $"Name mismatch: the certificate is issued to {names}, not to {host}. Use a name the certificate covers, or fix the server certificate.");
        }

        if (run.CertificateErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors))
        {
            parts.Add("Chain problem: " + (run.ChainProblems.Count > 0 ? string.Join("; ", run.ChainProblems.Distinct()) : "the certificate chain could not be validated")
                      + ". Self-signed or internal-CA certificates need that CA trusted on this computer.");
            parts[^1] += ChainHint(run.ChainProblems);
        }

        if (run.CertificateErrors.HasFlag(SslPolicyErrors.RemoteCertificateNotAvailable)) parts.Add("The server presented no certificate.");
        return "Certificate validation failure: " + string.Join(" ", parts);
    }

    private static string Names(X509Certificate2? cert)
    {
        if (cert is null) return "(no certificate)";
        var dns = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateDnsNames()).ToList();
        var ips = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().SelectMany(e => e.EnumerateIPAddresses()).Select(i => i.ToString()).ToList();
        var all = dns.Concat(ips).ToList();
        return all.Count > 0 ? string.Join(", ", all) : cert.GetNameInfo(X509NameType.SimpleName, false);
    }

    private static void LogCertificate(Run run)
    {
        if (run.Certificate is not { } x) return;
        run.Log.Tls($"Subject: {x.Subject}");
        run.Log.Tls($"Issuer: {x.Issuer}");
        run.Log.Tls($"Valid: {x.NotBefore:yyyy-MM-dd HH:mm} – {x.NotAfter:yyyy-MM-dd HH:mm} (local time)");
        run.Log.Tls($"Names: {Names(x)}");
        run.Log.Tls($"SHA-256 thumbprint: {x.GetCertHashString(System.Security.Cryptography.HashAlgorithmName.SHA256)}");
        run.Log.Tls(run.CertificateErrors == SslPolicyErrors.None ? "Validation: OK" : $"Validation: {run.CertificateErrors}{(run.ChainProblems.Count > 0 ? " — " + string.Join("; ", run.ChainProblems.Distinct()) : "")}");
    }

    private static void HandshakeFailed(Run run, Exception ex, DateTimeOffset start)
    {
        var c = run.C;
        var elapsed = DateTimeOffset.UtcNow - start;
        var greeted = run.Log.FirstServerAt is not null;
        var reply = run.Log.LastServerReply;
        LogCertificate(run);
        switch (ex)
        {
            case SslHandshakeException when run.Certificate is not null && run.CertificateErrors != SslPolicyErrors.None && c.ValidateCertificate:
                if (c.Security == SmtpConnectionSecurity.StartTlsRequired) run.Set(SmtpStage.Greeting, StageOutcome.Success, null, "Greeting received, EHLO answered, STARTTLS offered.");
                run.Set(SmtpStage.Tls, StageOutcome.Failed, elapsed, $"Server certificate rejected ({run.CertificateErrors}).", CertificateExplanation(run));
                return;
            case SslHandshakeException or AuthenticationException when c.Security == SmtpConnectionSecurity.ImplicitTls:
                run.Set(SmtpStage.Tls, StageOutcome.Failed, elapsed, Inner(ex),
                    c.Port is 25 or 587
                        ? $"TLS mismatch: port {c.Port} normally starts in plaintext and upgrades with STARTTLS. Choose STARTTLS Required (or port 465 for implicit TLS)."
                        : "TLS negotiation failed: the server did not complete a TLS handshake (not a TLS port, no common protocol version/cipher, or the connection was reset).");
                return;
            case SslHandshakeException:
                run.Set(SmtpStage.Greeting, StageOutcome.Success, null, "Greeting received, EHLO answered, STARTTLS accepted.");
                run.Set(SmtpStage.Tls, StageOutcome.Failed, elapsed, Inner(ex), "TLS negotiation failed after STARTTLS (no common protocol version or cipher, or the server reset the connection).");
                return;
            case NotSupportedException when c.Security == SmtpConnectionSecurity.StartTlsRequired:
                run.Set(SmtpStage.Greeting, StageOutcome.Success, null, "Greeting received and EHLO answered.");
                run.Set(SmtpStage.Tls, StageOutcome.Failed, null, "The server does not offer STARTTLS.",
                    "STARTTLS unavailable: the server did not advertise STARTTLS, so the required encryption cannot be used. The tester does not fall back to plaintext. Check the port, or choose Implicit TLS for port 465.");
                return;
            case SmtpCommandException cmd when c.Security == SmtpConnectionSecurity.StartTlsRequired && run.Log.LastClientVerb == "STARTTLS":
                run.Set(SmtpStage.Greeting, StageOutcome.Success, null, "Greeting received, EHLO answered, STARTTLS offered.");
                run.Set(SmtpStage.Tls, StageOutcome.Failed, elapsed, $"{(int)cmd.StatusCode} {cmd.Message}",
                    "The server advertised STARTTLS but refused the STARTTLS command (TLS temporarily unavailable or misconfigured on the server). The tester does not continue without encryption.", reply);
                return;
            case SmtpCommandException cmd:
                run.Set(SmtpStage.Greeting, StageOutcome.Failed, elapsed, $"{(int)cmd.StatusCode} {cmd.Message}", SmtpText.ExplainReply(SmtpStage.Greeting, (int)cmd.StatusCode, cmd.Message), reply);
                return;
            case SmtpProtocolException when c.Security != SmtpConnectionSecurity.ImplicitTls && !greeted:
            case IOException when c.Security != SmtpConnectionSecurity.ImplicitTls && !greeted:
                run.Set(SmtpStage.Greeting, StageOutcome.Failed, elapsed, Inner(ex), "The server closed the connection without a greeting.");
                return;
            case SmtpProtocolException or IOException when c.Security != SmtpConnectionSecurity.ImplicitTls && greeted && run.Log.ReceivedBinary:
                run.Set(SmtpStage.Greeting, StageOutcome.Failed, elapsed, Inner(ex), "The server answered with binary data: this port probably expects implicit TLS (465). Choose Implicit TLS.");
                return;
        }

        if (IsTimeout(ex, run.User))
        {
            var stage = c.Security == SmtpConnectionSecurity.ImplicitTls && !greeted ? SmtpStage.Tls : SmtpStage.Greeting;
            run.Set(stage, StageOutcome.Failed, elapsed, $"No answer within {c.OperationTimeoutSeconds} s.",
                !greeted
                    ? c.Port == 465 && c.Security != SmtpConnectionSecurity.ImplicitTls
                        ? "Timeout waiting for the greeting: port 465 expects implicit TLS, so the server waits for a TLS handshake. Choose Implicit TLS."
                        : "Timeout waiting for the server greeting: the server accepted TCP but sent nothing (overloaded, tarpitting, or a TLS-only port)."
                    : "Timeout during EHLO/STARTTLS: the server stopped answering.");
            return;
        }

        run.Set(greeted ? SmtpStage.Greeting : SmtpStage.Tls, StageOutcome.Failed, elapsed, Inner(ex), null, reply);
    }


    // ---------------- 5 authentication ----------------
    private static async Task<bool> AuthenticateAsync(Run run, DiagnosticSmtpClient client)
    {
        var c = run.C;
        if (c.AuthMode == SmtpAuthMode.None)
        {
            run.Skip(SmtpStage.Authentication, "Authentication: None.");
            return true;
        }

        if (!client.IsEncrypted && !c.AllowPlaintextAuth)
        {
            run.Set(SmtpStage.Authentication, StageOutcome.Failed, null, "Not attempted: the connection is not encrypted.",
                "Credentials are never sent over an unencrypted connection unless the lab override is ticked. Use STARTTLS Required or Implicit TLS.");
            return false;
        }

        if (string.IsNullOrEmpty(c.UserName) || string.IsNullOrEmpty(run.Request.Password))
        {
            run.Set(SmtpStage.Authentication, StageOutcome.Failed, null, "User name or password missing.");
            return false;
        }

        // OAuth mechanisms need tokens, not passwords: never chosen automatically
        client.AuthenticationMechanisms.Remove("XOAUTH2");
        client.AuthenticationMechanisms.Remove("OAUTHBEARER");
        if (client.AuthenticationMechanisms.Count == 0)
        {
            run.Set(SmtpStage.Authentication, StageOutcome.Failed, null, "The server advertises no usable AUTH mechanism on this connection.",
                client.IsEncrypted ? "The server does not offer authentication here (submission may be IP-based, or AUTH is on another port)." : "Many servers only offer AUTH after STARTTLS.");
            return false;
        }

        if (!client.IsEncrypted) run.Log.Error("Lab override: sending credentials over an UNENCRYPTED connection.");
        var sw = Stopwatch.StartNew();
        using var cts = Linked(run, c.OperationTimeoutSeconds);
        var credential = new NetworkCredential(c.UserName, run.Request.Password);
        try
        {
            if (c.Mechanism is "Auto" or "")
            {
                await client.AuthenticateAsync(credential, cts.Token).ConfigureAwait(false);
            }
            else
            {
                if (!client.AuthenticationMechanisms.Contains(c.Mechanism))
                {
                    run.Set(SmtpStage.Authentication, StageOutcome.Failed, null, $"The server does not advertise {c.Mechanism}.",
                        $"Offered mechanisms: {string.Join(", ", client.AuthenticationMechanisms)}. Choose one of them or Auto.");
                    return false;
                }

                var sasl = SaslMechanism.Create(c.Mechanism, credential)
                           ?? throw new NotSupportedException($"{c.Mechanism} is not supported by the SMTP library.");
                await client.AuthenticateAsync(sasl, cts.Token).ConfigureAwait(false);
            }

            run.Set(SmtpStage.Authentication, StageOutcome.Success, sw.Elapsed, $"Authenticated as {c.UserName}.", null, run.Log.LastServerReply);
            return true;
        }
        catch (AuthenticationException ex)
        {
            var reply = run.Log.LastServerReply;
            run.Set(SmtpStage.Authentication, StageOutcome.Failed, sw.Elapsed, ex.Message, SmtpText.ExplainReply(SmtpStage.Authentication, run.Log.LastServerCode, reply) ?? "Authentication failed.", reply);
            return false;
        }
        catch (Exception ex) when (ex is SmtpCommandException or SmtpProtocolException or IOException or NotSupportedException or OperationCanceledException && !run.User.IsCancellationRequested)
        {
            var reply = run.Log.LastServerReply;
            run.Set(SmtpStage.Authentication, StageOutcome.Failed, sw.Elapsed, IsTimeout(ex, run.User) ? $"No answer within {c.OperationTimeoutSeconds} s." : Inner(ex),
                SmtpText.ExplainReply(SmtpStage.Authentication, run.Log.LastServerCode, reply), reply);
            return false;
        }
    }

    // ---------------- 6 envelope only ----------------
    private static async Task EnvelopeAsync(Run run, DiagnosticSmtpClient client)
    {
        var env = SmtpMessages.Build(run.Request.Message, withMessage: false, out var errors);
        if (errors.Count > 0)
        {
            run.Set(SmtpStage.Recipients, StageOutcome.Failed, null, string.Join(" ", errors));
            return;
        }

        var sw = Stopwatch.StartNew();
        using var cts = Linked(run, run.C.OperationTimeoutSeconds);
        try
        {
            var mail = await client.CommandAsync($"MAIL FROM:<{env.Sender.Address}>", cts.Token).ConfigureAwait(false);
            if ((int)mail.StatusCode >= 400)
            {
                run.Set(SmtpStage.Recipients, StageOutcome.Failed, sw.Elapsed, $"Sender {env.Sender.Address} rejected: {(int)mail.StatusCode} {mail.Response}",
                    SmtpText.ExplainSender((int)mail.StatusCode, mail.Response), $"{(int)mail.StatusCode} {mail.Response}");
                await client.CommandAsync("RSET", cts.Token).ConfigureAwait(false);
                return;
            }

            foreach (var r in env.Recipients)
            {
                var resp = await client.CommandAsync($"RCPT TO:<{r.Address}>", cts.Token).ConfigureAwait(false);
                run.Recipients.Add(Recipient(r.Address, resp));
            }

            await client.CommandAsync("RSET", cts.Token).ConfigureAwait(false);
            run.Log.Info("RSET sent: envelope check finished without DATA.");
            var accepted = run.Recipients.Count(x => x.Accepted);
            var outcome = accepted == run.Recipients.Count ? StageOutcome.Success : StageOutcome.Failed;
            var rejected = run.Recipients.FirstOrDefault(x => !x.Accepted);
            run.Set(SmtpStage.Recipients, outcome, sw.Elapsed, $"Sender accepted; {accepted} of {run.Recipients.Count} recipient(s) accepted. Envelope acceptance does not guarantee relay authorisation or delivery.",
                rejected?.Explanation, rejected?.Response);
        }
        catch (Exception ex) when (ex is SmtpCommandException or SmtpProtocolException or IOException or OperationCanceledException && !run.User.IsCancellationRequested)
        {
            run.Set(SmtpStage.Recipients, StageOutcome.Failed, sw.Elapsed, IsTimeout(ex, run.User) ? $"No answer within {run.C.OperationTimeoutSeconds} s." : Inner(ex), null, run.Log.LastServerReply);
        }
    }

    internal static RecipientResult Recipient(string address, SmtpResponse r)
    {
        var code = (int)r.StatusCode;
        var accepted = code is >= 250 and < 260;
        return new RecipientResult(address, accepted, code, SmtpText.EnhancedCode(r.Response), $"{code} {r.Response}", accepted ? null : SmtpText.ExplainReply(SmtpStage.Recipients, code, r.Response));
    }

    // ---------------- 7 submission ----------------
    private static async Task SubmitAsync(Run run, DiagnosticSmtpClient client)
    {
        var env = SmtpMessages.Build(run.Request.Message, withMessage: true, out var errors);
        if (errors.Count > 0 || env.Message is null)
        {
            run.Set(SmtpStage.Submission, StageOutcome.Failed, null, string.Join(" ", errors));
            return;
        }

        using var m = env.Message!;
        run.Log.Info($"Message: subject \"{m.Subject}\", {(run.Request.Message.BodyFormat == SmtpBodyFormat.Html ? "HTML" : "plain text")} body of {run.Request.Message.Body.Length:N0} characters, "
                     + $"{m.Attachments.Count()} attachment(s){(m.Attachments.Any() ? ": " + string.Join(", ", m.Attachments.OfType<MimePart>().Select(a => a.FileName)) : "")}; envelope {env.Sender.Address} → {string.Join(", ", env.Recipients.Select(r => r.Address))}. Content is not logged.");
        client.ExpectedRecipients = env.Recipients.Count;
        client.AbortOnRejection = !run.Request.SendToAcceptedOnly;
        var sw = Stopwatch.StartNew();
        // Whole-transaction deadline grows with the upload (base64 ≈ 4/3; budget 32 KB/s); a stalled link is still caught
        // by client.Timeout (per I/O), so a large attachment on a slow uplink is not reported as a timeout (review S-03).
        var uploadBytes = run.Request.Message.Attachments.Where(File.Exists).Sum(a => new FileInfo(a).Length) * 4 / 3 + run.Request.Message.Body.Length;
        using var cts = Linked(run, (int)Math.Min(3600, Math.Max(run.C.OperationTimeoutSeconds, 60) + uploadBytes / 32_768));
        try
        {
            var response = await client.SendAsync(m, env.Sender, env.Recipients, cts.Token).ConfigureAwait(false);
            run.Recipients.AddRange(client.RecipientResults);
            run.FinalResponse = response;
            var acc = client.RecipientResults.Count(r => r.Accepted);
            run.Set(SmtpStage.Recipients, acc == env.Recipients.Count ? StageOutcome.Success : StageOutcome.Warning, null,
                $"Sender accepted; {acc} of {env.Recipients.Count} recipient(s) accepted.", client.RecipientResults.FirstOrDefault(r => !r.Accepted)?.Explanation);
            var queue = SmtpText.QueueId(response);
            run.Set(SmtpStage.Submission, StageOutcome.Success, sw.Elapsed, $"Accepted by the server: {response}{(queue is null ? "" : $" (queue id {queue})")}. This does not prove delivery to the inbox.", null, response);
        }
        catch (RecipientsRejectedException)
        {
            run.Recipients.AddRange(client.RecipientResults);
            var rej = client.RecipientResults.First(r => !r.Accepted);
            run.Set(SmtpStage.Recipients, StageOutcome.Failed, null,
                $"{client.RecipientResults.Count(r => !r.Accepted)} of {env.Recipients.Count} recipient(s) rejected.", rej.Explanation, rej.Response);
            run.Set(SmtpStage.Submission, StageOutcome.Failed, sw.Elapsed, "Aborted before DATA because a recipient was rejected; nothing was submitted.",
                "Choose \"send to the accepted recipients\" in the confirmation to submit anyway.");
            await TryResetAsync(client, run.Log).ConfigureAwait(false);
        }
        catch (SmtpCommandException ex)
        {
            run.Recipients.AddRange(client.RecipientResults);
            var code = (int)ex.StatusCode;
            var text = $"{code} {ex.Message}";
            switch (ex.ErrorCode)
            {
                case SmtpErrorCode.SenderNotAccepted:
                    run.Set(SmtpStage.Recipients, StageOutcome.Failed, null, $"Sender {env.Sender.Address} rejected: {text}", SmtpText.ExplainSender(code, ex.Message), text);
                    run.Set(SmtpStage.Submission, StageOutcome.Failed, sw.Elapsed, "Not submitted (sender rejected).");
                    break;
                case SmtpErrorCode.RecipientNotAccepted:
                    run.Set(SmtpStage.Recipients, StageOutcome.Failed, null, "No recipient was accepted.", client.RecipientResults.FirstOrDefault()?.Explanation ?? SmtpText.ExplainReply(SmtpStage.Recipients, code, ex.Message), text);
                    run.Set(SmtpStage.Submission, StageOutcome.Failed, sw.Elapsed, "Not submitted (no recipients).");
                    break;
                default:
                    run.Set(SmtpStage.Recipients, client.RecipientResults.Count > 0 ? StageOutcome.Success : StageOutcome.NotRun, null, $"{client.RecipientResults.Count(r => r.Accepted)} recipient(s) accepted.");
                    run.Set(SmtpStage.Submission, StageOutcome.Failed, sw.Elapsed, $"Message refused: {text}", SmtpText.ExplainReply(SmtpStage.Submission, code, ex.Message), text);
                    break;
            }

            await TryResetAsync(client, run.Log).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SmtpProtocolException or IOException or OperationCanceledException && !run.User.IsCancellationRequested)
        {
            run.Recipients.AddRange(client.RecipientResults);
            run.Set(SmtpStage.Submission, StageOutcome.Failed, sw.Elapsed, IsTimeout(ex, run.User) ? "No answer in time during submission." : Inner(ex),
                run.Log.DataCommandSent ? "The connection failed after DATA started: the server may or may not have accepted the message. Check the server log." : null, run.Log.LastServerReply);
        }
    }

    private static async Task TryResetAsync(DiagnosticSmtpClient client, SmtpSessionLogger log)
    {
        if (!client.IsConnected)
        {
            log.Info("The connection was closed after the abort (no RSET possible); DATA was not sent.");
            return;
        }
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.CommandAsync("RSET", cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SmtpCommandException or SmtpProtocolException or IOException or OperationCanceledException or InvalidOperationException)
        {
            log.Info("RSET not possible: " + ex.Message);
        }
    }

    private static async Task QuitAsync(DiagnosticSmtpClient client, SmtpSessionLogger log)
    {
        if (!client.IsConnected) return;
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await client.DisconnectAsync(true, cts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SmtpCommandException or SmtpProtocolException or IOException or OperationCanceledException)
        {
            log.Info("QUIT not acknowledged: " + ex.Message);
        }
    }

    // ---------------- helpers ----------------
    private static CancellationTokenSource Linked(Run run, int seconds)
    {
        var cts = CancellationTokenSource.CreateLinkedTokenSource(run.User);
        cts.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(seconds, 1, 3600)));
        return cts;
    }

    private static bool IsTimeout(Exception ex, CancellationToken user) => !user.IsCancellationRequested && (ex is TimeoutException or OperationCanceledException
        || ex.InnerException is TimeoutException || ex.InnerException is SocketException { SocketErrorCode: SocketError.TimedOut }
        || ex is IOException io && io.Message.Contains("timed out", StringComparison.OrdinalIgnoreCase));

    private static string Inner(Exception ex)
    {
        var msg = ex.Message;
        for (var e = ex.InnerException; e is not null; e = e.InnerException)
        {
            if (!msg.Contains(e.Message, StringComparison.Ordinal)) msg += " — " + e.Message;
        }

        return msg;
    }
}
