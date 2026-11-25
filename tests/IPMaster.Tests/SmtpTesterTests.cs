using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Scripted local SMTP server for the tester tests (loopback only; never relays anything).</summary>
internal sealed class SmtpFixture : IAsyncDisposable
{
    public enum Kind
    {
        Plain,
        StartTls,
        ImplicitTls,
    }

    private static readonly Lazy<X509Certificate2> LazyCert = new(CreateCertificate);
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public SmtpFixture(Kind kind = Kind.Plain)
    {
        Mode = kind;
        _listener.Start();
        _loop = Task.Run(AcceptLoopAsync);
    }

    public Kind Mode { get; }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    public string User { get; init; } = "alice";

    public string Password { get; init; } = "S3cret-Pa55!";

    public HashSet<string> RejectRecipients { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool RejectSender { get; init; }

    public bool Silent { get; init; }

    /// <summary>Also advertise and serve AUTH CRAM-MD5.</summary>
    public bool OfferCramMd5 { get; init; }

    /// <summary>STARTTLS is advertised but refused with 454.</summary>
    public bool RefuseStartTls { get; init; }

    /// <summary>MAIL FROM gets 421 and the connection is closed.</summary>
    public bool Reply421OnMail { get; init; }

    /// <summary>AUTH never gets an answer.</summary>
    public bool StallAuth { get; init; }

    /// <summary>With RejectSender: the connection is closed right after the 553, so the following RSET fails.</summary>
    public bool CloseAfterSenderReject { get; init; }

    public ConcurrentQueue<string> Commands { get; } = new();

    public string? Data { get; private set; }

    public bool DataSeen => Commands.Any(c => c.Equals("DATA", StringComparison.OrdinalIgnoreCase));

    public static X509Certificate2 Certificate => LazyCert.Value;

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=smtp.fixture.test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("smtp.fixture.test");
        req.CertificateExtensions.Add(san.Build());
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12), null);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient c;
            try
            {
                c = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = Task.Run(() => HandleAsync(c));
        }
    }

    private async Task HandleAsync(TcpClient tcp)
    {
        using var _ = tcp;
        Stream s = tcp.GetStream();
        var tls = false;
        try
        {
            if (Mode == Kind.ImplicitTls)
            {
                var ssl = new SslStream(s);
                await ssl.AuthenticateAsServerAsync(Certificate);
                s = ssl;
                tls = true;
            }

            if (Silent)
            {
                await Task.Delay(Timeout.Infinite, _cts.Token);
                return;
            }

            await WriteAsync(s, "220 fixture.test ESMTP ready");
            while (true)
            {
                var line = await ReadLineAsync(s);
                if (line is null) return;
                Commands.Enqueue(line);
                var verb = line.Split(' ', 2)[0].ToUpperInvariant();
                switch (verb)
                {
                    case "EHLO":
                        var caps = new List<string> { "fixture.test greets you", "SIZE 1000000", "PIPELINING", "8BITMIME" };
                        if (Mode == Kind.StartTls && !tls) caps.Add("STARTTLS");
                        if (tls || Mode == Kind.Plain) caps.Add(OfferCramMd5 ? "AUTH PLAIN LOGIN CRAM-MD5" : "AUTH PLAIN LOGIN");
                        await WriteAsync(s, string.Join("\r\n", caps.Select((c, i) => (i == caps.Count - 1 ? "250 " : "250-") + c)));
                        break;
                    case "STARTTLS" when RefuseStartTls:
                        await WriteAsync(s, "454 4.7.0 TLS not available due to local problem");
                        break;
                    case "STARTTLS" when Mode == Kind.StartTls && !tls:
                        await WriteAsync(s, "220 2.0.0 Ready to start TLS");
                        var ssl = new SslStream(s);
                        await ssl.AuthenticateAsServerAsync(Certificate);
                        s = ssl;
                        tls = true;
                        break;
                    case "AUTH":
                        if (StallAuth)
                        {
                            await Task.Delay(Timeout.Infinite, _cts.Token);
                            return;
                        }

                        await AuthAsync(s, line);
                        break;
                    case "MAIL":
                        if (Reply421OnMail)
                        {
                            await WriteAsync(s, "421 4.3.2 Service shutting down, closing transmission channel");
                            return;
                        }

                        await WriteAsync(s, RejectSender ? "553 5.7.1 Sender address rejected: not owned by user" : "250 2.1.0 Ok");
                        if (RejectSender && CloseAfterSenderReject) return;
                        break;
                    case "RCPT":
                        var addr = line[(line.IndexOf('<', StringComparison.Ordinal) + 1)..line.IndexOf('>', StringComparison.Ordinal)];
                        await WriteAsync(s, RejectRecipients.Contains(addr) ? "550 5.7.1 <" + addr + ">: Relay access denied" : "250 2.1.5 Ok");
                        break;
                    case "DATA":
                        await WriteAsync(s, "354 End data with <CR><LF>.<CR><LF>");
                        var sb = new StringBuilder();
                        while (await ReadLineAsync(s) is { } d && d != ".") sb.Append(d).Append("\r\n");
                        Data = sb.ToString();
                        await WriteAsync(s, "250 2.0.0 Ok: queued as FIX123ABC");
                        break;
                    case "RSET":
                    case "NOOP":
                        await WriteAsync(s, "250 2.0.0 Ok");
                        break;
                    case "QUIT":
                        await WriteAsync(s, "221 2.0.0 Bye");
                        return;
                    default:
                        await WriteAsync(s, "502 5.5.2 Error: command not recognized");
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or OperationCanceledException or ObjectDisposedException)
        {
            // client went away or failed TLS
        }
    }

    private async Task AuthAsync(Stream s, string line)
    {
        var parts = line.Split(' ');
        string user, pass;
        if (parts[1].Equals("CRAM-MD5", StringComparison.OrdinalIgnoreCase))
        {
            var challenge = $"<{Environment.TickCount64}.fixture@fixture.test>";
            await WriteAsync(s, "334 " + Convert.ToBase64String(Encoding.ASCII.GetBytes(challenge)));
            var response = await ReadLineAsync(s) ?? "";
            Commands.Enqueue(response);
            var decoded = Encoding.ASCII.GetString(Convert.FromBase64String(response)).Split(' ');
#pragma warning disable CA5351 // CRAM-MD5 is defined on HMAC-MD5; test-only server side of the protocol
            var expected = Convert.ToHexStringLower(HMACMD5.HashData(Encoding.UTF8.GetBytes(Password), Encoding.ASCII.GetBytes(challenge)));
#pragma warning restore CA5351
            await WriteAsync(s, decoded[0] == User && decoded[1] == expected ? "235 2.7.0 Authentication successful" : "535 5.7.8 Error: authentication failed");
            return;
        }

        if (parts[1].Equals("PLAIN", StringComparison.OrdinalIgnoreCase))
        {
            var payload = parts.Length > 2 ? parts[2] : null;
            if (payload is null)
            {
                await WriteAsync(s, "334 ");
                payload = await ReadLineAsync(s) ?? "";
                Commands.Enqueue(payload);
            }

            var f = Encoding.UTF8.GetString(Convert.FromBase64String(payload)).Split('\0');
            (user, pass) = (f[1], f[2]);
        }
        else
        {
            await WriteAsync(s, "334 VXNlcm5hbWU6");
            var u = await ReadLineAsync(s) ?? "";
            Commands.Enqueue(u);
            await WriteAsync(s, "334 UGFzc3dvcmQ6");
            var p = await ReadLineAsync(s) ?? "";
            Commands.Enqueue(p);
            (user, pass) = (Encoding.UTF8.GetString(Convert.FromBase64String(u)), Encoding.UTF8.GetString(Convert.FromBase64String(p)));
        }

        await WriteAsync(s, user == User && pass == Password ? "235 2.7.0 Authentication successful" : "535 5.7.8 Error: authentication failed: authentication failure");
    }

    private static async Task WriteAsync(Stream s, string text)
    {
        var b = Encoding.ASCII.GetBytes(text + "\r\n");
        await s.WriteAsync(b);
        await s.FlushAsync();
    }

    private static async Task<string?> ReadLineAsync(Stream s)
    {
        var sb = new StringBuilder();
        var one = new byte[1];
        while (true)
        {
            var n = await s.ReadAsync(one);
            if (n == 0) return sb.Length > 0 ? sb.ToString() : null;
            if (one[0] == '\n') return sb.ToString().TrimEnd('\r');
            sb.Append((char)one[0]);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _listener.Stop();
        try
        {
            await _loop;
        }
        catch (OperationCanceledException)
        {
        }

        _cts.Dispose();
    }
}

public class SmtpTesterTests
{
    private static readonly SmtpClientTester Tester = new();

    private static SmtpProfile Conn(SmtpFixture f, SmtpConnectionSecurity security, bool validate = false, SmtpAuthMode auth = SmtpAuthMode.None, string mechanism = "Auto") => new()
    {
        Server = "127.0.0.1",
        Port = f.Port,
        Security = security,
        ConnectTimeoutSeconds = 5,
        OperationTimeoutSeconds = 10,
        EhloName = "tester.lab",
        ValidateCertificate = validate,
        AuthMode = auth,
        UserName = f.User,
        Mechanism = mechanism,
    };

    private static readonly SmtpMessageTemplate Msg = new()
    {
        From = "IPMaster Test <sender@lab.test>",
        To = "a@lab.test",
        Cc = "c@lab.test",
        Bcc = "hidden@lab.test",
        Subject = "Diag",
        Body = "Body line\r\n.leading dot line",
    };

    private static async Task<(SmtpTestReport Report, List<SmtpLogEntry> Log)> RunAsync(SmtpTestRequest r, CancellationToken ct = default)
    {
        var log = new List<SmtpLogEntry>();
        var report = await Tester.RunAsync(r, e =>
        {
            lock (log) log.Add(e);
        }, ct);
        return (report, log);
    }

    private static StageOutcome O(SmtpTestReport r, SmtpStage s) => r.Stages.Single(x => x.Stage == s).Outcome;

    private static StageResult S(SmtpTestReport r, SmtpStage s) => r.Stages.Single(x => x.Stage == s);

    [Fact]
    public async Task Plaintext_connection_test_sends_no_envelope_or_data()
    {
        await using var f = new SmtpFixture();
        var (r, log) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.None) });
        Assert.Equal(StageOutcome.Success, O(r, SmtpStage.Dns));
        Assert.Equal(StageOutcome.Success, O(r, SmtpStage.Tcp));
        Assert.Equal(StageOutcome.Success, O(r, SmtpStage.Greeting));
        Assert.Equal(StageOutcome.Skipped, O(r, SmtpStage.Tls));
        Assert.Equal(StageOutcome.Skipped, O(r, SmtpStage.Recipients));
        Assert.Equal(StageOutcome.Skipped, O(r, SmtpStage.Submission));
        Assert.Contains("EHLO tester.lab", f.Commands);
        Assert.DoesNotContain(f.Commands, c => c.StartsWith("MAIL", StringComparison.Ordinal) || c.StartsWith("RCPT", StringComparison.Ordinal) || c == "DATA");
        Assert.False(r.DataSent);
        Assert.Contains(log, e => e.Kind == SmtpLogKind.Server && e.Text.StartsWith("250-SIZE", StringComparison.Ordinal)); // multiline EHLO kept
        Assert.True(r.Succeeded);
    }

    [Fact]
    public async Task Required_starttls_negotiates_and_repeats_ehlo()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls);
        var (r, log) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.StartTlsRequired) });
        Assert.Equal(StageOutcome.Success, O(r, SmtpStage.Greeting));
        Assert.Equal(StageOutcome.Warning, O(r, SmtpStage.Tls)); // self-signed, accepted only because the profile says so
        Assert.Equal(2, f.Commands.Count(c => c.StartsWith("EHLO", StringComparison.Ordinal)));
        Assert.Contains("STARTTLS", f.Commands);
        Assert.Contains(log, e => e.Kind == SmtpLogKind.Tls && e.Text.StartsWith("Subject: CN=smtp.fixture.test", StringComparison.Ordinal));
        Assert.Contains(log, e => e.Kind == SmtpLogKind.Tls && e.Text.StartsWith("Valid:", StringComparison.Ordinal));
        Assert.Contains("Tls", S(r, SmtpStage.Tls).Summary, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Required_starttls_never_falls_back_to_plaintext()
    {
        await using var f = new SmtpFixture(); // plain server: no STARTTLS offered
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Recipients, Connection = Conn(f, SmtpConnectionSecurity.StartTlsRequired), Message = Msg });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Tls));
        Assert.Contains("STARTTLS unavailable", S(r, SmtpStage.Tls).Explanation, StringComparison.Ordinal);
        Assert.Equal(StageOutcome.NotRun, O(r, SmtpStage.Recipients));
        Assert.DoesNotContain(f.Commands, c => c.StartsWith("MAIL", StringComparison.Ordinal) || c.StartsWith("AUTH", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Implicit_tls_connects()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.ImplicitTls);
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.ImplicitTls) });
        Assert.Equal(StageOutcome.Warning, O(r, SmtpStage.Tls));
        Assert.Equal(StageOutcome.Success, O(r, SmtpStage.Greeting));
        Assert.Single(f.Commands, c => c.StartsWith("EHLO", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Certificate_validation_failure_is_explained_including_ip_name_mismatch()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.ImplicitTls);
        var (r, log) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.ImplicitTls, validate: true) });
        var tls = S(r, SmtpStage.Tls);
        Assert.Equal(StageOutcome.Failed, tls.Outcome);
        Assert.Contains("Certificate validation failure", tls.Explanation, StringComparison.Ordinal);
        Assert.Contains("connected by IP address (127.0.0.1)", tls.Explanation, StringComparison.Ordinal);
        Assert.Contains("smtp.fixture.test", tls.Explanation, StringComparison.Ordinal);
        Assert.Contains(log, e => e.Kind == SmtpLogKind.Tls && e.Text.StartsWith("Issuer:", StringComparison.Ordinal));
        Assert.Empty(f.Commands); // nothing sent over a rejected TLS session
    }

    [Fact]
    public async Task Implicit_tls_against_a_starttls_port_is_a_tls_mismatch()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls);
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.ImplicitTls) with { OperationTimeoutSeconds = 3 } });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Tls));
    }

    [Fact]
    public async Task Password_is_not_sent_over_plaintext_without_the_lab_override()
    {
        await using var f = new SmtpFixture();
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.None, auth: SmtpAuthMode.UsernamePassword), Password = f.Password });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Authentication));
        Assert.DoesNotContain(f.Commands, c => c.StartsWith("AUTH", StringComparison.Ordinal));

        var (r2, log2) = await RunAsync(new SmtpTestRequest
        {
            Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.None, auth: SmtpAuthMode.UsernamePassword) with { AllowPlaintextAuth = true }, Password = f.Password,
        });
        Assert.Equal(StageOutcome.Success, O(r2, SmtpStage.Authentication));
        Assert.Contains(log2, e => e.Kind == SmtpLogKind.Error && e.Text.Contains("UNENCRYPTED", StringComparison.Ordinal));
        AssertNoSecrets(log2, f);
    }

    [Theory]
    [InlineData("Auto")]
    [InlineData("PLAIN")]
    [InlineData("LOGIN")]
    public async Task Authentication_success_and_failure_never_log_secrets(string mechanism)
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls);
        var conn = Conn(f, SmtpConnectionSecurity.StartTlsRequired, auth: SmtpAuthMode.UsernamePassword, mechanism: mechanism);
        var (ok, okLog) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = conn, Password = f.Password });
        Assert.Equal(StageOutcome.Success, O(ok, SmtpStage.Authentication));
        AssertNoSecrets(okLog, f);

        var (bad, badLog) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = conn, Password = "wrong-password-123" });
        var a = S(bad, SmtpStage.Authentication);
        Assert.Equal(StageOutcome.Failed, a.Outcome);
        Assert.Contains("Authentication failed", a.Explanation, StringComparison.Ordinal);
        Assert.Contains("535", a.ServerResponse, StringComparison.Ordinal);
        Assert.DoesNotContain(badLog, e => e.Text.Contains("wrong-password-123", StringComparison.Ordinal) || e.Text.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes("wrong-password-123")), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Unsupported_explicit_mechanism_is_reported_not_attempted()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls);
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.StartTlsRequired, auth: SmtpAuthMode.UsernamePassword, mechanism: "CRAM-MD5"), Password = f.Password });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Authentication));
        Assert.Contains("does not advertise CRAM-MD5", S(r, SmtpStage.Authentication).Summary, StringComparison.Ordinal);
    }

    private static void AssertNoSecrets(List<SmtpLogEntry> log, SmtpFixture f)
    {
        var all = string.Join("\n", log.Select(e => e.Format()));
        Assert.DoesNotContain(f.Password, all, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(f.Password)), all, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes($"\0{f.User}\0{f.Password}")), all, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes(f.User)), all, StringComparison.Ordinal); // LOGIN user name payload is AUTH data too
    }

    [Fact]
    public async Task Recipient_test_reports_each_recipient_then_resets_without_data()
    {
        await using var f = new SmtpFixture();
        f.RejectRecipients.Add("c@lab.test");
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Recipients, Connection = Conn(f, SmtpConnectionSecurity.None), Message = Msg });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Recipients));
        Assert.Equal(StageOutcome.Skipped, O(r, SmtpStage.Submission));
        Assert.Equal(3, r.Recipients.Count); // To + Cc + Bcc
        var rej = Assert.Single(r.Recipients, x => !x.Accepted);
        Assert.Equal("c@lab.test", rej.Address);
        Assert.Equal(550, rej.Code);
        Assert.Equal("5.7.1", rej.EnhancedCode);
        Assert.Contains("Relay denied", rej.Explanation, StringComparison.Ordinal);
        Assert.Contains("MAIL FROM:<sender@lab.test>", f.Commands);
        Assert.Contains("RSET", f.Commands);
        Assert.False(f.DataSeen);
        Assert.False(r.DataSent);
    }

    [Fact]
    public async Task Rejected_sender_is_explained()
    {
        await using var f = new SmtpFixture { RejectSender = true };
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Recipients, Connection = Conn(f, SmtpConnectionSecurity.None), Message = Msg });
        Assert.Contains("Sender rejected", S(r, SmtpStage.Recipients).Explanation, StringComparison.Ordinal);
        Assert.DoesNotContain(f.Commands, c => c.StartsWith("RCPT", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Send_aborts_before_data_when_a_recipient_is_rejected()
    {
        await using var f = new SmtpFixture();
        f.RejectRecipients.Add("c@lab.test");
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Send, Connection = Conn(f, SmtpConnectionSecurity.None), Message = Msg });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Submission));
        Assert.Equal(3, r.Recipients.Count);
        Assert.False(f.DataSeen);
        Assert.Null(f.Data);
        Assert.False(r.DataSent);
    }

    [Fact]
    public async Task Send_to_accepted_recipients_when_chosen()
    {
        await using var f = new SmtpFixture();
        f.RejectRecipients.Add("c@lab.test");
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Send, Connection = Conn(f, SmtpConnectionSecurity.None), Message = Msg, SendToAcceptedOnly = true });
        Assert.Equal(StageOutcome.Success, O(r, SmtpStage.Submission));
        Assert.Equal(StageOutcome.Warning, O(r, SmtpStage.Recipients));
        Assert.Equal("FIX123ABC", r.QueueId);
        Assert.NotNull(f.Data);
    }

    [Fact]
    public async Task Submission_succeeds_bcc_is_envelope_only_and_content_is_not_logged()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls);
        var (r, log) = await RunAsync(new SmtpTestRequest
        {
            Operation = SmtpOperation.Send, Connection = Conn(f, SmtpConnectionSecurity.StartTlsRequired, auth: SmtpAuthMode.UsernamePassword), Password = f.Password, Message = Msg,
        });
        Assert.True(r.Succeeded, string.Join("; ", r.Stages.Select(s => $"{s.Stage}:{s.Outcome}:{s.Summary}")));
        Assert.Equal("FIX123ABC", r.QueueId);
        Assert.Contains("queued as FIX123ABC", r.FinalResponse, StringComparison.Ordinal);
        Assert.Contains("RCPT TO:<hidden@lab.test>", f.Commands);
        var data = f.Data!;
        var headers = data[..data.IndexOf("\r\n\r\n", StringComparison.Ordinal)];
        Assert.DoesNotContain("Bcc", headers, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hidden@lab.test", data, StringComparison.Ordinal);
        Assert.Contains("To: a@lab.test", headers, StringComparison.Ordinal);
        Assert.Contains("..leading dot line", data, StringComparison.Ordinal); // dot-stuffing on the wire
        var text = string.Join("\n", log.Select(e => e.Text));
        Assert.DoesNotContain("Body line", text, StringComparison.Ordinal);
        Assert.Contains(log, e => e.Text.StartsWith("[message content:", StringComparison.Ordinal));
        AssertNoSecrets(log, f);
    }

    [Fact]
    public async Task Silent_server_times_out_with_an_explanation()
    {
        await using var f = new SmtpFixture { Silent = true };
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.None) with { OperationTimeoutSeconds = 2 } });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Greeting));
        Assert.Contains("Timeout", S(r, SmtpStage.Greeting).Explanation, StringComparison.Ordinal);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15));
    }

    [Fact]
    public async Task Cancellation_stops_promptly()
    {
        await using var f = new SmtpFixture { Silent = true };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = Conn(f, SmtpConnectionSecurity.None) with { OperationTimeoutSeconds = 60 } }, cts.Token);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), sw.Elapsed.ToString());
        Assert.Contains(r.Stages, s => s.Outcome == StageOutcome.Cancelled);
    }

    [Fact]
    public async Task Refused_port_and_unknown_host_are_explained()
    {
        var free = new TcpListener(IPAddress.Loopback, 0);
        free.Start();
        var port = ((IPEndPoint)free.LocalEndpoint).Port;
        free.Stop();
        var (r, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = new SmtpProfile { Server = "127.0.0.1", Port = port, Security = SmtpConnectionSecurity.None, ConnectTimeoutSeconds = 3 } });
        Assert.Equal(StageOutcome.Failed, O(r, SmtpStage.Tcp));
        Assert.Contains("Connection refused", S(r, SmtpStage.Tcp).Explanation, StringComparison.Ordinal);

        var (d, _) = await RunAsync(new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = new SmtpProfile { Server = "no-such-host.invalid", Port = 25, ConnectTimeoutSeconds = 5 } });
        Assert.Equal(StageOutcome.Failed, O(d, SmtpStage.Dns));
        Assert.Equal(StageOutcome.NotRun, O(d, SmtpStage.Tcp));
    }

    [Fact]
    public void Logger_redacts_auth_payloads_and_counts_message_content()
    {
        var log = new List<SmtpLogEntry>();
        var l = new SmtpSessionLogger(log.Add);
        void C(string s) => l.LogClient(Encoding.ASCII.GetBytes(s), 0, s.Length);
        void Srv(string s) => l.LogServer(Encoding.ASCII.GetBytes(s), 0, s.Length);
        Srv("220 hi\r\n");
        C("AUTH PLAIN AGFsaWNlAHNlY3JldA==\r\n");
        Srv("535 5.7.8 no\r\n");
        C("AUTH LOGIN\r\n");
        Srv("334 VXNlcm5hbWU6\r\n");
        C("YWxpY2U=\r\n");
        Srv("334 UGFzc3dvcmQ6\r\n");
        C("c2VjcmV0\r\n");
        Srv("235 ok\r\n");
        C("DATA\r\n");
        Srv("354 go\r\n");
        C("Subject: private\r\n\r\nconfidential body\r\n");
        C(".\r\n");
        Srv("250 2.0.0 Ok: queued as Q1\r\n");
        C("QUIT\r\n");
        var text = string.Join("\n", log.Select(e => e.Text));
        Assert.DoesNotContain("AGFsaWNlAHNlY3JldA", text, StringComparison.Ordinal);
        Assert.DoesNotContain("YWxpY2U=", text, StringComparison.Ordinal);
        Assert.DoesNotContain("c2VjcmV0", text, StringComparison.Ordinal);
        Assert.DoesNotContain("confidential", text, StringComparison.Ordinal);
        Assert.Contains("AUTH PLAIN ******** (authentication data hidden)", text, StringComparison.Ordinal);
        Assert.Contains("[message content: ", text, StringComparison.Ordinal);
        Assert.Contains("QUIT", text, StringComparison.Ordinal); // normal logging resumes after the message
        Assert.True(l.DataCommandSent);
    }

    [Fact]
    public async Task Profiles_round_trip_and_never_contain_a_password()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-smtp-").FullName;
        try
        {
            var store = new IPMaster.Infrastructure.Configuration.SettingsStore(dir);
            var profile = new SmtpProfile
            {
                Name = "Lab relay", Server = "mail.lab.test", Port = 465, Security = SmtpConnectionSecurity.ImplicitTls, AuthMode = SmtpAuthMode.UsernamePassword,
                UserName = "alice", CredentialId = Guid.NewGuid(), Mechanism = "SCRAM-SHA-256", ValidateCertificate = false, Message = Msg,
            };
            await store.SaveAsync(new IPMaster.Core.Configuration.AppSettings { Tools = new ToolSettings { SmtpProfiles = [profile] } });
            var json = await File.ReadAllTextAsync(Path.Combine(dir, IPMaster.Infrastructure.Configuration.SettingsStore.FileName));
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            var saved = doc.RootElement.GetProperty("tools").GetProperty("smtpProfiles")[0];
            Assert.DoesNotContain(saved.EnumerateObject(), p => p.Name.Contains("password", StringComparison.OrdinalIgnoreCase) && p.Name != "allowPlaintextAuth");
            var back = Assert.Single(store.Load().Settings.Tools.SmtpProfiles);
            Assert.Equal(profile with { Message = null }, back with { Message = null });
            Assert.Equal(Msg with { Attachments = [] }, back.Message! with { Attachments = [] });
            Assert.False(back.ValidateCertificate); // profile-specific exception survives, nothing global changes
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public void Envelope_defaults_validation_and_reply_helpers()
    {
        var env = SmtpMessages.Build(Msg, withMessage: true, out var errors);
        Assert.Empty(errors);
        Assert.Equal("sender@lab.test", env.Sender.Address);
        Assert.Equal(["a@lab.test", "c@lab.test", "hidden@lab.test"], env.Recipients.Select(x => x.Address));
        Assert.Empty(env.Message!.Bcc);
        var over = SmtpMessages.Build(Msg with { EnvelopeSender = "bounce@lab.test", EnvelopeRecipients = "x@lab.test; y@lab.test" }, false, out _);
        Assert.Equal("bounce@lab.test", over.Sender.Address);
        Assert.Equal(["x@lab.test", "y@lab.test"], over.Recipients.Select(x => x.Address));
        SmtpMessages.Build(new SmtpMessageTemplate { From = "not an address", To = "a@b" }, true, out var bad);
        Assert.Contains(bad, e => e.Contains("'not an address'", StringComparison.Ordinal));

        Assert.Equal("5.7.1", SmtpText.EnhancedCode("5.7.1 Relaying denied"));
        Assert.Null(SmtpText.EnhancedCode("Ok"));
        Assert.Equal("4XkF3", SmtpText.QueueId("2.0.0 Ok: queued as 4XkF3"));
        Assert.Equal("12345678", SmtpText.QueueId("2.6.0 <x@y> [InternalId=12345678, Hostname=EX] Queued mail for delivery"));
        Assert.Null(SmtpText.QueueId("2.0.0 Ok"));
        Assert.StartsWith("Message size limit", SmtpText.ExplainReply(SmtpStage.Submission, 552, "5.3.4 Message size exceeds fixed limit"), StringComparison.Ordinal);
        Assert.StartsWith("Message size limit", SmtpText.ExplainSender(552, "5.3.4 Message size exceeds limit"), StringComparison.Ordinal);
        Assert.StartsWith("Authentication failed", SmtpText.ExplainReply(SmtpStage.Authentication, 535, "5.7.8 bad"), StringComparison.Ordinal);
        Assert.Equal(SmtpConnectionSecurity.ImplicitTls, SmtpText.SuggestedSecurity(465));

        var (subject, body, id) = SmtpText.GenerateTestMessage(new DateTimeOffset(2026, 11, 16, 12, 0, 0, TimeSpan.Zero), Guid.Parse("0123456789abcdef0123456789abcdef"), "mail.lab", SmtpBodyFormat.PlainText);
        Assert.Equal("0123456789AB", id);
        Assert.Contains(id, subject, StringComparison.Ordinal);
        Assert.Contains("2026-11-16 12:00:00", subject, StringComparison.Ordinal);
        Assert.Contains("does not prove delivery", body, StringComparison.Ordinal);
    }
}
