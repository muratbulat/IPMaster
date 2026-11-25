using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

public class NetToolsTlsTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Direct-TLS loopback server with the fixture's self-signed certificate (CN/SAN smtp.fixture.test).</summary>
    private static (int Port, Task Server, TcpListener Listener) DirectTlsServer()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var server = Task.Run(async () =>
        {
            try
            {
                using var c = await l.AcceptTcpClientAsync(Ct);
                await using var ssl = new SslStream(c.GetStream());
                await ssl.AuthenticateAsServerAsync(SmtpFixture.Certificate);
                await Task.Delay(500, Ct);
            }
            catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or OperationCanceledException or SocketException)
            {
            }
        });
        return (((IPEndPoint)l.LocalEndpoint).Port, server, l);
    }

    [Fact]
    public async Task Direct_tls_is_inspected_and_self_signed_stays_untrusted()
    {
        var (port, server, l) = DirectTlsServer();
        var i = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = port, Sni = "smtp.fixture.test", Revocation = X509RevocationMode.NoCheck }, Ct);
        l.Stop();
        await server;
        Assert.Equal(TlsInspectOutcome.Inspected, i.Outcome);
        Assert.False(i.Trusted); // self-signed root is not trusted on this machine
        Assert.True(i.PolicyErrors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.True(i.ExpectedNameMatches);
        var leaf = i.Presented[0];
        Assert.Equal("CN=smtp.fixture.test", leaf.Subject);
        Assert.Contains("DNS:smtp.fixture.test", leaf.SubjectAlternativeNames);
        Assert.True(leaf.SelfSigned);
        Assert.StartsWith("RSA 2048", leaf.PublicKey, StringComparison.Ordinal);
        Assert.Equal(64, leaf.Sha256.Length);
        Assert.Contains("-----BEGIN CERTIFICATE-----", leaf.Pem, StringComparison.Ordinal);
        Assert.StartsWith("Not checked", i.RevocationStatus, StringComparison.Ordinal);
        Assert.StartsWith("127.0.0.1:", i.ConnectedTo, StringComparison.Ordinal);
        var report = TlsInspector.Report(i, DateTime.UtcNow);
        Assert.Contains("UNTRUSTED", report, StringComparison.Ordinal);
        Assert.Contains("Certificates presented by the server", report, StringComparison.Ordinal);
        Assert.Contains("Chain built on this computer", report, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Expected_name_mismatch_is_reported()
    {
        var (port, server, l) = DirectTlsServer();
        var i = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = port, Sni = "smtp.fixture.test", ExpectedName = "other.lab.test", Revocation = X509RevocationMode.NoCheck }, Ct);
        l.Stop();
        await server;
        Assert.False(i.ExpectedNameMatches);
        Assert.Contains("DOES NOT MATCH", TlsInspector.Report(i, DateTime.UtcNow), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Smtp_starttls_upgrades_after_ehlo_without_auth_or_mail()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls);
        var i = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = f.Port, Mode = TlsMode.SmtpStartTls, Sni = "smtp.fixture.test", Revocation = X509RevocationMode.NoCheck }, Ct);
        Assert.Equal(TlsInspectOutcome.Inspected, i.Outcome);
        Assert.Contains(i.SmtpLog, l => l == "C: STARTTLS");
        Assert.DoesNotContain(f.Commands, c => c.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase) || c.StartsWith("MAIL", StringComparison.OrdinalIgnoreCase));
        Assert.Equal("CN=smtp.fixture.test", i.Presented[0].Subject);
    }

    [Fact]
    public async Task Smtp_without_starttls_or_refusing_it_is_not_upgraded()
    {
        await using var plain = new SmtpFixture();
        var a = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = plain.Port, Mode = TlsMode.SmtpStartTls }, Ct);
        Assert.Equal(TlsInspectOutcome.StartTlsUnavailable, a.Outcome);
        Assert.Contains("does not offer STARTTLS", a.Detail, StringComparison.Ordinal);
        Assert.Empty(a.Presented);

        await using var refuse = new SmtpFixture(SmtpFixture.Kind.StartTls) { RefuseStartTls = true };
        var b = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = refuse.Port, Mode = TlsMode.SmtpStartTls }, Ct);
        Assert.Equal(TlsInspectOutcome.StartTlsUnavailable, b.Outcome);
        Assert.Contains("454", b.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Silent_server_times_out_and_cancel_is_reported()
    {
        await using var f = new SmtpFixture { Silent = true };
        var i = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = f.Port, Timeout = TimeSpan.FromMilliseconds(700) }, Ct);
        Assert.Equal(TlsInspectOutcome.Timeout, i.Outcome);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(200);
        var c = await TlsInspector.InspectAsync(new TlsInspectRequest { Host = "127.0.0.1", Port = f.Port, Timeout = TimeSpan.FromSeconds(10) }, cts.Token);
        Assert.Equal(TlsInspectOutcome.Cancelled, c.Outcome);
    }
}

public class NetToolsTlsRevocationTests
{
    [Fact]
    public async Task Revocation_is_not_claimed_for_an_untrusted_chain()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((System.Net.IPEndPoint)l.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            try
            {
                using var c = await l.AcceptTcpClientAsync(TestContext.Current.CancellationToken);
                await using var ssl = new System.Net.Security.SslStream(c.GetStream());
                await ssl.AuthenticateAsServerAsync(SmtpFixture.Certificate);
                await Task.Delay(300, TestContext.Current.CancellationToken);
            }
            catch (Exception ex) when (ex is IOException or System.Security.Authentication.AuthenticationException or OperationCanceledException)
            {
            }
        });
        var i = await IPMaster.Infrastructure.Tools.TlsInspector.InspectAsync(new IPMaster.Infrastructure.Tools.TlsInspectRequest
        {
            Host = "127.0.0.1", Port = port, Sni = "smtp.fixture.test", Revocation = System.Security.Cryptography.X509Certificates.X509RevocationMode.Online,
        }, TestContext.Current.CancellationToken);
        l.Stop();
        await server;
        Assert.StartsWith("Not determinable", i.RevocationStatus, StringComparison.Ordinal);
    }
}
