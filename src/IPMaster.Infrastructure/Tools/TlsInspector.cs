using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IPMaster.Infrastructure.Tools;

public enum TlsMode
{
    DirectTls,
    SmtpStartTls,
}

public enum TlsInspectOutcome
{
    Inspected,
    Timeout,
    ConnectFailed,
    StartTlsUnavailable,
    HandshakeFailed,
    Cancelled,
}

public sealed record TlsInspectRequest
{
    public required string Host { get; init; }

    public int Port { get; init; } = 443;

    public TlsMode Mode { get; init; } = TlsMode.DirectTls;

    /// <summary>Server name sent in SNI and used for the name check; empty = the host (no SNI for an IP address).</summary>
    public string Sni { get; init; } = "";

    /// <summary>Name the certificate should be valid for; empty = the SNI name / host.</summary>
    public string ExpectedName { get; init; } = "";

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    public X509RevocationMode Revocation { get; init; } = X509RevocationMode.Online;
}

public sealed record CertificateInfo(
    string Subject,
    string Issuer,
    IReadOnlyList<string> SubjectAlternativeNames,
    string Serial,
    DateTime NotBefore,
    DateTime NotAfter,
    string PublicKey,
    string SignatureAlgorithm,
    string Sha256,
    string KeyUsage,
    string ExtendedKeyUsage,
    bool SelfSigned,
    string Pem)
{
    public int RemainingDays(DateTime nowUtc) => (int)Math.Floor((NotAfter.ToUniversalTime() - nowUtc).TotalDays);

    public static CertificateInfo From(X509Certificate2 c)
    {
        ArgumentNullException.ThrowIfNull(c);
        var san = c.Extensions.OfType<X509SubjectAlternativeNameExtension>()
            .SelectMany(e => e.EnumerateDnsNames().Select(d => "DNS:" + d).Concat(e.EnumerateIPAddresses().Select(i => "IP:" + i))).ToList();
        var ku = c.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault()?.KeyUsages.ToString() ?? "";
        var eku = string.Join(", ", c.Extensions.OfType<X509EnhancedKeyUsageExtension>().SelectMany(e => e.EnhancedKeyUsages.Cast<Oid>()).Select(o => o.FriendlyName ?? o.Value));
        string key;
        using (var rsa = c.GetRSAPublicKey())
        using (var ecdsa = c.GetECDsaPublicKey())
        {
            key = rsa is not null ? $"RSA {rsa.KeySize} bits" : ecdsa is not null ? $"ECDSA {ecdsa.KeySize} bits" : c.PublicKey.Oid.FriendlyName ?? c.PublicKey.Oid.Value ?? "";
        }

        return new CertificateInfo(c.Subject, c.Issuer, san, c.SerialNumber, c.NotBefore, c.NotAfter, key, c.SignatureAlgorithm.FriendlyName ?? c.SignatureAlgorithm.Value ?? "",
            c.GetCertHashString(HashAlgorithmName.SHA256), ku, eku, c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData), c.ExportCertificatePem());
    }
}

public sealed record ChainElementInfo(string Subject, string Issuer, IReadOnlyList<string> Status);

public sealed record TlsInspection(
    TlsInspectRequest Request,
    TlsInspectOutcome Outcome,
    string Detail,
    string? ConnectedTo,
    string? Protocol,
    string? CipherSuite,
    IReadOnlyList<CertificateInfo> Presented,
    IReadOnlyList<ChainElementInfo> LocalChain,
    SslPolicyErrors PolicyErrors,
    bool? ExpectedNameMatches,
    string RevocationStatus,
    IReadOnlyList<string> SmtpLog,
    TimeSpan Duration)
{
    /// <summary>Trusted = no policy errors and the expected name matches. Anything else stays visibly untrusted.</summary>
    public bool Trusted => Outcome == TlsInspectOutcome.Inspected && PolicyErrors == SslPolicyErrors.None && ExpectedNameMatches != false;
}

/// <summary>
/// TLS Certificate Inspector (D-075): one handshake, read-only. Validation errors are recorded and the handshake continues
/// only so the certificate can be shown; the result is then marked untrusted. Nothing is sent after the handshake.
/// One handshake shows one negotiated protocol and cipher; it is not a scan of everything the server supports.
/// </summary>
public static class TlsInspector
{
    public static async Task<TlsInspection> InspectAsync(TlsInspectRequest r, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(r);
        var sw = Stopwatch.StartNew();
        var smtp = new List<string>();
        var presented = new List<CertificateInfo>();
        var chain = new List<ChainElementInfo>();
        var errors = SslPolicyErrors.None;
        string revocation = r.Revocation == X509RevocationMode.NoCheck ? "Not checked (revocation checking was off)." : "Not reported.";
        TlsInspection Result(TlsInspectOutcome o, string detail, string? connected = null, string? protocol = null, string? cipher = null, bool? nameOk = null) =>
            new(r, o, detail, connected, protocol, cipher, presented, chain, errors, nameOk, revocation, smtp, sw.Elapsed);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(r.Timeout);
        using var tcp = new TcpClient();
        string connected;
        try
        {
            await tcp.ConnectAsync(r.Host, r.Port, cts.Token).ConfigureAwait(false);
            connected = tcp.Client.RemoteEndPoint is System.Net.IPEndPoint ep
                ? new System.Net.IPEndPoint(ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address, ep.Port).ToString()
                : "";
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Result(TlsInspectOutcome.Cancelled, "Cancelled.");
        }
        catch (OperationCanceledException)
        {
            return Result(TlsInspectOutcome.Timeout, $"No TCP connection within {r.Timeout.TotalSeconds:0} s.");
        }
        catch (SocketException ex)
        {
            return Result(TlsInspectOutcome.ConnectFailed, $"{ex.SocketErrorCode}: {ex.Message}");
        }

        var stream = tcp.GetStream();
        try
        {
            if (r.Mode == TlsMode.SmtpStartTls && await StartTlsAsync(stream, smtp, cts.Token).ConfigureAwait(false) is { } problem)
            {
                return Result(TlsInspectOutcome.StartTlsUnavailable, problem, connected);
            }

            var sni = r.Sni.Trim().Length > 0 ? r.Sni.Trim() : r.Host.Trim();
            var expected = r.ExpectedName.Trim().Length > 0 ? r.ExpectedName.Trim() : sni;
            await using var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                CertificateRevocationCheckMode = r.Revocation,
                // inspection only: record the verdict, continue so the certificate can be shown, mark the result untrusted
                RemoteCertificateValidationCallback = (_, cert, ch, e) =>
                {
                    errors = e;
                    if (cert is not null)
                    {
                        using var leafCopy = new X509Certificate2(cert);
                        presented.Add(CertificateInfo.From(leafCopy));
                    }
                    if (ch is not null)
                    {
                        foreach (var extra in ch.ChainPolicy.ExtraStore) presented.Add(CertificateInfo.From(extra)); // sent by the server
                        foreach (var el in ch.ChainElements)
                        {
                            chain.Add(new ChainElementInfo(el.Certificate.Subject, el.Certificate.Issuer,
                                el.ChainElementStatus.Where(s => s.Status != X509ChainStatusFlags.NoError).Select(s => $"{s.Status}: {s.StatusInformation.Trim()}").ToList()));
                        }

                        revocation = r.Revocation == X509RevocationMode.NoCheck ? "Not checked (revocation checking was off)."
                            : ch.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.Revoked)) ? "REVOKED."
                            : ch.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.UntrustedRoot) || s.Status.HasFlag(X509ChainStatusFlags.PartialChain))
                                ? "Not determinable: the chain does not end in a trusted root, so revocation cannot be meaningfully checked."
                            : ch.ChainStatus.Any(s => s.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) || s.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                                ? "Unknown: the revocation status could not be determined (CRL/OCSP unreachable or not provided)."
                                : $"Checked ({r.Revocation}): not revoked.";
                    }

                    return true;
                },
            };
            try
            {
                await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException)
            {
                return Result(TlsInspectOutcome.HandshakeFailed, ex.InnerException?.Message ?? ex.Message, connected);
            }

            bool? nameOk = null;
            if (ssl.RemoteCertificate is { } rc)
            {
                using var leaf = new X509Certificate2(rc);
                nameOk = IPAddress.TryParse(expected, out _) ? leaf.MatchesHostname(expected, allowWildcards: false, allowCommonName: false) : leaf.MatchesHostname(expected);
            }

            return Result(TlsInspectOutcome.Inspected, "", connected, ssl.SslProtocol.ToString(), ssl.NegotiatedCipherSuite.ToString(), nameOk);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Result(TlsInspectOutcome.Cancelled, "Cancelled.", connected);
        }
        catch (OperationCanceledException)
        {
            return Result(TlsInspectOutcome.Timeout, $"No complete answer within {r.Timeout.TotalSeconds:0} s.", connected);
        }
        catch (IOException ex)
        {
            return Result(TlsInspectOutcome.HandshakeFailed, ex.Message, connected);
        }
    }

    /// <summary>SMTP STARTTLS (RFC 3207): greeting, EHLO (capabilities parsed), STARTTLS answered with 220. No AUTH, no mail.</summary>
    private static async Task<string?> StartTlsAsync(NetworkStream s, List<string> log, CancellationToken ct)
    {
        var reader = new SmtpLineReader(s);
        var (code, lines) = await reader.ReplyAsync(ct).ConfigureAwait(false);
        log.AddRange(lines.Select(l => "S: " + l));
        if (code != 220) return $"The server greeting was {code}, not 220.";
        await WriteAsync(s, "EHLO ipmaster.invalid", log, ct).ConfigureAwait(false);
        (code, lines) = await reader.ReplyAsync(ct).ConfigureAwait(false);
        log.AddRange(lines.Select(l => "S: " + l));
        if (code != 250) return $"EHLO was answered with {code}.";
        var caps = lines.Skip(1).Select(l => l.Length > 4 ? l[4..].Trim() : "").ToList();
        if (!caps.Any(c => c.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase))) return "The server does not offer STARTTLS (not in the EHLO capabilities).";
        await WriteAsync(s, "STARTTLS", log, ct).ConfigureAwait(false);
        (code, lines) = await reader.ReplyAsync(ct).ConfigureAwait(false);
        log.AddRange(lines.Select(l => "S: " + l));
        return code == 220 ? null : $"STARTTLS was refused: {string.Join(" ", lines)}";
    }

    private static async Task WriteAsync(NetworkStream s, string line, List<string> log, CancellationToken ct)
    {
        log.Add("C: " + line);
        await s.WriteAsync(Encoding.ASCII.GetBytes(line + "\r\n"), ct).ConfigureAwait(false);
    }

    /// <summary>Reads SMTP replies byte by byte (so no TLS bytes are consumed after the 220), multiline aware, bounded.</summary>
    private sealed class SmtpLineReader(NetworkStream s)
    {
        public async Task<(int Code, List<string> Lines)> ReplyAsync(CancellationToken ct)
        {
            var lines = new List<string>();
            while (lines.Count < 100)
            {
                var line = await LineAsync(ct).ConfigureAwait(false);
                lines.Add(line);
                if (line.Length < 4 || line[3] != '-') break;
            }

            return (lines.Count > 0 && lines[^1].Length >= 3 && int.TryParse(lines[^1].AsSpan(0, 3), NumberStyles.None, CultureInfo.InvariantCulture, out var c) ? c : 0, lines);
        }

        private async Task<string> LineAsync(CancellationToken ct)
        {
            var sb = new StringBuilder();
            var one = new byte[1];
            while (sb.Length < 2048)
            {
                if (await s.ReadAsync(one, ct).ConfigureAwait(false) == 0) throw new IOException("The server closed the connection.");
                if (one[0] == '\n') break;
                if (one[0] != '\r') sb.Append((char)one[0]);
            }

            return sb.ToString();
        }
    }

    public static string Report(TlsInspection i, DateTime nowUtc)
    {
        ArgumentNullException.ThrowIfNull(i);
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine(c, $"TLS inspection of {i.Request.Host}:{i.Request.Port} ({(i.Request.Mode == TlsMode.SmtpStartTls ? "SMTP STARTTLS" : "direct TLS")}) — {i.Duration.TotalMilliseconds:0} ms");
        sb.AppendLine(c, $"Outcome: {i.Outcome}{(i.Detail.Length > 0 ? " — " + i.Detail : "")}");
        if (i.ConnectedTo is not null) sb.AppendLine("Connected to: " + i.ConnectedTo);
        foreach (var l in i.SmtpLog) sb.AppendLine("  " + l);
        if (i.Outcome != TlsInspectOutcome.Inspected) return sb.ToString();
        sb.AppendLine(c, $"Negotiated: {i.Protocol}, {i.CipherSuite} (one handshake; not a list of everything the server supports)");
        sb.AppendLine(i.Trusted ? "Verdict: TRUSTED (chain valid, name matches)" : "Verdict: UNTRUSTED — the certificate was inspected for diagnosis only.");
        sb.AppendLine("Policy errors: " + (i.PolicyErrors == SslPolicyErrors.None ? "none" : i.PolicyErrors.ToString()));
        var expected = i.Request.ExpectedName.Trim().Length > 0 ? i.Request.ExpectedName.Trim() : i.Request.Sni.Trim().Length > 0 ? i.Request.Sni.Trim() : i.Request.Host;
        sb.AppendLine(c, $"Name check for '{expected}': {(i.ExpectedNameMatches switch { true => "matches", false => "DOES NOT MATCH", _ => "not available" })}");
        sb.AppendLine("Revocation: " + i.RevocationStatus);
        sb.AppendLine();
        sb.AppendLine(c, $"== Certificates presented by the server ({i.Presented.Count}) ==");
        foreach (var (cert, n) in i.Presented.Select((x, n) => (x, n)))
        {
            sb.AppendLine(c, $"[{n}] Subject: {cert.Subject}");
            sb.AppendLine("    Issuer: " + cert.Issuer + (cert.SelfSigned ? " (self-signed)" : ""));
            if (cert.SubjectAlternativeNames.Count > 0) sb.AppendLine("    SAN: " + string.Join(", ", cert.SubjectAlternativeNames));
            sb.AppendLine("    Serial: " + cert.Serial);
            sb.AppendLine(c, $"    Valid: {cert.NotBefore:yyyy-MM-dd HH:mm} – {cert.NotAfter:yyyy-MM-dd HH:mm} ({cert.RemainingDays(nowUtc)} days remaining)");
            sb.AppendLine("    Public key: " + cert.PublicKey + "; signature: " + cert.SignatureAlgorithm);
            sb.AppendLine("    SHA-256: " + cert.Sha256);
            if (cert.KeyUsage.Length > 0) sb.AppendLine("    Key usage: " + cert.KeyUsage);
            if (cert.ExtendedKeyUsage.Length > 0) sb.AppendLine("    Extended key usage: " + cert.ExtendedKeyUsage);
        }

        sb.AppendLine();
        sb.AppendLine(c, $"== Chain built on this computer ({i.LocalChain.Count}) ==");
        foreach (var (el, n) in i.LocalChain.Select((x, n) => (x, n)))
        {
            sb.AppendLine(c, $"[{n}] {el.Subject}");
            foreach (var s in el.Status) sb.AppendLine("    ⚠ " + s);
        }

        return sb.ToString();
    }
}
