using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Probes;

/// <summary>
/// Read-only service identification. Every probe sends at most a protocol greeting or capability request, never
/// credentials, and reads a bounded amount of data (≤ 16 KB) within the timeout. TLS certificates are inspected,
/// not trusted: validation results are recorded (D-034) and no data is sent over an unverified channel except an
/// unauthenticated HEAD request.
/// </summary>
public sealed class ServiceProbe : IServiceProbe
{
    private const int MaxRead = 16 * 1024;

    /// <summary>Common unauthenticated stream paths tried with RTSP DESCRIBE (no credentials are ever sent).</summary>
    internal static readonly string[] RtspPaths =
    [
        "/", "/live", "/live.sdp", "/stream1", "/h264", "/video1", "/Streaming/Channels/101", "/cam/realmonitor?channel=1&subtype=0",
        "/axis-media/media.amp", "/live/ch00_0",
    ];

    public async Task<ServiceBanner?> GrabTcpBannerAsync(IPAddress address, BannerService service, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(service);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            using var client = await ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            if (client is null) return null;
            var stream = client.GetStream();
            var text = service.Id switch
            {
                "http" => await HttpHeadAsync(stream, address, port, cts.Token).ConfigureAwait(false),
                "tls" => await TlsBannerAsync(stream, address, port, cts.Token).ConfigureAwait(false),
                "ssh" or "ftp" or "smtp" or "pop3" or "imap" => FirstLine(await ReadSomeAsync(stream, cts.Token).ConfigureAwait(false)),
                "mysql" => MySqlGreeting(await ReadSomeAsync(stream, cts.Token).ConfigureAwait(false)),
                "mssql" => await MssqlPreloginAsync(stream, cts.Token).ConfigureAwait(false),
                "smb" => await SmbNegotiateAsync(stream, cts.Token).ConfigureAwait(false),
                "mqtt" => await MqttConnectAsync(stream, cts.Token).ConfigureAwait(false),
                _ => null,
            };
            return string.IsNullOrWhiteSpace(text) ? null : new ServiceBanner(service.Name, PortProtocol.Tcp, port, Clean(text));
        }
        catch (Exception ex) when (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested
                                   || ex is IOException or SocketException or AuthenticationException or FormatException or ArgumentException)
        {
            return null;
        }
    }

    public async Task<TlsCertificateInfo?> GetCertificateAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            using var client = await ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
            if (client is null) return null;
            X509Certificate2? cert = null;
            SslPolicyErrors errors = SslPolicyErrors.None;
            X509ChainStatusFlags chainFlags = X509ChainStatusFlags.NoError;
#pragma warning disable CA5359 // inspection only: certificate details and validation result are recorded, nothing sensitive is sent (D-034)
            await using var ssl = new SslStream(client.GetStream(), false, (_, c, chain, e) =>
            {
                if (c is not null) cert = new X509Certificate2(c);
                errors = e;
                if (chain is not null) foreach (var s in chain.ChainStatus) chainFlags |= s.Status;
                return true; // inspection only (D-034)
            });
#pragma warning restore CA5359
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = address.ToString() }, cts.Token).ConfigureAwait(false);
            if (cert is null) return null;
            using (cert)
            {
                var sans = new List<string>();
                foreach (var ext in cert.Extensions)
                {
                    if (ext is X509SubjectAlternativeNameExtension san)
                    {
                        sans.AddRange(san.EnumerateDnsNames());
                        sans.AddRange(san.EnumerateIPAddresses().Select(a => a.ToString()));
                    }
                }

                // The target is addressed by IP, so a name mismatch is expected and does not make the chain invalid.
                var chainErrors = errors & ~SslPolicyErrors.RemoteCertificateNameMismatch;
                var status = chainErrors == SslPolicyErrors.None ? null : chainFlags != X509ChainStatusFlags.NoError ? chainFlags.ToString() : chainErrors.ToString();
                return new TlsCertificateInfo(port, cert.Subject, cert.Issuer, new DateTimeOffset(cert.NotBefore.ToUniversalTime(), TimeSpan.Zero),
                    new DateTimeOffset(cert.NotAfter.ToUniversalTime(), TimeSpan.Zero), cert.SerialNumber, cert.Thumbprint, sans,
                    ProtocolName(ssl.SslProtocol), chainErrors == SslPolicyErrors.None, status);
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested
                                   || ex is IOException or SocketException or AuthenticationException or CryptographicException)
        {
            return null;
        }
    }

    public async Task<IReadOnlyList<string>> FindRtspStreamsAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        var found = new List<string>();
        var host = address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout * (RtspPaths.Length + 1));
        TcpClient? client = null;
        try
        {
            var seq = 1;
            foreach (var path in RtspPaths)
            {
                client ??= await ConnectAsync(address, port, cts.Token).ConfigureAwait(false);
                if (client is null) return found;
                var url = $"rtsp://{host}:{port}{path}";
                var method = seq == 1 ? "OPTIONS" : "DESCRIBE";
                var request = $"{method} {url} RTSP/1.0\r\nCSeq: {seq++}\r\nUser-Agent: IPMaster\r\n" + (method == "DESCRIBE" ? "Accept: application/sdp\r\n" : "") + "\r\n";
                string reply;
                try
                {
                    await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token).ConfigureAwait(false);
                    reply = Encoding.ASCII.GetString(await ReadSomeAsync(client.GetStream(), cts.Token).ConfigureAwait(false));
                }
                catch (IOException)
                {
                    client.Dispose();
                    client = null;
                    continue;
                }

                if (!reply.StartsWith("RTSP/1.", StringComparison.Ordinal))
                {
                    if (method == "OPTIONS") return found; // not an RTSP server
                    continue;
                }

                if (method == "OPTIONS")
                {
                    // also try the root path with DESCRIBE on the next iteration
                    var root = await DescribeAsync(client, url, seq++, cts.Token).ConfigureAwait(false);
                    if (root is not null) found.Add(root);
                    continue;
                }

                var code = StatusCode(reply);
                if (code == 200) found.Add(url + " (open)");
                else if (code == 401) found.Add(url + " (authentication required)");
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested || ex is IOException or SocketException)
        {
            // partial results are still useful
        }
        finally
        {
            client?.Dispose();
        }

        return found.Distinct().ToList();
    }

    private static async Task<string?> DescribeAsync(TcpClient client, string url, int seq, CancellationToken ct)
    {
        var request = $"DESCRIBE {url} RTSP/1.0\r\nCSeq: {seq}\r\nUser-Agent: IPMaster\r\nAccept: application/sdp\r\n\r\n";
        await client.GetStream().WriteAsync(Encoding.ASCII.GetBytes(request), ct).ConfigureAwait(false);
        var reply = Encoding.ASCII.GetString(await ReadSomeAsync(client.GetStream(), ct).ConfigureAwait(false));
        return StatusCode(reply) switch
        {
            200 => url + " (open)",
            401 => url + " (authentication required)",
            _ => null,
        };
    }

    private static int StatusCode(string reply)
    {
        var parts = reply.Split(' ', 3);
        return parts.Length >= 2 && int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var c) ? c : 0;
    }

    private static async Task<TcpClient?> ConnectAsync(IPAddress address, int port, CancellationToken ct)
    {
        var client = new TcpClient(address.AddressFamily) { LingerState = new LingerOption(true, 0), NoDelay = true };
        try
        {
            await client.ConnectAsync(address, port, ct).ConfigureAwait(false);
            return client;
        }
        catch (SocketException)
        {
            client.Dispose();
            return null;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    private static async Task<byte[]> ReadSomeAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[MaxRead];
        var total = 0;
        // read the first chunk, then whatever arrives within a short grace period
        total += await stream.ReadAsync(buffer.AsMemory(total), ct).ConfigureAwait(false);
        while (total < buffer.Length)
        {
            using var grace = CancellationTokenSource.CreateLinkedTokenSource(ct);
            grace.CancelAfter(150);
            try
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total), grace.Token).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                break;
            }
        }

        return buffer[..total];
    }

    private static async Task<string?> HttpHeadAsync(Stream stream, IPAddress address, int port, CancellationToken ct)
    {
        var host = address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
        var request = $"HEAD / HTTP/1.0\r\nHost: {host}:{port}\r\nUser-Agent: IPMaster\r\nConnection: close\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), ct).ConfigureAwait(false);
        return DescribeHttp(Encoding.Latin1.GetString(await ReadSomeAsync(stream, ct).ConfigureAwait(false)));
    }

    internal static string? DescribeHttp(string response)
    {
        var lines = response.Split("\r\n");
        if (lines.Length == 0 || !lines[0].StartsWith("HTTP/", StringComparison.Ordinal)) return null;
        var status = lines[0];
        var server = lines.FirstOrDefault(l => l.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))?[7..].Trim();
        return server is { Length: > 0 } ? $"{server} ({status})" : status;
    }

    private static async Task<string?> TlsBannerAsync(Stream stream, IPAddress address, int port, CancellationToken ct)
    {
#pragma warning disable CA5359 // banner probe only sends an unauthenticated HEAD request (D-034)
        await using var ssl = new SslStream(stream, false, (_, _, _, _) => true);
#pragma warning restore CA5359
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = address.ToString() }, ct).ConfigureAwait(false);
        string? http = null;
        try
        {
            http = await HttpHeadAsync(ssl, address, port, ct).ConfigureAwait(false);
        }
        catch (IOException)
        {
            // TLS service that is not HTTP
        }

        return ProtocolName(ssl.SslProtocol) + (http is null ? "" : ", " + http);
    }

    private static string ProtocolName(SslProtocols p) => p switch
    {
        SslProtocols.Tls13 => "TLS 1.3",
        SslProtocols.Tls12 => "TLS 1.2",
#pragma warning disable SYSLIB0039, CA5397 // reporting what the server negotiated, not enabling it
        SslProtocols.Tls11 => "TLS 1.1",
        SslProtocols.Tls => "TLS 1.0",
#pragma warning restore SYSLIB0039, CA5397
        _ => p.ToString(),
    };

    private static string? FirstLine(byte[] data)
    {
        var s = Encoding.Latin1.GetString(data);
        var end = s.IndexOfAny(['\r', '\n']);
        return end >= 0 ? s[..end] : s;
    }

    internal static string? MySqlGreeting(byte[] p)
    {
        if (p.Length < 6) return null;
        if (p[4] == 0xFF) return "MySQL (refused: " + Encoding.UTF8.GetString(p, 7, Math.Max(0, p.Length - 7)).Trim() + ")";
        if (p[4] != 10) return null;
        var end = Array.IndexOf(p, (byte)0, 5);
        return end > 5 ? "MySQL " + Encoding.ASCII.GetString(p, 5, end - 5) : null;
    }

    private static async Task<string?> MssqlPreloginAsync(Stream stream, CancellationToken ct)
    {
        byte[] payload = [0x00, 0x00, 0x0B, 0x00, 0x06, 0x01, 0x00, 0x11, 0x00, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0x02];
        var packet = new byte[8 + payload.Length];
        packet[0] = 0x12; // PRELOGIN
        packet[1] = 0x01; // EOM
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
        payload.CopyTo(packet, 8);
        await stream.WriteAsync(packet, ct).ConfigureAwait(false);
        return DescribeMssql(await ReadSomeAsync(stream, ct).ConfigureAwait(false));
    }

    internal static string? DescribeMssql(byte[] r)
    {
        if (r.Length < 9 || r[0] != 0x04) return null;
        var payload = r.AsSpan(8);
        for (var i = 0; i + 5 <= payload.Length && payload[i] != 0xFF; i += 5)
        {
            if (payload[i] != 0x00) continue;
            var off = BinaryPrimitives.ReadUInt16BigEndian(payload[(i + 1)..]);
            if (off + 6 > payload.Length) return null;
            var v = payload.Slice(off, 6);
            return string.Create(CultureInfo.InvariantCulture, $"SQL Server {v[0]}.{v[1]}.{BinaryPrimitives.ReadUInt16BigEndian(v[2..])}");
        }

        return "SQL Server";
    }

    private static async Task<string?> SmbNegotiateAsync(Stream stream, CancellationToken ct)
    {
        ushort[] dialects = [0x0202, 0x0210, 0x0300, 0x0302];
        var body = new byte[36 + (dialects.Length * 2)];
        BinaryPrimitives.WriteUInt16LittleEndian(body, 36);
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(2), (ushort)dialects.Length);
        BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(4), 1); // signing enabled
        RandomNumberGenerator.Fill(body.AsSpan(12, 16)); // client GUID
        for (var i = 0; i < dialects.Length; i++) BinaryPrimitives.WriteUInt16LittleEndian(body.AsSpan(36 + (i * 2)), dialects[i]);
        var header = new byte[64];
        header[0] = 0xFE;
        header[1] = (byte)'S';
        header[2] = (byte)'M';
        header[3] = (byte)'B';
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(4), 64);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(14), 1); // credits requested
        var message = header.Concat(body).ToArray();
        var frame = new byte[4 + message.Length];
        frame[1] = (byte)(message.Length >> 16);
        frame[2] = (byte)(message.Length >> 8);
        frame[3] = (byte)message.Length;
        message.CopyTo(frame, 4);
        await stream.WriteAsync(frame, ct).ConfigureAwait(false);
        return DescribeSmb(await ReadSomeAsync(stream, ct).ConfigureAwait(false));
    }

    internal static string? DescribeSmb(byte[] r)
    {
        if (r.Length < 8) return null;
        var m = r.AsSpan(4);
        if (m[0] == 0xFF && m[1] == (byte)'S') return "SMB1 only";
        if (m.Length < 64 + 6 || m[0] != 0xFE || m[1] != (byte)'S') return null;
        var status = BinaryPrimitives.ReadUInt32LittleEndian(m[8..]);
        if (status != 0) return string.Create(CultureInfo.InvariantCulture, $"SMB2 (negotiate status 0x{status:X8})");
        var dialect = BinaryPrimitives.ReadUInt16LittleEndian(m[(64 + 4)..]);
        var signing = BinaryPrimitives.ReadUInt16LittleEndian(m[(64 + 2)..]);
        var name = dialect switch
        {
            0x0202 => "SMB 2.0.2",
            0x0210 => "SMB 2.1",
            0x0300 => "SMB 3.0",
            0x0302 => "SMB 3.0.2",
            0x0311 => "SMB 3.1.1",
            _ => string.Create(CultureInfo.InvariantCulture, $"SMB dialect 0x{dialect:X4}"),
        };
        return name + ((signing & 0x02) != 0 ? ", signing required" : "");
    }

    private static async Task<string?> MqttConnectAsync(Stream stream, CancellationToken ct)
    {
        var clientId = Encoding.ASCII.GetBytes("ipmaster-" + RandomNumberGenerator.GetHexString(8, true));
        byte[] variable = [0x00, 0x04, (byte)'M', (byte)'Q', (byte)'T', (byte)'T', 0x04, 0x02, 0x00, 0x3C];
        var payload = new byte[2 + clientId.Length];
        BinaryPrimitives.WriteUInt16BigEndian(payload, (ushort)clientId.Length);
        clientId.CopyTo(payload, 2);
        var remaining = variable.Length + payload.Length;
        byte[] packet = [0x10, (byte)remaining, .. variable, .. payload];
        await stream.WriteAsync(packet, ct).ConfigureAwait(false);
        var r = await ReadSomeAsync(stream, ct).ConfigureAwait(false);
        if (r.Length < 4 || r[0] != 0x20) return null;
        var rc = r[3];
        if (rc == 0) await stream.WriteAsync(new byte[] { 0xE0, 0x00 }, ct).ConfigureAwait(false); // DISCONNECT
        return rc switch
        {
            0 => "MQTT broker (anonymous connection accepted)",
            4 or 5 => "MQTT broker (authentication required)",
            _ => string.Create(CultureInfo.InvariantCulture, $"MQTT broker (CONNACK code {rc})"),
        };
    }

    private static string Clean(string s)
    {
        var sb = new StringBuilder(Math.Min(s.Length, 200));
        foreach (var c in s)
        {
            if (sb.Length >= 200) break;
            sb.Append(char.IsControl(c) ? ' ' : c);
        }

        return sb.ToString().Trim();
    }
}
