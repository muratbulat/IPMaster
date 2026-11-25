using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using IPMaster.Core.Management;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure.Management;
using Renci.SshNet;
using Renci.SshNet.Common;

namespace IPMaster.Infrastructure.Queries;

/// <summary>Remote XML / JSON (HTP-01/02): one GET, bounded body, TLS verified unless the query has the lab exception.</summary>
public sealed class HttpQueryProvider(QueryKind kind) : IRemoteQueryProvider
{
    public const int MaxBody = 2 * 1024 * 1024;

    public QueryKind Kind { get; } = kind;

    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("HTTP/HTTPS.");

    public static Uri BuildUri(IPAddress address, HttpOptions o)
    {
        ArgumentNullException.ThrowIfNull(o);
        var path = string.IsNullOrEmpty(o.Path) ? "/" : o.Path.StartsWith('/') ? o.Path : "/" + o.Path;
        return new Uri(DeviceUrls.For(o.UseHttps ? "https" : "http", address, o.Port).TrimEnd('/') + path);
    }

    /// <summary>Fetches the response text (also used by the JSON/Redfish query builders).</summary>
    public static async Task<(HttpStatusCode Status, string Body)> FetchAsync(Uri uri, Core.Security.ResolvedCredential? basic, bool acceptInvalidCertificates,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(uri);
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10), UseCookies = false };
        if (acceptInvalidCertificates)
        {
#pragma warning disable CA5359 // explicit per-query lab exception; off by default and shown as a warning in the editor
            handler.SslOptions.RemoteCertificateValidationCallback = static (_, _, _, _) => true;
#pragma warning restore CA5359
        }
        using var http = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        req.Headers.UserAgent.ParseAdd("IPMaster/" + (typeof(HttpQueryProvider).Assembly.GetName().Version?.ToString(3) ?? "0"));
        req.Headers.Accept.ParseAdd("application/json, application/xml, text/xml, text/html;q=0.8, */*;q=0.5");
        if (basic is not null)
        {
            if (uri.Scheme != Uri.UriSchemeHttps && !IPAddress.TryParse(uri.Host.Trim('[', ']'), out _))
            {
                // never send Basic credentials in clear text to a name we did not scan
                throw new InvalidOperationException("Basic authentication over HTTP is only sent to scanned IP addresses.");
            }

            req.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{basic.UserName}:{basic.Password}")));
        }

        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if ((int)resp.StatusCode is >= 300 and < 400)
        {
            throw new HttpRequestException($"Redirected to {resp.Headers.Location} (redirects are not followed; adjust port/path/HTTPS).", null, resp.StatusCode);
        }

        return (resp.StatusCode, await Bounded.ReadAsync(resp, MaxBody, ct).ConfigureAwait(false));
    }

    public async Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var o = call.Query.Http ?? new HttpOptions();
        var basic = o.BasicAuthentication ? call.Credential : null;
        var now = DateTimeOffset.UtcNow;
        if (o.BasicAuthentication && basic is null) return Observation<string>.Of(ObservationState.Failed, now, "Basic authentication needs a credential.");
        try
        {
            var (status, body) = await FetchAsync(BuildUri(call.Device.Address, o), basic, o.AcceptInvalidCertificates, cancellationToken).ConfigureAwait(false);
            now = DateTimeOffset.UtcNow;
            if (status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) return Observation<string>.Of(ObservationState.AccessDenied, now, $"HTTP {(int)status}");
            if ((int)status >= 400) return Observation<string>.Of(ObservationState.Failed, now, $"HTTP {(int)status} {status}");
            var values = Extract(body, o);
            return values.Count == 0 ? Observation<string>.Of(ObservationState.Empty, now, "The expression matched nothing.") : Observation<string>.Ok(string.Join('\n', values), now);
        }
        catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
        {
            return Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, "TLS certificate not trusted: " + ex.InnerException.Message);
        }
        catch (HttpRequestException ex) when (ex.InnerException is System.Net.Sockets.SocketException)
        {
            return Observation<string>.Of(ObservationState.NoResponse, DateTimeOffset.UtcNow, ex.Message);
        }
        catch (Exception ex) when (ex is HttpRequestException or FormatException or System.Xml.XmlException or InvalidOperationException)
        {
            return Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, ex.Message);
        }
    }

    public static IReadOnlyList<string> Extract(string body, HttpOptions o)
    {
        ArgumentNullException.ThrowIfNull(o);
        if (string.IsNullOrWhiteSpace(o.Expression)) return [body.Trim()];
        return o.Extraction switch
        {
            HttpExtraction.XPath => Extraction.XPath(body, o.Expression),
            HttpExtraction.JsonPath => Extraction.JsonPath(body, o.Expression),
            _ => Extraction.Regex(body, o.Expression),
        };
    }
}

/// <summary>
/// SSH host keys (SSH-02): keys trusted in IPMaster plus the user's OpenSSH known_hosts (plain and hashed entries).
/// Trust-on-first-use additions are reported through <see cref="Trusted"/> so the owner can persist them.
/// </summary>
public sealed class KnownHostStore
{
    private readonly object _lock = new();
    private List<KnownHostKey> _keys = [];

    public event EventHandler<KnownHostKey>? Trusted;

    public IReadOnlyList<KnownHostKey> All
    {
        get
        {
            lock (_lock) return _keys.ToList();
        }
    }

    public void Load(IEnumerable<KnownHostKey> keys)
    {
        lock (_lock) _keys = keys.ToList();
    }

    public enum Verdict
    {
        Trusted,
        Unknown,
        Changed,
    }

    public Verdict Check(string host, int port, string algorithm, string fingerprint)
    {
        lock (_lock)
        {
            var mine = _keys.Where(k => k.Port == port && string.Equals(k.Host, host, StringComparison.OrdinalIgnoreCase)).ToList();
            if (mine.Any(k => k.Fingerprint == fingerprint)) return Verdict.Trusted;
            // any other key on record for this host (whatever its algorithm) means the host identity changed (review C-08)
            if (mine.Count > 0) return Verdict.Changed;
        }

        foreach (var (alg, fp) in OpenSshKnownHosts(host, port))
        {
            if (fp == fingerprint) return Verdict.Trusted;
        }

        return OpenSshKnownHosts(host, port).Any() ? Verdict.Changed : Verdict.Unknown;
    }

    public void Trust(KnownHostKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        lock (_lock)
        {
            _keys.RemoveAll(k => k.Port == key.Port && k.Algorithm == key.Algorithm && string.Equals(k.Host, key.Host, StringComparison.OrdinalIgnoreCase));
            _keys.Add(key);
        }

        Trusted?.Invoke(this, key);
    }

    /// <summary>Entries of ~/.ssh/known_hosts for this host: (algorithm, SHA256 fingerprint).</summary>
    public static IEnumerable<(string Algorithm, string Fingerprint)> OpenSshKnownHosts(string host, int port, string? path = null)
    {
        path ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh", "known_hosts");
        if (!File.Exists(path) || new FileInfo(path).Length > 4 * 1024 * 1024) yield break;
        var names = port == 22 ? new[] { host } : [$"[{host}]:{port}"];
        foreach (var raw in File.ReadLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#' || line.StartsWith('@')) continue;
            var f = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (f.Length < 3) continue;
            if (!f[0].Split(',').Any(p => names.Any(n => MatchesHost(p, n)))) continue;
            byte[] blob;
            try
            {
                blob = Convert.FromBase64String(f[2]);
            }
            catch (FormatException)
            {
                continue;
            }

            yield return (f[1], Fingerprint(blob));
        }
    }

    private static bool MatchesHost(string pattern, string name)
    {
        if (pattern.StartsWith("|1|", StringComparison.Ordinal))
        {
            var parts = pattern.Split('|');
            if (parts.Length != 4) return false;
            try
            {
#pragma warning disable CA5350 // OpenSSH HashKnownHosts format is defined with HMAC-SHA1
                var h = HMACSHA1.HashData(Convert.FromBase64String(parts[2]), Encoding.ASCII.GetBytes(name));
#pragma warning restore CA5350
                return Convert.ToBase64String(h) == parts[3];
            }
            catch (FormatException)
            {
                return false;
            }
        }

        return string.Equals(pattern, name, StringComparison.OrdinalIgnoreCase);
    }

    public static string Fingerprint(byte[] keyBlob) => Convert.ToBase64String(SHA256.HashData(keyBlob)).TrimEnd('=');
}

/// <summary>Remote SSH (SSH-01/02): one command per item; password or private-key authentication; host keys verified.</summary>
public sealed class SshQueryProvider(KnownHostStore knownHosts) : IRemoteQueryProvider
{
    public const int MaxOutput = 1024 * 1024;

    public QueryKind Kind => QueryKind.Ssh;

    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("SSH (SSH.NET).");

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var o = call.Query.Ssh ?? new SshOptions();
        if (call.Credential is null) return Task.FromResult(Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, "SSH needs a credential."));
        return RunAsync(call.Device.Address.ToString(), o.Port, call.Credential, o.Command, o.HostKeys, TimeSpan.FromSeconds(Math.Max(1, call.Query.TimeoutSeconds)),
            cancellationToken);
    }

    /// <summary>Also used by the editor's Run against a chosen host.</summary>
    public async Task<Observation<string>> RunAsync(string host, int port, Core.Security.ResolvedCredential credential, string command, HostKeyPolicy policy,
        TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(credential);
        AuthenticationMethod auth;
        var secret = credential.Password;
        // Manual: a password field that holds a path to an existing file switches to public-key authentication.
        if (secret.Length > 0 && secret.Length < 1024 && secret.IndexOfAny(Path.GetInvalidPathChars()) < 0 && File.Exists(secret))
        {
            try
            {
                auth = new PrivateKeyAuthenticationMethod(credential.UserName, new PrivateKeyFile(secret));
            }
            catch (SshException ex)
            {
                return Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, "Private key could not be read (encrypted keys are not supported): " + ex.Message);
            }
        }
        else
        {
            auth = new PasswordAuthenticationMethod(credential.UserName, secret);
        }

        var info = new ConnectionInfo(host, port, credential.UserName, auth) { Timeout = timeout };
        using var client = new SshClient(info);
        string? hostKeyProblem = null;
        client.HostKeyReceived += (_, e) =>
        {
            var verdict = knownHosts.Check(host, port, e.HostKeyName, e.FingerPrintSHA256);
            switch (verdict)
            {
                case KnownHostStore.Verdict.Trusted:
                    e.CanTrust = true;
                    break;
                case KnownHostStore.Verdict.Changed:
                    e.CanTrust = policy == HostKeyPolicy.AcceptAny;
                    if (!e.CanTrust) hostKeyProblem = $"HOST KEY CHANGED for {host}:{port} ({e.HostKeyName} SHA256:{e.FingerPrintSHA256}). Connection refused.";
                    break;
                default:
                    if (policy == HostKeyPolicy.Strict)
                    {
                        e.CanTrust = false;
                        hostKeyProblem = $"Unknown host key {e.HostKeyName} SHA256:{e.FingerPrintSHA256}. Trust it in the SSH editor (Run) or use trust-on-first-use.";
                    }
                    else
                    {
                        e.CanTrust = true;
                        if (policy == HostKeyPolicy.TrustOnFirstUse)
                        {
                            knownHosts.Trust(new KnownHostKey { Host = host, Port = port, Algorithm = e.HostKeyName, Fingerprint = e.FingerPrintSHA256 });
                        }
                    }

                    break;
            }
        };

        try
        {
            await client.ConnectAsync(ct).ConfigureAwait(false);
            using var cmd = client.CreateCommand(command);
            cmd.CommandTimeout = timeout;
            await cmd.ExecuteAsync(ct).ConfigureAwait(false);
            var text = cmd.Result ?? "";
            if (text.Length > MaxOutput) text = text[..MaxOutput];
            var clean = AnsiText.Strip(text);
            var now = DateTimeOffset.UtcNow;
            if (clean.Length == 0 && cmd.ExitStatus is { } code && code != 0)
            {
                return Observation<string>.Of(ObservationState.Failed, now, $"Exit status {code}: {AnsiText.Strip(cmd.Error ?? "")}");
            }

            return clean.Length == 0 ? Observation<string>.Of(ObservationState.Empty, now) : Observation<string>.Ok(clean, now);
        }
        catch (SshConnectionException ex) when (hostKeyProblem is not null)
        {
            _ = ex;
            return Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, hostKeyProblem);
        }
        catch (SshAuthenticationException ex)
        {
            return Observation<string>.Of(ObservationState.AccessDenied, DateTimeOffset.UtcNow, ex.Message);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            return Observation<string>.Of(ObservationState.NoResponse, DateTimeOffset.UtcNow, ex.Message);
        }
        catch (Exception ex) when (ex is SshException or ProxyException)
        {
            return Observation<string>.Of(ObservationState.Failed, DateTimeOffset.UtcNow, hostKeyProblem ?? ex.Message);
        }
    }

    /// <summary>Fetches the host key without authenticating (for the editor's trust prompt).</summary>
    public static async Task<(string Algorithm, string Fingerprint)?> ProbeHostKeyAsync(string host, int port, CancellationToken ct)
    {
        (string, string)? found = null;
        var info = new ConnectionInfo(host, port, "ipmaster-hostkey-probe", new NoneAuthenticationMethod("ipmaster-hostkey-probe")) { Timeout = TimeSpan.FromSeconds(10) };
        using var client = new SshClient(info);
        client.HostKeyReceived += (_, e) =>
        {
            found = (e.HostKeyName, e.FingerPrintSHA256);
            e.CanTrust = false;
        };
        try
        {
            await client.ConnectAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SshException or System.Net.Sockets.SocketException)
        {
            // expected: we refuse the key
        }

        return found;
    }
}
