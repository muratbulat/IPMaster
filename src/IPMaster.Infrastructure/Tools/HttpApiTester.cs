using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace IPMaster.Infrastructure.Tools;

public enum HttpAuthKind
{
    None,
    Basic,
    Bearer,
}

public enum HttpBodyKind
{
    None,
    Text,
    Json,
    FormUrlEncoded,
    Multipart,
}

public enum HttpProxyMode
{
    System,
    None,
    Custom,
}

public sealed record HttpTestRequest
{
    public string Method { get; init; } = "GET";

    public required string Url { get; init; }

    public IReadOnlyList<KeyValuePair<string, string>> Parameters { get; init; } = [];

    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = [];

    public HttpAuthKind Auth { get; init; }

    public string UserName { get; init; } = "";

    /// <summary>Password (Basic) or token (Bearer). Session-only; never written to reports.</summary>
    public string Secret { get; init; } = "";

    public HttpBodyKind BodyKind { get; init; }

    public string BodyText { get; init; } = "";

    /// <summary>Form fields (urlencoded/multipart). For multipart, a value starting with "@" is a local file path.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Form { get; init; } = [];

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(30);

    public int MaxRedirects { get; init; } = 5;

    public HttpProxyMode Proxy { get; init; }

    public string ProxyUrl { get; init; } = "";

    public bool UseCookies { get; init; }

    public bool ValidateCertificate { get; init; } = true;

    public long MaxResponseBytes { get; init; } = 10 * 1024 * 1024;
}

public enum HttpTestOutcome
{
    /// <summary>A response arrived (any status, including 4xx/5xx).</summary>
    Response,
    Timeout,
    TransportError,
    InvalidRequest,
    Cancelled,
}

public sealed record HttpHop(string Method, string Url, int? Status, string? Location, string Note);

public sealed record HttpTestResult(
    HttpTestOutcome Outcome,
    string Detail,
    int? Status,
    string? Reason,
    string? Version,
    IReadOnlyList<KeyValuePair<string, string>> Headers,
    string? ContentType,
    byte[] Body,
    bool BodyTruncated,
    IReadOnlyList<HttpHop> Redirects,
    TimeSpan Total,
    TimeSpan? ConnectionSetup,
    TimeSpan? TimeToHeaders,
    TimeSpan? BodyDownload,
    IReadOnlyList<string> Diagnostics);

/// <summary>
/// HTTP / API Tester (D-076). Redirects are followed by hand so every hop is visible and credentials can be removed on a
/// change of origin; a redirect that would resend a state-changing request body is reported, not followed. Requests are
/// never retried automatically. Reports redact credentials and secret-looking headers and parameters.
/// </summary>
public sealed class HttpApiTester : IDisposable
{
    public static readonly IReadOnlyList<string> Methods = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

    private readonly CookieContainer _cookies = new();
    private SocketsHttpHandler? _handler;
    private HttpClient? _client;
    private (HttpProxyMode, string, bool, bool) _config;
    private TimeSpan? _lastConnect;
    private bool _acceptInvalidCertificates;
    private System.Net.Security.SslPolicyErrors _ignoredCertificateErrors;

    /// <summary>Session cookies kept between requests of this window (when enabled).</summary>
    public CookieContainer Cookies => _cookies;

    private HttpClient Client(HttpTestRequest r)
    {
        var config = (r.Proxy, r.ProxyUrl, r.UseCookies, r.ValidateCertificate);
        if (_client is not null && _config == config) return _client;
        _client?.Dispose();
        _handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = r.UseCookies,
            CookieContainer = _cookies,
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            UseProxy = r.Proxy != HttpProxyMode.None,
            Proxy = r.Proxy == HttpProxyMode.Custom && Uri.TryCreate(r.ProxyUrl, UriKind.Absolute, out var p) ? new WebProxy(p) : null,
            // measures DNS + TCP connect of new connections (reused connections report none)
            ConnectCallback = async (ctx, ct) =>
            {
                var sw = Stopwatch.StartNew();
                var s = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await s.ConnectAsync(ctx.DnsEndPoint, ct).ConfigureAwait(false);
                    _lastConnect = sw.Elapsed;
                    return new NetworkStream(s, ownsSocket: true);
                }
                catch
                {
                    s.Dispose();
                    throw;
                }
            },
        };
        _acceptInvalidCertificates = !r.ValidateCertificate;
        _handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, errors) =>
        {
            _ignoredCertificateErrors = errors;
            return errors == System.Net.Security.SslPolicyErrors.None || _acceptInvalidCertificates; // the user turned validation off: shown as a banner and in the report
        };
        _client = new HttpClient(_handler) { Timeout = Timeout.InfiniteTimeSpan };
        _config = config;
        return _client;
    }

    public static string BuildUrl(string url, IReadOnlyList<KeyValuePair<string, string>> parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        var list = parameters.Where(p => p.Key.Length > 0).ToList();
        if (list.Count == 0) return url;
        var q = string.Join("&", list.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        var hash = url.IndexOf('#', StringComparison.Ordinal);
        var fragment = hash >= 0 ? url[hash..] : "";
        var baseUrl = hash >= 0 ? url[..hash] : url;
        return baseUrl + (baseUrl.Contains('?', StringComparison.Ordinal) ? "&" : "?") + q + fragment;
    }

    public async Task<HttpTestResult> SendAsync(HttpTestRequest r, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(r);
        var diagnostics = new List<string>();
        var hops = new List<HttpHop>();
        var total = Stopwatch.StartNew();
        HttpTestResult Fail(HttpTestOutcome o, string detail) => new(o, detail, null, null, null, [], null, [], false, hops, total.Elapsed, _lastConnect, null, null, diagnostics);
        if (!Methods.Contains(r.Method)) return Fail(HttpTestOutcome.InvalidRequest, "Unsupported method.");
        if (!Uri.TryCreate(BuildUrl(r.Url.Trim(), r.Parameters), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
        {
            return Fail(HttpTestOutcome.InvalidRequest, "Enter an absolute http:// or https:// URL.");
        }

        if (r.Auth == HttpAuthKind.Basic && uri.Scheme == "http") diagnostics.Add("⚠ Basic authentication over plain HTTP sends the password readable on the network.");
        if (!r.ValidateCertificate) diagnostics.Add("⚠ Certificate validation is OFF for this request: any server certificate is accepted.");
        var client = Client(r);
        var method = new HttpMethod(r.Method);
        var origin = Origin(uri);
        var sendAuth = r.Auth != HttpAuthKind.None;
        var keepBody = true;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(r.Timeout);
        try
        {
            for (var hop = 0; ; hop++)
            {
                _lastConnect = null;
                using var request = new HttpRequestMessage(method, uri);
                foreach (var (k, v) in r.Headers.Where(h => h.Key.Trim().Length > 0))
                {
                    if (!sendAuth && IsCredentialHeader(k)) continue; // removed after a cross-origin redirect
                    if (!request.Headers.TryAddWithoutValidation(k.Trim(), v)) diagnostics.Add($"Header '{k}' is a content header; it is sent with the body.");
                }

                if (sendAuth)
                {
                    request.Headers.Authorization = r.Auth == HttpAuthKind.Basic
                        ? new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(r.UserName + ":" + r.Secret)))
                        : new AuthenticationHeaderValue("Bearer", r.Secret);
                }

                if (keepBody) request.Content = Content(r, diagnostics);
                if (request.Content is not null)
                {
                    foreach (var (k, v) in r.Headers.Where(h => h.Key.Trim().Length > 0 && h.Key.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)))
                    {
                        request.Content.Headers.Remove(k.Trim());
                        request.Content.Headers.TryAddWithoutValidation(k.Trim(), v);
                    }
                }

                var headersWatch = Stopwatch.StartNew();
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                var toHeaders = headersWatch.Elapsed;
                var status = (int)response.StatusCode;
                var location = response.Headers.Location;
                if (status is 301 or 302 or 303 or 307 or 308 && location is not null)
                {
                    var next = location.IsAbsoluteUri ? location : new Uri(uri, location);
                    if (hop >= r.MaxRedirects)
                    {
                        hops.Add(new HttpHop(method.Method, Redact(uri.ToString()), status, Redact(next.ToString()), "redirect limit reached; not followed"));
                        return await ReadAsync(response, r, hops, total, toHeaders, diagnostics, cts.Token).ConfigureAwait(false);
                    }

                    var stateChanging = method != HttpMethod.Get && method != HttpMethod.Head && method != HttpMethod.Options;
                    if (status is 307 or 308 && stateChanging)
                    {
                        hops.Add(new HttpHop(method.Method, Redact(uri.ToString()), status, Redact(next.ToString()), "not followed: it would resend the " + method.Method + " request"));
                        return await ReadAsync(response, r, hops, total, toHeaders, diagnostics, cts.Token).ConfigureAwait(false);
                    }

                    var note = "";
                    if (status is 301 or 302 or 303 && method != HttpMethod.Get && method != HttpMethod.Head)
                    {
                        method = HttpMethod.Get; // RFC 9110: 303 (and in practice 301/302) continue with GET, without the body
                        keepBody = false;
                        note = "continued as GET without the body";
                    }

                    if (sendAuth && Origin(next) != origin)
                    {
                        sendAuth = false;
                        note = (note.Length > 0 ? note + "; " : "") + "credentials removed (different origin)";
                    }

                    if (uri.Scheme == "https" && next.Scheme == "http") note = (note.Length > 0 ? note + "; " : "") + "⚠ downgrade to plain HTTP";
                    hops.Add(new HttpHop(method.Method, Redact(uri.ToString()), status, Redact(next.ToString()), note));
                    uri = next;
                    continue;
                }

                return await ReadAsync(response, r, hops, total, toHeaders, diagnostics, cts.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Fail(HttpTestOutcome.Cancelled, "Cancelled.");
        }
        catch (OperationCanceledException)
        {
            return Fail(HttpTestOutcome.Timeout, $"No complete response within {r.Timeout.TotalSeconds:0} s.");
        }
        catch (HttpRequestException ex)
        {
            return Fail(HttpTestOutcome.TransportError, $"{ex.HttpRequestError}: {(ex.InnerException?.Message ?? ex.Message)}");
        }
        catch (IOException ex)
        {
            return Fail(HttpTestOutcome.TransportError, ex.Message);
        }
    }

    private async Task<HttpTestResult> ReadAsync(HttpResponseMessage response, HttpTestRequest r, List<HttpHop> hops, Stopwatch total, TimeSpan toHeaders, List<string> diagnostics,
        CancellationToken ct)
    {
        var bodyWatch = Stopwatch.StartNew();
        var connect = _lastConnect;
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        var truncated = false;
        int n;
        while ((n = await stream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            var room = r.MaxResponseBytes - ms.Length;
            if (n > room)
            {
                ms.Write(buffer, 0, (int)Math.Max(0, room));
                truncated = true;
                break;
            }

            ms.Write(buffer, 0, n);
        }

        if (truncated) diagnostics.Add($"Body truncated at the {r.MaxResponseBytes:N0}-byte limit.");
        if (_acceptInvalidCertificates && _ignoredCertificateErrors != System.Net.Security.SslPolicyErrors.None) diagnostics.Add("⚠ Certificate problems ignored (validation off): " + _ignoredCertificateErrors);
        var headers = response.Headers.Concat(response.Content.Headers)
            .SelectMany(h => h.Value.Select(v => new KeyValuePair<string, string>(h.Key, v))).ToList();
        return new HttpTestResult(HttpTestOutcome.Response, "", (int)response.StatusCode, response.ReasonPhrase, "HTTP/" + response.Version.ToString(2), headers,
            response.Content.Headers.ContentType?.ToString(), ms.ToArray(), truncated, hops, total.Elapsed, connect, toHeaders, bodyWatch.Elapsed, diagnostics);
    }

    private static HttpContent? Content(HttpTestRequest r, List<string> diagnostics)
    {
        switch (r.BodyKind)
        {
            case HttpBodyKind.Text:
                return new StringContent(r.BodyText, Encoding.UTF8, "text/plain");
            case HttpBodyKind.Json:
                try
                {
                    using var _ = JsonDocument.Parse(r.BodyText);
                }
                catch (JsonException ex)
                {
                    diagnostics.Add("⚠ The JSON body is not valid JSON: " + ex.Message);
                }

                return new StringContent(r.BodyText, Encoding.UTF8, "application/json");
            case HttpBodyKind.FormUrlEncoded:
                return new FormUrlEncodedContent(r.Form.Where(f => f.Key.Length > 0));
            case HttpBodyKind.Multipart:
                var m = new MultipartFormDataContent();
                foreach (var (k, v) in r.Form.Where(f => f.Key.Length > 0))
                {
                    if (v.StartsWith('@') && File.Exists(v[1..]))
                    {
                        m.Add(new ByteArrayContent(File.ReadAllBytes(v[1..])), k, Path.GetFileName(v[1..]));
                    }
                    else
                    {
                        m.Add(new StringContent(v), k);
                    }
                }

                return m;
            default:
                return null;
        }
    }

    private static string Origin(Uri u) => $"{u.Scheme}://{u.IdnHost}:{u.Port.ToString(CultureInfo.InvariantCulture)}".ToLowerInvariant();

    public static bool IsCredentialHeader(string name) =>
        name.Trim().ToLowerInvariant() is "authorization" or "proxy-authorization" or "cookie" || IsSecretName(name);

    /// <summary>Header or parameter names whose values are treated as secrets in reports.</summary>
    public static bool IsSecretName(string name)
    {
        var n = name.Trim().ToLowerInvariant();
        return n is "authorization" or "proxy-authorization" or "cookie" or "set-cookie" || n.Contains("token", StringComparison.Ordinal) || n.Contains("secret", StringComparison.Ordinal)
               || n.Contains("password", StringComparison.Ordinal) || n.Contains("api-key", StringComparison.Ordinal) || n.Contains("apikey", StringComparison.Ordinal)
               || n.Contains("api_key", StringComparison.Ordinal) || n == "key" || n.Contains("signature", StringComparison.Ordinal);
    }

    /// <summary>URL with user info and secret-looking query values replaced.</summary>
    public static string Redact(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u)) return url;
        var b = new UriBuilder(u) { UserName = u.UserInfo.Length > 0 ? "[redacted]" : "", Password = "" };
        if (u.Query.Length > 1)
        {
            b.Query = string.Join("&", u.Query[1..].Split('&').Select(p =>
            {
                var eq = p.IndexOf('=', StringComparison.Ordinal);
                var key = Uri.UnescapeDataString(eq < 0 ? p : p[..eq]);
                return eq >= 0 && IsSecretName(key) ? p[..eq] + "=[redacted]" : p;
            }));
        }

        return b.Uri.ToString();
    }

    public static string FormatBody(HttpTestResult r, bool pretty)
    {
        ArgumentNullException.ThrowIfNull(r);
        if (r.Body.Length == 0) return "";
        var isText = r.ContentType is null || r.ContentType.Contains("text", StringComparison.OrdinalIgnoreCase) || r.ContentType.Contains("json", StringComparison.OrdinalIgnoreCase)
                     || r.ContentType.Contains("xml", StringComparison.OrdinalIgnoreCase) || r.ContentType.Contains("javascript", StringComparison.OrdinalIgnoreCase)
                     || r.ContentType.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase);
        if (!isText) return $"[binary content, {r.Body.Length:N0} bytes ({r.ContentType}); use Save Body to download it]";
        var text = Encoding.UTF8.GetString(r.Body);
        if (pretty && (r.ContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true || text.TrimStart().StartsWith('{') || text.TrimStart().StartsWith('[')))
        {
            try
            {
                using var doc = JsonDocument.Parse(text);
                return JsonSerializer.Serialize(doc.RootElement, PrettyJson);
            }
            catch (JsonException)
            {
                return text;
            }
        }

        return text;
    }

    private static readonly JsonSerializerOptions PrettyJson = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    /// <summary>Response headers for display/export: secret-looking values redacted.</summary>
    public static string HeadersText(HttpTestResult r) =>
        string.Join("\n", r.Headers.Select(h => $"{h.Key}: {(IsSecretName(h.Key) ? "[redacted]" : h.Value)}"));

    public static string Report(HttpTestRequest q, HttpTestResult r)
    {
        ArgumentNullException.ThrowIfNull(q);
        ArgumentNullException.ThrowIfNull(r);
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine(c, $"{q.Method} {Redact(BuildUrl(q.Url.Trim(), q.Parameters))}");
        foreach (var (k, v) in q.Headers.Where(h => h.Key.Trim().Length > 0)) sb.AppendLine(c, $"  {k}: {(IsSecretName(k) ? "[redacted]" : v)}");
        if (q.Auth != HttpAuthKind.None) sb.AppendLine(c, $"  Authorization: {q.Auth} [redacted]");
        sb.AppendLine();
        sb.AppendLine(r.Outcome == HttpTestOutcome.Response
            ? $"Response: {r.Status} {r.Reason} ({r.Version}){(r.Status >= 400 ? " — an HTTP error response (the request reached the server)" : "")}"
            : $"No response: {r.Outcome} — {r.Detail}");
        var setup = r.ConnectionSetup is { } cs ? string.Create(c, $"; new connection (DNS + TCP): {cs.TotalMilliseconds:0} ms") : "; connection reused or not measured";
        var headersAt = r.TimeToHeaders is { } th ? string.Create(c, $"; headers after {th.TotalMilliseconds:0} ms") : "";
        var bodyTime = r.BodyDownload is { } bd ? string.Create(c, $"; body {bd.TotalMilliseconds:0} ms") : "";
        sb.AppendLine(c, $"Total: {r.Total.TotalMilliseconds:0} ms{setup}{headersAt}{bodyTime}");
        if (r.Outcome == HttpTestOutcome.Response) sb.AppendLine(c, $"Body: {r.Body.Length:N0} bytes after decoding{(r.BodyTruncated ? " (truncated at the limit)" : "")}; Content-Type: {r.ContentType ?? "(none)"}");
        foreach (var h in r.Redirects) sb.AppendLine(c, $"Redirect: {h.Method} {h.Url} → {h.Status} → {h.Location}{(h.Note.Length > 0 ? " (" + h.Note + ")" : "")}");
        foreach (var d in r.Diagnostics) sb.AppendLine(d);
        if (r.Headers.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine(HeadersText(r));
        }

        return sb.ToString();
    }

    public void Dispose()
    {
        _client?.Dispose();
        _handler?.Dispose();
    }
}
