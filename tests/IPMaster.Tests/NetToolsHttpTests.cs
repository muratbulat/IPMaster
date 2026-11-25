using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Minimal scripted HTTP/1.1 server on 127.0.0.1 (one request per connection). Test-only.</summary>
internal sealed class HttpFixture : IAsyncDisposable
{
    public sealed record Seen(string Method, string Target, Dictionary<string, string> Headers, string Body);

    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public HttpFixture(Func<Seen, string?> respond)
    {
        _l.Start();
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient c;
                try
                {
                    c = await _l.AcceptTcpClientAsync(_cts.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

                _ = Task.Run(async () =>
                {
                    using (c)
                    {
                        try
                        {
                            var s = c.GetStream();
                            var head = new StringBuilder();
                            var one = new byte[1];
                            while (!head.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal) && await s.ReadAsync(one) > 0) head.Append((char)one[0]);
                            var lines = head.ToString().Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                            var first = lines[0].Split(' ');
                            var headers = lines.Skip(1).Select(l => l.Split(':', 2)).ToDictionary(p => p[0].Trim(), p => p[1].Trim(), StringComparer.OrdinalIgnoreCase);
                            var body = "";
                            if (headers.TryGetValue("Content-Length", out var len) && int.Parse(len, System.Globalization.CultureInfo.InvariantCulture) > 0)
                            {
                                var buf = new byte[int.Parse(len, System.Globalization.CultureInfo.InvariantCulture)];
                                await s.ReadExactlyAsync(buf);
                                body = Encoding.UTF8.GetString(buf);
                            }

                            var seen = new Seen(first[0], first[1], headers, body);
                            Requests.Enqueue(seen);
                            if (respond(seen) is { } reply) await s.WriteAsync(Encoding.UTF8.GetBytes(reply));
                            else await Task.Delay(Timeout.Infinite, _cts.Token);
                        }
                        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
                        {
                        }
                    }
                });
            }
        });
    }

    public ConcurrentQueue<Seen> Requests { get; } = new();

    public string Base => $"http://127.0.0.1:{((IPEndPoint)_l.LocalEndpoint).Port}";

    public static string Response(int status, string reason, string body = "", string contentType = "text/plain", params string[] headers) =>
        $"HTTP/1.1 {status} {reason}\r\nContent-Type: {contentType}\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n{string.Concat(headers.Select(h => h + "\r\n"))}\r\n{body}";

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _l.Stop();
        await _loop;
    }
}

public class NetToolsHttpTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task Get_with_parameters_headers_and_json_formatting()
    {
        await using var f = new HttpFixture(_ => HttpFixture.Response(200, "OK", "{\"a\":1,\"b\":[true,null]}", "application/json"));
        using var t = new HttpApiTester();
        var r = await t.SendAsync(new HttpTestRequest
        {
            Url = f.Base + "/api", Parameters = [new("q", "a b&c"), new("n", "1")], Headers = [new("X-Trace", "abc")],
        }, Ct);
        Assert.Equal(HttpTestOutcome.Response, r.Outcome);
        Assert.Equal(200, r.Status);
        Assert.Equal("HTTP/1.1", r.Version);
        var seen = Assert.Single(f.Requests);
        Assert.Equal("/api?q=a%20b%26c&n=1", seen.Target);
        Assert.Equal("abc", seen.Headers["X-Trace"]);
        Assert.Contains("\n  \"a\": 1", HttpApiTester.FormatBody(r, pretty: true).Replace("\r\n", "\n", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.NotNull(r.TimeToHeaders);
    }

    [Fact]
    public async Task Http_error_status_is_a_response_not_a_transport_failure()
    {
        await using var f = new HttpFixture(_ => HttpFixture.Response(503, "Service Unavailable", "down"));
        using var t = new HttpApiTester();
        var r = await t.SendAsync(new HttpTestRequest { Url = f.Base + "/" }, Ct);
        Assert.Equal(HttpTestOutcome.Response, r.Outcome);
        Assert.Equal(503, r.Status);
        Assert.Contains("an HTTP error response", HttpApiTester.Report(new HttpTestRequest { Url = f.Base }, r), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Refused_and_silent_servers_are_transport_failure_and_timeout()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        using var t = new HttpApiTester();
        var refused = await t.SendAsync(new HttpTestRequest { Url = $"http://127.0.0.1:{port}/", Timeout = TimeSpan.FromSeconds(5) }, Ct);
        Assert.Equal(HttpTestOutcome.TransportError, refused.Outcome);
        Assert.Contains("ConnectionError", refused.Detail, StringComparison.Ordinal);

        await using var silent = new HttpFixture(_ => null);
        var timeout = await t.SendAsync(new HttpTestRequest { Url = silent.Base + "/", Timeout = TimeSpan.FromMilliseconds(600) }, Ct);
        Assert.Equal(HttpTestOutcome.Timeout, timeout.Outcome);
    }

    [Fact]
    public async Task Cross_origin_redirect_strips_credentials_same_origin_keeps_them()
    {
        await using var other = new HttpFixture(_ => HttpFixture.Response(200, "OK", "other"));
        await using var f = new HttpFixture(s => s.Target switch
        {
            "/start" => HttpFixture.Response(302, "Found", "", "text/plain", "Location: /same"),
            "/same" => HttpFixture.Response(302, "Found", "", "text/plain", "Location: " + other.Base + "/far"),
            _ => HttpFixture.Response(404, "Not Found"),
        });
        using var t = new HttpApiTester();
        var r = await t.SendAsync(new HttpTestRequest
        {
            Url = f.Base + "/start", Auth = HttpAuthKind.Bearer, Secret = "tok-123", Headers = [new("X-Api-Key", "k-456"), new("Accept", "*/*")],
        }, Ct);
        Assert.Equal(200, r.Status);
        Assert.Equal(2, r.Redirects.Count);
        var seen = f.Requests.ToList();
        Assert.Equal("Bearer tok-123", seen[0].Headers["Authorization"]);
        Assert.Equal("Bearer tok-123", seen[1].Headers["Authorization"]); // same origin
        var far = Assert.Single(other.Requests);
        Assert.False(far.Headers.ContainsKey("Authorization"));
        Assert.False(far.Headers.ContainsKey("X-Api-Key"));
        Assert.True(far.Headers.ContainsKey("Accept"));
        Assert.Contains("credentials removed", r.Redirects[1].Note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task State_changing_requests_are_not_resent_by_redirects()
    {
        await using var f = new HttpFixture(s => s.Target switch
        {
            "/p307" => HttpFixture.Response(307, "Temporary Redirect", "", "text/plain", "Location: /elsewhere"),
            "/p303" => HttpFixture.Response(303, "See Other", "", "text/plain", "Location: /result"),
            "/result" => HttpFixture.Response(200, "OK", "done"),
            _ => HttpFixture.Response(404, "Not Found"),
        });
        using var t = new HttpApiTester();
        var a = await t.SendAsync(new HttpTestRequest { Method = "POST", Url = f.Base + "/p307", BodyKind = HttpBodyKind.Json, BodyText = "{\"x\":1}" }, Ct);
        Assert.Equal(307, a.Status);
        Assert.Contains("not followed", a.Redirects.Single().Note, StringComparison.Ordinal);
        Assert.Single(f.Requests);

        var b = await t.SendAsync(new HttpTestRequest { Method = "POST", Url = f.Base + "/p303", BodyKind = HttpBodyKind.Json, BodyText = "{\"x\":1}" }, Ct);
        Assert.Equal(200, b.Status);
        var last = f.Requests.Last();
        Assert.Equal("GET", last.Method);
        Assert.Equal("", last.Body);
    }

    [Fact]
    public async Task Redirect_limit_and_body_bound()
    {
        await using var loop = new HttpFixture(_ => HttpFixture.Response(302, "Found", "", "text/plain", "Location: /again"));
        using var t = new HttpApiTester();
        var r = await t.SendAsync(new HttpTestRequest { Url = loop.Base + "/", MaxRedirects = 3 }, Ct);
        Assert.Equal(302, r.Status);
        Assert.Contains("limit", r.Redirects[^1].Note, StringComparison.Ordinal);
        Assert.Equal(4, loop.Requests.Count);

        await using var big = new HttpFixture(_ => HttpFixture.Response(200, "OK", new string('x', 5000)));
        var b = await t.SendAsync(new HttpTestRequest { Url = big.Base + "/", MaxResponseBytes = 1000 }, Ct);
        Assert.True(b.BodyTruncated);
        Assert.Equal(1000, b.Body.Length);
    }

    [Fact]
    public async Task Bodies_basic_auth_and_redaction()
    {
        await using var f = new HttpFixture(_ => HttpFixture.Response(200, "OK", "ok", "text/plain", "Set-Cookie: sid=s3cr3t"));
        using var t = new HttpApiTester();
        var form = new HttpTestRequest
        {
            Method = "POST", Url = f.Base + "/f?api_key=abc&page=2", BodyKind = HttpBodyKind.FormUrlEncoded, Form = [new("a", "1 2"), new("b", "x&y")],
            Auth = HttpAuthKind.Basic, UserName = "alice", Secret = "pa55",
        };
        var r = await t.SendAsync(form, Ct);
        var seen = f.Requests.Single();
        Assert.Equal("a=1+2&b=x%26y", seen.Body);
        Assert.StartsWith("application/x-www-form-urlencoded", seen.Headers["Content-Type"], StringComparison.Ordinal);
        Assert.Equal("Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:pa55")), seen.Headers["Authorization"]);
        var report = HttpApiTester.Report(form, r);
        Assert.DoesNotContain("pa55", report, StringComparison.Ordinal);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("alice:pa55")), report, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cr3t", report, StringComparison.Ordinal);
        Assert.Contains("api_key=[redacted]", report, StringComparison.Ordinal);
        Assert.Contains("page=2", report, StringComparison.Ordinal);

        var multi = await t.SendAsync(new HttpTestRequest { Method = "POST", Url = f.Base + "/m", BodyKind = HttpBodyKind.Multipart, Form = [new("field", "v")] }, Ct);
        Assert.StartsWith("multipart/form-data", f.Requests.Last().Headers["Content-Type"], StringComparison.Ordinal);
        Assert.Equal(200, multi.Status);
    }
}
