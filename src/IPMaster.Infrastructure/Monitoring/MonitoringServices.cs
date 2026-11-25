using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Security;
using IPMaster.Infrastructure.Management;
using IPMaster.Infrastructure.Queries;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace IPMaster.Infrastructure.Monitoring;

/// <summary>
/// Recognises the current LAN (HIS-01): fingerprint = MAC of the default gateway (stable across DHCP renumbering), else the
/// gateway address, else the first subnet; friendly name = Wi-Fi SSID, else the gateway's reverse DNS name, else the address.
/// </summary>
public sealed class NetworkIdentifier(INetworkAdapterProvider adapters, INeighborTable neighbors, IHostNameResolver dns)
{
    public async Task<NetworkIdentity> IdentifyAsync(CancellationToken ct)
    {
        var list = adapters.GetAdapters();
        var adapter = list.FirstOrDefault(a => a.Gateways.Any(IsUsableGateway)) ?? list.FirstOrDefault();
        var gw = adapter?.Gateways.FirstOrDefault(IsUsableGateway);
        if (adapter is null) return new NetworkIdentity("local", "Local computer");
        if (gw is null)
        {
            var a = adapter.IPv4.FirstOrDefault();
            return new NetworkIdentity("subnet:" + (a is null ? adapter.Id : $"{a.Address}/{a.PrefixLength}"), adapter.Name);
        }

        string? mac = null;
        if (neighbors.Capability.Available)
        {
            try
            {
                var n = (await neighbors.SnapshotAsync(ct).ConfigureAwait(false)).FirstOrDefault(x => x.Address.Equals(gw));
                if (n is not null && n.Mac.GetAddressBytes().Any(b => b != 0)) mac = Formats.Mac(n.Mac, ":").ToUpperInvariant();
            }
            catch (Exception ex) when (ex is InvalidOperationException or NetworkInformationException)
            {
                // no neighbour table: fall back to the address
            }
        }

        var name = adapter.Type.Contains("Wireless", StringComparison.OrdinalIgnoreCase) ? await SsidAsync(ct).ConfigureAwait(false) : null;
        if (name is null)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(3));
                name = await dns.ReverseLookupAsync(gw, cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                ct.ThrowIfCancellationRequested();
            }
        }

        return new NetworkIdentity(mac is null ? "gateway:" + gw : "gateway-mac:" + mac, name is { Length: > 0 } ? name : "Network " + gw) { Gateway = "gateway:" + gw };
    }

    private static bool IsUsableGateway(IPAddress g) => g.AddressFamily == AddressFamily.InterNetwork && !g.Equals(IPAddress.Any);

    /// <summary>SSID of the connected Wi-Fi network (Windows: netsh wlan; elsewhere not attempted).</summary>
    private static async Task<string?> SsidAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var r = await ProcessRunner.RunAsync(Path.Combine(Environment.SystemDirectory, "netsh.exe"), ["wlan", "show", "interfaces"], cts.Token, maxOutput: 64 * 1024,
                outputEncoding: Encoding.UTF8).ConfigureAwait(false);
            return ParseSsid(r.Output);
        }
        catch (Exception ex) when (ex is InvalidOperationException or OperationCanceledException or IOException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    public static string? ParseSsid(string netshOutput)
    {
        foreach (var line in (netshOutput ?? "").Split('\n'))
        {
            var t = line.Trim();
            var colon = t.IndexOf(':', StringComparison.Ordinal);
            if (colon > 0 && t[..colon].Trim() == "SSID") return t[(colon + 1)..].Trim() is { Length: > 0 } s ? s : null;
        }

        return null;
    }
}

/// <summary>ICMP traceroute (MON-04). Routers often rate-limit ICMP time-exceeded replies, so hop loss may not be real loss.</summary>
public sealed class RouteTracer : IRouteTracer
{
    public async Task<IReadOnlyList<RouteHop>> TraceAsync(IPAddress destination, int maxHops, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        var hops = new List<RouteHop>();
        using var ping = new Ping();
        for (var ttl = 1; ttl <= Math.Clamp(maxHops, 1, 64); ttl++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            PingReply reply;
            try
            {
                // default payload: the only one the system ping utility (unprivileged Linux/macOS) can send (D-067)
                reply = await ping.SendPingAsync(destination, timeout, null, new PingOptions(ttl, false), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is PingException or PlatformNotSupportedException)
            {
                hops.Add(new RouteHop(ttl, null, null));
                continue;
            }

            var answered = reply.Status is IPStatus.Success or IPStatus.TtlExpired or IPStatus.TimeExceeded;
            var addr = answered && !reply.Address.Equals(IPAddress.Any) ? reply.Address : null;
            hops.Add(new RouteHop(ttl, addr, answered ? reply.RoundtripTime : null));
            if (reply.Status == IPStatus.Success) break;
        }

        return hops;
    }
}

/// <summary>
/// Notification actions for background events (BKG-04): balloon (callback), sound, launch application, log to file, SMTP
/// e-mail (MailKit; certificates validated) and JSON webhook (HTTPS recommended, 10 s timeout, no redirects).
/// Failures are reported to the caller; an action never blocks the scan.
/// </summary>
public sealed partial class NotificationDispatcher(ISecretSource secrets)
{
    public Action<string, string>? Balloon { get; set; }

    public async Task<IReadOnlyList<string>> DispatchAsync(BackgroundEvent e, BackgroundSettings s, IReadOnlyList<ResultColumn> columns, ColumnFormat format,
        CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(s);
        var a = s.For(e.Type);
        var errors = new List<string>();
        if (!a.Enabled) return errors;
        var code = BackgroundEvent.Code(e.Type);
        if (a.Balloon) Balloon?.Invoke($"IPMaster: {code}", e.Message);
        if (a.PlaySound && a.SoundFile.Length > 0)
        {
            if (!OperatingSystem.IsWindows()) errors.Add("Sound: only on Windows in this build.");
            else if (!File.Exists(a.SoundFile)) errors.Add("Sound: file not found.");
            else _ = PlaySound(a.SoundFile, IntPtr.Zero, 0x00020001); // SND_FILENAME | SND_ASYNC
        }

        if (a.Launch && a.LaunchCommand.Length > 0)
        {
            var r = Shell.Launch(OfflineClearer.Expand(a.LaunchCommand, e, columns, format));
            if (!r.Success) errors.Add("Launch: " + r.Message);
        }

        if (a.LogToFile && a.LogFile.Length > 0)
        {
            try
            {
                await File.AppendAllTextAsync(a.LogFile, $"{e.At.ToLocalTime():yyyy-MM-dd HH:mm:ss}\t{code}\t{e.Address}\t{e.Message}{Environment.NewLine}", ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                errors.Add("Log file: " + ex.Message);
            }
        }

        if (a.Email && a.EmailTo.Length > 0)
        {
            try
            {
                await SendMailAsync(s.Smtp, a.EmailTo, $"IPMaster {code}: {e.Address}", Body(e, columns, format), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add("E-mail: " + ex.Message);
            }
        }

        if (a.Webhook && a.WebhookUrl.Length > 0)
        {
            try
            {
                await PostWebhookAsync(new Uri(a.WebhookUrl), Payload(e, columns, format), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or UriFormatException or TaskCanceledException or InvalidOperationException)
            {
                errors.Add("Webhook: " + ex.Message);
            }
        }

        return errors;
    }

    private static string Body(BackgroundEvent e, IReadOnlyList<ResultColumn> columns, ColumnFormat format)
    {
        var sb = new StringBuilder().AppendLine(e.Message).AppendLine().AppendLine(CultureInfo.InvariantCulture, $"Time: {e.At.ToLocalTime():yyyy-MM-dd HH:mm:ss zzz}");
        if (e.Device is { } d)
        {
            foreach (var c in columns)
            {
                var v = c.Text(d, format);
                if (v.Length > 0) sb.AppendLine(CultureInfo.InvariantCulture, $"{c.Header}: {v}");
            }
        }

        return sb.ToString();
    }

    /// <summary>JSON payload: event type, message, timestamp and the device's displayed column values.</summary>
    public static string Payload(BackgroundEvent e, IReadOnlyList<ResultColumn> columns, ColumnFormat format)
    {
        ArgumentNullException.ThrowIfNull(e);
        ArgumentNullException.ThrowIfNull(columns);
        using var ms = new MemoryStream();
        using (var w = new Utf8JsonWriter(ms))
        {
            w.WriteStartObject();
            w.WriteString("event", BackgroundEvent.Code(e.Type));
            w.WriteString("message", e.Message);
            w.WriteString("timestamp", e.At.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            w.WriteString("ip", e.Address.ToString());
            if (e.Mac is not null) w.WriteString("mac", Formats.Mac(e.Mac, ":"));
            w.WriteStartObject("device");
            if (e.Device is { } d)
            {
                foreach (var c in columns) w.WriteString(c.Header, c.Text(d, format));
            }

            w.WriteEndObject();
            w.WriteEndObject();
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    public static async Task PostWebhookAsync(Uri url, string json, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(url);
        if (url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp) throw new InvalidOperationException("Webhook URLs must use http or https.");
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(10) };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var content = new StringContent(json, Encoding.UTF8, "application/json");
        using var resp = await http.PostAsync(url, content, ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"HTTP {(int)resp.StatusCode}", null, resp.StatusCode);
    }

    /// <summary>Sends one message (also the E-mail settings "Test"). Certificate validation stays on.</summary>
    public async Task SendMailAsync(SmtpSettings smtp, string to, string subject, string body, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(smtp);
        if (string.IsNullOrWhiteSpace(smtp.Host)) throw new InvalidOperationException("No SMTP server configured (manual SMTP settings; no vendor e-mail backend, D-006).");
        var msg = new MimeMessage();
        msg.From.Add(MailboxAddress.Parse(smtp.From.Length > 0 ? smtp.From : "ipmaster@localhost"));
        foreach (var addr in to.Split([',', ';'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)) msg.To.Add(MailboxAddress.Parse(addr));
        msg.Subject = subject;
        msg.Body = new TextPart("plain") { Text = body };
        using var client = new SmtpClient { Timeout = 20_000 };
        var options = smtp.Security switch
        {
            SmtpSecurity.Tls => SecureSocketOptions.SslOnConnect,
            SmtpSecurity.StartTls => SecureSocketOptions.StartTls,
            _ => SecureSocketOptions.None,
        };
        await client.ConnectAsync(smtp.Host, smtp.Port, options, ct).ConfigureAwait(false);
        if (smtp.CredentialId is { } id)
        {
            var c = secrets.Credential(id) ?? throw new InvalidOperationException("The SMTP credential is not available.");
            if (smtp.Security == SmtpSecurity.None) throw new InvalidOperationException("Refusing to send SMTP credentials over an unencrypted connection; use STARTTLS or TLS.");
            await client.AuthenticateAsync(c.UserName, c.Password, ct).ConfigureAwait(false);
        }

        await client.SendAsync(msg, ct).ConfigureAwait(false);
        await client.DisconnectAsync(true, ct).ConfigureAwait(false);
    }

    [LibraryImport("winmm.dll", EntryPoint = "PlaySoundW", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool PlaySound(string sound, IntPtr module, uint flags);
}

/// <summary>Background scan log (BKG-03): bounded, newest last.</summary>
public sealed class BackgroundLog
{
    public const int Capacity = 5000;
    private readonly LinkedList<(DateTimeOffset At, string Text)> _items = new();
    private readonly object _lock = new();

    public event EventHandler? Changed;

    public IReadOnlyList<(DateTimeOffset At, string Text)> Items
    {
        get
        {
            lock (_lock) return _items.ToList();
        }
    }

    public void Add(DateTimeOffset at, string text)
    {
        lock (_lock)
        {
            _items.AddLast((at, text));
            while (_items.Count > Capacity) _items.RemoveFirst();
        }

        Changed?.Invoke(this, EventArgs.Empty);
    }
}
