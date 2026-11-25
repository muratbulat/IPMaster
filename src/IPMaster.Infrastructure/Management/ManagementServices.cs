using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using IPMaster.Core.Management;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Management;

/// <summary>Sends magic packets over UDP to broadcast, unicast, IPv6 multicast or a resolved host name.</summary>
public sealed class WakeOnLanSender : IWakeOnLanSender
{
    public async Task<OperationResult> WakeAsync(WolTarget target, int port, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(target);
        var mac = Formats.ParseMac(target.Mac);
        if (mac is null) return new OperationResult(target.Mac, false, "Invalid MAC address.");
        IPAddress? dest;
        if (target.Kind == WolDestinationKind.HostName || !IPAddress.TryParse(target.Destination, out dest))
        {
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(target.Destination, cancellationToken).ConfigureAwait(false);
                dest = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
            }
            catch (SocketException ex)
            {
                return new OperationResult(target.Mac, false, $"Cannot resolve {target.Destination}: {ex.Message}");
            }

            if (dest is null) return new OperationResult(target.Mac, false, $"{target.Destination} has no address.");
        }

        try
        {
            using var socket = new Socket(dest.AddressFamily, SocketType.Dgram, ProtocolType.Udp) { EnableBroadcast = dest.AddressFamily == AddressFamily.InterNetwork };
            if (dest.AddressFamily == AddressFamily.InterNetworkV6 && dest.IsIPv6Multicast && dest.ScopeId != 0)
            {
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, (int)dest.ScopeId);
            }

            var packet = WakeOnLan.MagicPacket(mac);
            await socket.SendToAsync(packet, SocketFlags.None, new IPEndPoint(dest, port), cancellationToken).ConfigureAwait(false);
            return new OperationResult(target.Mac, true, $"Magic packet sent to {dest}:{port.ToString(CultureInfo.InvariantCulture)}.");
        }
        catch (SocketException ex)
        {
            return new OperationResult(target.Mac, false, ex.Message);
        }
    }

    /// <summary>Wakes targets sequentially with the configured delay; returns one result per target.</summary>
    public async Task<IReadOnlyList<OperationResult>> WakeAllAsync(IReadOnlyList<WolTarget> targets, WolSettings settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(settings);
        var results = new List<OperationResult>();
        for (var i = 0; i < targets.Count; i++)
        {
            if (i > 0 && settings.DelayMs > 0) await Task.Delay(settings.DelayMs, cancellationToken).ConfigureAwait(false);
            results.Add(await WakeAsync(targets[i], settings.Port, cancellationToken).ConfigureAwait(false));
        }

        return results;
    }
}

/// <summary>Remote shutdown (InitiateSystemShutdownEx) and messages (WTSSendMessage to every active session).</summary>
public sealed partial class WindowsRemoteControl : IRemoteControl
{
    public CapabilityStatus Capability { get; } = OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes("Windows remote shutdown and messages with the current account.")
        : CapabilityStatus.No("Remote shutdown and messages need a Windows scanner.");

    public Task<OperationResult> ShutdownAsync(string host, ShutdownOptions options, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(new OperationResult(host, false, Capability.Description));
        return Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows()) return new OperationResult(host, false, Capability.Description);
            const uint reasonPlanned = 0x80000000 | 0x00040000 | 0x00000000; // planned, application: maintenance
            var ok = InitiateSystemShutdownEx(@"\\" + host, string.IsNullOrEmpty(options.Message) ? null : options.Message,
                (uint)Math.Clamp(options.TimeoutSeconds, 0, 315_360_000), options.ForceAppsClosed, options.Reboot, reasonPlanned);
            if (ok) return new OperationResult(host, true, options.Reboot ? "Restart initiated." : "Shutdown initiated.");
            var err = Marshal.GetLastPInvokeError();
            return new OperationResult(host, false, Describe(err));
        }, cancellationToken);
    }

    public Task<OperationResult> SendMessageAsync(string host, string title, string message, int seconds, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(new OperationResult(host, false, Capability.Description));
        return Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows()) return new OperationResult(host, false, Capability.Description);
            var server = WTSOpenServer(host);
            if (server == IntPtr.Zero) return new OperationResult(host, false, Describe(Marshal.GetLastPInvokeError()));
            try
            {
                if (!WTSEnumerateSessions(server, 0, 1, out var sessions, out var count))
                {
                    return new OperationResult(host, false, Describe(Marshal.GetLastPInvokeError()));
                }

                var sent = 0;
                try
                {
                    var size = Marshal.SizeOf<WtsSessionInfo>();
                    for (var i = 0; i < count; i++)
                    {
                        var s = Marshal.PtrToStructure<WtsSessionInfo>(sessions + (i * size));
                        if (s.State != 0) continue; // WTSActive only
                        if (WTSSendMessage(server, s.SessionId, title, (uint)(title.Length * 2), message, (uint)(message.Length * 2), 0x40,
                                (uint)Math.Clamp(seconds, 1, 86_400), out _, false))
                        {
                            sent++;
                        }
                    }
                }
                finally
                {
                    WTSFreeMemory(sessions);
                }

                return sent > 0
                    ? new OperationResult(host, true, $"Message shown in {sent} session(s).")
                    : new OperationResult(host, false, "No active user session.");
            }
            finally
            {
                WTSCloseServer(server);
            }
        }, cancellationToken);
    }

    private static string Describe(int error) => error switch
    {
        5 => "Access is denied (administrator rights on the target are required).",
        53 => "The network path was not found (admin shares, file sharing or firewall).",
        1115 => "A shutdown is already in progress.",
        1722 => "The RPC server is unavailable.",
        _ => new Win32Exception(error).Message,
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "InitiateSystemShutdownExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InitiateSystemShutdownEx(string machine, string? message, uint timeout,
        [MarshalAs(UnmanagedType.Bool)] bool forceAppsClosed, [MarshalAs(UnmanagedType.Bool)] bool reboot, uint reason);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSOpenServerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial IntPtr WTSOpenServer(string server);

    [LibraryImport("wtsapi32.dll")]
    [SupportedOSPlatform("windows")]
    private static partial void WTSCloseServer(IntPtr server);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [LibraryImport("wtsapi32.dll")]
    [SupportedOSPlatform("windows")]
    private static partial void WTSFreeMemory(IntPtr memory);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSSendMessageW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSSendMessage(IntPtr server, int sessionId, string title, uint titleLength, string message, uint messageLength,
        uint style, uint timeout, out int response, [MarshalAs(UnmanagedType.Bool)] bool wait);
}

/// <summary>Opens URLs, explores shares, launches external applications and maps network drives.</summary>
public static partial class Shell
{
    private static readonly string[] AllowedSchemes = ["http", "https", "ftp", "ssh", "telnet", "rtsp", "file"];

    public static OperationResult OpenUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || !AllowedSchemes.Contains(uri.Scheme, StringComparer.OrdinalIgnoreCase))
        {
            return new OperationResult(url, false, "Only http, https, ftp, ssh, telnet, rtsp and file URLs are opened.");
        }

        if (uri.Scheme == "ssh" && OperatingSystem.IsWindows()) return OpenSsh(uri.Host.Trim('[', ']'));
        try
        {
            Process.Start(new ProcessStartInfo(uri.ToString()) { UseShellExecute = true })?.Dispose();
            return new OperationResult(url, true, "Opened.");
        }
        catch (Win32Exception ex)
        {
            return new OperationResult(url, false, $"No application is registered for {uri.Scheme}: {ex.Message}");
        }
    }

    /// <summary>Windows has no default ssh:// handler: open OpenSSH in Windows Terminal or a console.</summary>
    private static OperationResult OpenSsh(string host)
    {
        try
        {
            var psi = new ProcessStartInfo("wt.exe") { UseShellExecute = true };
            psi.ArgumentList.Add("ssh");
            psi.ArgumentList.Add(host);
            Process.Start(psi)?.Dispose();
            return new OperationResult(host, true, "Opened SSH in Windows Terminal.");
        }
        catch (Win32Exception)
        {
            try
            {
                var psi = new ProcessStartInfo("cmd.exe") { UseShellExecute = true };
                psi.ArgumentList.Add("/k");
                psi.ArgumentList.Add("ssh");
                psi.ArgumentList.Add(host);
                Process.Start(psi)?.Dispose();
                return new OperationResult(host, true, "Opened SSH in a console.");
            }
            catch (Win32Exception ex)
            {
                return new OperationResult(host, false, ex.Message);
            }
        }
    }

    public static OperationResult Explore(string uncPath)
    {
        try
        {
            var psi = OperatingSystem.IsWindows() ? new ProcessStartInfo("explorer.exe") { UseShellExecute = false } : new ProcessStartInfo(uncPath) { UseShellExecute = true };
            if (OperatingSystem.IsWindows()) psi.ArgumentList.Add(uncPath);
            Process.Start(psi)?.Dispose();
            return new OperationResult(uncPath, true, "Opened.");
        }
        catch (Win32Exception ex)
        {
            return new OperationResult(uncPath, false, ex.Message);
        }
    }

    /// <summary>Starts an expanded application command line (no shell interpretation of the arguments).</summary>
    public static OperationResult Launch(string commandLine)
    {
        var (file, args) = CommandTemplate.SplitCommand(commandLine);
        if (file.Length == 0) return new OperationResult(commandLine, false, "Empty command line.");
        try
        {
            Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = false })?.Dispose();
            return new OperationResult(commandLine, true, "Started.");
        }
        catch (Win32Exception)
        {
            try
            {
                // e.g. documents or App Paths entries that only the shell resolves
                Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = true })?.Dispose();
                return new OperationResult(commandLine, true, "Started.");
            }
            catch (Win32Exception ex)
            {
                return new OperationResult(commandLine, false, ex.Message);
            }
        }
    }

    /// <summary>Maps a drive letter ("Z:") to a UNC path with the current credentials.</summary>
    public static OperationResult MapDrive(string letter, string uncPath, bool persistent)
    {
        if (!OperatingSystem.IsWindows()) return new OperationResult(uncPath, false, "Mapping network drives needs Windows.");
        var nr = new NetResource { Type = 1, LocalName = letter, RemoteName = uncPath };
        var rc = WNetAddConnection2(ref nr, null, null, persistent ? 1u : 0u);
        return rc == 0 ? new OperationResult(uncPath, true, $"{letter} mapped to {uncPath}.") : new OperationResult(uncPath, false, new Win32Exception(rc).Message);
    }

    /// <summary>Windows "Disconnect Network Drives" dialog.</summary>
    public static OperationResult DisconnectDialog(IntPtr owner)
    {
        if (!OperatingSystem.IsWindows()) return new OperationResult("", false, "Needs Windows.");
        var rc = WNetDisconnectDialog(owner, 1);
        return rc is 0 or -1 ? new OperationResult("", true, "") : new OperationResult("", false, new Win32Exception(rc).Message);
    }

    public static IReadOnlyList<string> FreeDriveLetters()
    {
        var used = DriveInfo.GetDrives().Select(d => char.ToUpperInvariant(d.Name[0])).ToHashSet();
        return Enumerable.Range('D', 'Z' - 'D' + 1).Select(c => (char)c).Where(c => !used.Contains(c)).Reverse().Select(c => c + ":").ToList();
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string? RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("mpr.dll", EntryPoint = "WNetAddConnection2W", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WNetAddConnection2(ref NetResource resource, string? password, string? user, uint flags);

    [LibraryImport("mpr.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WNetDisconnectDialog(IntPtr owner, int type);
}

/// <summary>Geolocation through a user-configured JSON endpoint (ENG-10, D-044). Responses are bounded and cached.</summary>
public sealed class HttpGeoLocator : IGeoLocator, IDisposable
{
    private const int MaxBody = 64 * 1024;
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly System.Collections.Concurrent.ConcurrentDictionary<string, GeoLocation?> _cache = new();

    public HttpGeoLocator() => _http.DefaultRequestHeaders.UserAgent.ParseAdd("IPMaster/0.3");

    public CapabilityStatus Capability(ScanSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        return Uri.TryCreate(settings.GeoUrlTemplate.Replace("{ip}", "192.0.2.1", StringComparison.Ordinal), UriKind.Absolute, out var u)
               && u.Scheme == Uri.UriSchemeHttps && settings.GeoUrlTemplate.Contains("{ip}", StringComparison.Ordinal)
            ? CapabilityStatus.Yes("Geolocation via " + u.Host)
            : CapabilityStatus.No("Geolocation needs an HTTPS URL template containing {ip} (Options → General).");
    }

    public async Task<GeoLocation?> LocateAsync(IPAddress address, ScanSettings settings, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(settings);
        var ip = address.ToString();
        if (_cache.TryGetValue(ip, out var cached)) return cached;
        var url = settings.GeoUrlTemplate.Replace("{ip}", Uri.EscapeDataString(ip), StringComparison.Ordinal);
        using var response = await _http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var body = await Bounded.ReadAsync(response, MaxBody, cancellationToken).ConfigureAwait(false);
        var result = Parse(body, settings);
        _cache[ip] = result;
        return result;
    }

    internal static GeoLocation? Parse(string json, ScanSettings s)
    {
        using var doc = JsonDocument.Parse(json);
        string Field(string path)
        {
            var e = doc.RootElement;
            foreach (var part in path.Split('.', StringSplitOptions.RemoveEmptyEntries))
            {
                if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(part, out e)) return "";
            }

            return e.ValueKind == JsonValueKind.String ? e.GetString() ?? "" : "";
        }

        var g = new GeoLocation(Field(s.GeoCityField), Field(s.GeoRegionField), Field(s.GeoCountryField));
        return g.City.Length + g.Region.Length + g.Country.Length == 0 ? null : g;
    }

    public void Dispose() => _http.Dispose();
}

public sealed record ExternalAddress(IPAddress Address, string Country, string Raw);

/// <summary>Manual "External…": asks Cloudflare's trace endpoint for the public IPv4/IPv6 address (explicit user action).</summary>
public static class ExternalIp
{
    public static readonly Uri TraceUrl = new("https://www.cloudflare.com/cdn-cgi/trace");

    public static async Task<ExternalAddress?> LookupAsync(AddressFamily family, CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (ctx, ct) =>
            {
                var addrs = (await Dns.GetHostAddressesAsync(ctx.DnsEndPoint.Host, family, ct).ConfigureAwait(false));
                if (addrs.Length == 0) throw new SocketException((int)SocketError.HostNotFound);
                var s = new Socket(family, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                try
                {
                    await s.ConnectAsync(addrs[0], ctx.DnsEndPoint.Port, ct).ConfigureAwait(false);
                    return new NetworkStream(s, ownsSocket: true);
                }
                catch
                {
                    s.Dispose();
                    throw;
                }
            },
        };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(8) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("IPMaster/0.3");
        using var response = await http.GetAsync(TraceUrl, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        return ParseTrace(await Bounded.ReadAsync(response, 16 * 1024, cancellationToken).ConfigureAwait(false));
    }

    internal static ExternalAddress? ParseTrace(string text)
    {
        var map = text.Split('\n').Select(l => l.Split('=', 2)).Where(p => p.Length == 2).ToDictionary(p => p[0].Trim(), p => p[1].Trim());
        return map.TryGetValue("ip", out var ip) && IPAddress.TryParse(ip, out var a) ? new ExternalAddress(a, map.GetValueOrDefault("loc") ?? "", text) : null;
    }
}

/// <summary>Bounded HTTP body reading.</summary>
public static class Bounded
{
    public static async Task<string> ReadAsync(HttpResponseMessage response, int maxBytes, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(response);
        if (response.Content.Headers.ContentLength > maxBytes) throw new InvalidOperationException($"Response larger than {maxBytes} bytes.");
        await using var s = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var ms = new MemoryStream();
        var buffer = new byte[16 * 1024];
        int n;
        while ((n = await s.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
        {
            if (ms.Length + n > maxBytes) throw new InvalidOperationException($"Response larger than {maxBytes} bytes.");
            ms.Write(buffer, 0, n);
        }

        return System.Text.Encoding.UTF8.GetString(ms.ToArray());
    }
}
