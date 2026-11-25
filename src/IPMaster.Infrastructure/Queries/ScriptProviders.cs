using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using IPMaster.Core.Discovery;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Queries;

/// <summary>Runs a user script with the generated prelude and maps errors back to the user's line numbers.</summary>
internal static partial class ScriptHost
{
    public static async Task<Observation<string>> RunAsync(string executable, IReadOnlyList<string> argumentsBeforeFile, string extension, string prelude,
        string script, QueryCall call, Func<string, string, CancellationToken, Task<string>>? extra, Encoding fileEncoding, CancellationToken ct,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var dir = Directory.CreateTempSubdirectory("ipm-script-").FullName;
        try
        {
            var file = Path.Combine(dir, "query" + extension);
            var (userScript, header) = HoistOptionExplicit(script, extension);
            await File.WriteAllTextAsync(file, header + prelude + userScript, fileEncoding, ct).ConfigureAwait(false);
            var offset = ScriptPreludes.LineCount(header + prelude);
            var bridge = new ScriptBridge(call.Context, extra, ct);
            var result = await ProcessRunner.RunAsync(executable, [.. argumentsBeforeFile, file], ct, environment: environment, bridge: bridge.HandleAsync,
                workingDirectory: dir, outputEncoding: extension == ".py" ? new UTF8Encoding(false) : null).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            if (result.Truncated) return Observation<string>.Of(ObservationState.Failed, now, "Script output exceeded the limit.");
            var error = MapLines(result.Error, file, offset);
            if (result.ExitCode != 0 || (error.Length > 0 && !bridge.WroteOutput))
            {
                var message = error.Length > 0 ? error : result.Output.Length > 0 ? result.Output : $"Exit code {result.ExitCode}.";
                return Observation<string>.Of(ObservationState.Failed, now, Shorten(message));
            }

            return bridge.WroteOutput ? Observation<string>.Ok(bridge.Output, now) : Observation<string>.Of(ObservationState.Empty, now, "The script wrote no output (use Output.Write).");
        }
        finally
        {
            try
            {
                Directory.Delete(dir, recursive: true);
            }
            catch (IOException)
            {
                // the process may still hold the file briefly
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static (string Script, string Header) HoistOptionExplicit(string script, string extension)
    {
        if (extension != ".vbs") return (script, "");
        var m = OptionExplicit().Match(script);
        return m.Success ? (OptionExplicit().Replace(script, "' (Option Explicit moved to the top)", 1), "Option Explicit\r\n") : (script, "");
    }

    [GeneratedRegex(@"^\s*Option\s+Explicit\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.CultureInvariant)]
    private static partial Regex OptionExplicit();

    /// <summary>"file(12, 3)" / "line 12" → user line numbers.</summary>
    private static string MapLines(string error, string file, int offset)
    {
        if (error.Length == 0) return error;
        var s = error.Replace(file, "script", StringComparison.OrdinalIgnoreCase);
        s = WshLine().Replace(s, m => $"script({Math.Max(1, int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) - offset)},");
        s = PyLine().Replace(s, m => $"line {Math.Max(1, int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture) - offset)}");
        return s.Trim();
    }

    [GeneratedRegex(@"script\((\d+),", RegexOptions.CultureInvariant)]
    private static partial Regex WshLine();

    [GeneratedRegex(@"line (\d+)", RegexOptions.CultureInvariant)]
    private static partial Regex PyLine();

    private static string Shorten(string s) => s.Length > 2000 ? s[..2000] + "…" : s;
}

/// <summary>Host implementations of the WSH Internal DNS and SNMP objects (VBS-02).</summary>
internal static class InternalObjects
{
    public static async Task<string> HandleAsync(string op, string args, IPAddress current, CancellationToken ct)
    {
        var a = args.Split('\u0001');
        return op switch
        {
            "dns" => await DnsAsync(a[0], a.Length > 1 ? a[1] : "a", ct).ConfigureAwait(false),
            "snmp" => await SnmpAsync(a[0], current, ct).ConfigureAwait(false),
            _ => throw new InvalidOperationException($"Unknown request '{op}'."),
        };
    }

    /// <summary>GetName(target, type) with optional comma-separated servers ("type|servers").</summary>
    public static async Task<string> DnsAsync(string target, string typeAndServers, CancellationToken ct)
    {
        var bar = typeAndServers.IndexOf('|', StringComparison.Ordinal);
        var type = (bar < 0 ? typeAndServers : typeAndServers[..bar]).Trim().ToLowerInvariant();
        var servers = (bar < 0 ? "" : typeAndServers[(bar + 1)..]).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (type is not ("a" or "aaaa" or "ptr" or "txt" or "srv")) throw new ArgumentException($"Unsupported record type '{type}' (a, aaaa, ptr, txt, srv).");
        if (servers.Length == 0)
        {
            if (type == "ptr")
            {
                if (!IPAddress.TryParse(target, out var ip)) throw new ArgumentException("PTR lookups need an IP address.");
                return (await Dns.GetHostEntryAsync(ip.ToString(), ct).ConfigureAwait(false)).HostName;
            }

            if (type is "a" or "aaaa")
            {
                var family = type == "a" ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6;
                var list = await Dns.GetHostAddressesAsync(target, family, ct).ConfigureAwait(false);
                return string.Join(", ", list.Select(x => x.ToString()));
            }

            throw new ArgumentException("TXT and SRV lookups need a DNS server (set the Server property).");
        }

        foreach (var server in servers)
        {
            if (!IPAddress.TryParse(server, out var srv)) throw new ArgumentException($"'{server}' is not an IP address.");
            var answer = await QueryAsync(srv, target, type, ct).ConfigureAwait(false);
            if (answer is not null) return answer;
        }

        return "";
    }

    private static async Task<string?> QueryAsync(IPAddress server, string target, string type, CancellationToken ct)
    {
        var qtype = type switch { "a" => (ushort)1, "aaaa" => (ushort)28, "ptr" => (ushort)12, "txt" => (ushort)16, _ => (ushort)33 };
        var name = type == "ptr" && IPAddress.TryParse(target, out var ip) ? ReverseName(ip) : target.TrimEnd('.');
        var id = (ushort)Random.Shared.Next(1, 65535);
        var q = new List<byte> { (byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var b = Encoding.ASCII.GetBytes(label);
            if (b.Length > 63) throw new ArgumentException("DNS label too long.");
            q.Add((byte)b.Length);
            q.AddRange(b);
        }

        q.AddRange(new byte[] { 0, (byte)(qtype >> 8), (byte)qtype, 0, 1 });
        using var udp = new UdpClient(server.AddressFamily);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(3));
        await udp.SendAsync(q.ToArray(), new IPEndPoint(server, 53), cts.Token).ConfigureAwait(false);
        try
        {
            while (true)
            {
                var r = await udp.ReceiveAsync(cts.Token).ConfigureAwait(false);
                if (r.Buffer.Length < 12 || r.Buffer[0] != (byte)(id >> 8) || r.Buffer[1] != (byte)id) continue;
                var records = DnsMessage.Parse(r.Buffer).Where(x => x.Type == qtype).ToList();
                return string.Join(", ", records.Select(x => x.Address?.ToString() ?? (x.Port > 0 ? $"{x.Data}:{x.Port}" : x.Data)));
            }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return null;
        }
    }

    private static string ReverseName(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetwork
            ? string.Join('.', b.Reverse()) + ".in-addr.arpa"
            : string.Join('.', Convert.ToHexString(b).ToLowerInvariant().Reverse()) + ".ip6.arpa";
    }

    /// <summary>SNMP object: key=value lines in; "errorStatus" then "oid\ttype\tvalue" lines out.</summary>
    public static async Task<string> SnmpAsync(string parameters, IPAddress current, CancellationToken ct)
    {
        var p = parameters.Split('\n').Select(l => l.Split('=', 2)).Where(x => x.Length == 2)
            .ToDictionary(x => x[0].Trim().ToLowerInvariant(), x => x[1], StringComparer.Ordinal);
        string Get(string k, string d = "") => p.TryGetValue(k, out var v) && v.Length > 0 ? v : d;
        var hostText = Get("host", current.ToString());
        if (!IPAddress.TryParse(hostText, out var host))
        {
            host = (await Dns.GetHostAddressesAsync(hostText, ct).ConfigureAwait(false)).FirstOrDefault()
                   ?? throw new ArgumentException($"Host '{hostText}' could not be resolved.");
        }

        var version = Get("version", "2") switch { "1" => Core.Queries.SnmpVersion.V1, "3" => Core.Queries.SnmpVersion.V3, _ => Core.Queries.SnmpVersion.V2c };
        var security = Enum.TryParse<SnmpSecurity>(Get("v3security", "NoAuthNoPriv"), true, out var s) ? s : SnmpSecurity.NoAuthNoPriv;
        var auth = Get("v3authmode", "SHA1").ToUpperInvariant() switch
        {
            "MD5" => SnmpAuth.Md5,
            "SHA224" => SnmpAuth.Sha224,
            "SHA256" => SnmpAuth.Sha256,
            "SHA384" => SnmpAuth.Sha384,
            "SHA512" => SnmpAuth.Sha512,
            _ => SnmpAuth.Sha1,
        };
        var priv = Get("v3privmode", "AES").ToUpperInvariant() switch
        {
            "DES" => SnmpPriv.Des,
            "3DES" => SnmpPriv.TripleDes,
            "AES192" => SnmpPriv.Aes192,
            "AES256" => SnmpPriv.Aes256,
            _ => SnmpPriv.Aes128,
        };
        var target = new SnmpTarget(new IPEndPoint(host, 161), version, [Get("community", "public")], Get("v3username"), security, auth,
            Get("v3authpass"), priv, Get("v3privpass"));
        var pdu = ParseInt(Get("pdutype", "160")) switch { 0xA1 => SnmpPduKind.GetNext, 0xA5 => SnmpPduKind.GetBulk, _ => SnmpPduKind.Get };
        var oids = Get("oids").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (oids.Length == 0) throw new ArgumentException("No OID added (Query.AddOid).");
        try
        {
            var values = await SnmpClient.RequestAsync(target, oids, pdu, ct, ParseInt(Get("nonrepeaters", "0")), ParseInt(Get("maxrepetitions", "10"))).ConfigureAwait(false);
            return "0" + string.Concat(values.Select(v => $"\n{v.Oid}\t{(int)v.Type}\t{SnmpQueryProvider.Render(v, SnmpDisplay.Automatic).Replace('\n', ' ').Replace('\t', ' ')}"));
        }
        catch (SnmpException ex) when (ex.ErrorStatus != 0)
        {
            return ex.ErrorStatus.ToString(CultureInfo.InvariantCulture);
        }
    }

    private static int ParseInt(string s) =>
        s.StartsWith("&H", StringComparison.OrdinalIgnoreCase) ? Convert.ToInt32(s[2..], 16)
        : s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? Convert.ToInt32(s[2..], 16)
        : int.Parse(s, CultureInfo.InvariantCulture);
}

/// <summary>VBScript/JScript through Windows Script Host (VBS-01..03). WSH and the VBScript engine are detected (C-03).</summary>
public sealed class WshScriptProvider : IRemoteQueryProvider
{
    public QueryKind Kind => QueryKind.Script;

    public CapabilityStatus Capability { get; } = Detect();

    public static bool VbScriptAvailable => OperatingSystem.IsWindows() && File.Exists(Path.Combine(Environment.SystemDirectory, "vbscript.dll"));

    private static CapabilityStatus Detect()
    {
        if (!OperatingSystem.IsWindows()) return CapabilityStatus.No("Windows Script Host exists only on Windows.");
        var cscript = Path.Combine(Environment.SystemDirectory, "cscript.exe");
        if (!File.Exists(cscript)) return CapabilityStatus.No("cscript.exe was not found.");
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Script Host\Settings");
            if (key?.GetValue("Enabled") is int enabled && enabled == 0) return CapabilityStatus.No("Windows Script Host is disabled by policy (Settings\\Enabled = 0).");
        }
        catch (System.Security.SecurityException)
        {
            // cannot read the policy: assume enabled
        }

        return CapabilityStatus.Yes(VbScriptAvailable
            ? "Windows Script Host (VBScript and JScript)."
            : "Windows Script Host with JScript only: the VBScript optional feature is not installed.");
    }

    public async Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var o = call.Query.Script ?? new ScriptOptions();
        var vbs = o.Language == ScriptLanguage.VBScript;
        if (vbs && !VbScriptAvailable)
        {
            return Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow,
                "VBScript is not installed (Windows optional feature, deprecated by Microsoft). Use JScript or Python.");
        }

        var current = ScriptBridge.Hex(call.Device.Key.ToString());
        var prelude = vbs ? ScriptPreludes.VbScript(current) : ScriptPreludes.JScript(current);
        var cscript = Path.Combine(Environment.SystemDirectory, "cscript.exe");
        // The script file is UTF-16 with BOM (WSH reads it as Unicode); console I/O stays ASCII thanks to the hex bridge.
        return await ScriptHost.RunAsync(cscript, ["//Nologo", vbs ? "//E:vbscript" : "//E:jscript"], vbs ? ".vbs" : ".js", prelude, o.Script, call,
            (op, args, ct) => InternalObjects.HandleAsync(op, args, call.Device.Address, ct), new UnicodeEncoding(false, true), cancellationToken).ConfigureAwait(false);
    }
}

/// <summary>Remote Python (PY-01): local interpreter, isolated mode, same Input/Output/Remote API without the WSH objects.</summary>
public sealed class PythonQueryProvider(Func<string> configuredPath) : IRemoteQueryProvider
{
    /// <summary>Process-wide, keyed by the configured path ("" = search PATH); "not found" is cached too (review C-12).</summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (string? Path, string? Version, DateTime At)> Cache = new(StringComparer.OrdinalIgnoreCase);

    private static readonly TimeSpan CacheLifetime = TimeSpan.FromMinutes(1);

    public QueryKind Kind => QueryKind.Python;

    public CapabilityStatus Capability
    {
        get
        {
            var (path, version) = DetectAsync(CancellationToken.None).GetAwaiter().GetResult();
            return path is null || version is null
                ? CapabilityStatus.No("Python was not found. Please install it, or point to the interpreter with Choose Location… (Options → Remote Python).")
                : CapabilityStatus.Yes($"{version} ({path})");
        }
    }

    /// <summary>Interpreter path and version; the Windows Store "python.exe" alias (which only opens the Store) is rejected.</summary>
    /// <remarks>Synchronous callers (the <see cref="Capability"/> getter) must not be on the UI thread; the query window reads it on the
    /// thread pool.</remarks>
    public (string? Path, string? Version) Detect() => DetectAsync(CancellationToken.None).GetAwaiter().GetResult();

    public async Task<(string? Path, string? Version)> DetectAsync(CancellationToken cancellationToken)
    {
        var configured = configuredPath();
        if (Cache.TryGetValue(configured, out var c) && DateTime.UtcNow - c.At < CacheLifetime) return (c.Path, c.Version);
        var candidates = configured.Length > 0
            ? [configured]
            : new[] { ProcessRunner.FindOnPath("python3"), ProcessRunner.FindOnPath("python"), OperatingSystem.IsWindows() ? ProcessRunner.FindOnPath("py") : null }
                .Where(p => p is not null).Cast<string>().ToArray();
        foreach (var p in candidates)
        {
            var version = await VersionAsync(p, cancellationToken).ConfigureAwait(false);
            if (version is null) continue;
            Cache[configured] = (p, version, DateTime.UtcNow);
            return (p, version);
        }

        Cache[configured] = (candidates.FirstOrDefault(), null, DateTime.UtcNow);
        return (candidates.FirstOrDefault(), null);
    }

    private static async Task<string?> VersionAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var r = await ProcessRunner.RunAsync(path, ["--version"], cts.Token, maxOutput: 4096).ConfigureAwait(false);
            var text = (r.Output + " " + r.Error).Trim();
            return r.ExitCode == 0 && text.StartsWith("Python 3", StringComparison.Ordinal) ? text : null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or OperationCanceledException or IOException)
        {
            return null;
        }
    }

    public async Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var (path, version) = await DetectAsync(cancellationToken).ConfigureAwait(false);
        if (path is null || version is null) return Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description);
        var args = Path.GetFileNameWithoutExtension(path).Equals("py", StringComparison.OrdinalIgnoreCase) ? new[] { "-3", "-I", "-X", "utf8" } : ["-I", "-X", "utf8"];
        var env = new Dictionary<string, string> { ["PYTHONIOENCODING"] = "utf-8", ["PYTHONUNBUFFERED"] = "1" };
        return await ScriptHost.RunAsync(path, args, ".py", ScriptPreludes.Python(ScriptBridge.Hex(call.Device.Key.ToString())),
            call.Query.Python?.Script ?? "", call, null, new UTF8Encoding(false), cancellationToken, env).ConfigureAwait(false);
    }
}

/// <summary>
/// Remote PowerShell (PSH-01): Invoke-Command over WinRM from a local Windows PowerShell/pwsh process. The script is
/// passed base64-encoded in an environment variable and the password on stdin, so neither appears on a command line.
/// </summary>
public sealed class PowerShellQueryProvider : IRemoteQueryProvider
{
    private const string Wrapper = """
        $ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
        $script = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:IPM_SCRIPT))
        $params = @{ ComputerName = $env:IPM_TARGET; ScriptBlock = [ScriptBlock]::Create($script); SessionOption = (New-PSSessionOption -NoMachineProfile) }
        if ($env:IPM_SSL -eq '1') { $params.UseSSL = $true }
        if ($env:IPM_USER) { $pw = [Console]::In.ReadLine(); $params.Credential = New-Object System.Management.Automation.PSCredential($env:IPM_USER, (ConvertTo-SecureString $pw -AsPlainText -Force)) }
        try { Invoke-Command @params | Out-String -Width 4096 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 2 }
        """;

    private const string LocalWrapper = """
        $ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
        $script = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($env:IPM_SCRIPT))
        try { & ([ScriptBlock]::Create($script)) | Out-String -Width 4096 } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 2 }
        """;

    public QueryKind Kind => QueryKind.PowerShell;

    public CapabilityStatus Capability { get; } = Executable() is { } p
        ? CapabilityStatus.Yes($"PowerShell ({p}); targets need WinRM (Enable-PSRemoting).")
        : CapabilityStatus.No("PowerShell was not found.");

    public static string? Executable()
    {
        if (OperatingSystem.IsWindows())
        {
            var winps = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            if (File.Exists(winps)) return winps;
        }

        return ProcessRunner.FindOnPath("pwsh");
    }

    public async Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var o = call.Query.PowerShell ?? new PowerShellOptions();
        var env = new Dictionary<string, string>
        {
            ["IPM_SCRIPT"] = Convert.ToBase64String(Encoding.Unicode.GetBytes(o.Script)),
            ["IPM_TARGET"] = call.Device.Key.ToString(),
            ["IPM_SSL"] = o.UseSsl ? "1" : "0",
            ["IPM_USER"] = call.Credential?.UserName ?? "",
        };
        return await RunAsync(Wrapper, env, call.Credential?.Password, o.NoProfile, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Editor "Run": executes the script on this computer only (clearly separate from remote execution).</summary>
    public static Task<Observation<string>> RunLocalAsync(string script, CancellationToken ct) =>
        RunAsync(LocalWrapper, new Dictionary<string, string> { ["IPM_SCRIPT"] = Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) }, null, true, ct);

    private static async Task<Observation<string>> RunAsync(string wrapper, Dictionary<string, string> env, string? password, bool noProfile, CancellationToken ct)
    {
        var exe = Executable() ?? throw new InvalidOperationException("PowerShell was not found.");
        var args = new List<string> { "-NoLogo", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-OutputFormat", "Text" };
        if (noProfile) args.Add("-NoProfile");
        args.Add("-EncodedCommand");
        args.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(wrapper)));
        var r = await ProcessRunner.RunAsync(exe, args, ct, stdin: password, environment: env).ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (r.Truncated) return Observation<string>.Of(ObservationState.Failed, now, "Output exceeded the limit.");
        if (r.ExitCode != 0)
        {
            var msg = Regex.Replace(r.Error.Length > 0 ? r.Error : r.Output, @"#< CLIXMLs*|<Objs[sS]*?</Objs>", "", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)).Trim();
            var state = msg.Contains("Access is denied", StringComparison.OrdinalIgnoreCase) || msg.Contains("AccessDenied", StringComparison.Ordinal)
                ? ObservationState.AccessDenied
                : msg.Contains("WinRM cannot complete", StringComparison.OrdinalIgnoreCase) || msg.Contains("cannot connect", StringComparison.OrdinalIgnoreCase)
                    ? ObservationState.NoResponse
                    : ObservationState.Failed;
            return Observation<string>.Of(state, now, msg.Length > 2000 ? msg[..2000] : msg);
        }

        return Observation<string>.Ok(string.Join('\n', r.Output.Split('\n').Select(l => l.TrimEnd())).Trim('\n', '\r', ' '), now);
    }
}

/// <summary>Nmap integration (NMP-01/02): external nmap only, argument list, XML on stdout, XPath extraction.</summary>
public sealed partial class NmapQueryProvider(Func<NmapSettings> settings) : IRemoteQueryProvider
{
    /// <summary>Additional parameters are an allow-list (review C-18): timing, performance, discovery and scan-technique options only.
    /// Block-lists missed nmap's single-dash long options, unique prefixes and extra targets.</summary>
    private static readonly HashSet<string> AllowedFlags = new(StringComparer.Ordinal)
    {
        "-T0", "-T1", "-T2", "-T3", "-T4", "-T5", "-Pn", "-n", "-R", "-F", "-r", "-v", "-vv", "-d", "-sS", "-sT", "-sU", "-sA", "-sW", "-sN", "-sF", "-sX",
        "--reason", "--open", "--traceroute", "--defeat-rst-ratelimit", "--disable-arp-ping",
    };

    /// <summary>Allowed options that take a value (as the next argument or as <c>--option=value</c>).</summary>
    private static readonly HashSet<string> AllowedWithValue = new(StringComparer.Ordinal)
    {
        "--max-retries", "--host-timeout", "--min-rate", "--max-rate", "--min-parallelism", "--max-parallelism", "--min-hostgroup", "--max-hostgroup",
        "--scan-delay", "--max-scan-delay", "--initial-rtt-timeout", "--min-rtt-timeout", "--max-rtt-timeout", "--top-ports", "--version-intensity",
    };

    private static void CheckExtraArguments(IReadOnlyList<string> extra)
    {
        for (var i = 0; i < extra.Count; i++)
        {
            var a = extra[i];
            if (AllowedFlags.Contains(a)) continue;
            var eq = a.IndexOf('=', StringComparison.Ordinal);
            if (eq > 0 && AllowedWithValue.Contains(a[..eq])) continue;
            if (AllowedWithValue.Contains(a) && i + 1 < extra.Count && !extra[i + 1].StartsWith('-'))
            {
                i++; // its value
                continue;
            }

            throw new ArgumentException($"'{a}' is not allowed in the additional parameters. Allowed: timing and performance options (-T0…-T5, --max-retries, --host-timeout, --min-rate…), "
                                        + "discovery and scan techniques (-Pn, -n, -sS, -sT, --top-ports…). IPMaster controls targets, input and output.");
        }
    }

    public QueryKind Kind => QueryKind.Nmap;

    /// <summary>Path and version of the configured or found nmap (bounded version check, cached for a minute per path, D-072).
    /// Synchronous: callers (the manager window) read it on the thread pool.</summary>
    public CapabilityStatus Capability
    {
        get
        {
            var path = Find(settings().ExecutablePath) ?? "";
            if (DetectCache.TryGetValue(path, out var c) && DateTime.UtcNow - c.At < TimeSpan.FromMinutes(1)) return c.Status;
            var status = DetectAsync(path.Length == 0 ? null : path, CancellationToken.None).GetAwaiter().GetResult();
            DetectCache[path] = (status, DateTime.UtcNow);
            return status;
        }
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (CapabilityStatus Status, DateTime At)> DetectCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Validates an nmap executable with <c>nmap --version</c> (5 s limit). "Not found" only when there is no file to run.</summary>
    public static async Task<CapabilityStatus> DetectAsync(string? path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return CapabilityStatus.No("Nmap was not found. Please install it.");
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromSeconds(5));
            var r = await ProcessRunner.RunAsync(path, ["--version"], cts.Token, maxOutput: 16 * 1024).ConfigureAwait(false);
            var m = NmapVersion().Match(r.Output);
            return m.Success
                ? CapabilityStatus.Yes($"Nmap {m.Groups[1].Value} ({path})")
                : CapabilityStatus.No($"{path} did not report an Nmap version ({FirstLine(r.Output, r.Error)}).");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return CapabilityStatus.No($"{path} did not answer the version check within 5 s.");
        }
        catch (InvalidOperationException ex)
        {
            return CapabilityStatus.No($"{path} could not be started: {ex.Message}");
        }
    }

    private static string FirstLine(string output, string error) =>
        (output + "\n" + error).Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) is { } l ? (l.Length > 80 ? l[..80] + "…" : l) : "no output";

    [GeneratedRegex(@"Nmap version (\S+)", RegexOptions.CultureInvariant)]
    private static partial Regex NmapVersion();

    public static string? Find(string configured)
    {
        if (!string.IsNullOrWhiteSpace(configured)) return File.Exists(configured) ? configured : null;
        var onPath = ProcessRunner.FindOnPath("nmap");
        if (onPath is not null) return onPath;
        string[] defaults = OperatingSystem.IsWindows()
            ? [@"C:\Program Files (x86)\Nmap\nmap.exe", @"C:\Program Files\Nmap\nmap.exe"]
            : ["/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap"];
        return defaults.FirstOrDefault(File.Exists);
    }

    public static IReadOnlyList<string> Arguments(NmapOptions o, NmapSettings s, IPAddress target)
    {
        ArgumentNullException.ThrowIfNull(o);
        ArgumentNullException.ThrowIfNull(s);
        ArgumentNullException.ThrowIfNull(target);
        var args = new List<string>();
        switch (o.ScanType)
        {
            case NmapScanType.OsDetection:
                args.Add("-O");
                if (o.OsLimit) args.Add("--osscan-limit");
                if (o.OsGuess) args.Add("--osscan-guess");
                break;
            case NmapScanType.VersionDetection:
                args.Add("-sV");
                if (o.Intensity == NmapIntensity.Fast) args.Add("--version-light");
                if (o.Intensity == NmapIntensity.Thorough) args.Add("--version-all");
                break;
            default:
                if (string.IsNullOrWhiteSpace(o.ScriptName)) throw new ArgumentException("No NSE script name.");
                if (!ScriptName().IsMatch(o.ScriptName)) throw new ArgumentException("Script names may contain letters, digits, '-', '_', ',', '*' and '.' only.");
                args.Add("--script=" + o.ScriptName);
                if (!string.IsNullOrWhiteSpace(o.ScriptArgs)) args.Add("--script-args=" + o.ScriptArgs);
                break;
        }

        if (!string.IsNullOrWhiteSpace(s.Ports)) args.AddRange(["-p", s.Ports.Trim()]);
        if (!string.IsNullOrWhiteSpace(s.ExcludePorts)) args.Add("--exclude-ports=" + s.ExcludePorts.Trim());
        var extra = ProcessRunner.SplitArguments(s.ExtraArguments);
        CheckExtraArguments(extra);
        args.AddRange(extra);
        if (target.AddressFamily == AddressFamily.InterNetworkV6) args.Add("-6");
        args.AddRange(["-oX", "-", "--noninteractive", target.ToString()]);
        return args;
    }

    [GeneratedRegex(@"^[A-Za-z0-9_\-,\*\.]+$", RegexOptions.CultureInvariant)]
    private static partial Regex ScriptName();

    [GeneratedRegex(@"<!DOCTYPE[^>\[]*>", RegexOptions.CultureInvariant)]
    private static partial Regex Doctype();

    /// <summary>Nmap XML starts with a plain DOCTYPE (no internal subset); it is removed so the DTD-prohibiting parser accepts it.</summary>
    public static string StripDoctype(string xml) => Doctype().Replace(xml, "", 1);

    public async Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var now = DateTimeOffset.UtcNow;
        var s = settings();
        var exe = Find(s.ExecutablePath);
        if (exe is null) return Observation<string>.Of(ObservationState.Unsupported, now, Capability.Description);
        IReadOnlyList<string> args;
        try
        {
            args = Arguments(call.Query.Nmap ?? new NmapOptions(), s, call.Device.Address);
        }
        catch (ArgumentException ex)
        {
            return Observation<string>.Of(ObservationState.Failed, now, ex.Message);
        }

        var r = await ProcessRunner.RunAsync(exe, args, cancellationToken, maxOutput: 8 * 1024 * 1024).ConfigureAwait(false);
        now = DateTimeOffset.UtcNow;
        if (r.Truncated) return Observation<string>.Of(ObservationState.Failed, now, "Nmap output exceeded 8 MB.");
        if (r.ExitCode != 0) return Observation<string>.Of(ObservationState.Failed, now, $"nmap exited with {r.ExitCode}: {(r.Error.Length > 0 ? r.Error : r.Output)}");
        try
        {
            var values = Extraction.XPath(StripDoctype(r.Output), (call.Query.Nmap ?? new NmapOptions()).XPath);
            return values.Count == 0 ? Observation<string>.Of(ObservationState.Empty, now) : Observation<string>.Ok(string.Join('\n', values), now);
        }
        catch (Exception ex) when (ex is FormatException or System.Xml.XmlException)
        {
            return Observation<string>.Of(ObservationState.Failed, now, ex.Message);
        }
    }
}
