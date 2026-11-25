using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Management;

// ---------------------------------------------------------------- Wake-on-LAN

public enum WolDestinationKind
{
    IPv4,
    IPv6,
    HostName,
}

/// <summary>A Wake-on-LAN manager entry (manual: MAC address, destination, host name, friendly name).</summary>
public sealed record WolTarget
{
    public string Mac { get; set; } = "";

    public WolDestinationKind Kind { get; set; } = WolDestinationKind.IPv4;

    /// <summary>Broadcast/unicast IPv4, IPv6 (multicast, e.g. ff02::1%12) or host name the packet is sent to.</summary>
    public string Destination { get; set; } = "255.255.255.255";

    public string HostName { get; set; } = "";

    public string FriendlyName { get; set; } = "";
}

public sealed record WolSettings
{
    /// <summary>Default destination. Zero octets are taken from the device address (0.0.0.255 → subnet broadcast).</summary>
    public string DefaultDestination { get; set; } = "255.255.255.255";

    public int Port { get; set; } = 9;

    /// <summary>Delay between packets when waking several devices.</summary>
    public int DelayMs { get; set; } = 100;

    public IReadOnlyList<WolTarget> Targets { get; set; } = [];
}

public static class WakeOnLan
{
    /// <summary>Magic packet: 6 × 0xFF followed by the MAC address 16 times (102 bytes).</summary>
    public static byte[] MagicPacket(PhysicalAddress mac)
    {
        ArgumentNullException.ThrowIfNull(mac);
        var m = mac.GetAddressBytes();
        if (m.Length != 6) throw new ArgumentException("A MAC address has 6 bytes.", nameof(mac));
        var p = new byte[102];
        for (var i = 0; i < 6; i++) p[i] = 0xFF;
        for (var r = 0; r < 16; r++) m.CopyTo(p, 6 + (r * 6));
        return p;
    }

    /// <summary>Manual: "adding 192.168.1.10 with a default of 0.0.0.255 creates a WOL entry targeted at 192.168.1.255".
    /// Each zero octet of the default is replaced by the device's octet.</summary>
    public static string CombineDestination(string defaultDestination, IPAddress? deviceAddress)
    {
        ArgumentNullException.ThrowIfNull(defaultDestination);
        if (!TargetParser.TryParseStrictIPv4(defaultDestination, out var def)) return defaultDestination;
        if (deviceAddress is null || deviceAddress.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            // No device address: a template with zero octets degrades to the limited broadcast.
            return (def & 0xFF000000) == 0 || (def & 0xFF) == 0 ? "255.255.255.255" : defaultDestination;
        }

        var dev = AddressKey.From(deviceAddress).V4;
        uint result = 0;
        for (var shift = 24; shift >= 0; shift -= 8)
        {
            var d = (def >> shift) & 0xFF;
            result |= (d == 0 ? (dev >> shift) & 0xFF : d) << shift;
        }

        return AddressKey.FromIPv4(result).ToString();
    }

    public static WolTarget FromDevice(DeviceResult device, WolSettings settings)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(settings);
        if (!device.Mac.HasValue) throw new InvalidOperationException("The device has no MAC address.");
        var v6 = device.Key.IsV6;
        return new WolTarget
        {
            Mac = Formats.Mac(device.Mac.Value!),
            Kind = v6 ? WolDestinationKind.IPv6 : WolDestinationKind.IPv4,
            Destination = v6 ? $"ff02::1%{device.Key.ScopeId}" : CombineDestination(settings.DefaultDestination, device.Address),
            HostName = device.HostName.Value?.Name ?? "",
        };
    }

    /// <summary>Parses a MAC list file (one per line; '#' comments). Invalid lines are reported.</summary>
    public static (IReadOnlyList<PhysicalAddress> Macs, IReadOnlyList<RejectedLine> Rejected) ParseMacList(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var macs = new List<PhysicalAddress>();
        var rejected = new List<RejectedLine>();
        var n = 0;
        foreach (var raw in text.Split('\n'))
        {
            n++;
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var first = line.Split([' ', '\t', ',', ';'], StringSplitOptions.RemoveEmptyEntries)[0];
            if (Formats.ParseMac(first) is { } mac) macs.Add(mac);
            else rejected.Add(new RejectedLine(n, line, "Not a MAC address."));
        }

        return (macs, rejected);
    }
}

public sealed record OperationResult(string Target, bool Success, string Message);

public interface IWakeOnLanSender
{
    Task<OperationResult> WakeAsync(WolTarget target, int port, CancellationToken cancellationToken);
}

// ---------------------------------------------------------------- External applications

public sealed record ExternalApplication
{
    /// <summary>Menu name; '|' creates submenus ("FTP clients | FileZilla").</summary>
    public string Name { get; set; } = "";

    public string CommandLine { get; set; } = "";

    /// <summary>Key gesture, e.g. "Ctrl+Shift+R"; empty = none.</summary>
    public string Hotkey { get; set; } = "";
}

public sealed record GlobalVariable
{
    public string Name { get; set; } = "";

    public string Value { get; set; } = "";

    /// <summary>When true, <see cref="Value"/> names an environment variable whose value is used.</summary>
    public bool FromEnvironment { get; set; }
}

public sealed record ApplicationSettings
{
    public IReadOnlyList<ExternalApplication> Applications { get; set; } = [];

    public IReadOnlyList<GlobalVariable> Variables { get; set; } = [];
}

public sealed record PromptParameter(string Name, string Default)
{
    /// <summary>Manual: a browse button appears when the name contains "file" or "path".</summary>
    public bool IsPath => Name.Contains("file", StringComparison.OrdinalIgnoreCase) || Name.Contains("path", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Application command-line templates (manual Applications tab): <c>%0</c> IP, <c>%1</c> host name, <c>%2</c> MAC,
/// <c>{Name}</c> / <c>{Name:default}</c> prompted parameters, <c>{{</c> and <c>}}</c> literal braces, and global
/// variables written as <c>{$Name}</c> (D-042).
/// </summary>
public static class CommandTemplate
{
    public static IReadOnlyList<PromptParameter> Prompts(string template)
    {
        ArgumentNullException.ThrowIfNull(template);
        var list = new List<PromptParameter>();
        foreach (var (token, _) in Tokens(template))
        {
            if (token is null || token.StartsWith('$')) continue;
            var colon = token.IndexOf(':', StringComparison.Ordinal);
            var name = colon < 0 ? token : token[..colon];
            var def = colon < 0 ? "" : token[(colon + 1)..];
            if (!list.Any(p => p.Name == name)) list.Add(new PromptParameter(name, def));
        }

        return list;
    }

    /// <summary>Expands the template. Missing prompt values use their default; unknown variables are an error.</summary>
    public static string Expand(string template, string ip, string hostName, string mac, IReadOnlyDictionary<string, string> prompts,
        IReadOnlyList<GlobalVariable> variables, Func<string, string?>? environment = null)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(prompts);
        ArgumentNullException.ThrowIfNull(variables);
        environment ??= Environment.GetEnvironmentVariable;
        var sb = new StringBuilder();
        foreach (var (token, literal) in Tokens(template))
        {
            if (token is null)
            {
                sb.Append(literal.Replace("%0", ip, StringComparison.Ordinal).Replace("%1", BatchFile.SafeArgument(hostName), StringComparison.Ordinal)
                    .Replace("%2", BatchFile.SafeArgument(mac), StringComparison.Ordinal)); // device-supplied (review C-07)
                continue;
            }

            if (token.StartsWith('$'))
            {
                var name = token[1..];
                var v = variables.FirstOrDefault(x => string.Equals(x.Name, name, StringComparison.OrdinalIgnoreCase))
                        ?? throw new KeyNotFoundException($"Unknown variable '{name}'.");
                sb.Append(v.FromEnvironment ? environment(v.Value) ?? "" : v.Value);
                continue;
            }

            var colon = token.IndexOf(':', StringComparison.Ordinal);
            var pname = colon < 0 ? token : token[..colon];
            var def = colon < 0 ? "" : token[(colon + 1)..];
            sb.Append(prompts.TryGetValue(pname, out var value) ? value : def);
        }

        return sb.ToString();
    }

    /// <summary>Splits text into literal segments (token = null, escapes resolved) and {tokens}.</summary>
    private static IEnumerable<(string? Token, string Literal)> Tokens(string s)
    {
        var lit = new StringBuilder();
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '{' && i + 1 < s.Length && s[i + 1] == '{')
            {
                lit.Append('{');
                i++;
            }
            else if (c == '}' && i + 1 < s.Length && s[i + 1] == '}')
            {
                lit.Append('}');
                i++;
            }
            else if (c == '{')
            {
                var close = s.IndexOf('}', i + 1);
                if (close < 0)
                {
                    lit.Append(s, i, s.Length - i);
                    break;
                }

                if (lit.Length > 0)
                {
                    yield return (null, lit.ToString());
                    lit.Clear();
                }

                yield return (s[(i + 1)..close], "");
                i = close;
            }
            else
            {
                lit.Append(c);
            }
        }

        if (lit.Length > 0) yield return (null, lit.ToString());
    }

    /// <summary>Splits an expanded command line into executable and arguments (Windows rules: quoted or first token).</summary>
    public static (string FileName, string Arguments) SplitCommand(string commandLine)
    {
        ArgumentNullException.ThrowIfNull(commandLine);
        var s = commandLine.Trim();
        if (s.StartsWith('"'))
        {
            var close = s.IndexOf('"', 1);
            return close < 0 ? (s.Trim('"'), "") : (s[1..close], s[(close + 1)..].TrimStart());
        }

        var space = s.IndexOf(' ', StringComparison.Ordinal);
        return space < 0 ? (s, "") : (s[..space], s[(space + 1)..].TrimStart());
    }
}

// ---------------------------------------------------------------- Batch files

public sealed record BatchExample(string Name, string Template);

/// <summary>Manual "Create Batch File": <c>%0</c> = IP address, <c>%1</c> = share name (a line per share when used),
/// <c>[Column]</c> = any column. Other <c>%</c> sequences are left for cmd.exe (D-043).</summary>
public static class BatchFile
{
    public static IReadOnlyList<BatchExample> Examples { get; } =
    [
        new("Disable a service", "sc \\\\%0 config \"wuauserv\" start= disabled"),
        new("Copy files to a remote device", "copy /Y \"C:\\Deploy\\setup.exe\" \"\\\\%0\\%1\\\""),
        new("Add a value to the registry", "reg add \"\\\\%0\\HKLM\\SOFTWARE\\Example\" /v Setting /t REG_SZ /d Value /f"),
    ];

    public static string Generate(string template, IEnumerable<DeviceResult> devices, IReadOnlyList<ResultColumn> columns, ColumnFormat format)
    {
        ArgumentNullException.ThrowIfNull(template);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(format);
        var perShare = template.Contains("%1", StringComparison.Ordinal);
        var sb = new StringBuilder("@echo off\r\nrem Generated by IPMaster\r\n");
        foreach (var d in devices)
        {
            var withColumns = ReplaceColumns(template, d, columns, format);
            if (perShare)
            {
                var shares = d.Shares.HasValue ? d.Shares.Value!.Where(s => s.Kind == ShareKind.Folder && format.ShareMatches(s)).ToList() : [];
                foreach (var s in shares)
                {
                    sb.Append(withColumns.Replace("%0", d.Key.ToString(), StringComparison.Ordinal).Replace("%1", Safe(s.Name), StringComparison.Ordinal)).Append("\r\n");
                }
            }
            else
            {
                sb.Append(withColumns.Replace("%0", d.Key.ToString(), StringComparison.Ordinal)).Append("\r\n");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Device-supplied text (host names, share names, banners, SNMP values) is untrusted: control characters (a CR/LF would
    /// start a new batch line) become spaces, cmd.exe operators and quotes become '_', and '%' is doubled so no variable
    /// expands. The template itself is the user's and is left as written (review C-07).
    /// </summary>
    public static string Safe(string? value) => SafeArgument(value).Replace("%", "%%", StringComparison.Ordinal);

    /// <summary>The same for a launched command line (no cmd.exe variable expansion): device text cannot close the
    /// template's quotes, chain a command or start a new line.</summary>
    public static string SafeArgument(string? value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (char.IsControl(c)) sb.Append(' ');
            else if (c is '"' or '&' or '|' or '<' or '>' or '^') sb.Append('_');
            else sb.Append(c);
        }

        return sb.ToString();
    }

    private static string ReplaceColumns(string template, DeviceResult d, IReadOnlyList<ResultColumn> columns, ColumnFormat format)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < template.Length; i++)
        {
            if (template[i] == '[')
            {
                var close = template.IndexOf(']', i + 1);
                if (close > i)
                {
                    var name = template[(i + 1)..close];
                    var col = columns.FirstOrDefault(c => string.Equals(c.Header, name, StringComparison.OrdinalIgnoreCase)
                                                          || string.Equals(c.Id, name, StringComparison.OrdinalIgnoreCase));
                    if (col is not null)
                    {
                        sb.Append(Safe(col.Text(d, format)));
                        i = close;
                        continue;
                    }
                }
            }

            sb.Append(template[i]);
        }

        return sb.ToString();
    }
}

// ---------------------------------------------------------------- Remote control

public sealed record ShutdownOptions
{
    public bool Reboot { get; init; }

    public bool ForceAppsClosed { get; init; }

    public string Message { get; init; } = "";

    /// <summary>Seconds the warning is shown before shutdown (0 = immediately, max 315360000 per Windows).</summary>
    public int TimeoutSeconds { get; init; } = 30;
}

/// <summary>Remote power management and messaging (Windows targets).</summary>
public interface IRemoteControl
{
    CapabilityStatus Capability { get; }

    Task<OperationResult> ShutdownAsync(string host, ShutdownOptions options, CancellationToken cancellationToken);

    Task<OperationResult> SendMessageAsync(string host, string title, string message, int seconds, CancellationToken cancellationToken);
}

/// <summary>Manual: "Before connecting to a device, the scanner can check whether it is online."</summary>
public sealed record BrowsingSettings
{
    public bool CheckIcmp { get; set; } = true;

    public bool CheckArp { get; set; }

    public bool CheckNetBios { get; set; }
}

/// <summary>Builds open-device URLs (HTTP, HTTPS, FTP, SSH); IPv6 literals are bracketed.</summary>
public static class DeviceUrls
{
    public static string For(string scheme, IPAddress address, int? port = null)
    {
        ArgumentNullException.ThrowIfNull(scheme);
        ArgumentNullException.ThrowIfNull(address);
        var host = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? "[" + address.ToString().Replace("%", "%25", StringComparison.Ordinal) + "]"
            : address.ToString();
        return port is { } p ? $"{scheme}://{host}:{p.ToString(CultureInfo.InvariantCulture)}/" : $"{scheme}://{host}/";
    }
}
