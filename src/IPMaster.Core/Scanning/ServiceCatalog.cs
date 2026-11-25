using System.Globalization;

namespace IPMaster.Core.Scanning;

public enum MacMethod
{
    /// <summary>Neighbour cache / ARP request (local subnets).</summary>
    Arp,

    /// <summary>NetBIOS node-status reply (UDP 137) — works across routers.</summary>
    NetBios,

    /// <summary>WMI Win32_NetworkAdapterConfiguration on the target (Windows targets, works across routers).</summary>
    Wmi,

    /// <summary>ARP cache of the default gateways and listed routers via SNMP (ipNetToMediaPhysAddress).</summary>
    RouterMib,
}

[Flags]
public enum ShareTypeSelection
{
    None = 0,
    Folders = 1,
    Printers = 2,
    Devices = 4,
    Administrative = 8,
    Ipc = 16,
    FoldersAndPrinters = Folders | Printers,
    All = Folders | Printers | Devices | Administrative | Ipc,
}

public sealed record BannerService(string Id, string Name, PortProtocol Protocol, int[] Ports);

/// <summary>Services probed by "Grab service banners" (manual list).</summary>
public static class BannerServices
{
    public static IReadOnlyList<BannerService> All { get; } =
    [
        new("http", "HTTP", PortProtocol.Tcp, [80, 8080]),
        new("tls", "TLS/HTTPS", PortProtocol.Tcp, [443]),
        new("ssh", "SSH", PortProtocol.Tcp, [22]),
        new("ftp", "FTP", PortProtocol.Tcp, [21]),
        new("smtp", "SMTP", PortProtocol.Tcp, [25, 587]),
        new("pop3", "POP3", PortProtocol.Tcp, [110]),
        new("imap", "IMAP", PortProtocol.Tcp, [143]),
        new("mysql", "MySQL", PortProtocol.Tcp, [3306]),
        new("mssql", "MSSQL", PortProtocol.Tcp, [1433]),
        new("smb", "SMB", PortProtocol.Tcp, [445]),
        new("mqtt", "MQTT", PortProtocol.Tcp, [1883]),
        new("dns", "DNS", PortProtocol.Udp, [53]),
        new("ntp", "NTP", PortProtocol.Udp, [123]),
        new("nbns", "NBNS", PortProtocol.Udp, [137]),
        new("snmp", "SNMP", PortProtocol.Udp, [161]),
        new("tftp", "TFTP", PortProtocol.Udp, [69]),
    ];

    public static IReadOnlyList<string> DefaultIds { get; } = All.Select(s => s.Id).ToList();

    public static BannerService? Find(string id) => All.FirstOrDefault(s => string.Equals(s.Id, id, StringComparison.OrdinalIgnoreCase));
}

public sealed record UdpService(string Id, string Name, int Port);

/// <summary>Protocol-specific UDP probes (manual Ports tab: DNS, TFTP, NTP, NBNS, MSSQL, RADIUS; plus SNMP).</summary>
public static class UdpServices
{
    public static IReadOnlyList<UdpService> All { get; } =
    [
        new("dns", "DNS", 53),
        new("tftp", "TFTP", 69),
        new("ntp", "NTP", 123),
        new("nbns", "NBNS", 137),
        new("snmp", "SNMP", 161),
        new("mssql", "MSSQL Browser", 1434),
        new("radius", "RADIUS", 1812),
    ];

    public static IReadOnlyList<string> DefaultIds { get; } = All.Select(s => s.Id).ToList();
}

/// <summary>Port list parsing ("21, 80, 110-115, 443") and well-known service names (our own table).</summary>
public static class PortList
{
    public const int MaxPorts = 65_535;

    public static bool TryParse(string? text, out IReadOnlyList<int> ports, out string error)
    {
        ports = [];
        error = "";
        var set = new SortedSet<int>();
        if (string.IsNullOrWhiteSpace(text))
        {
            return true;
        }

        foreach (var raw in text.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = raw.IndexOf('-', StringComparison.Ordinal);
            if (dash < 0)
            {
                if (!TryPort(raw, out var p))
                {
                    error = $"'{raw}' is not a port number (1-65535).";
                    return false;
                }

                set.Add(p);
                continue;
            }

            if (!TryPort(raw[..dash], out var a) || !TryPort(raw[(dash + 1)..], out var b) || a > b)
            {
                error = $"'{raw}' is not a valid port range.";
                return false;
            }

            for (var p = a; p <= b; p++) set.Add(p);
        }

        ports = set.ToList();
        return true;
    }

    private static bool TryPort(string s, out int p) =>
        int.TryParse(s.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out p) && p is >= 1 and <= 65535;

    private static readonly Dictionary<int, string> TcpNames = new()
    {
        [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "domain", [67] = "dhcp",
        [69] = "tftp", [80] = "http", [88] = "kerberos", [110] = "pop3", [111] = "rpcbind", [119] = "nntp", [123] = "ntp",
        [135] = "msrpc", [137] = "netbios-ns", [139] = "netbios-ssn", [143] = "imap", [161] = "snmp", [162] = "snmptrap",
        [179] = "bgp", [389] = "ldap", [443] = "https", [445] = "microsoft-ds", [465] = "smtps", [514] = "syslog",
        [515] = "printer", [548] = "afp", [554] = "rtsp", [587] = "submission", [631] = "ipp", [636] = "ldaps",
        [873] = "rsync", [902] = "vmware-auth", [993] = "imaps", [995] = "pop3s", [1080] = "socks", [1194] = "openvpn",
        [1433] = "ms-sql-s", [1434] = "ms-sql-m", [1521] = "oracle", [1723] = "pptp", [1812] = "radius", [1883] = "mqtt",
        [2049] = "nfs", [2375] = "docker", [3000] = "http-alt", [3268] = "globalcat", [3306] = "mysql", [3389] = "ms-wbt-server",
        [5000] = "upnp", [5060] = "sip", [5353] = "mdns", [5432] = "postgresql", [5900] = "vnc", [5985] = "wsman",
        [5986] = "wsmans", [6379] = "redis", [8000] = "http-alt", [8080] = "http-proxy", [8443] = "https-alt",
        [8883] = "secure-mqtt", [9100] = "jetdirect", [9200] = "elasticsearch", [11211] = "memcache", [27017] = "mongodb",
    };

    public static IReadOnlyDictionary<int, string> WellKnown => TcpNames;

    public static string? ServiceName(int port) => TcpNames.TryGetValue(port, out var n) ? n : null;
}
