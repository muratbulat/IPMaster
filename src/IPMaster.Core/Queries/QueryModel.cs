namespace IPMaster.Core.Queries;

/// <summary>The remote query families of the manual (Options → Remote …). Each produces one dynamic result column.</summary>
public enum QueryKind
{
    Wmi,
    Registry,
    Files,
    Services,
    Groups,
    Performance,
    PowerShell,

    /// <summary>VBScript or JScript through Windows Script Host ("Remote Scripting").</summary>
    Script,
    Snmp,
    Ssh,
    Xml,
    Json,
    Nmap,
    Python,
}

/// <summary>
/// One configured remote query. Only the options object matching <see cref="Kind"/> is used; the others stay null.
/// A single shape (instead of a polymorphic hierarchy) keeps the JSON and XML configuration formats simple (D-050).
/// </summary>
public sealed record QueryDefinition
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public QueryKind Kind { get; set; }

    /// <summary>Item name = column header; unique per kind; used by <c>Remote.Kind("name")</c>.</summary>
    public string Name { get; set; } = "";

    public bool Enabled { get; set; } = true;

    /// <summary>Credential Manager entry; null = current account (Windows), anonymous (HTTP) or none.</summary>
    public Guid? CredentialId { get; set; }

    public int TimeoutSeconds { get; set; } = 15;

    public WmiOptions? Wmi { get; set; }

    public RegistryOptions? Registry { get; set; }

    public FileOptions? Files { get; set; }

    public ServiceOptions? Service { get; set; }

    public GroupOptions? Group { get; set; }

    public PerformanceOptions? Performance { get; set; }

    public PowerShellOptions? PowerShell { get; set; }

    public ScriptOptions? Script { get; set; }

    public SnmpOptions? Snmp { get; set; }

    public SshOptions? Ssh { get; set; }

    public HttpOptions? Http { get; set; }

    public NmapOptions? Nmap { get; set; }

    public PythonOptions? Python { get; set; }

    /// <summary>Column id: stable across renames (layouts and results refer to it).</summary>
    public string ColumnId => QueryColumns.Prefix + Id.ToString("N");

    public static QueryDefinition New(QueryKind kind, string name = "") => new()
    {
        Kind = kind,
        Name = name,
        Wmi = kind == QueryKind.Wmi ? new WmiOptions() : null,
        Registry = kind == QueryKind.Registry ? new RegistryOptions() : null,
        Files = kind == QueryKind.Files ? new FileOptions() : null,
        Service = kind == QueryKind.Services ? new ServiceOptions() : null,
        Group = kind == QueryKind.Groups ? new GroupOptions() : null,
        Performance = kind == QueryKind.Performance ? new PerformanceOptions() : null,
        PowerShell = kind == QueryKind.PowerShell ? new PowerShellOptions() : null,
        Script = kind == QueryKind.Script ? new ScriptOptions() : null,
        Snmp = kind == QueryKind.Snmp ? new SnmpOptions() : null,
        Ssh = kind == QueryKind.Ssh ? new SshOptions() : null,
        Http = kind is QueryKind.Xml or QueryKind.Json ? new HttpOptions { Extraction = kind == QueryKind.Json ? HttpExtraction.JsonPath : HttpExtraction.XPath } : null,
        Nmap = kind == QueryKind.Nmap ? new NmapOptions() : null,
        Python = kind == QueryKind.Python ? new PythonOptions() : null,
        TimeoutSeconds = kind switch
        {
            QueryKind.Nmap => 300,
            QueryKind.PowerShell or QueryKind.Script or QueryKind.Python => 60,
            QueryKind.Files => 120,
            _ => 15,
        },
    };

    /// <summary>Short description of what the item queries, for the manager list.</summary>
    public string Summary => Kind switch
    {
        QueryKind.Wmi => Wmi?.Query ?? "",
        QueryKind.Registry => Registry is { } r ? $@"{r.Root}\{r.Key}" + (r.Action == RegistryAction.KeyExists ? " (exists)" : $" → {r.ValueName}") : "",
        QueryKind.Files => Files is { } f ? $"{f.Path} → {f.Property}" : "",
        QueryKind.Services => Service is { } s ? $"{s.ServiceName} → {s.Property}" : "",
        QueryKind.Groups => Group is { } g ? $"{g.Type}: {g.Name}" : "",
        QueryKind.Performance => Performance?.CounterPath ?? "",
        QueryKind.PowerShell => FirstLine(PowerShell?.Script),
        QueryKind.Script => FirstLine(Script?.Script),
        QueryKind.Snmp => Snmp is { } n ? $"{n.Version} {n.Oid}" : "",
        QueryKind.Ssh => FirstLine(Ssh?.Command),
        QueryKind.Xml or QueryKind.Json => Http is { } h ? $"{(h.UseHttps ? "https" : "http")}:{h.Port}{h.Path} → {h.Expression}" : "",
        QueryKind.Nmap => Nmap is { } m ? $"{m.ScanType} → {m.XPath}" : "",
        QueryKind.Python => FirstLine(Python?.Script),
        _ => "",
    };

    private static string FirstLine(string? s) => (s ?? "").Split('\n')[0].Trim();
}

public sealed record WmiOptions
{
    public string Query { get; set; } = "SELECT Caption FROM Win32_OperatingSystem";

    public string Namespace { get; set; } = @"root\cimv2";

    /// <summary>RPC_C_AUTHN_LEVEL_PKT_PRIVACY: the WMI traffic is encrypted.</summary>
    public bool PacketPrivacy { get; set; } = true;
}

public enum RegistryRoot
{
    LocalMachine,
    Users,
    CurrentUser,
}

public enum RegistryAction
{
    /// <summary>Read a value from one key (simple path).</summary>
    ReadValue,

    /// <summary>Read a value from every key matching wildcards; result is a list of <c>key: value</c>.</summary>
    ReadWildcard,

    /// <summary>Report whether the key exists.</summary>
    KeyExists,
}

public sealed record RegistryOptions
{
    public RegistryRoot Root { get; set; } = RegistryRoot.LocalMachine;

    public string Key { get; set; } = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    public string ValueName { get; set; } = "ProductName";

    public RegistryAction Action { get; set; } = RegistryAction.ReadValue;
}

public enum FileProperty
{
    FileSize,
    FolderSize,
    Exists,
    Crc32,
    Md5,
    Sha1,
    Sha256,
    Created,
    Modified,
    Accessed,
    FileVersion,
    ProductVersion,
}

public sealed record FileOptions
{
    public string Path { get; set; } = @"C:\Windows\System32\ntoskrnl.exe";

    public FileProperty Property { get; set; } = FileProperty.FileVersion;
}

public enum ServiceProperty
{
    Status,
    ImagePath,
    StartupType,
}

public sealed record ServiceOptions
{
    public string ServiceName { get; set; } = "wuauserv";

    public ServiceProperty Property { get; set; } = ServiceProperty.Status;
}

public enum GroupQueryType
{
    LocalMembers,
    GlobalMembers,
    LocalParticipation,
    GlobalParticipation,
}

public sealed record GroupOptions
{
    /// <summary>Group name (members queries) or user/computer name (participation queries).</summary>
    public string Name { get; set; } = "Administrators";

    public GroupQueryType Type { get; set; } = GroupQueryType.LocalMembers;

    public bool StripDomain { get; set; }

    /// <summary>Account patterns to disregard (* and ?), e.g. <c>NT AUTHORITY\*</c>.</summary>
    public IReadOnlyList<string> Exclusions { get; set; } = [];
}

public sealed record PerformanceOptions
{
    /// <summary>Counter path with a single leading backslash, e.g. <c>\Processor(_Total)\% Processor Time</c>.</summary>
    public string CounterPath { get; set; } = @"\Processor(_Total)\% Processor Time";

    /// <summary>Interval between the two samples that rate counters need.</summary>
    public int SampleMilliseconds { get; set; } = 1000;
}

public sealed record PowerShellOptions
{
    public string Script { get; set; } = "Get-PSDrive C | Select-Object Used, Free";

    public bool UseSsl { get; set; }

    public bool NoProfile { get; set; } = true;
}

public enum ScriptLanguage
{
    VBScript,
    JScript,
}

public sealed record ScriptOptions
{
    public ScriptLanguage Language { get; set; } = ScriptLanguage.VBScript;

    public string Script { get; set; } = "Output.Write \"Address: \" & Input.Current";
}

public enum SnmpVersion
{
    V1,
    V2c,
    V3,
}

public enum SnmpSecurity
{
    NoAuthNoPriv,
    AuthNoPriv,
    AuthPriv,
}

public enum SnmpAuth
{
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

/// <summary>Privacy algorithms named by the manual. AES-192/256 use the Blumenthal key extension (draft-blumenthal-aes-usm);
/// the "-B" variants are tracked separately because some agents implement the Reeder (Cisco) extension instead (D-054).</summary>
public enum SnmpPriv
{
    Des,
    TripleDes,
    Aes128,
    Aes192,
    Aes256,
    Aes192B,
    Aes256B,
}

public enum SnmpDisplay
{
    Automatic,
    Ascii,
    Hex,
}

public enum SnmpOperation
{
    Get,
    GetNext,

    /// <summary>Walk the subtree below the OID (GETBULK on v2c/v3, GETNEXT on v1); bounded.</summary>
    Walk,
}

public sealed record SnmpOptions
{
    public SnmpVersion Version { get; set; } = SnmpVersion.V2c;

    /// <summary>Comma-separated community strings (v1/v2c), stored encrypted (protected text).</summary>
    public string Communities { get; set; } = "";

    public SnmpSecurity Security { get; set; } = SnmpSecurity.AuthPriv;

    public SnmpAuth Auth { get; set; } = SnmpAuth.Sha256;

    public SnmpPriv Priv { get; set; } = SnmpPriv.Aes128;

    /// <summary>SNMPv3 privacy password (protected text); empty = same as the authentication password.</summary>
    public string PrivPassword { get; set; } = "";

    /// <summary>OID; <c>%0</c> = IP octets, <c>%1</c> = MAC octets.</summary>
    public string Oid { get; set; } = "1.3.6.1.2.1.1.1.0";

    public SnmpOperation Operation { get; set; } = SnmpOperation.Get;

    public SnmpDisplay Display { get; set; } = SnmpDisplay.Automatic;

    public int Port { get; set; } = 161;
}

/// <summary>Reusable SNMP credentials (manual "Save / Load"). Secrets are protected text.</summary>
public sealed record SnmpProfile
{
    public string Name { get; set; } = "";

    public SnmpVersion Version { get; set; } = SnmpVersion.V2c;

    public string Communities { get; set; } = "";

    public SnmpSecurity Security { get; set; } = SnmpSecurity.AuthPriv;

    public SnmpAuth Auth { get; set; } = SnmpAuth.Sha256;

    public SnmpPriv Priv { get; set; } = SnmpPriv.Aes128;

    public Guid? CredentialId { get; set; }

    public string PrivPassword { get; set; } = "";
}

public enum HostKeyPolicy
{
    /// <summary>Only hosts whose key is already trusted (IPMaster list or the user's known_hosts).</summary>
    Strict,

    /// <summary>Trust and record the key the first time; reject a changed key.</summary>
    TrustOnFirstUse,

    /// <summary>Lab exception: accept any key (explicit per query; shown as a warning).</summary>
    AcceptAny,
}

public sealed record SshOptions
{
    public string Command { get; set; } = "uname -or";

    public int Port { get; set; } = 22;

    public HostKeyPolicy HostKeys { get; set; } = HostKeyPolicy.Strict;
}

public enum HttpExtraction
{
    XPath,
    Regex,
    JsonPath,
}

public sealed record HttpOptions
{
    public int Port { get; set; } = 80;

    public string Path { get; set; } = "/";

    public bool UseHttps { get; set; }

    /// <summary>Basic authentication when a credential is selected; none otherwise.</summary>
    public bool BasicAuthentication { get; set; }

    public HttpExtraction Extraction { get; set; } = HttpExtraction.XPath;

    public string Expression { get; set; } = "";

    /// <summary>Lab exception: accept invalid TLS certificates for this query only.</summary>
    public bool AcceptInvalidCertificates { get; set; }
}

public enum NmapScanType
{
    OsDetection,
    VersionDetection,
    Script,
}

public enum NmapIntensity
{
    Fast,
    Standard,
    Thorough,
}

public sealed record NmapOptions
{
    public NmapScanType ScanType { get; set; } = NmapScanType.OsDetection;

    /// <summary>--osscan-limit.</summary>
    public bool OsLimit { get; set; }

    /// <summary>--osscan-guess.</summary>
    public bool OsGuess { get; set; }

    public NmapIntensity Intensity { get; set; } = NmapIntensity.Standard;

    /// <summary>NSE script name(s) for <see cref="NmapScanType.Script"/>.</summary>
    public string ScriptName { get; set; } = "";

    public string ScriptArgs { get; set; } = "";

    /// <summary>XPath over the XML report (<c>-oX -</c>).</summary>
    public string XPath { get; set; } = "/nmaprun/host/os/osmatch[1]/@name";
}

public sealed record PythonOptions
{
    public string Script { get; set; } = "Output.Write(\"Address: \" + Input.Current)";
}

public sealed record NmapSettings
{
    /// <summary>Full path to nmap; empty = search PATH and the default install folders.</summary>
    public string ExecutablePath { get; set; } = "";

    public string Ports { get; set; } = "";

    public string ExcludePorts { get; set; } = "";

    /// <summary>Extra arguments, split like a command line (no shell). Output options are rejected.</summary>
    public string ExtraArguments { get; set; } = "";
}

public sealed record KnownHostKey
{
    public string Host { get; set; } = "";

    public int Port { get; set; } = 22;

    public string Algorithm { get; set; } = "";

    /// <summary>SHA256 fingerprint, base64 without padding (OpenSSH style).</summary>
    public string Fingerprint { get; set; } = "";
}

/// <summary>Everything the query framework persists.</summary>
public sealed record QuerySettings
{
    public IReadOnlyList<QueryDefinition> Items { get; set; } = [];

    /// <summary>Concurrent authenticated/expensive queries per scan (separate budget).</summary>
    public int Concurrency { get; set; } = 16;

    public NmapSettings Nmap { get; set; } = new();

    /// <summary>Python interpreter; empty = detect.</summary>
    public string PythonPath { get; set; } = "";

    public IReadOnlyList<KnownHostKey> KnownHosts { get; set; } = [];

    public IReadOnlyList<SnmpProfile> SnmpProfiles { get; set; } = [];

    public IEnumerable<QueryDefinition> Enabled => Items.Where(q => q.Enabled && q.Name.Length > 0);
}
