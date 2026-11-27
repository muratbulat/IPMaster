namespace IPMaster.Core.Queries;

/// <summary>
/// One built-in, read-only example of a remote query (D-110). <see cref="Create"/> builds a fresh, disabled item
/// without a credential; the user tests and enables it in the manager.
/// </summary>
public sealed record QueryExample(string Id, QueryKind Kind, string Name, string Category, string Description, string Platform, string Requirements,
    Action<QueryDefinition> Configure)
{
    public QueryDefinition Create()
    {
        var q = QueryDefinition.New(Kind, Name) with { Id = Guid.NewGuid(), Enabled = false, CredentialId = null };
        Configure(q);
        return q;
    }

    public bool Matches(string search) => search.Length == 0
        || Name.Contains(search, StringComparison.OrdinalIgnoreCase) || Category.Contains(search, StringComparison.OrdinalIgnoreCase)
        || Description.Contains(search, StringComparison.OrdinalIgnoreCase) || Preview(Create()).Contains(search, StringComparison.OrdinalIgnoreCase);

    /// <summary>The configuration the example adds, as shown in the preview.</summary>
    public static string Preview(QueryDefinition q)
    {
        ArgumentNullException.ThrowIfNull(q);
        return q.Kind switch
        {
            QueryKind.Wmi when q.Wmi is { } w => $"Namespace: {w.Namespace}\nWQL: {w.Query}\nPacket privacy: {(w.PacketPrivacy ? "on" : "off")}",
            QueryKind.Registry when q.Registry is { } r => $"Root: {r.Root}\nKey: {r.Key}\nValue: {r.ValueName}\nAction: {r.Action}",
            QueryKind.Services when q.Service is { } s => $"Service: {s.ServiceName}\nProperty: {s.Property}",
            QueryKind.Files when q.Files is { } f => $"Path: {f.Path}\nProperty: {f.Property}",
            QueryKind.Groups when q.Group is { } g => $"Query: {g.Type}\nGroup: {g.Name}",
            QueryKind.Performance when q.Performance is { } p => $"Counter: {p.CounterPath}\nSample interval: {p.SampleMilliseconds} ms",
            QueryKind.PowerShell when q.PowerShell is { } p => p.Script,
            QueryKind.Script when q.Script is { } s => $"Language: {s.Language}\n\n{s.Script}",
            QueryKind.Python when q.Python is { } p => p.Script,
            QueryKind.Snmp when q.Snmp is { } n => $"Version: {n.Version} ({n.Security})\nOID: {n.Oid}\nOperation: {n.Operation}",
            QueryKind.Ssh when q.Ssh is { } s => $"Command: {s.Command}\nPort: {s.Port}\nHost keys: {s.HostKeys}",
            QueryKind.Xml or QueryKind.Json when q.Http is { } h =>
                $"URL: {(h.UseHttps ? "https" : "http")}://<device>:{h.Port}{h.Path}\n{h.Extraction}: {h.Expression}",
            QueryKind.Nmap when q.Nmap is { } m => $"Scan: {m.ScanType} ({m.Intensity})\nXPath: {m.XPath}",
            _ => q.Summary,
        };
    }
}

/// <summary>Offline catalog of built-in examples per query family (D-110). Typed definitions only: no database, no network.</summary>
public static class QueryExamples
{
    private const string Windows = "Windows";
    private const string WindowsRpc = "Remote Windows: RPC/DCOM and administrative rights on the target (or a Credential Manager entry).";
    private const string Local = "Runs on this computer with the query context; it is not executed on the target.";

    public static IReadOnlyList<QueryExample> All { get; } = Build();

    public static IReadOnlyList<QueryExample> For(QueryKind kind) => All.Where(e => e.Kind == kind).ToList();

    /// <summary>Appends a new item from <paramref name="example"/>; existing items are kept and a name clash in the same kind gets a suffix.</summary>
    public static (IReadOnlyList<QueryDefinition> Items, QueryDefinition Added) Add(IReadOnlyList<QueryDefinition> items, QueryExample example)
    {
        ArgumentNullException.ThrowIfNull(items);
        ArgumentNullException.ThrowIfNull(example);
        var q = example.Create();
        var taken = items.Where(i => i.Kind == q.Kind).Select(i => i.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var name = q.Name;
        for (var n = 2; taken.Contains(name); n++) name = $"{q.Name} ({n})";
        q.Name = name;
        return ([.. items, q], q);
    }

    private static List<QueryExample> Build()
    {
        var l = new List<QueryExample>();

        void Wmi(string id, string name, string wql, string description, string category = "System") =>
            l.Add(new("wmi." + id, QueryKind.Wmi, name, category, description, Windows, WindowsRpc + " WMI (Winmgmt) service running.",
                q => q.Wmi = new WmiOptions { Namespace = @"root\cimv2", Query = wql, PacketPrivacy = true }));

        Wmi("os-version", "Windows Version", "SELECT Caption, Version, BuildNumber FROM Win32_OperatingSystem", "Edition name, version and build number.");
        Wmi("computer-model", "Computer Model", "SELECT Manufacturer, Model FROM Win32_ComputerSystem", "Manufacturer and model reported by the firmware.", "Hardware");
        Wmi("bios-serial", "BIOS Serial", "SELECT SerialNumber FROM Win32_BIOS", "Serial number from the BIOS/UEFI (some systems report a placeholder).", "Hardware");
        Wmi("processor", "Processor", "SELECT Name, NumberOfLogicalProcessors FROM Win32_Processor", "CPU name and logical processor count, one line per socket.", "Hardware");
        Wmi("memory", "Physical Memory", "SELECT TotalPhysicalMemory FROM Win32_ComputerSystem", "Installed memory visible to Windows, in bytes.", "Hardware");
        Wmi("disk-free", "Disk Free Space", "SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3", "Size and free space of each local fixed disk, in bytes.", "Storage");
        Wmi("last-boot", "Last Boot Time", "SELECT LastBootUpTime FROM Win32_OperatingSystem", "When Windows last started (WMI date format).");
        Wmi("network-adapters", "Network Adapters", "SELECT Description, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE",
            "Name and MAC address of each adapter with IP enabled.", "Network");
        Wmi("wuauserv", "Windows Update Service", "SELECT Name, State, StartMode FROM Win32_Service WHERE Name = 'wuauserv'",
            "Runtime state and start mode of the Windows Update service.", "Services");

        void Reg(string id, string name, string key, string value, string description, string category) =>
            l.Add(new("registry." + id, QueryKind.Registry, name, category, description + " A missing key or value is reported as no data.", Windows,
                WindowsRpc + " Remote Registry service running on the target.",
                q => q.Registry = new RegistryOptions { Root = RegistryRoot.LocalMachine, Key = key, ValueName = value, Action = RegistryAction.ReadValue }));

        const string cv = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        Reg("product-name", "Windows Product Name", cv, "ProductName", "Edition name as stored in the registry (Windows 11 may still say \"Windows 10\").", "System");
        Reg("current-build", "Windows Build", cv, "CurrentBuild", "Build number, for example 26100.", "System");
        Reg("display-version", "Windows Display Version", cv, "DisplayVersion", "Feature update name, for example 24H2 (absent before 20H2).", "System");
        Reg("enable-lua", "UAC Enabled", @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA",
            "User Account Control: 1 = on, 0 = off (applies after a restart).", "Security");
        Reg("deny-ts", "RDP Connections Denied", @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections",
            "1 = Remote Desktop connections are refused, 0 = allowed by this setting. A value of 0 does not prove that RDP is reachable or allowed: the firewall, group policy and the service also decide.", "Security");
        Reg("remote-registry-start", "Remote Registry Start Type", @"SYSTEM\CurrentControlSet\Services\RemoteRegistry", "Start",
            "Configured start type: 2 = automatic, 3 = manual, 4 = disabled. This is configuration, not runtime status.", "Services");

        foreach (var (svc, display) in new[]
                 {
                     ("wuauserv", "Windows Update"), ("RemoteRegistry", "Remote Registry"), ("WinRM", "WinRM"), ("TermService", "Remote Desktop Services"),
                     ("W32Time", "Windows Time"), ("LanmanServer", "Server (file sharing)"),
                 })
        {
            foreach (var (prop, label, what) in new[]
                     {
                         (ServiceProperty.Status, "Status", "Current status (running, stopped, …)."),
                         (ServiceProperty.StartupType, "Startup Type", "Configured startup type (automatic, manual, disabled)."),
                     })
            {
                l.Add(new($"services.{svc.ToLowerInvariant()}.{prop.ToString().ToLowerInvariant()}", QueryKind.Services, $"{display} {label}", display,
                    $"{what} Read-only: the service is never started or stopped.", Windows, WindowsRpc + " Service Control Manager access.",
                    q => q.Service = new ServiceOptions { ServiceName = svc, Property = prop }));
            }
        }

        const string perfNote = " Counter names are localized: on a non-English target use its local names. One sample is a snapshot, not a long-term measurement.";
        void Perf(string id, string name, string path, string description) =>
            l.Add(new("performance." + id, QueryKind.Performance, name, "Performance", description + perfNote, Windows,
                WindowsRpc + " Remote Registry service (performance data) on the target.", q => q.Performance!.CounterPath = path));

        Perf("cpu", "CPU Usage", @"\Processor(_Total)\% Processor Time", "Processor time over the sample interval, in percent.");
        Perf("memory", "Available Memory", @"\Memory\Available MBytes", "Memory available to processes, in MB.");
        Perf("disk-queue", "Disk Queue Length", @"\PhysicalDisk(_Total)\Current Disk Queue Length", "Requests waiting on all physical disks.");
        Perf("network", "Network Throughput", @"\Network Interface(*)\Bytes Total/sec",
            "Bytes per second for every interface; replace * with one interface instance name to read a single adapter.");

        void Fs(string id, string name, string path, FileProperty property, string description) =>
            l.Add(new("files." + id, QueryKind.Files, name, "Files", description, Windows, WindowsRpc + " Administrative share (C$) reachable over SMB.",
                q => q.Files = new FileOptions { Path = path, Property = property }));

        Fs("ntoskrnl-version", "Kernel File Version", @"C:\Windows\System32\ntoskrnl.exe", FileProperty.FileVersion, "File version of the Windows kernel image.");
        Fs("powershell-version", "Windows PowerShell Version", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", FileProperty.FileVersion,
            "File version of Windows PowerShell 5.1.");
        Fs("exists", "File Exists", @"C:\Windows\System32\drivers\etc\hosts", FileProperty.Exists, "Yes or No. Edit the path to check another file.");
        Fs("sha256", "Kernel SHA-256", @"C:\Windows\System32\ntoskrnl.exe", FileProperty.Sha256,
            "SHA-256 of a system file. Warning: the whole file is read over the network for every device (about 10 MB here).");

        const string groupNote = " Group names are localized (for example \"Administratoren\" on German Windows): edit the name for non-English targets.";
        void Group(string id, string name, string group) =>
            l.Add(new("groups." + id, QueryKind.Groups, name, "Groups", $"Members of the local {group} group." + groupNote, Windows, WindowsRpc,
                q => q.Group = new GroupOptions { Name = group, Type = GroupQueryType.LocalMembers }));

        Group("administrators", "Local Administrators", "Administrators");
        Group("users", "Local Users", "Users");
        Group("remote-desktop-users", "Remote Desktop Users", "Remote Desktop Users");

        const string winrm = "WinRM must be configured on the target (Enable-PSRemoting); IPMaster never enables it.";
        void Ps(string id, string name, string script, string description, string category) =>
            l.Add(new("powershell." + id, QueryKind.PowerShell, name, category, description + " Runs remotely through WinRM.", Windows,
                winrm + " Rights to use PowerShell remoting on the target.", q => q.PowerShell!.Script = script));

        Ps("os", "OS Version (PowerShell)", "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber", "Edition, version and build.", "System");
        Ps("disks", "Disk Space (PowerShell)", "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID, Size, FreeSpace",
            "Size and free space of local fixed disks.", "Storage");
        Ps("wuauserv", "Windows Update Service (PowerShell)", "Get-Service -Name wuauserv | Select-Object Name, Status, StartType",
            "Status and start type of Windows Update.", "Services");
        Ps("last-boot", "Last Boot Time (PowerShell)", "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime", "When Windows last started.", "System");

        void Snmp(string id, string name, string oid, string description) =>
            l.Add(new("snmp." + id, QueryKind.Snmp, name, "System (MIB-II)", description, "Any SNMP agent",
                "SNMP agent on UDP 161. SNMPv3 is preset: choose a credential or load a saved profile; no community string is filled in.",
                q => q.Snmp = new SnmpOptions { Version = SnmpVersion.V3, Communities = "", Oid = oid, Operation = SnmpOperation.Get }));

        Snmp("sysdescr", "sysDescr", "1.3.6.1.2.1.1.1.0", "Description of the device: vendor, model and software.");
        Snmp("sysuptime", "sysUpTime", "1.3.6.1.2.1.1.3.0", "Time since the SNMP agent restarted (not always the device uptime).");
        Snmp("sysname", "sysName", "1.3.6.1.2.1.1.5.0", "Administratively assigned name.");
        Snmp("syslocation", "sysLocation", "1.3.6.1.2.1.1.6.0", "Configured physical location.");

        void Ssh(string id, string name, string command, string platform, string description) =>
            l.Add(new("ssh." + id, QueryKind.Ssh, name, "System", description, platform,
                "SSH server on TCP 22, a credential, and a trusted host key (host-key checking stays as configured).", q => q.Ssh!.Command = command));

        Ssh("uname-r", "Kernel Release", "uname -r", "Linux, macOS, BSD", "Kernel release.");
        Ssh("uname-s", "Kernel Name", "uname -s", "Linux, macOS, BSD", "Operating system kernel name (Linux, Darwin, FreeBSD).");
        Ssh("uptime", "Uptime", "uptime", "Linux, macOS, BSD", "Time since boot and load averages.");
        Ssh("df-root", "Root File System Usage", "df -h /", "Linux, macOS, BSD", "Size, used and free space of the root file system.");
        Ssh("free", "Memory Usage", "free -h", "Linux only", "Memory and swap usage (the free command is Linux-specific).");

        l.Add(new("json.redfish-version", QueryKind.Json, "Redfish Version", "Management controllers", "Redfish version of a BMC (iDRAC, iLO, XCC …) from the service root.",
            "Redfish BMC", "HTTPS on TCP 443. The service root normally needs no credential; self-signed BMC certificates fail until trusted.",
            q => q.Http = new HttpOptions { UseHttps = true, Port = 443, Path = "/redfish/v1/", Extraction = HttpExtraction.JsonPath, Expression = "$.RedfishVersion" }));
        l.Add(new("json.template", QueryKind.Json, "JSON Field (configure first)", "Templates",
            "Template: configure first. Replace the path and the JSONPath with your device's endpoint and field.", "Any HTTP device",
            "An HTTP JSON endpoint on the device.",
            q => q.Http = new HttpOptions { Port = 80, Path = "/configure/endpoint.json", Extraction = HttpExtraction.JsonPath, Expression = "$.field" }));
        l.Add(new("xml.template", QueryKind.Xml, "XML Element (configure first)", "Templates",
            "Template: configure first. Replace the path and the XPath with your device's endpoint and element.", "Any HTTP device",
            "An HTTP XML endpoint on the device.",
            q => q.Http = new HttpOptions { Port = 80, Path = "/configure/endpoint.xml", Extraction = HttpExtraction.XPath, Expression = "/root/element" }));

        const string nmap = "Nmap installed on this computer; OS detection needs administrator rights (raw packets). Scan only networks you are allowed to scan.";
        l.Add(new("nmap.os", QueryKind.Nmap, "Operating System (Nmap)", "Nmap", "Best OS match. Limited to promising hosts (--osscan-limit), no guessing.",
            "Any", nmap, q => q.Nmap = new NmapOptions { ScanType = NmapScanType.OsDetection, OsLimit = true, XPath = "/nmaprun/host/os/osmatch[1]/@name" }));
        l.Add(new("nmap.services", QueryKind.Nmap, "Service Versions (Nmap)", "Nmap", "Product names of open ports with light version probes (--version-light).",
            "Any", nmap,
            q => q.Nmap = new NmapOptions { ScanType = NmapScanType.VersionDetection, Intensity = NmapIntensity.Fast, XPath = "/nmaprun/host/ports/port/service/@product" }));

        l.Add(new("python.reverse-dns", QueryKind.Python, "Reverse DNS (Python)", "Local", "PTR name of the device's address. " + Local,
            "This computer", "Python 3 installed on this computer.",
            q => q.Python!.Script = "import socket\ntry:\n    Output.Write(socket.gethostbyaddr(Input.Current)[0])\nexcept OSError:\n    pass\n"));
        l.Add(new("python.tcp-443", QueryKind.Python, "HTTPS Port Open (Python)", "Local", "Whether TCP 443 accepts a connection from this computer. " + Local,
            "This computer", "Python 3 installed on this computer.",
            q => q.Python!.Script = "import socket\ntry:\n    socket.create_connection((Input.Current, 443), timeout=3).close()\n    Output.Write(\"open\")\nexcept OSError:\n    Output.Write(\"closed\")\n"));

        l.Add(new("script.ping", QueryKind.Script, "Ping Exit Code (JScript)", "Local", "Exit code of one ping from this computer (0 = ping reported success). " + Local,
            "This computer (Windows)", "Windows Script Host on this computer.",
            q => q.Script = new ScriptOptions
            {
                Language = ScriptLanguage.JScript,
                Script = "var p = Internal.CreateObject(\"Process\");\np.Execute(\"ping -n 1 \" + Input.Current);\nOutput.Write(p.ExitCode);",
            }));
        return l;
    }
}
