using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using IPMaster.Core.Configuration;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Security;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Windows;

namespace IPMaster.Tests;

internal sealed class GapWindows : IWindowsHostProbe
{
    public List<string> Calls { get; } = [];

    public CapabilityStatus Capability => CapabilityStatus.Yes("fake");

    private Observation<T> Log<T>(string name, Observation<T> o)
    {
        lock (Calls) Calls.Add(name);
        return o;
    }

    public Observation<string> GetWorkgroup(string host, DateTimeOffset now) => Log("workgroup", Observation<string>.Ok("WG", now));

    public Observation<string> GetWindowsVersion(string host, DateTimeOffset now) => Log("os", Observation<string>.Ok("Windows 11", now));

    public Observation<IReadOnlyList<string>> GetAccounts(string host, DateTimeOffset now) => Log("accounts", Observation<IReadOnlyList<string>>.Ok(["a"], now));

    public Observation<IReadOnlyList<string>> GetLoggedOnUsers(string host, DateTimeOffset now) => Log("users", Observation<IReadOnlyList<string>>.Ok([], now));

    public Observation<IReadOnlyList<string>> GetLoggedOnSids(string host, DateTimeOffset now) => Log("sids", Observation<IReadOnlyList<string>>.Ok([], now));

    public Observation<DateTimeOffset> GetRemoteTime(string host, DateTimeOffset now) => Log("time", Observation<DateTimeOffset>.Ok(now, now));

    public Observation<IReadOnlyList<InstalledApplication>> GetInstalledApplications(string host, DateTimeOffset now) =>
        Log("apps", Observation<IReadOnlyList<InstalledApplication>>.Ok([], now));

    public Observation<IReadOnlyList<ShareInfo>> GetShares(string host, ShareTypeSelection types, bool diskSpace, bool security, bool writeCheck,
        DateTimeOffset now, CancellationToken cancellationToken) => Log("shares", Observation<IReadOnlyList<ShareInfo>>.Ok([], now));
}

internal sealed class FakeExtras : IWindowsExtras
{
    public List<string> Events { get; } = [];

    public CapabilityStatus Capability => CapabilityStatus.Yes("fake");

    public IDisposable? OpenSession(string host, ResolvedCredential credential)
    {
        if (credential.UserName == "bad") throw new UnauthorizedAccessException("The user name or password is incorrect.");
        lock (Events) Events.Add($"open {host} {credential.UserName}");
        return new Closer(this, host);
    }

    private sealed class Closer(FakeExtras owner, string host) : IDisposable
    {
        public void Dispose()
        {
            lock (owner.Events) owner.Events.Add($"close {host}");
        }
    }

    public Observation<IReadOnlyList<MonitorInfo>> GetMonitors(string host, DateTimeOffset now) =>
        Observation<IReadOnlyList<MonitorInfo>>.Ok([new MonitorInfo("DEL", "DELL P2419H", "ABC123", 2020)], now);

    public Observation<IReadOnlyList<TerminalSession>> GetTerminalSessions(string host, DateTimeOffset now) =>
        Observation<IReadOnlyList<TerminalSession>>.Ok([new TerminalSession(2, @"CORP\alice", "Active", "LAPTOP7", "10.0.0.99")], now);

    public Observation<PhysicalAddress> GetMacViaWmi(IPAddress address, ResolvedCredential? credential, TimeSpan timeout, DateTimeOffset now) =>
        address.ToString() == "10.0.0.5" ? Observation<PhysicalAddress>.Ok(PhysicalAddress.Parse("00-50-56-00-00-05"), now) : Observation<PhysicalAddress>.Of(ObservationState.Empty, now, "no adapter");
}

internal sealed class FakeRouterArp(Dictionary<IPAddress, PhysicalAddress> table) : IRouterArpSource
{
    public int Walks;

    public Task<IReadOnlyDictionary<IPAddress, PhysicalAddress>> ArpTableAsync(IPAddress router, string community, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Walks);
        return Task.FromResult<IReadOnlyDictionary<IPAddress, PhysicalAddress>>(table);
    }
}

public class Phase4GapTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);

    private static ScanSettings Base => new() { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false, DeviceDeadlineSeconds = 0 };

    private static async Task<ListSink> Run(ScanProbes probes, ScanSettings settings, Func<ScanRequest, ScanRequest>? configure, params string[] targets)
    {
        var sink = new ListSink();
        var request = new ScanRequest { Plan = TestPlans.Plan(targets), Settings = settings };
        using var s = new ScanEngine(probes).Start(configure?.Invoke(request) ?? request, sink);
        await s.Completion.WaitAsync(Wait);
        return sink;
    }

    private static FakeIcmp Alive(params string[] ips)
    {
        var icmp = new FakeIcmp();
        foreach (var ip in ips) icmp.Alive.Add(ip);
        return icmp;
    }

    public static byte[] SampleEdid(bool withDescriptors = true)
    {
        var e = new byte[128];
        new byte[] { 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 }.CopyTo(e, 0);
        e[8] = 0x10; // "DEL" = (4<<10)|(5<<5)|12 = 0x10AC
        e[9] = 0xAC;
        e[10] = 0xC2;
        e[11] = 0xA0;
        BitConverter.GetBytes(0x12345678u).CopyTo(e, 12);
        e[17] = 30;
        e[54] = 0x01; // detailed timing (ignored)
        e[55] = 0x1D;
        if (withDescriptors)
        {
            new byte[] { 0, 0, 0, 0xFC, 0 }.CopyTo(e, 72);
            Encoding.ASCII.GetBytes("DELL P2419H\n ").CopyTo(e, 77);
            new byte[] { 0, 0, 0, 0xFF, 0 }.CopyTo(e, 90);
            Encoding.ASCII.GetBytes("ABC123\n      ").CopyTo(e, 95);
        }

        return e;
    }

    [Fact]
    public void Edid_decoding()
    {
        var m = Edid.Parse(SampleEdid())!;
        Assert.Equal(new MonitorInfo("DEL", "DELL P2419H", "ABC123", 2020), m);
        Assert.Equal("DEL DELL P2419H (S/N ABC123)", m.ToString());
        var plain = Edid.Parse(SampleEdid(withDescriptors: false))!;
        Assert.Equal("DELA0C2", plain.Model);
        Assert.Equal("305419896", plain.Serial);
        Assert.Null(Edid.Parse(new byte[128]));
        Assert.Null(Edid.Parse(SampleEdid().AsSpan(0, 100)));
    }

    [Fact]
    public void Active_directory_filters_escape_user_text()
    {
        Assert.Equal(@"a\2ab\28c\29\5c", ActiveDirectoryFilters.Escape(@"a*b(c)\"));
        var nameContains = ActiveDirectoryFilters.Presets.Single(p => p.Name == "Name contains string");
        var f = ActiveDirectoryFilters.Build(nameContains, "pc)(objectClass=*");
        Assert.Equal(@"(&(objectCategory=computer)(name=*pc\29\28objectClass=\2a*))", f);
        Assert.Null(ActiveDirectoryFilters.Validate(f));
        Assert.NotNull(ActiveDirectoryFilters.Validate("(&(a=b)"));
        Assert.NotNull(ActiveDirectoryFilters.Validate("objectClass=computer"));
        Assert.Equal("DC=corp,DC=example,DC=com", ActiveDirectoryFilters.BaseFromDomain("corp.example.com."));
        Assert.Equal("pc1.corp.example.com", new AdComputer("PC1", "pc1.corp.example.com", "Windows 11 Pro").Target);
        Assert.Equal("PC2", new AdComputer("PC2", "", "").Target);
    }

    [Fact]
    public void Router_arp_table_parsing()
    {
        var values = new[]
        {
            new SnmpValue("1.3.6.1.2.1.4.22.1.2.3.10.0.0.5", Lextm.SharpSnmpLib.SnmpType.OctetString, [0, 0x11, 0x22, 0x33, 0x44, 0x55], ""),
            new SnmpValue("1.3.6.1.2.1.4.22.1.2.3.10.0.0.6", Lextm.SharpSnmpLib.SnmpType.OctetString, [0, 0, 0, 0, 0, 0], ""), // incomplete entry
            new SnmpValue("1.3.6.1.2.1.4.22.1.2.3.10.0.0.7", Lextm.SharpSnmpLib.SnmpType.OctetString, [1, 2, 3], ""),
        };
        var map = RouterArpSource.Parse(values);
        Assert.Equal("001122334455", Assert.Single(map).Value.ToString());
        Assert.True(map.ContainsKey(IPAddress.Parse("10.0.0.5")));
    }

    [Fact]
    public async Task Workstation_credential_session_wraps_lookups_and_shares_use_their_own()
    {
        var win = new GapWindows();
        var extras = new FakeExtras();
        var probes = new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns()) { Windows = win, Tcp = new FakeTcp(445), WindowsExtras = extras };
        var settings = Base with { LookupWindowsVersion = true, LookupMonitors = true, ListTerminalSessions = true, ScanShares = true };
        var sink = await Run(probes, settings, r => r with
        {
            WorkstationCredential = new ResolvedCredential(@"CORP\admin", "pw"),
            SharesCredential = new ResolvedCredential("filer", "pw2"),
        }, "10.0.0.5");
        var d = sink.Get("10.0.0.5");
        Assert.Equal("Windows 11", d.OsVersion.Value);
        Assert.Equal("DELL P2419H", Assert.Single(d.Monitors.Value!).Model);
        Assert.Equal("10.0.0.99", Assert.Single(d.TerminalSessions.Value!).ClientAddress);
        Assert.Equal(["open 10.0.0.5 CORP\\admin", "close 10.0.0.5", "open 10.0.0.5 filer", "close 10.0.0.5"], extras.Events);
        var cols = ColumnCatalog.EnabledFor(settings).Select(c => c.Header).ToList();
        Assert.Contains("Monitor", cols);
        Assert.Contains("Terminal Sessions", cols);
        Assert.Equal(@"CORP\alice [Active] from LAPTOP7 (10.0.0.99)", ColumnCatalog.TerminalSessions.Text(d));
    }

    // Review C-15: an IPC$ session that opens only after its call was abandoned (timeout) is closed, not leaked.
    [Fact]
    public async Task Session_opened_after_timeout_is_disposed()
    {
        var extras = new SlowExtras();
        var probes = new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns()) { Windows = new GapWindows(), Tcp = new FakeTcp(445), WindowsExtras = extras };
        var sink = await Run(probes, Base with { LookupWindowsVersion = true, WindowsTimeoutMs = 200 },
            r => r with { WorkstationCredential = new ResolvedCredential(@"CORP\admin", "pw") }, "10.0.0.5");
        Assert.Equal(ObservationState.Timeout, sink.Get("10.0.0.5").OsVersion.State);
        Assert.True(extras.Closed.Wait(TimeSpan.FromSeconds(10)), "the late session was never disposed");
    }

    [Fact]
    public async Task Rejected_credential_marks_lookups_access_denied_without_calls()
    {
        var win = new GapWindows();
        var probes = new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns()) { Windows = win, Tcp = new FakeTcp(445), WindowsExtras = new FakeExtras() };
        var sink = await Run(probes, Base with { LookupWindowsVersion = true, LookupMonitors = true },
            r => r with { WorkstationCredential = new ResolvedCredential("bad", "x") }, "10.0.0.5");
        var d = sink.Get("10.0.0.5");
        Assert.Equal(ObservationState.AccessDenied, d.OsVersion.State);
        Assert.Contains("incorrect", d.Monitors.Detail, StringComparison.Ordinal);
        Assert.Empty(win.Calls);
    }

    [Fact]
    public async Task Wmi_and_router_mib_mac_methods_in_order()
    {
        var arp = new FakeRouterArp(new Dictionary<IPAddress, PhysicalAddress> { [IPAddress.Parse("10.0.1.7")] = PhysicalAddress.Parse("AA-00-00-00-01-07") });
        var probes = new ScanProbes(Alive("10.0.0.5", "10.0.1.7", "10.0.1.8"), new FakeArp(), new FakeDns()) { WindowsExtras = new FakeExtras(), RouterArp = arp };
        var settings = Base with { ResolveMac = true, MacMethods = [MacMethod.Wmi, MacMethod.RouterMib] };
        var sink = await Run(probes, settings, r => r with { Routers = [IPAddress.Parse("10.0.0.1")] }, "10.0.0.5", "10.0.1.7", "10.0.1.8");
        Assert.Equal(MacSource.Wmi, sink.Get("10.0.0.5").MacSource);
        Assert.Equal(MacSource.RouterMib, sink.Get("10.0.1.7").MacSource);
        Assert.Equal("router 10.0.0.1", sink.Get("10.0.1.7").Mac.Detail);
        Assert.Equal(ObservationState.Empty, sink.Get("10.0.1.8").Mac.State);
        Assert.Contains("Router MIB: not in the routers' ARP tables", sink.Get("10.0.1.8").Mac.Detail, StringComparison.Ordinal);
        Assert.Equal(1, arp.Walks); // walked once per scan, not per device
    }

    [Fact]
    public void Scan_context_resolves_routers_and_credentials()
    {
        var secrets = new FakeSecrets();
        var id = Guid.NewGuid();
        secrets.Credentials[id] = new ResolvedCredential("admin", "pw");
        var adapters = new FakeAdapters(new NetworkAdapterInfo("1", "eth", "", "Ethernet", null, [], [IPAddress.Parse("10.0.0.1")], 0));
        var s = new AppSettings
        {
            Scan = new ScanSettings
            {
                ResolveMac = true, MacMethods = [MacMethod.RouterMib], RouterMibRouters = "10.0.2.1, nope", WorkstationCredentialId = id, SharesCredentialId = Guid.NewGuid(),
            },
        };
        var ctx = ScanContext.Resolve(s, secrets, adapters);
        Assert.Equal(["10.0.0.1", "10.0.2.1"], ctx.Routers.Select(r => r.ToString()));
        Assert.Equal("admin", ctx.WorkstationCredential!.UserName);
        Assert.Null(ctx.SharesCredential);
        Assert.Equal(2, ctx.Warnings.Count); // bad router + missing credential
    }

    [Fact]
    public void Monitors_and_sessions_round_trip_through_results_xml()
    {
        var d = Samples.Device("10.0.0.5") with
        {
            Monitors = Observation<IReadOnlyList<MonitorInfo>>.Ok([new MonitorInfo("DEL", "DELL P2419H", "ABC123", 2020), new MonitorInfo("SAM", "S24", "", null)], Samples.T),
            TerminalSessions = Observation<IReadOnlyList<TerminalSession>>.Ok([new TerminalSession(2, "alice", "Active", "", "")], Samples.T),
        };
        var doc = ResultsXml.ToDocument(ColumnCatalog.All, [d], new ScanMetadata { ExportedAt = Samples.T, StartedAt = Samples.T });
        using var ms = new MemoryStream();
        doc.Save(ms);
        ms.Position = 0;
        var back = ResultsXml.Read(ms).Devices[0];
        Assert.Equal(d.Monitors.Value, back.Monitors.Value);
        Assert.Equal(d.TerminalSessions.Value, back.TerminalSessions.Value);
    }
}

public class LocalEdidTests
{
    /// <summary>Cross-check with real hardware: the EDIDs of this computer's attached displays decode to the same
    /// manufacturer, name and serial that Windows reports through WmiMonitorID.</summary>
    [Fact]
    public void Local_edids_match_wmi_monitor_id()
    {
        if (!OperatingSystem.IsWindows()) return;
        var parsed = new List<MonitorInfo>();
        using (var display = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\DISPLAY"))
        {
            if (display is null) return;
            foreach (var model in display.GetSubKeyNames())
            {
                using var mk = display.OpenSubKey(model);
                foreach (var inst in mk?.GetSubKeyNames() ?? [])
                {
                    using var ik = mk!.OpenSubKey(inst);
                    if (ik is null || !ik.GetSubKeyNames().Contains("Control", StringComparer.OrdinalIgnoreCase)) continue;
                    using var p = ik.OpenSubKey("Device Parameters");
                    if (p?.GetValue("EDID") is byte[] e && Edid.Parse(e) is { } m) parsed.Add(m);
                }
            }
        }

        var wmi = new List<(string Mfg, string Name, string Serial)>();
        try
        {
            using var s = new System.Management.ManagementObjectSearcher(@"root\wmi", "SELECT ManufacturerName, UserFriendlyName, SerialNumberID FROM WmiMonitorID WHERE Active = TRUE");
            foreach (var o in s.Get().Cast<System.Management.ManagementBaseObject>())
            {
                static string Text(object? v) => v is ushort[] a ? new string(a.TakeWhile(c => c != 0).Select(c => (char)c).ToArray()).Trim() : "";
                wmi.Add((Text(o["ManufacturerName"]), Text(o["UserFriendlyName"]), Text(o["SerialNumberID"])));
            }
        }
        catch (System.Management.ManagementException)
        {
            return; // WmiMonitorID not available (e.g. some virtual machines)
        }

        if (parsed.Count == 0 || wmi.Count == 0) return; // headless or no EDID
        foreach (var w in wmi)
        {
            Assert.Contains(parsed, m => m.Manufacturer == w.Mfg && (w.Name.Length == 0 || m.Model == w.Name) && (w.Serial.Length == 0 || w.Serial == "0" || m.Serial == w.Serial));
        }
    }
}

/// <summary>OpenSession takes 1 s (longer than the Windows timeout in the test), then returns a session that records Dispose.</summary>
internal sealed class SlowExtras : IWindowsExtras
{
    public ManualResetEventSlim Closed { get; } = new();

    public int Opened;

    public CapabilityStatus Capability => CapabilityStatus.Yes("fake");

    public IDisposable? OpenSession(string host, ResolvedCredential credential)
    {
        Thread.Sleep(1000);
        Interlocked.Increment(ref Opened);
        return new Closer(Closed);
    }

    private sealed class Closer(ManualResetEventSlim closed) : IDisposable
    {
        public void Dispose() => closed.Set();
    }

    public Observation<IReadOnlyList<MonitorInfo>> GetMonitors(string host, DateTimeOffset now) => Observation<IReadOnlyList<MonitorInfo>>.Of(ObservationState.Empty, now);

    public Observation<IReadOnlyList<TerminalSession>> GetTerminalSessions(string host, DateTimeOffset now) => Observation<IReadOnlyList<TerminalSession>>.Of(ObservationState.Empty, now);

    public Observation<PhysicalAddress> GetMacViaWmi(IPAddress address, ResolvedCredential? credential, TimeSpan timeout, DateTimeOffset now) => Observation<PhysicalAddress>.Of(ObservationState.Empty, now);
}
