using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IPMaster.Cli;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure;
using IPMaster.Infrastructure.Network;
using IPMaster.Infrastructure.Probes;
using IPMaster.Infrastructure.Windows;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Tests;

public class ProtocolParserTests
{
    internal static byte[] NbstatResponse(params (string Name, byte Suffix, bool Group)[] names)
    {
        var b = new List<byte>();
        b.AddRange(new byte[] { 0x12, 0x34, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0 });
        b.Add(0x20);
        b.AddRange(Encoding.ASCII.GetBytes("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        b.Add(0);
        b.AddRange(new byte[] { 0, 0x21, 0, 1, 0, 0, 0, 0 });
        var rdata = new List<byte> { (byte)names.Length };
        foreach (var (name, suffix, group) in names)
        {
            rdata.AddRange(Encoding.ASCII.GetBytes(name.PadRight(15)));
            rdata.Add(suffix);
            rdata.Add((byte)(group ? 0x84 : 0x04));
            rdata.Add(0);
        }

        rdata.AddRange(new byte[] { 0x00, 0x15, 0x5D, 0x01, 0x02, 0x03 });
        rdata.AddRange(new byte[40]);
        b.Add((byte)(rdata.Count >> 8));
        b.Add((byte)rdata.Count);
        b.AddRange(rdata);
        return b.ToArray();
    }

    [Fact]
    public void NetBios_node_status_parsed()
    {
        var info = NetBiosProbe.Parse(NbstatResponse(("PC-42", 0x00, false), ("CORP", 0x00, true), ("PC-42", 0x20, false), ("ALICE", 0x03, false)));
        Assert.NotNull(info);
        Assert.Equal("PC-42", info.ComputerName);
        Assert.Equal("CORP", info.Domain);
        Assert.Equal("ALICE", info.UserName);
        Assert.Equal("00155D010203", info.Mac!.ToString());
        Assert.Equal(4, info.Names.Count);
    }

    [Fact]
    public void NetBios_request_encodes_wildcard()
    {
        var p = NetBiosProbe.BuildRequest();
        Assert.Equal(50, p.Length);
        Assert.Equal("CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Encoding.ASCII.GetString(p, 13, 32));
        Assert.Equal(0x21, BinaryPrimitives.ReadUInt16BigEndian(p.AsSpan(46)));
    }

    [Fact]
    public void Truncated_netbios_reply_is_null() => Assert.Null(NetBiosProbe.Parse(new byte[] { 1, 2, 3 }));

    [Fact]
    public void Udp_banner_descriptions()
    {
        var ntp = new byte[48];
        ntp[0] = 0x24; // v4, server
        ntp[1] = 2;
        new byte[] { 192, 0, 2, 1 }.CopyTo(ntp, 12);
        Assert.Equal("NTP v4, stratum 2, reference 192.0.2.1", UdpServiceProbe.Describe("ntp", ntp));

        var mssql = new List<byte> { 0x05, 0, 0 };
        mssql.AddRange(Encoding.ASCII.GetBytes("ServerName;SRV;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;;"));
        Assert.Equal("SQL Server MSSQLSERVER 15.0.2000.5 (tcp 1433)", UdpServiceProbe.Describe("mssql", mssql.ToArray()));

        Assert.Equal("TFTP server (error 1: File not found)", UdpServiceProbe.Describe("tftp", [0, 5, 0, 1, .. "File not found"u8, 0]));
    }

    [Fact]
    public void Snmp_get_response_string_extracted()
    {
        // GetResponse for sysDescr = "Linux router 5.15"
        var value = "Linux router 5.15"u8.ToArray();
        byte[] varbind = [0x30, (byte)(10 + 2 + value.Length), 0x06, 0x08, 0x2B, 6, 1, 2, 1, 1, 1, 0, 0x04, (byte)value.Length, .. value];
        byte[] vbl = [0x30, (byte)varbind.Length, .. varbind];
        byte[] pdu = [0xA2, (byte)(9 + vbl.Length), 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, .. vbl];
        byte[] msg = [0x30, (byte)(3 + 8 + pdu.Length), 0x02, 0x01, 0x01, 0x04, 0x06, .. "public"u8, .. pdu];
        Assert.Equal("Linux router 5.15", UdpServiceProbe.Describe("snmp", msg));
    }

    [Fact]
    public void Tcp_banner_descriptions()
    {
        Assert.Equal("nginx/1.24.0 (HTTP/1.1 200 OK)", ServiceProbe.DescribeHttp("HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"));
        Assert.Null(ServiceProbe.DescribeHttp("SSH-2.0-x"));
        byte[] mysql = [0x4A, 0, 0, 0, 10, .. "8.0.36"u8, 0, 1, 2, 3];
        Assert.Equal("MySQL 8.0.36", ServiceProbe.MySqlGreeting(mysql));
        byte[] tds = [0x04, 0x01, 0, 0x1A, 0, 0, 1, 0, 0x00, 0x00, 0x06, 0x00, 0x06, 0xFF, 0x0F, 0x00, 0x10, 0x31, 0x00, 0x00];
        Assert.Equal("SQL Server 15.0.4145", ServiceProbe.DescribeMssql(tds));
        var smb = new byte[4 + 64 + 65];
        smb[4] = 0xFE;
        smb[5] = (byte)'S';
        smb[6] = (byte)'M';
        smb[7] = (byte)'B';
        BinaryPrimitives.WriteUInt16LittleEndian(smb.AsSpan(4 + 64 + 2), 0x03); // signing required
        BinaryPrimitives.WriteUInt16LittleEndian(smb.AsSpan(4 + 64 + 4), 0x0302);
        Assert.Equal("SMB 3.0.2, signing required", ServiceProbe.DescribeSmb(smb));
    }

    [Fact]
    public void Oui_registry_longest_prefix_wins()
    {
        var map = new Dictionary<string, string>();
        OuiDatabase.Parse(new StringReader("""
            Registry,Assignment,Organization Name,Organization Address
            MA-L,00155D,"Microsoft Corporation","One Microsoft Way, Redmond"
            MA-M,00155D1,Example "Sub" Vendor,Somewhere
            MA-S,00155D123,Tiny Vendor,Elsewhere
            """), map);
        Assert.Equal("Microsoft Corporation", map["00155D"]);
        Assert.Equal("Example Sub Vendor", map["00155D1"]);
        var dir = Directory.CreateTempSubdirectory("ipm-oui-").FullName;
        File.WriteAllText(Path.Combine(dir, "oui.csv"), "MA-L,00155D,\"Microsoft Corporation\",x\nMA-L,AABBCC,Vendor A,y\n");
        File.WriteAllText(Path.Combine(dir, "oui36.csv"), "MA-S,00155D123,Tiny Vendor,z\n");
        var db = new OuiDatabase(dir);
        Assert.True(db.Capability.Available);
        Assert.Equal("Tiny Vendor", db.Lookup(PhysicalAddress.Parse("00-15-5D-12-34-56")));
        Assert.Equal("Microsoft Corporation", db.Lookup(PhysicalAddress.Parse("00-15-5D-99-34-56")));
        Assert.Null(db.Lookup(PhysicalAddress.Parse("12-34-56-78-9A-BC")));
        Assert.False(new OuiDatabase(Directory.CreateTempSubdirectory("ipm-oui-empty-").FullName).Capability.Available);
    }

    [Fact]
    public void Neighbor_table_parsers()
    {
        var arp = NeighborTable.ParseProcArp("IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n").ToList();
        Assert.Single(arp);
        Assert.Equal("AABBCCDDEEFF", arp[0].Mac.ToString());
        var neigh = NeighborTable.ParseIpNeigh("fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 router STALE\nfe80::2 dev eth0  FAILED\n").ToList();
        Assert.True(Assert.Single(neigh).IsStale);
        var mac = NeighborTable.ParseArpAn("? (192.168.1.1) at a:b:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.2) at (incomplete) on en0\n").ToList();
        Assert.Equal("0A0B0C0D0E0F", Assert.Single(mac).Mac.ToString());
        var ndp = NeighborTable.ParseNdp("Neighbor                        Linklayer Address  Netif Expire    St Flgs Prbs\nfe80::1%en0                     a:b:c:d:e:f        en0 23h59m58s S  R\n").ToList();
        Assert.Equal("fe80::1", Assert.Single(ndp).Address.ToString());
    }

    [Fact]
    public void Share_rights_mapping()
    {
        Assert.Equal("Full Control", WindowsHostProbe.ShareRights(0x1F01FF));
        Assert.Equal("Read", WindowsHostProbe.ShareRights(0x1200A9));
        Assert.Equal("0x10", WindowsHostProbe.ShareRights(0x10));
    }
}

/// <summary>Real sockets against loopback services started by the test (no LAN involved).</summary>
public class LoopbackProbeTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    [Fact]
    public async Task Tcp_open_and_closed()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var probe = new TcpPortProbe();
        Assert.Equal(PortState.Open, (await probe.ProbeAsync(IPAddress.Loopback, port, Timeout, CancellationToken.None)).State);
        listener.Stop();
        Assert.Equal(PortState.Closed, (await probe.ProbeAsync(IPAddress.Loopback, port, Timeout, CancellationToken.None)).State);
    }

    [Fact]
    public async Task Ssh_style_greeting_banner()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            await c.GetStream().WriteAsync("SSH-2.0-TestServer_1.0\r\n"u8.ToArray());
            await Task.Delay(500);
        });
        var banner = await new ServiceProbe().GrabTcpBannerAsync(IPAddress.Loopback, BannerServices.Find("ssh")!, port, Timeout, CancellationToken.None);
        Assert.Equal("SSH-2.0-TestServer_1.0", banner?.Text);
        await server;
    }

    [Fact]
    public async Task Tls_certificate_is_inspected_and_self_signed_is_flagged()
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=ipmaster-test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("test.local");
        req.CertificateExtensions.Add(san.Build());
        using var ephemeral = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        using var cert = X509CertificateLoader.LoadPkcs12(ephemeral.Export(X509ContentType.Pfx), null);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            await using var ssl = new SslStream(c.GetStream());
            try
            {
                await ssl.AuthenticateAsServerAsync(cert);
                await Task.Delay(300);
            }
            catch (IOException)
            {
            }
        });
        var info = await new ServiceProbe().GetCertificateAsync(IPAddress.Loopback, port, Timeout, CancellationToken.None);
        Assert.NotNull(info);
        Assert.Equal("CN=ipmaster-test", info.Subject);
        Assert.False(info.ChainValid); // self-signed: recorded, not trusted
        Assert.Contains("test.local", info.SubjectAlternativeNames);
        Assert.InRange(info.DaysUntilExpiry(DateTimeOffset.UtcNow), 28, 30);
        await server;
    }

    [Fact]
    public async Task Udp_silence_is_never_open()
    {
        using var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0)); // bound, never answers
        var port = ((IPEndPoint)silent.Client.LocalEndPoint!).Port;
        var (result, banner) = await new UdpServiceProbe().ProbeAsync(IPAddress.Loopback, new UdpService("ntp", "NTP", port), "public",
            TimeSpan.FromMilliseconds(400), CancellationToken.None);
        Assert.Equal(PortState.OpenOrFiltered, result.State);
        Assert.Null(banner);
    }

    [Fact]
    public async Task Udp_reply_is_open_with_banner()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        var responder = Task.Run(async () =>
        {
            var req = await server.ReceiveAsync();
            var reply = new byte[48];
            reply[0] = 0x24;
            reply[1] = 1;
            "GPS\0"u8.CopyTo(reply.AsSpan(12));
            await server.SendAsync(reply, req.RemoteEndPoint);
        });
        var (result, banner) = await new UdpServiceProbe().ProbeAsync(IPAddress.Loopback, new UdpService("ntp", "NTP", port), "public", Timeout, CancellationToken.None);
        Assert.Equal(PortState.Open, result.State);
        Assert.Equal("NTP v4, stratum 1, reference GPS", banner?.Text);
        await responder;
    }

    [Fact]
    public void Share_write_check_cleans_up_its_file()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dir = Directory.CreateTempSubdirectory("ipm-share-").FullName;
        var r = WindowsHostProbe.CheckAccess(dir + Path.DirectorySeparatorChar, writeCheck: true, DateTimeOffset.Now);
        Assert.True(r.Value!.Readable);
        Assert.True(r.Value.Writable);
        Assert.Empty(Directory.GetFileSystemEntries(dir));
        var noWrite = WindowsHostProbe.CheckAccess(dir + Path.DirectorySeparatorChar, writeCheck: false, DateTimeOffset.Now);
        Assert.Null(noWrite.Value!.Writable);
    }
}

internal sealed class FakeTcp(params int[] open) : ITcpPortProbe
{
    public int Calls;

    public Task<PortResult> ProbeAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return Task.FromResult(new PortResult(PortProtocol.Tcp, port, open.Contains(port) ? PortState.Open : port % 2 == 0 ? PortState.Closed : PortState.Filtered));
    }
}

internal sealed class FakeNeighbors(params NeighborEntry[] entries) : INeighborTable
{
    public CapabilityStatus Capability => CapabilityStatus.Yes("fake");

    public Task<IReadOnlyList<NeighborEntry>> SnapshotAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<NeighborEntry>>(entries);
}

internal sealed class FakeNetBios(NetBiosInfo? info) : INetBiosProbe
{
    public Task<NetBiosInfo?> QueryAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken) => Task.FromResult(info);
}

internal sealed class FakeVendors : IVendorLookup
{
    public CapabilityStatus Capability => CapabilityStatus.Yes("fake");

    public string? Lookup(PhysicalAddress mac) => mac.GetAddressBytes()[0] == 0x00 ? "Vendor Zero" : null;
}

public class EnrichmentStageTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(30);

    private static async Task<ListSink> Run(ScanProbes probes, ScanSettings settings, params string[] targets)
    {
        var sink = new ListSink();
        using var s = new ScanEngine(probes).Start(new ScanRequest { Plan = TestPlans.Plan(targets), Settings = settings }, sink);
        await s.Completion.WaitAsync(Wait);
        return sink;
    }

    private static FakeIcmp Alive(params string[] ips)
    {
        var icmp = new FakeIcmp();
        foreach (var ip in ips) icmp.Alive.Add(ip);
        return icmp;
    }

    private static ScanSettings Base => new() { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false, DeviceDeadlineSeconds = 0 };

    [Fact]
    public async Task Tcp_ports_keep_open_and_summarise_the_rest()
    {
        var tcp = new FakeTcp(22, 80);
        var sink = await Run(new ScanProbes(Alive("10.0.0.1"), new FakeArp(), new FakeDns()) { Tcp = tcp },
            Base with { ScanTcpPorts = true, TcpPorts = "20-25, 80" }, "10.0.0.1");
        var ports = sink.Get("10.0.0.1").TcpPorts;
        Assert.Equal([22, 80], ports.Value!.Select(p => p.Port));
        Assert.Equal("ssh", ports.Value![0].Service);
        Assert.Equal("2 open, 2 closed, 3 filtered of 7", ports.Detail); // fake: even ports closed, odd filtered
        Assert.Equal(7, tcp.Calls);
    }

    [Fact]
    public async Task Invalid_port_list_is_a_failure_not_silence()
    {
        var sink = await Run(new ScanProbes(Alive("10.0.0.1"), new FakeArp(), new FakeDns()) { Tcp = new FakeTcp() },
            Base with { ScanTcpPorts = true, TcpPorts = "80-70" }, "10.0.0.1");
        Assert.Equal(ObservationState.Failed, sink.Get("10.0.0.1").TcpPorts.State);
    }

    [Fact]
    public async Task Mac_from_neighbor_cache_then_vendor_and_ipv6()
    {
        var mac = PhysicalAddress.Parse("00-11-22-33-44-55");
        var probes = new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns())
        {
            Neighbors = new FakeNeighbors(new NeighborEntry(IPAddress.Parse("10.0.0.5"), mac, 3, false),
                new NeighborEntry(IPAddress.Parse("fe80::5%3"), mac, 3, false), new NeighborEntry(IPAddress.Parse("10.0.0.6"), PhysicalAddress.Parse("02-00-00-00-00-01"), 3, false)),
            Vendors = new FakeVendors(),
        };
        var sink = await Run(probes, Base with { ResolveMac = true, LookupVendor = true, ResolveIPv6 = true }, "10.0.0.5-10.0.0.6");
        var d = sink.Get("10.0.0.5");
        Assert.Equal(mac, d.Mac.Value);
        Assert.Equal(MacSource.NeighborCache, d.MacSource);
        Assert.Equal("Vendor Zero", d.Vendor.Value);
        Assert.Equal("fe80::5%3", Assert.Single(d.IPv6Addresses.Value!).ToString());
        Assert.False(sink.Has("10.0.0.6")); // offline (not in ICMP alive set) and inactive devices hidden
    }

    [Fact]
    public async Task Mac_via_netbios_across_routers_and_legacy_host_name()
    {
        var nb = new NetBiosInfo("REMOTE-PC", "CORP", null, PhysicalAddress.Parse("00-AA-BB-CC-DD-EE"), []);
        var probes = new ScanProbes(Alive("10.9.0.5"), new FakeArp(), new FakeDns()) { NetBios = new FakeNetBios(nb), Neighbors = new FakeNeighbors() };
        var sink = await Run(probes, Base with
        {
            ResolveMac = true,
            ResolveHostNames = true,
            HostNameMode = HostNameMode.Legacy,
            LookupWorkgroup = true,
        }, "10.9.0.5");
        var d = sink.Get("10.9.0.5");
        Assert.Equal(MacSource.NetBios, d.MacSource);
        Assert.Equal("REMOTE-PC", d.HostName.Value!.Name); // DNS had no PTR → NetBIOS fallback
        Assert.Equal("CORP", d.Workgroup.Value); // portable fallback: Windows probe unavailable in this configuration
    }

    [Fact]
    public async Task Default_host_name_mode_falls_back_to_netbios()
    {
        var nb = new NetBiosInfo("NAS-01", "WORKGROUP", null, null, []);
        var probes = new ScanProbes(Alive("10.9.0.5"), new FakeArp(), new FakeDns()) { NetBios = new FakeNetBios(nb), Neighbors = new FakeNeighbors() };
        var sink = await Run(probes, Base with { ResolveHostNames = true, HostNameMode = new ScanSettings().HostNameMode }, "10.9.0.5");
        Assert.Equal("NAS-01", sink.Get("10.9.0.5").HostName.Value!.Name); // DNS had no PTR (D-085)
    }

    [Fact]
    public async Task Locally_administered_mac_is_labelled()
    {
        var arp = new FakeArp { Capability = CapabilityStatus.Yes("fake") };
        var probes = new ScanProbes(Alive("10.0.0.5"), arp, new FakeDns())
        {
            Neighbors = new FakeNeighbors(new NeighborEntry(IPAddress.Parse("10.0.0.5"), PhysicalAddress.Parse("02-11-22-33-44-55"), 1, false)),
            Vendors = new FakeVendors(),
        };
        var sink = await Run(probes, Base with { ResolveMac = true, LookupVendor = true }, "10.0.0.5");
        Assert.Equal("(locally administered address)", sink.Get("10.0.0.5").Vendor.Value);
    }

    [Fact]
    public async Task Windows_lookups_report_unsupported_reason_when_unavailable()
    {
        var sink = await Run(new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns()),
            Base with { ScanShares = true, LookupWindowsVersion = true }, "10.0.0.5");
        var d = sink.Get("10.0.0.5");
        Assert.Equal(ObservationState.Unsupported, d.Shares.State);
        Assert.Equal(ObservationState.Unsupported, d.OsVersion.State);
        Assert.False(d.HasPending);
    }

    [Fact]
    public async Task Account_filters_apply_wildcards_and_dedupe()
    {
        var win = new FakeWindows();
        var probes = new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns()) { Windows = win, Tcp = new FakeTcp(445) };
        var sink = await Run(probes, Base with { EnumerateAccounts = true, ExcludedAccounts = ["svc_*", "Guest"] }, "10.0.0.5");
        Assert.Equal(["Administrator", "alice"], sink.Get("10.0.0.5").Accounts.Value);
    }

    [Fact]
    public async Task Windows_lookups_skip_hosts_without_smb()
    {
        var win = new FakeWindows();
        var probes = new ScanProbes(Alive("10.0.0.5"), new FakeArp(), new FakeDns()) { Windows = win, Tcp = new FakeTcp() };
        var sink = await Run(probes, Base with { EnumerateAccounts = true }, "10.0.0.5");
        Assert.Equal(ObservationState.NoResponse, sink.Get("10.0.0.5").Accounts.State);
        Assert.Equal(0, win.Calls);
    }

    [Fact]
    public async Task Rescan_publishes_offline_results_for_known_addresses()
    {
        var sink = new ListSink();
        var key = Core.Targets.AddressKey.From(IPAddress.Parse("10.0.0.7"));
        using var s = new ScanEngine(new FakeIcmp(), new FakeArp(), new FakeDns()).Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.7-10.0.0.8"),
            Settings = Base,
            KnownAddresses = new HashSet<Core.Targets.AddressKey> { key },
        }, sink);
        await s.Completion.WaitAsync(Wait);
        Assert.Equal(DeviceStatus.Offline, sink.Get("10.0.0.7").Status);
        Assert.False(sink.Has("10.0.0.8"));
        var merged = DeviceResult.MergeRescan(Samples.Device("10.0.0.7"), sink.Get("10.0.0.7"));
        Assert.Equal(Samples.T, merged.LastSeen);
    }

    [Fact]
    public async Task Revisions_increase_across_sessions()
    {
        var first = await Run(new ScanProbes(Alive("10.0.0.1"), new FakeArp(), new FakeDns()), Base, "10.0.0.1");
        var second = await Run(new ScanProbes(Alive("10.0.0.1"), new FakeArp(), new FakeDns()), Base, "10.0.0.1");
        Assert.True(second.Get("10.0.0.1").Revision > first.Get("10.0.0.1").Revision);
    }

    private sealed class FakeWindows : IWindowsHostProbe
    {
        public int Calls;

        public CapabilityStatus Capability => CapabilityStatus.Yes("fake");

        private Observation<T> Count<T>(Observation<T> o)
        {
            Interlocked.Increment(ref Calls);
            return o;
        }

        public Observation<string> GetWorkgroup(string host, DateTimeOffset now) => Count(Observation<string>.Ok("WG", now));

        public Observation<string> GetWindowsVersion(string host, DateTimeOffset now) => Count(Observation<string>.Ok("Windows 11", now));

        public Observation<IReadOnlyList<string>> GetAccounts(string host, DateTimeOffset now) =>
            Count(Observation<IReadOnlyList<string>>.Ok(["Administrator", "alice", "ALICE", "svc_backup", "Guest"], now));

        public Observation<IReadOnlyList<string>> GetLoggedOnUsers(string host, DateTimeOffset now) => Count(Observation<IReadOnlyList<string>>.Ok([], now));

        public Observation<IReadOnlyList<string>> GetLoggedOnSids(string host, DateTimeOffset now) => Count(Observation<IReadOnlyList<string>>.Ok([], now));

        public Observation<DateTimeOffset> GetRemoteTime(string host, DateTimeOffset now) => Count(Observation<DateTimeOffset>.Ok(now, now));

        public Observation<IReadOnlyList<InstalledApplication>> GetInstalledApplications(string host, DateTimeOffset now) => Count(Observation<IReadOnlyList<InstalledApplication>>.Ok([], now));

        public Observation<IReadOnlyList<ShareInfo>> GetShares(string host, ShareTypeSelection types, bool diskSpace, bool security, bool writeCheck,
            DateTimeOffset now, CancellationToken cancellationToken) => Count(Observation<IReadOnlyList<ShareInfo>>.Ok([], now));
    }
}

public class CliPhase2Tests
{
    private static (CliApp App, StringWriter Out, StringWriter Err, string Dir) Create(FakeIcmp icmp)
    {
        var dir = Directory.CreateTempSubdirectory("ipm-cli2-").FullName;
        var services = new ServiceCollection().AddIPMaster(dir);
        services.AddSingleton<ScanProbes>(new ScanProbes(icmp, new FakeArp(), new FakeDns()));
        services.AddSingleton<INetworkAdapterProvider>(new FakeAdapters());
        var sp = services.BuildServiceProvider();
        var o = new StringWriter();
        var e = new StringWriter();
        return (new CliApp(sp, o, e, () => new DateTime(2026, 1, 2, 3, 4, 5)), o, e, dir);
    }

    [Theory]
    [InlineData("r.xml")]
    [InlineData("r.htm")]
    [InlineData("r.txt")]
    [InlineData("r.db")]
    public async Task All_output_formats(string name)
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var (app, _, err, dir) = Create(icmp);
        var path = Path.Combine(dir, name);
        Assert.Equal(ExitCodes.Ok, await app.RunAsync(["/auto:" + path, "/range:10.0.0.1-10.0.0.3", "/quiet"], CancellationToken.None));
        Assert.True(new FileInfo(path).Length > 0, err.ToString());
    }

    [Fact]
    public async Task Load_and_rescan_merges_and_keeps_last_seen()
    {
        var icmp = new FakeIcmp();
        var (app, _, _, dir) = Create(icmp);
        var input = Path.Combine(dir, "in.xml");
        await ResultsXml.ExportAsync(input, ColumnCatalog.All, [Samples.Device("10.0.0.7"), Samples.Device("10.0.0.8")], new ScanMetadata());
        icmp.Alive.Add("10.0.0.8");
        var output = Path.Combine(dir, "out.xml");
        Assert.Equal(ExitCodes.Ok, await app.RunAsync(["/load:" + input, "/auto:" + output, "/quiet"], CancellationToken.None));
        var doc = await ResultsXml.LoadAsync(output);
        Assert.Equal(2, doc.Devices.Count);
        var gone = doc.Devices.Single(d => d.Key.ToString() == "10.0.0.7");
        Assert.Equal(DeviceStatus.Offline, gone.Status);
        Assert.Equal(Samples.T, gone.LastSeen);
        Assert.Equal(DeviceStatus.Online, doc.Devices.Single(d => d.Key.ToString() == "10.0.0.8").Status);
    }

    [Fact]
    public async Task Config_switch_uses_xml_configuration()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var (app, stdout, _, dir) = Create(icmp);
        var cfg = Path.Combine(dir, "c.xml");
        await IPMaster.Infrastructure.Configuration.ConfigXml.SaveAsync(cfg, new Core.Configuration.AppSettings
        {
            Ranges = [new Core.Configuration.RangeEntry { Target = "10.0.0.2" }],
            Scan = new ScanSettings { ResolveHostNames = false, ShowTimestamps = false, ResolveMac = false, ShowDeviceType = false, PingTimeoutMs = 50 },
        });
        Assert.Equal(ExitCodes.Ok, await app.RunAsync(["/config:" + cfg, "/auto", "/quiet"], CancellationToken.None));
        Assert.Equal("IP Address\tResponse Time\r\n10.0.0.2\t1 ms\r\n", stdout.ToString());
    }

    [Theory]
    [InlineData(new[] { "/auto:x.xml", "/append", "/range:10.0.0.1" }, ExitCodes.Usage)]
    [InlineData(new[] { "/auto:x.csv", "/append", "/merge", "/range:10.0.0.1" }, ExitCodes.Usage)]
    [InlineData(new[] { "/auto", "/sharetype:XZ", "/range:10.0.0.1" }, ExitCodes.Usage)]
    [InlineData(new[] { "/auto", "/load:missing.xml" }, ExitCodes.Targets)]
    [InlineData(new[] { "/auto", "/config:missing.xml" }, ExitCodes.Settings)]
    public async Task Phase2_switch_errors(string[] args, int expected)
    {
        var (app, _, _, _) = Create(new FakeIcmp());
        Assert.Equal(expected, await app.RunAsync(args, CancellationToken.None));
    }
}
