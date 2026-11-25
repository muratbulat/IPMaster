using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using IPMaster.Cli;
using IPMaster.Core.Configuration;
using IPMaster.Core.Discovery;
using IPMaster.Core.Management;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Discovery;
using IPMaster.Infrastructure.Management;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Tests;

public class WakeOnLanTests
{
    [Fact]
    public void Magic_packet_layout()
    {
        var p = WakeOnLan.MagicPacket(PhysicalAddress.Parse("AA-BB-CC-DD-EE-FF"));
        Assert.Equal(102, p.Length);
        Assert.All(p[..6], b => Assert.Equal(0xFF, b));
        for (var i = 0; i < 16; i++) Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, p[(6 + (i * 6))..(12 + (i * 6))]);
    }

    [Theory]
    [InlineData("0.0.0.255", "192.168.1.10", "192.168.1.255")] // manual example
    [InlineData("255.255.255.255", "192.168.1.10", "255.255.255.255")]
    [InlineData("10.0.0.0", "192.168.1.10", "10.168.1.10")]
    [InlineData("0.0.0.255", null, "255.255.255.255")]
    [InlineData("wol.example", "10.0.0.1", "wol.example")]
    public void Destination_combination(string def, string? device, string expected) =>
        Assert.Equal(expected, WakeOnLan.CombineDestination(def, device is null ? null : IPAddress.Parse(device)));

    [Fact]
    public void Mac_list_parsing_reports_bad_lines()
    {
        var (macs, rejected) = WakeOnLan.ParseMacList("AABBCCDDEEFF\n# comment\n00:11:22:33:44:55 office pc\nnot-a-mac\n\n");
        Assert.Equal(2, macs.Count);
        Assert.Equal(4, Assert.Single(rejected).LineNumber);
    }

    [Fact]
    public void Target_from_device_uses_default_destination()
    {
        var t = WakeOnLan.FromDevice(Samples.Device("192.168.1.10", "pc1"), new WolSettings { DefaultDestination = "0.0.0.255" });
        Assert.Equal("192.168.1.255", t.Destination);
        Assert.Equal("AA-BB-CC-00-11-22", t.Mac);
        Assert.Equal("pc1", t.HostName);
    }

    [Fact]
    public async Task Sender_delivers_packet_over_udp()
    {
        using var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
        var receive = listener.ReceiveAsync();
        var r = await new WakeOnLanSender().WakeAsync(new WolTarget { Mac = "00-11-22-33-44-55", Destination = "127.0.0.1" }, port, CancellationToken.None);
        Assert.True(r.Success, r.Message);
        var got = await receive.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(WakeOnLan.MagicPacket(PhysicalAddress.Parse("00-11-22-33-44-55")), got.Buffer);
    }

    [Fact]
    public async Task Invalid_mac_fails_without_sending()
    {
        var r = await new WakeOnLanSender().WakeAsync(new WolTarget { Mac = "nope", Destination = "127.0.0.1" }, 9, CancellationToken.None);
        Assert.False(r.Success);
    }
}

public class CommandTemplateTests
{
    private static readonly GlobalVariable[] Vars = [new() { Name = "User", Value = "admin" }, new() { Name = "Home", Value = "IPM_TEST_HOME", FromEnvironment = true }];

    [Fact]
    public void Manual_example_with_prompts_and_defaults()
    {
        const string t = @"psexec.exe \\%0 -u {User name:Admin} -p {Password} {Command}";
        var prompts = CommandTemplate.Prompts(t);
        Assert.Equal(["User name", "Password", "Command"], prompts.Select(p => p.Name));
        Assert.Equal("Admin", prompts[0].Default);
        var line = CommandTemplate.Expand(t, "10.0.0.5", "pc5", "AA-BB", new Dictionary<string, string> { ["Password"] = "x", ["Command"] = "cmd" }, Vars);
        Assert.Equal(@"psexec.exe \\10.0.0.5 -u Admin -p x cmd", line);
    }

    [Fact]
    public void Literal_braces_variables_and_placeholders()
    {
        var line = CommandTemplate.Expand("tool {{12345678-ABCD}} %1 %2 {$User} {$Home}", "10.0.0.5", "pc5", "AA-BB",
            new Dictionary<string, string>(), Vars, name => name == "IPM_TEST_HOME" ? "C:\\Users\\x" : null);
        Assert.Equal("tool {12345678-ABCD} pc5 AA-BB admin C:\\Users\\x", line);
        Assert.Empty(CommandTemplate.Prompts("tool {{literal}} {$User}"));
        Assert.Throws<KeyNotFoundException>(() => CommandTemplate.Expand("{$Missing}", "", "", "", new Dictionary<string, string>(), Vars));
    }

    [Fact]
    public void Path_prompts_and_command_split()
    {
        Assert.True(new PromptParameter("Script file", "").IsPath);
        Assert.False(new PromptParameter("User", "").IsPath);
        Assert.Equal(("C:\\Program Files\\PuTTY\\putty.exe", "-ssh 10.0.0.1"), CommandTemplate.SplitCommand("\"C:\\Program Files\\PuTTY\\putty.exe\" -ssh 10.0.0.1"));
        Assert.Equal(("mstsc", "/v:10.0.0.1"), CommandTemplate.SplitCommand("mstsc /v:10.0.0.1"));
    }
}

public class BatchFileTests
{
    [Fact]
    public void Per_device_and_per_share_lines()
    {
        var cols = ColumnCatalog.All;
        var devices = new[] { RichSamples.Full("10.0.0.2"), Samples.Device("10.0.0.3", "pc3") };
        var perDevice = BatchFile.Generate("ping %0 & echo [Host Name] %%PATH%%", devices, cols, ColumnFormat.Default);
        Assert.Contains("ping 10.0.0.3 & echo pc3 %%PATH%%\r\n", perDevice, StringComparison.Ordinal);
        Assert.StartsWith("@echo off\r\n", perDevice, StringComparison.Ordinal);
        var perShare = BatchFile.Generate(@"dir \\%0\%1", devices, cols, ColumnFormat.Default);
        // folder shares only (C$, Public, Secret); printer excluded; device without shares produces nothing
        Assert.Equal(3, perShare.Split("\r\n").Count(l => l.StartsWith("dir ", StringComparison.Ordinal)));
        Assert.Contains(@"dir \\10.0.0.2\Public", perShare, StringComparison.Ordinal);
        Assert.Equal(3, BatchFile.Examples.Count);
    }
}

public class DiscoveryProtocolTests
{
    [Fact]
    public void Dhcp_discover_and_offer_round_trip()
    {
        var mac = PhysicalAddress.Parse("00-11-22-33-44-55");
        var d = DhcpPacket.Discover(0x12345678, mac, [160]);
        Assert.Equal(1, d[0]);
        Assert.Equal(0x12345678u, BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(4)));
        Assert.Equal(0x80, d[10]); // broadcast flag
        var opts = d.AsSpan(240).ToArray();
        Assert.Equal(new byte[] { 53, 1, 1 }, opts[..3]); // DHCPDISCOVER — never REQUEST
        Assert.Contains((byte)160, opts);

        var offer = new byte[300];
        offer[0] = 2;
        BinaryPrimitives.WriteUInt32BigEndian(offer.AsSpan(4), 0x12345678);
        new byte[] { 10, 0, 0, 50 }.CopyTo(offer, 16);
        new byte[] { 0x63, 0x82, 0x53, 0x63 }.CopyTo(offer, 236);
        byte[] o = [53, 1, 2, 54, 4, 10, 0, 0, 1, 3, 4, 10, 0, 0, 1, 6, 8, 10, 0, 0, 53, 8, 8, 8, 8, 51, 4, 0, 0, 0x1C, 0x20, 66, 4, (byte)'t', (byte)'f', (byte)'t', (byte)'p', 255];
        o.CopyTo(offer, 240);
        var parsed = DhcpPacket.ParseOffer(offer, 0x12345678, IPAddress.Parse("10.0.0.1"));
        Assert.NotNull(parsed);
        Assert.Equal("10.0.0.50", parsed.OfferedAddress.ToString());
        Assert.Equal("10.0.0.1", parsed.ServerDisplay);
        Assert.Equal(["10.0.0.53", "8.8.8.8"], parsed.DnsServers.Select(a => a.ToString()));
        Assert.Equal(TimeSpan.FromHours(2), parsed.LeaseTime);
        Assert.Equal("tftp", DhcpPacket.FormatOption(66, parsed.Options[66]));
        Assert.Null(DhcpPacket.ParseOffer(offer, 0x99, IPAddress.Loopback)); // other transaction
    }

    [Fact]
    public void Dhcp_custom_option_codes()
    {
        Assert.Equal([160, 66, 67], DhcpPacket.ParseOptionCodes("160, 66 67", out _));
        Assert.Empty(DhcpPacket.ParseOptionCodes("300", out var e));
        Assert.NotEmpty(e);
    }

    [Fact]
    public void Dns_query_and_compressed_response()
    {
        var q = DnsMessage.Query([("_services._dns-sd._udp.local", DnsMessage.PtrType)]);
        Assert.Equal(0x80, q[^2]); // QU bit
        // response: PTR _ipp._tcp.local -> "Office Printer._ipp._tcp.local" (compressed), SRV, TXT, A
        var b = new List<byte> { 0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0 };
        var svcName = 12;
        b.AddRange(Label("_ipp")); b.AddRange(Label("_tcp")); b.AddRange(Label("local")); b.Add(0);
        b.AddRange(new byte[] { 0, 12, 0, 1, 0, 0, 0, 120 });
        var rdata = new List<byte>(); rdata.AddRange(Label("Office Printer")); rdata.Add(0xC0); rdata.Add((byte)svcName);
        b.Add(0); b.Add((byte)rdata.Count); var instanceOffset = b.Count; b.AddRange(rdata);
        b.AddRange(new byte[] { 0xC0, (byte)instanceOffset, 0, 33, 0, 1, 0, 0, 0, 120 });
        var srv = new List<byte> { 0, 0, 0, 0, 0x02, 0x77 }; srv.AddRange(Label("printer")); srv.Add(0xC0); srv.Add((byte)(svcName + 10));
        b.Add(0); b.Add((byte)srv.Count); var hostOffset = b.Count + 6; b.AddRange(srv);
        b.AddRange(new byte[] { 0xC0, (byte)instanceOffset, 0, 16, 0, 1, 0, 0, 0, 120, 0, 8, 7 }); b.AddRange("ty=MF-1"u8.ToArray());
        b.AddRange(new byte[] { 0xC0, (byte)hostOffset, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 9 });
        var records = DnsMessage.Parse(b.ToArray());
        Assert.Equal(4, records.Count);
        Assert.Equal("Office Printer._ipp._tcp.local", records[0].Data);
        Assert.Equal(631, records[1].Port);
        Assert.Equal("printer.local", records[1].Data);
        Assert.Equal("ty=MF-1", records[2].Data);
        Assert.Equal("10.0.0.9", records[3].Address!.ToString());
        var devices = MdnsDiscovery.Build(records.Select(r => (r, IPAddress.Parse("10.0.0.9"))).ToList());
        var dev = Assert.Single(devices);
        Assert.Equal("Office Printer", dev.Name);
        Assert.Equal("Printer (IPP)", dev.DeviceType);
        Assert.Equal("MF-1", dev.Model);
        Assert.Empty(DnsMessage.Parse(new byte[] { 1, 2, 3 }));
    }

    private static byte[] Label(string s) => [(byte)s.Length, .. Encoding.ASCII.GetBytes(s)];

    [Fact]
    public void Ssdp_response_and_description()
    {
        var h = Ssdp.ParseResponse("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://10.0.0.1:1900/desc.xml\r\nST: upnp:rootdevice\r\nSERVER: Linux UPnP/1.0\r\n\r\n");
        Assert.Equal("http://10.0.0.1:1900/desc.xml", h!["LOCATION"]);
        Assert.Null(Ssdp.ParseResponse("garbage"));
        const string xml = """
            <root xmlns="urn:schemas-upnp-org:device-1-0"><device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
            <friendlyName>NAS Media</friendlyName><manufacturer>Example</manufacturer><modelName>NS-1</modelName>
            <presentationURL>/web/</presentationURL></device></root>
            """;
        var d = Ssdp.ParseDescription(xml, new Uri("http://10.0.0.1:1900/desc.xml"));
        Assert.Equal("NAS Media", d["friendlyName"]);
        Assert.Equal("http://10.0.0.1:1900/web/", d["presentationURL"]);
        Assert.Equal("MediaServer", Ssdp.ShortType(d["deviceType"]));
        Assert.Throws<System.Xml.XmlException>(() => Ssdp.ParseDescription("<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///c:/x\">]><root>&e;</root>", new Uri("http://x/")));
    }

    [Fact]
    public void Ws_discovery_probe_matches_metadata_and_onvif_scopes()
    {
        var probe = Encoding.UTF8.GetString(WsDiscovery.Probe("dn:NetworkVideoTransmitter", Guid.Empty));
        Assert.Contains("<wsd:Types>dn:NetworkVideoTransmitter</wsd:Types>", probe, StringComparison.Ordinal);
        const string matches = """
            <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <s:Body><d:ProbeMatches><d:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:1</a:Address></a:EndpointReference>
            <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
            <d:Scopes>onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/IPC-1 onvif://www.onvif.org/type/video_encoder</d:Scopes>
            <d:XAddrs>http://10.0.0.20/onvif/device_service http://[fe80::1]/onvif/device_service</d:XAddrs>
            </d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>
            """;
        var m = Assert.Single(WsDiscovery.ParseProbeMatches(matches));
        Assert.Equal(2, m.XAddrs.Count);
        var scopes = WsDiscovery.OnvifScopes(m.Scopes);
        Assert.Equal("Front Door", scopes["name"]);
        Assert.Equal("IPC-1", scopes["hardware"]);
        var meta = WsDiscovery.ParseMetadata("<x xmlns:p='urn:p'><p:FriendlyName>Printer 2</p:FriendlyName><p:Manufacturer>Acme</p:Manufacturer><p:PresentationUrl>http://10.0.0.7/</p:PresentationUrl></x>");
        Assert.Equal("Printer 2", meta["FriendlyName"]);
        Assert.Equal("Printer", WsdDiscovery.TypeLabel("wprt:PrintDeviceType"));
    }

    [Fact]
    public void Onvif_username_token_and_responses()
    {
        var nonce = new byte[16];
        var env = OnvifSoap.Envelope(OnvifSoap.GetDeviceInformation, "admin", "secret", new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), nonce);
#pragma warning disable CA5350 // the WS-Security UsernameToken profile mandates SHA-1
        var expectedDigest = Convert.ToBase64String(System.Security.Cryptography.SHA1.HashData(nonce.Concat("2026-01-01T00:00:00.000Z"u8.ToArray()).Concat("secret"u8.ToArray()).ToArray()));
#pragma warning restore CA5350
        Assert.Contains(expectedDigest, env, StringComparison.Ordinal);
        Assert.DoesNotContain("secret", env, StringComparison.Ordinal); // password never in clear text
        Assert.DoesNotContain("Security", OnvifSoap.Envelope(OnvifSoap.GetProfiles, null, null, DateTimeOffset.UtcNow));
        var doc = SafeXml.Parse("<e xmlns:t='urn:t'><t:Capabilities><t:Media><t:XAddr>http://10.0.0.20/onvif/media</t:XAddr></t:Media></t:Capabilities><t:Profiles token='prof1'/><t:Uri>rtsp://10.0.0.20/live</t:Uri></e>");
        Assert.Equal("http://10.0.0.20/onvif/media", OnvifSoap.MediaXAddr(doc));
        Assert.Equal("prof1", OnvifSoap.FirstProfileToken(doc));
        Assert.Equal("rtsp://10.0.0.20/live", OnvifSoap.Value(doc, "Uri"));
        Assert.True(OnvifSoap.IsAuthFault("<Fault><Subcode>ter:NotAuthorized</Subcode></Fault>"));
    }

    [Fact]
    public void Arp_frames_and_duplicate_analysis()
    {
        var me = PhysicalAddress.Parse("00-11-22-33-44-55");
        var req = ArpFrame.Request(me, IPAddress.Parse("10.0.0.2"), IPAddress.Parse("10.0.0.9"));
        Assert.Equal(42, req.Length);
        Assert.All(req[..6], b => Assert.Equal(0xFF, b));
        Assert.Equal(1, req[21]);
        Assert.Null(ArpFrame.ParseReply(req)); // a request is not a reply
        var reply = (byte[])req.Clone();
        reply[21] = 2;
        new byte[] { 0xAA, 0xBB, 0xCC, 0, 0, 1 }.CopyTo(reply, 22);
        new byte[] { 10, 0, 0, 9 }.CopyTo(reply, 28);
        var parsed = ArpFrame.ParseReply(reply)!;
        Assert.Equal("10.0.0.9", parsed.SenderIp.ToString());

        var a = PhysicalAddress.Parse("AA-AA-AA-AA-AA-01");
        var b = PhysicalAddress.Parse("BB-BB-BB-BB-BB-02");
        var gw = PhysicalAddress.Parse("CC-CC-CC-CC-CC-03");
        var replies = new List<ArpReply> { new(IPAddress.Parse("10.0.0.5"), a), new(IPAddress.Parse("10.0.0.5"), b), new(IPAddress.Parse("10.0.0.5"), a), new(IPAddress.Parse("10.0.0.6"), a) };
        for (var i = 20; i < 60; i++) replies.Add(new ArpReply(IPAddress.Parse($"10.0.0.{i}"), gw));
        var report = DuplicateIpAnalyzer.Analyze(replies, gw);
        var dup = Assert.Single(report.Duplicates);
        Assert.Equal("10.0.0.5", dup.Address.ToString());
        Assert.Equal(2, dup.Macs.Count);
        Assert.Contains("proxy ARP", Assert.Single(report.Warnings), StringComparison.Ordinal);
        Assert.Contains("gateway", report.Warnings[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Duplicate_ip_scanner_reports_missing_capture_library()
    {
        var s = new DuplicateIpScanner(new PcapLibrary(new FakeAdapters()));
        if (s.Capability.Available) return; // capture library installed on this machine
        Assert.Contains(OperatingSystem.IsWindows() ? "Npcap" : "libpcap", s.Capability.Description, StringComparison.Ordinal);
        Assert.Empty(s.Interfaces());
    }

    [Fact]
    public void Public_address_classification_and_geo_parsing()
    {
        Assert.True(PublicAddress.IsPublic(IPAddress.Parse("1.1.1.1")));
        foreach (var p in new[] { "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "169.254.1.1", "127.0.0.1", "192.0.2.5", "fe80::1", "fd00::1", "2001:db8::1", "224.0.0.1" })
        {
            Assert.False(PublicAddress.IsPublic(IPAddress.Parse(p)), p);
        }

        Assert.True(PublicAddress.IsPublic(IPAddress.Parse("2606:4700::1111")));
        var s = new ScanSettings { GeoCityField = "location.city", GeoCountryField = "country_name" };
        var g = HttpGeoLocator.Parse("""{"location":{"city":"Zürich"},"country_name":"Switzerland"}""", s);
        Assert.Equal("Zürich, Switzerland", g!.ToString());
        Assert.Null(HttpGeoLocator.Parse("{}", s));
        Assert.False(new HttpGeoLocator().Capability(new ScanSettings { GeoUrlTemplate = "http://insecure/{ip}" }).Available);
        Assert.True(new HttpGeoLocator().Capability(new ScanSettings { GeoUrlTemplate = "https://geo.example/{ip}" }).Available);
        var trace = ExternalIp.ParseTrace("fl=1\nh=www.cloudflare.com\nip=203.0.113.7\nloc=DE\n");
        Assert.Equal("203.0.113.7", trace!.Address.ToString());
        Assert.Equal("DE", trace.Country);
    }

    [Fact]
    public void Device_urls_bracket_ipv6()
    {
        Assert.Equal("http://10.0.0.1/", DeviceUrls.For("http", IPAddress.Parse("10.0.0.1")));
        Assert.Equal("https://[fe80::1%253]:8443/", DeviceUrls.For("https", IPAddress.Parse("fe80::1%3"), 8443));
    }
}

public class CliWolTests
{
    [Fact]
    public async Task Wol_switches_send_to_configured_destination()
    {
        using var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
        var dir = Directory.CreateTempSubdirectory("ipm-wol-").FullName;
        await new SettingsStore(dir).SaveAsync(new AppSettings
        {
            Wol = new WolSettings
            {
                DefaultDestination = "127.0.0.1",
                Port = port,
                DelayMs = 0,
                Targets = [new WolTarget { Mac = "00-00-00-00-00-03", Destination = "127.0.0.1" }],
            },
        });
        var macFile = Path.Combine(dir, "macs.txt");
        await File.WriteAllTextAsync(macFile, "00:00:00:00:00:02\nbad\n");
        var sp = new ServiceCollection().AddIPMaster(dir).BuildServiceProvider();
        var o = new StringWriter();
        var e = new StringWriter();
        var app = new CliApp(sp, o, e);
        Assert.Equal(ExitCodes.Ok, await app.RunAsync(["/wol:00-00-00-00-00-01", $"/wolfile:{macFile}", "/wakeall"], CancellationToken.None));
        var received = new List<byte>();
        for (var i = 0; i < 3; i++) received.Add((await listener.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(5))).Buffer[^1]);
        Assert.Equal(new byte[] { 1, 2, 3 }, received.Order().ToArray());
        Assert.Contains(":2: ignored", e.ToString(), StringComparison.Ordinal);
        Assert.Equal(ExitCodes.Usage, await app.RunAsync(["/wol:nonsense"], CancellationToken.None));
    }
}
