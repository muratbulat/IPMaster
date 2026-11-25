using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using IPMaster.Core.Results;

namespace IPMaster.Core.Discovery;

public enum DiscoveryProtocol
{
    Ssdp,
    Mdns,
    Wsd,
    Onvif,
}

/// <summary>A device found by a broadcast/multicast discovery tool (manual: Device Type, Device Name, IP, UI URL).</summary>
public sealed record DiscoveredDevice
{
    public required DiscoveryProtocol Protocol { get; init; }

    public required IPAddress Address { get; init; }

    public string DeviceType { get; init; } = "";

    public string Name { get; init; } = "";

    /// <summary>Device user interface / presentation URL, or the ONVIF stream URL.</summary>
    public string Url { get; init; } = "";

    public string Manufacturer { get; init; } = "";

    public string Model { get; init; } = "";

    public string Firmware { get; init; } = "";

    public string Serial { get; init; } = "";

    public string StreamUrl { get; init; } = "";

    /// <summary>Every raw attribute, for the Properties view.</summary>
    public IReadOnlyDictionary<string, string> Details { get; init; } = new Dictionary<string, string>();
}

// ---------------------------------------------------------------- DHCP

public sealed record DhcpOffer
{
    public required IPAddress ServerAddress { get; init; }

    public IPAddress? ServerIdentifier { get; init; }

    public required IPAddress OfferedAddress { get; init; }

    public IReadOnlyList<IPAddress> Gateways { get; init; } = [];

    public IReadOnlyList<IPAddress> DnsServers { get; init; } = [];

    public IPAddress? SubnetMask { get; init; }

    public TimeSpan? LeaseTime { get; init; }

    public string DomainName { get; init; } = "";

    /// <summary>All options by code (raw bytes).</summary>
    public IReadOnlyDictionary<byte, byte[]> Options { get; init; } = new Dictionary<byte, byte[]>();

    public string ServerDisplay => (ServerIdentifier ?? ServerAddress).ToString();

    /// <summary>Time from our DISCOVER to this offer; null for passively observed replies (D-095).</summary>
    public TimeSpan? ResponseTime { get; init; }

    /// <summary>OFFER, ACK or NAK; passive listening sees all three (D-095).</summary>
    public string MessageType { get; init; } = "OFFER";

    /// <summary>The client the reply was for (passive listening; our own MAC for an active probe).</summary>
    public string ClientMac { get; init; } = "";

    /// <summary>Any server reply seen on the wire (D-095), as an offer row.</summary>
    public static DhcpOffer FromReply(DhcpMessage m, IPAddress source)
    {
        ArgumentNullException.ThrowIfNull(m);
        ArgumentNullException.ThrowIfNull(source);
        static List<IPAddress> Addrs(DhcpMessage msg, byte code) =>
            msg.Options.TryGetValue(code, out var v) ? Enumerable.Range(0, v.Length / 4).Select(i => new IPAddress(v.AsSpan(i * 4, 4))).ToList() : [];
        return new DhcpOffer
        {
            ServerAddress = source, ServerIdentifier = m.ServerIdentifier, OfferedAddress = m.YourAddress, Gateways = Addrs(m, 3), DnsServers = Addrs(m, 6),
            SubnetMask = m.Address(1), LeaseTime = m.Options.TryGetValue(51, out var l) && l.Length == 4 ? TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(l)) : null,
            DomainName = m.Options.TryGetValue(15, out var d) ? Encoding.ASCII.GetString(d).TrimEnd('\0') : "", Options = m.Options,
            MessageType = m.Type?.ToString().ToUpperInvariant() ?? "BOOTREPLY", ClientMac = Results.Formats.Mac(m.ClientMac),
        };
    }
}

public sealed record DhcpOptionDifference(byte Code, string Name, IReadOnlyDictionary<string, string> ValueByServer, bool Differs);

/// <summary>
/// DHCP diagnostics (D-095): compares what several servers offer and assesses the answers. "Rogue" is only ever a
/// suspicion (a server that is not on the expected list), never a verdict.
/// </summary>
public static class DhcpDiagnostics
{
    private static readonly byte[] Compared = [1, 3, 6, 15, 42, 51, 66, 67, 119, 121, 150, 252];

    public static IReadOnlyList<DhcpOptionDifference> Compare(IReadOnlyList<DhcpOffer> offers)
    {
        ArgumentNullException.ThrowIfNull(offers);
        var byServer = offers.Where(o => o.MessageType is "OFFER" or "ACK").GroupBy(o => o.ServerDisplay).Select(g => g.First()).ToList();
        return Compared.Concat(byServer.SelectMany(o => o.Options.Keys)).Distinct().Where(c => c is not (53 or 54 or 58 or 59 or 255)).Order()
            .Select(code =>
            {
                var values = byServer.ToDictionary(o => o.ServerDisplay, o => o.Options.TryGetValue(code, out var v) ? DhcpPacket.FormatOption(code, v) : "—");
                return new DhcpOptionDifference(code, DhcpPacket.OptionName(code), values, values.Values.Distinct().Count() > 1);
            })
            .Where(d => d.ValueByServer.Values.Any(v => v != "—")).ToList();
    }

    /// <summary>Findings in words: none, one or several servers; unexpected servers; differing network settings; slow answers.</summary>
    public static IReadOnlyList<string> Assess(IReadOnlyList<DhcpOffer> offers, IReadOnlyCollection<IPAddress> expectedServers)
    {
        ArgumentNullException.ThrowIfNull(offers);
        ArgumentNullException.ThrowIfNull(expectedServers);
        var servers = offers.Select(o => o.ServerIdentifier ?? o.ServerAddress).Distinct().ToList();
        if (servers.Count == 0) return ["No DHCP server answered."];
        var f = new List<string> { servers.Count == 1 ? $"One DHCP server answered: {servers[0]}." : $"{servers.Count} DHCP servers answer on this network: {string.Join(", ", servers)}." };
        if (expectedServers.Count > 0)
        {
            foreach (var s in servers.Where(s => !expectedServers.Contains(s)))
            {
                f.Add($"{s} is not on the expected list: a suspected rogue DHCP server (verify it before acting; it may be a relay or a new legitimate server).");
            }
        }
        else if (servers.Count > 1)
        {
            f.Add("Several servers answer: enter the expected server(s) to see which ones are unexpected.");
        }

        foreach (var d in Compare(offers).Where(d => d.Differs && d.Code is 1 or 3 or 6 or 15))
        {
            f.Add($"Servers hand out different {d.Name.ToLowerInvariant()}: " + string.Join("; ", d.ValueByServer.Select(kv => $"{kv.Key}: {kv.Value}")) + ".");
        }

        foreach (var o in offers.Where(o => o.ResponseTime is { TotalSeconds: > 1 }))
        {
            f.Add($"{o.ServerDisplay} answered after {o.ResponseTime!.Value.TotalMilliseconds:N0} ms (slow; clients usually retry after 4 s).");
        }

        return f;
    }
}

/// <summary>DHCP DISCOVER builder and OFFER parser (RFC 2131/2132). Only DISCOVER is ever sent: no lease is requested
/// or applied (DSC-01).</summary>
public static class DhcpPacket
{
    private static readonly byte[] Cookie = [0x63, 0x82, 0x53, 0x63];

    public static byte[] Discover(uint xid, PhysicalAddress clientMac, IReadOnlyList<byte> extraRequestedOptions)
    {
        ArgumentNullException.ThrowIfNull(clientMac);
        ArgumentNullException.ThrowIfNull(extraRequestedOptions);
        var mac = clientMac.GetAddressBytes();
        var p = new List<byte>(300);
        p.AddRange(new byte[] { 1, 1, (byte)Math.Min(mac.Length, 16), 0 }); // BOOTREQUEST, Ethernet, hlen, hops
        var x = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(x, xid);
        p.AddRange(x);
        p.AddRange(new byte[] { 0, 0, 0x80, 0x00 }); // secs, flags = broadcast reply
        p.AddRange(new byte[16]); // ciaddr, yiaddr, siaddr, giaddr
        var chaddr = new byte[16];
        Array.Copy(mac, chaddr, Math.Min(mac.Length, 16));
        p.AddRange(chaddr);
        p.AddRange(new byte[64 + 128]); // sname, file
        p.AddRange(Cookie);
        p.AddRange(new byte[] { 53, 1, 1 }); // DHCPDISCOVER
        var requested = new List<byte> { 1, 3, 6, 15, 51, 54, 28, 42, 44, 66, 67 };
        foreach (var o in extraRequestedOptions) if (!requested.Contains(o)) requested.Add(o);
        p.Add(55);
        p.Add((byte)requested.Count);
        p.AddRange(requested);
        p.AddRange(new byte[] { 60, 8 }); // vendor class id "IPMaster"
        p.AddRange("IPMaster"u8.ToArray());
        p.Add(255);
        while (p.Count < 300) p.Add(0);
        return p.ToArray();
    }

    public static DhcpOffer? ParseOffer(ReadOnlySpan<byte> r, uint xid, IPAddress source)
    {
        ArgumentNullException.ThrowIfNull(source);
        if (r.Length < 240 || r[0] != 2) return null;
        if (BinaryPrimitives.ReadUInt32BigEndian(r[4..]) != xid) return null;
        if (!r.Slice(236, 4).SequenceEqual(Cookie)) return null;
        var options = new Dictionary<byte, byte[]>();
        var pos = 240;
        while (pos < r.Length)
        {
            var code = r[pos++];
            if (code == 0) continue;
            if (code == 255 || pos >= r.Length) break;
            var len = r[pos++];
            if (pos + len > r.Length) break;
            options[code] = r.Slice(pos, len).ToArray();
            pos += len;
        }

        if (!options.TryGetValue(53, out var type) || type.Length != 1 || type[0] != 2) return null; // DHCPOFFER only

        static List<IPAddress> Addrs(Dictionary<byte, byte[]> o, byte code) =>
            o.TryGetValue(code, out var v) ? Enumerable.Range(0, v.Length / 4).Select(i => new IPAddress(v.AsSpan(i * 4, 4))).ToList() : [];

        return new DhcpOffer
        {
            ServerAddress = source,
            ServerIdentifier = Addrs(options, 54).FirstOrDefault(),
            OfferedAddress = new IPAddress(r.Slice(16, 4)),
            Gateways = Addrs(options, 3),
            DnsServers = Addrs(options, 6),
            SubnetMask = Addrs(options, 1).FirstOrDefault(),
            LeaseTime = options.TryGetValue(51, out var l) && l.Length == 4 ? TimeSpan.FromSeconds(BinaryPrimitives.ReadUInt32BigEndian(l)) : null,
            DomainName = options.TryGetValue(15, out var d) ? Encoding.ASCII.GetString(d).TrimEnd('\0') : "",
            Options = options,
        };
    }

    private static readonly Dictionary<byte, string> Names = new()
    {
        [1] = "Subnet mask", [3] = "Router", [6] = "DNS servers", [12] = "Host name", [15] = "Domain name", [28] = "Broadcast address",
        [42] = "NTP servers", [44] = "NetBIOS name servers", [51] = "Lease time", [53] = "Message type", [54] = "Server identifier",
        [58] = "Renewal time", [59] = "Rebinding time", [60] = "Vendor class", [66] = "TFTP server name", [67] = "Boot file name",
        [119] = "Domain search", [121] = "Classless static routes", [150] = "TFTP server addresses", [252] = "WPAD URL",
    };

    private static readonly HashSet<byte> AddressOptions = [1, 3, 6, 28, 42, 44, 54, 150];
    private static readonly HashSet<byte> TextOptions = [12, 15, 60, 66, 67, 252];

    public static string OptionName(byte code) => Names.TryGetValue(code, out var n) ? n : "Option " + code.ToString(CultureInfo.InvariantCulture);

    /// <summary>Human-readable option value: addresses, text, seconds, or hex.</summary>
    public static string FormatOption(byte code, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (AddressOptions.Contains(code) && value.Length % 4 == 0)
            return string.Join(", ", Enumerable.Range(0, value.Length / 4).Select(i => new IPAddress(value.AsSpan(i * 4, 4)).ToString()));
        if (code is 51 or 58 or 59 && value.Length == 4) return BinaryPrimitives.ReadUInt32BigEndian(value).ToString(CultureInfo.InvariantCulture) + " s";
        var printable = value.All(b => b is >= 0x20 and < 0x7F || b == 0);
        if (TextOptions.Contains(code) || (printable && value.Length > 1)) return Encoding.ASCII.GetString(value).TrimEnd('\0');
        return Convert.ToHexString(value);
    }

    /// <summary>Parses user-entered custom option codes ("160, 66, 67").</summary>
    public static IReadOnlyList<byte> ParseOptionCodes(string text, out string error)
    {
        error = "";
        var list = new List<byte>();
        foreach (var t in (text ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries))
        {
            if (byte.TryParse(t, NumberStyles.None, CultureInfo.InvariantCulture, out var b) && b is > 0 and < 255) list.Add(b);
            else
            {
                error = $"'{t}' is not a DHCP option code (1-254).";
                return [];
            }
        }

        return list;
    }
}

// ---------------------------------------------------------------- DNS (mDNS / DNS-SD)

public sealed record DnsRecord(string Name, ushort Type, string Data, IPAddress? Address = null, int Port = 0, IReadOnlyList<string>? Text = null);

/// <summary>Minimal DNS message codec with name compression, enough for mDNS / DNS-SD (PTR, SRV, TXT, A, AAAA).</summary>
public static class DnsMessage
{
    public const ushort A = 1;
    public const ushort PtrType = 12;
    public const ushort Txt = 16;
    public const ushort Aaaa = 28;
    public const ushort Srv = 33;
    public const ushort Any = 255;

    /// <summary>Query with the unicast-response bit (QU) set, so responders answer our ephemeral port directly.</summary>
    public static byte[] Query(IEnumerable<(string Name, ushort Type)> questions)
    {
        ArgumentNullException.ThrowIfNull(questions);
        var q = questions.ToList();
        var b = new List<byte>(512) { 0, 0, 0, 0, 0, (byte)q.Count, 0, 0, 0, 0, 0, 0 };
        foreach (var (name, type) in q)
        {
            foreach (var label in name.TrimEnd('.').Split('.'))
            {
                var bytes = Encoding.UTF8.GetBytes(label);
                b.Add((byte)Math.Min(bytes.Length, 63));
                b.AddRange(bytes.Take(63));
            }

            b.Add(0);
            b.Add((byte)(type >> 8));
            b.Add((byte)type);
            b.Add(0x80); // QU
            b.Add(1); // IN
        }

        return b.ToArray();
    }

    /// <summary>Returns every answer/authority/additional record. Malformed packets yield what was parsed so far.</summary>
    public static IReadOnlyList<DnsRecord> Parse(ReadOnlySpan<byte> m)
    {
        var records = new List<DnsRecord>();
        if (m.Length < 12) return records;
        int qd = BinaryPrimitives.ReadUInt16BigEndian(m[4..]);
        var rr = BinaryPrimitives.ReadUInt16BigEndian(m[6..]) + BinaryPrimitives.ReadUInt16BigEndian(m[8..]) + BinaryPrimitives.ReadUInt16BigEndian(m[10..]);
        var pos = 12;
        try
        {
            for (var i = 0; i < qd; i++)
            {
                ReadName(m, ref pos);
                pos += 4;
            }

            for (var i = 0; i < rr && pos + 10 <= m.Length; i++)
            {
                var name = ReadName(m, ref pos);
                var type = BinaryPrimitives.ReadUInt16BigEndian(m[pos..]);
                var len = BinaryPrimitives.ReadUInt16BigEndian(m[(pos + 8)..]);
                pos += 10;
                if (pos + len > m.Length) break;
                var start = pos;
                switch (type)
                {
                    case A when len == 4:
                        records.Add(new DnsRecord(name, type, new IPAddress(m.Slice(pos, 4)).ToString(), new IPAddress(m.Slice(pos, 4))));
                        break;
                    case Aaaa when len == 16:
                        records.Add(new DnsRecord(name, type, new IPAddress(m.Slice(pos, 16)).ToString(), new IPAddress(m.Slice(pos, 16))));
                        break;
                    case PtrType:
                    {
                        var p = pos;
                        records.Add(new DnsRecord(name, type, ReadName(m, ref p)));
                        break;
                    }

                    case Srv when len >= 7:
                    {
                        var port = BinaryPrimitives.ReadUInt16BigEndian(m[(pos + 4)..]);
                        var p = pos + 6;
                        records.Add(new DnsRecord(name, type, ReadName(m, ref p), Port: port));
                        break;
                    }

                    case Txt:
                    {
                        var texts = new List<string>();
                        var p = pos;
                        while (p < start + len)
                        {
                            int l = m[p++];
                            if (p + l > start + len) break;
                            texts.Add(Encoding.UTF8.GetString(m.Slice(p, l)));
                            p += l;
                        }

                        records.Add(new DnsRecord(name, type, string.Join("; ", texts), Text: texts));
                        break;
                    }
                }

                pos = start + len;
            }
        }
        catch (IndexOutOfRangeException)
        {
            // truncated packet: keep what was parsed
        }
        catch (ArgumentOutOfRangeException)
        {
            // truncated packet
        }

        return records;
    }

    private static string ReadName(ReadOnlySpan<byte> m, ref int pos)
    {
        var labels = new List<string>();
        var jumped = false;
        var p = pos;
        for (var guard = 0; guard < 128; guard++)
        {
            int len = m[p];
            if (len == 0)
            {
                p++;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                var target = ((len & 0x3F) << 8) | m[p + 1];
                if (!jumped) pos = p + 2;
                jumped = true;
                if (target >= m.Length) break;
                p = target;
                continue;
            }

            labels.Add(Encoding.UTF8.GetString(m.Slice(p + 1, len)));
            p += 1 + len;
        }

        if (!jumped) pos = p;
        return string.Join('.', labels);
    }

    /// <summary>Friendly names for common DNS-SD service types.</summary>
    public static string ServiceLabel(string serviceType)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        var t = serviceType.Replace(".local", "", StringComparison.OrdinalIgnoreCase).TrimEnd('.');
        return t switch
        {
            "_ipp._tcp" or "_ipps._tcp" => "Printer (IPP)",
            "_printer._tcp" or "_pdl-datastream._tcp" => "Printer",
            "_airplay._tcp" => "AirPlay",
            "_raop._tcp" => "AirPlay audio",
            "_googlecast._tcp" => "Chromecast",
            "_http._tcp" => "Web server",
            "_https._tcp" => "Web server (HTTPS)",
            "_smb._tcp" => "SMB file sharing",
            "_afpovertcp._tcp" => "AFP file sharing",
            "_ssh._tcp" => "SSH",
            "_sftp-ssh._tcp" => "SFTP",
            "_workstation._tcp" => "Workstation",
            "_device-info._tcp" => "Device info",
            "_hap._tcp" => "HomeKit accessory",
            "_scanner._tcp" or "_uscan._tcp" => "Scanner",
            "_spotify-connect._tcp" => "Spotify Connect",
            "_companion-link._tcp" => "Apple device",
            _ => t,
        };
    }
}

// ---------------------------------------------------------------- SSDP

public static class Ssdp
{
    public static byte[] Search(string target = "ssdp:all", int mx = 2) => Encoding.ASCII.GetBytes(
        $"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: {mx.ToString(CultureInfo.InvariantCulture)}\r\nST: {target}\r\nUSER-AGENT: IPMaster/0.3 UPnP/1.1\r\n\r\n");

    /// <summary>Parses an M-SEARCH response or NOTIFY into upper-case header names.</summary>
    public static IReadOnlyDictionary<string, string>? ParseResponse(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var lines = text.Split("\r\n");
        if (lines.Length == 0 || !(lines[0].StartsWith("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase) || lines[0].StartsWith("NOTIFY", StringComparison.OrdinalIgnoreCase))) return null;
        var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var l in lines.Skip(1))
        {
            var c = l.IndexOf(':', StringComparison.Ordinal);
            if (c > 0) h[l[..c].Trim().ToUpperInvariant()] = l[(c + 1)..].Trim();
        }

        return h;
    }

    /// <summary>Parses a UPnP device description (XML) into name, type, manufacturer, model, serial and presentation URL.</summary>
    public static Dictionary<string, string> ParseDescription(string xml, Uri location)
    {
        ArgumentNullException.ThrowIfNull(location);
        var doc = SafeXml.Parse(xml);
        var device = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
        var r = new Dictionary<string, string>(StringComparer.Ordinal);
        if (device is null) return r;
        foreach (var name in new[] { "friendlyName", "deviceType", "manufacturer", "modelName", "modelNumber", "serialNumber", "presentationURL", "UDN" })
        {
            var v = device.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();
            if (!string.IsNullOrEmpty(v)) r[name] = v;
        }

        if (r.TryGetValue("presentationURL", out var p) && Uri.TryCreate(location, p, out var abs)) r["presentationURL"] = abs.ToString();
        return r;
    }

    /// <summary>Short device type from a URN ("urn:schemas-upnp-org:device:MediaServer:1" → "MediaServer").</summary>
    public static string ShortType(string urn)
    {
        ArgumentNullException.ThrowIfNull(urn);
        var parts = urn.Split(':');
        return parts.Length >= 5 && parts[2] == "device" ? parts[3] : urn;
    }
}

/// <summary>XML parsing for network responses: no DTD, no resolver, bounded size.</summary>
public static class SafeXml
{
    public const int MaxCharacters = 2 * 1024 * 1024;

    public static XDocument Parse(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        using var reader = XmlReader.Create(new StringReader(xml), new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxCharacters,
            MaxCharactersFromEntities = 0,
        });
        return XDocument.Load(reader);
    }
}

// ---------------------------------------------------------------- WS-Discovery / ONVIF

public sealed record WsdMatch(string EndpointAddress, IReadOnlyList<string> Types, IReadOnlyList<string> Scopes, IReadOnlyList<Uri> XAddrs);

public static class WsDiscovery
{
    public const string NsSoap = "http://www.w3.org/2003/05/soap-envelope";
    public const string NsAddressing = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public const string NsDiscovery = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

    /// <summary>Probe message; <paramref name="types"/> e.g. "wsdp:Device" or "dn:NetworkVideoTransmitter".</summary>
    public static byte[] Probe(string types, Guid messageId)
    {
        ArgumentNullException.ThrowIfNull(types);
        var xml = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <soap:Envelope xmlns:soap="{NsSoap}" xmlns:wsa="{NsAddressing}" xmlns:wsd="{NsDiscovery}" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:dn="http://www.onvif.org/ver10/network/wsdl" xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
              <soap:Header>
                <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
                <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
                <wsa:MessageID>urn:uuid:{messageId}</wsa:MessageID>
              </soap:Header>
              <soap:Body><wsd:Probe>{(types.Length > 0 ? $"<wsd:Types>{types}</wsd:Types>" : "")}</wsd:Probe></soap:Body>
            </soap:Envelope>
            """;
        return Encoding.UTF8.GetBytes(xml);
    }

    public static IReadOnlyList<WsdMatch> ParseProbeMatches(string xml)
    {
        var doc = SafeXml.Parse(xml);
        var list = new List<WsdMatch>();
        foreach (var m in doc.Descendants().Where(e => e.Name.LocalName == "ProbeMatch"))
        {
            string Text(string local) => m.Descendants().FirstOrDefault(e => e.Name.LocalName == local)?.Value.Trim() ?? "";
            var xaddrs = Text("XAddrs").Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(x => Uri.TryCreate(x, UriKind.Absolute, out var u) ? u : null).OfType<Uri>().ToList();
            list.Add(new WsdMatch(Text("Address"), Text("Types").Split(' ', StringSplitOptions.RemoveEmptyEntries),
                Text("Scopes").Split(' ', StringSplitOptions.RemoveEmptyEntries), xaddrs));
        }

        return list;
    }

    /// <summary>WS-Transfer Get request for device metadata (Devices Profile).</summary>
    public static string TransferGet(Uri to, string endpointAddress) => $"""
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="{NsSoap}" xmlns:wsa="{NsAddressing}">
          <soap:Header>
            <wsa:To>{SecurityElementEscape(endpointAddress)}</wsa:To>
            <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
            <wsa:MessageID>urn:uuid:{Guid.NewGuid()}</wsa:MessageID>
            <wsa:ReplyTo><wsa:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
          </soap:Header>
          <soap:Body />
        </soap:Envelope>
        """;

    /// <summary>Extracts FriendlyName, Manufacturer, ModelName, SerialNumber, FirmwareVersion, PresentationUrl from metadata.</summary>
    public static Dictionary<string, string> ParseMetadata(string xml)
    {
        var doc = SafeXml.Parse(xml);
        var r = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in new[] { "FriendlyName", "Manufacturer", "ModelName", "ModelNumber", "SerialNumber", "FirmwareVersion", "PresentationUrl" })
        {
            var v = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim();
            if (!string.IsNullOrEmpty(v)) r[name] = v;
        }

        return r;
    }

    internal static string SecurityElementEscape(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
        .Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal);

    /// <summary>Decoded ONVIF scope values ("onvif://www.onvif.org/name/Front%20Door" → name = Front Door).</summary>
    public static Dictionary<string, string> OnvifScopes(IEnumerable<string> scopes)
    {
        ArgumentNullException.ThrowIfNull(scopes);
        var r = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in scopes)
        {
            const string prefix = "onvif://www.onvif.org/";
            if (!s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) continue;
            var rest = s[prefix.Length..];
            var slash = rest.IndexOf('/', StringComparison.Ordinal);
            if (slash <= 0) continue;
            var key = rest[..slash];
            var value = Uri.UnescapeDataString(rest[(slash + 1)..]);
            r[key] = r.TryGetValue(key, out var existing) ? existing + ", " + value : value;
        }

        return r;
    }
}

/// <summary>ONVIF SOAP requests with optional WS-UsernameToken (PasswordDigest) authentication.</summary>
public static class OnvifSoap
{
    public static string Envelope(string body, string? user, string? password, DateTimeOffset now, byte[]? nonce = null)
    {
        var security = "";
        if (!string.IsNullOrEmpty(user))
        {
            nonce ??= RandomNumberGenerator.GetBytes(16);
            var created = now.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
            var digest = PasswordDigest(nonce, created, password ?? "");
            security = $"""
                <s:Header><wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                <wsse:UsernameToken><wsse:Username>{WsDiscovery.SecurityElementEscape(user)}</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{digest}</wsse:Password>
                <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{Convert.ToBase64String(nonce)}</wsse:Nonce>
                <wsu:Created>{created}</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header>
                """;
        }

        return $"""<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema">{security}<s:Body>{body}</s:Body></s:Envelope>""";
    }

    /// <summary>WS-Security UsernameToken digest: Base64(SHA1(nonce + created + password)).</summary>
    public static string PasswordDigest(byte[] nonce, string created, string password)
    {
        ArgumentNullException.ThrowIfNull(nonce);
        var bytes = nonce.Concat(Encoding.UTF8.GetBytes(created)).Concat(Encoding.UTF8.GetBytes(password)).ToArray();
#pragma warning disable CA5350 // SHA-1 is mandated by the WS-Security UsernameToken profile used by ONVIF devices.
        return Convert.ToBase64String(SHA1.HashData(bytes));
#pragma warning restore CA5350
    }

    public const string GetDeviceInformation = "<tds:GetDeviceInformation/>";
    public const string GetCapabilities = "<tds:GetCapabilities><tds:Category>Media</tds:Category></tds:GetCapabilities>";
    public const string GetProfiles = "<trt:GetProfiles/>";

    public static string GetStreamUri(string profileToken) =>
        $"<trt:GetStreamUri><trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream><tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup><trt:ProfileToken>{WsDiscovery.SecurityElementEscape(profileToken)}</trt:ProfileToken></trt:GetStreamUri>";

    public static string? Value(XDocument doc, string localName) =>
        doc.Descendants().FirstOrDefault(e => e.Name.LocalName == localName)?.Value.Trim();

    public static string? MediaXAddr(XDocument doc) =>
        doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Media")?.Elements().FirstOrDefault(e => e.Name.LocalName == "XAddr")?.Value.Trim();

    public static string? FirstProfileToken(XDocument doc) =>
        doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "Profiles")?.Attribute("token")?.Value;

    public static bool IsAuthFault(string xml) =>
        xml.Contains("NotAuthorized", StringComparison.OrdinalIgnoreCase) || xml.Contains("FailedAuthentication", StringComparison.OrdinalIgnoreCase)
        || xml.Contains("Sender not authorized", StringComparison.OrdinalIgnoreCase);
}

// ---------------------------------------------------------------- ARP / duplicate IP

public sealed record ArpReply(IPAddress SenderIp, PhysicalAddress SenderMac);

public static class ArpFrame
{
    /// <summary>Ethernet broadcast ARP request (who-has target, tell source).</summary>
    public static byte[] Request(PhysicalAddress sourceMac, IPAddress sourceIp, IPAddress targetIp)
    {
        ArgumentNullException.ThrowIfNull(sourceMac);
        ArgumentNullException.ThrowIfNull(sourceIp);
        ArgumentNullException.ThrowIfNull(targetIp);
        var src = sourceMac.GetAddressBytes();
        var f = new byte[42];
        for (var i = 0; i < 6; i++) f[i] = 0xFF;
        src.CopyTo(f, 6);
        f[12] = 0x08;
        f[13] = 0x06; // ARP
        f[14] = 0;
        f[15] = 1; // Ethernet
        f[16] = 0x08;
        f[17] = 0x00; // IPv4
        f[18] = 6;
        f[19] = 4;
        f[20] = 0;
        f[21] = 1; // request
        src.CopyTo(f, 22);
        sourceIp.GetAddressBytes().CopyTo(f, 28);
        targetIp.GetAddressBytes().CopyTo(f, 38);
        return f;
    }

    public static ArpReply? ParseReply(ReadOnlySpan<byte> f)
    {
        if (f.Length < 42 || f[12] != 0x08 || f[13] != 0x06) return null;
        if (f[20] != 0 || f[21] != 2) return null; // reply
        var mac = new PhysicalAddress(f.Slice(22, 6).ToArray());
        return new ArpReply(new IPAddress(f.Slice(28, 4)), mac);
    }
}

public sealed record DuplicateIpFinding(IPAddress Address, IReadOnlyList<PhysicalAddress> Macs);

public sealed record DuplicateIpReport(IReadOnlyList<DuplicateIpFinding> Duplicates, int AddressesAnswered, IReadOnlyList<string> Warnings);

/// <summary>Groups ARP replies by sender IP; two or more distinct MACs for one IP is a duplicate (DSC-06). A single MAC that
/// answers for many addresses suggests proxy ARP, which is reported as a caveat instead of a conflict (DSC-07).</summary>
public static class DuplicateIpAnalyzer
{
    public static DuplicateIpReport Analyze(IEnumerable<ArpReply> replies, PhysicalAddress? gatewayMac = null)
    {
        ArgumentNullException.ThrowIfNull(replies);
        var byIp = replies.GroupBy(r => r.SenderIp).ToDictionary(g => g.Key, g => g.Select(r => r.SenderMac).Distinct().ToList());
        var dups = byIp.Where(kv => kv.Value.Count > 1).Select(kv => new DuplicateIpFinding(kv.Key, kv.Value))
            .OrderBy(d => Targets.AddressKey.From(d.Address)).ToList();
        var warnings = new List<string>();
        var answeredPerMac = byIp.SelectMany(kv => kv.Value.Select(m => (m, kv.Key))).GroupBy(x => x.m).Where(g => g.Count() > 16).ToList();
        foreach (var g in answeredPerMac)
        {
            var who = gatewayMac is not null && g.Key.Equals(gatewayMac) ? " (the gateway)" : "";
            warnings.Add($"{Formats.Mac(g.Key)}{who} answered for {g.Count()} addresses: likely proxy ARP. Those addresses cannot be checked reliably.");
        }

        return new DuplicateIpReport(dups, byIp.Count, warnings);
    }
}
