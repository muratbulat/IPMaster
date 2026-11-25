using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using IPMaster.Core.Discovery;
using IPMaster.Infrastructure.Management;

namespace IPMaster.Infrastructure.Discovery;

/// <summary>Collects UDP datagrams on a socket until the deadline (bounded count and size).</summary>
internal static class UdpCollector
{
    public const int MaxDatagrams = 4096;

    public static async Task<List<(byte[] Data, IPEndPoint From)>> CollectAsync(Socket socket, TimeSpan duration, CancellationToken ct) =>
        (await CollectTimedAsync(socket, duration, ct).ConfigureAwait(false)).Select(d => (d.Data, d.From)).ToList();

    /// <summary>Like <see cref="CollectAsync"/>, with each datagram's arrival time since the call (DHCP response timing, D-095).</summary>
    public static async Task<List<(byte[] Data, IPEndPoint From, TimeSpan Elapsed)>> CollectTimedAsync(Socket socket, TimeSpan duration, CancellationToken ct)
    {
        var started = System.Diagnostics.Stopwatch.StartNew();
        var list = new List<(byte[], IPEndPoint, TimeSpan)>();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(duration);
        var buffer = new byte[65_535];
        EndPoint any = socket.AddressFamily == AddressFamily.InterNetworkV6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
        while (list.Count < MaxDatagrams)
        {
            try
            {
                var r = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token).ConfigureAwait(false);
                list.Add((buffer[..r.ReceivedBytes], (IPEndPoint)r.RemoteEndPoint, started.Elapsed));
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                // ignore ICMP errors / oversize datagrams
            }
        }

        ct.ThrowIfCancellationRequested();
        return list;
    }

    public static async Task<string?> HttpTextAsync(HttpClient http, Uri uri, HttpContent? post, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(post is null ? HttpMethod.Get : HttpMethod.Post, uri) { Content = post };
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (response.StatusCode == HttpStatusCode.Unauthorized) return "NotAuthorized";
            return await Bounded.ReadAsync(response, 512 * 1024, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or InvalidOperationException or TaskCanceledException && !ct.IsCancellationRequested)
        {
            return null;
        }
    }

    public static HttpClient NewHttp()
    {
        var http = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(3) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("IPMaster/0.3");
        return http;
    }
}

/// <summary>DHCP server discovery: broadcasts DHCPDISCOVER and lists OFFERs. Never sends DHCPREQUEST (no lease).</summary>
public sealed class DhcpDiscovery
{
    /// <param name="bindAddress">Probe through this local address only (the adapter of Device IP Discovery, D-090); default: any.</param>
    public async Task<(IReadOnlyList<DhcpOffer> Offers, string? Error)> DiscoverAsync(IReadOnlyList<byte> customOptions, TimeSpan duration,
        CancellationToken cancellationToken, IPAddress? bindAddress = null)
    {
        var mac = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
            .Select(n => n.GetPhysicalAddress()).FirstOrDefault(m => m.GetAddressBytes().Length == 6)
            ?? new PhysicalAddress(RandomNumberGenerator.GetBytes(6));
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp) { EnableBroadcast = true };
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        try
        {
            socket.Bind(new IPEndPoint(bindAddress ?? IPAddress.Any, 68));
        }
        catch (SocketException ex)
        {
            return ([], OperatingSystem.IsWindows()
                ? $"UDP port 68 is not available ({ex.SocketErrorCode}). Another DHCP tool may be running."
                : $"UDP port 68 is not available ({ex.SocketErrorCode}). Run with permission to bind privileged ports (e.g. CAP_NET_BIND_SERVICE).");
        }

        var xid = (uint)RandomNumberGenerator.GetInt32(int.MaxValue);
        var packet = DhcpPacket.Discover(xid, mac, customOptions);
        var collecting = UdpCollector.CollectTimedAsync(socket, duration, cancellationToken); // receive first, so the time starts at the DISCOVER
        for (var i = 0; i < 2; i++) await socket.SendToAsync(packet, SocketFlags.None, new IPEndPoint(IPAddress.Broadcast, 67), cancellationToken).ConfigureAwait(false);
        var datagrams = await collecting.ConfigureAwait(false);
        var offers = datagrams.Select(d => DhcpPacket.ParseOffer(d.Data, xid, d.From.Address) is { } o ? o with { ResponseTime = d.Elapsed, ClientMac = Core.Results.Formats.Mac(mac) } : null)
            .OfType<DhcpOffer>().DistinctBy(o => (o.ServerDisplay, o.OfferedAddress.ToString())).ToList();
        return (offers, null);
    }

    /// <summary>
    /// Passive DHCP diagnostics (D-095): listens on UDP 68 for server replies (OFFER, ACK, NAK) to any client and sends
    /// nothing. Only broadcast replies reach this computer (clients that set the broadcast flag, relays).
    /// </summary>
    public async Task<(IReadOnlyList<DhcpOffer> Replies, string? Error)> ListenAsync(TimeSpan duration, CancellationToken cancellationToken, IPAddress? bindAddress = null)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        try
        {
            socket.Bind(new IPEndPoint(bindAddress ?? IPAddress.Any, 68));
        }
        catch (SocketException ex)
        {
            return ([], $"UDP port 68 is not available ({ex.SocketErrorCode}).");
        }

        var datagrams = await UdpCollector.CollectAsync(socket, duration, cancellationToken).ConfigureAwait(false);
        return (datagrams.Select(d => DhcpMessage.Parse(d.Data) is { Op: 2 } m ? DhcpOffer.FromReply(m, d.From.Address) : null).OfType<DhcpOffer>().ToList(), null);
    }
}

/// <summary>UPnP discovery via SSDP M-SEARCH, then the device description of each LOCATION (XXE-safe, bounded).</summary>
public sealed class SsdpDiscovery
{
    public async Task<IReadOnlyList<DiscoveredDevice>> DiscoverAsync(TimeSpan duration, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 2);
        var target = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
        foreach (var st in new[] { "ssdp:all", "upnp:rootdevice" }) await socket.SendToAsync(Ssdp.Search(st), SocketFlags.None, target, ct).ConfigureAwait(false);
        var datagrams = await UdpCollector.CollectAsync(socket, duration, ct).ConfigureAwait(false);
        var byLocation = new Dictionary<string, (IPAddress From, IReadOnlyDictionary<string, string> Headers)>();
        foreach (var (data, from) in datagrams)
        {
            var h = Ssdp.ParseResponse(Encoding.UTF8.GetString(data));
            if (h is null || !h.TryGetValue("LOCATION", out var loc)) continue;
            byLocation.TryAdd(loc, (from.Address, h));
        }

        using var http = UdpCollector.NewHttp();
        var results = new ConcurrentBag<DiscoveredDevice>();
        await Parallel.ForEachAsync(byLocation, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (kv, t) =>
        {
            var details = new Dictionary<string, string>(kv.Value.Headers.ToDictionary(p => p.Key, p => p.Value)) { ["LOCATION"] = kv.Key };
            if (Uri.TryCreate(kv.Key, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https"
                && await UdpCollector.HttpTextAsync(http, uri, null, t).ConfigureAwait(false) is { } xml)
            {
                try
                {
                    foreach (var (k, v) in Ssdp.ParseDescription(xml, uri)) details[k] = v;
                }
                catch (System.Xml.XmlException)
                {
                    details["error"] = "Invalid device description.";
                }
            }

            results.Add(new DiscoveredDevice
            {
                Protocol = DiscoveryProtocol.Ssdp,
                Address = kv.Value.From,
                DeviceType = Ssdp.ShortType(details.GetValueOrDefault("deviceType") ?? details.GetValueOrDefault("ST") ?? ""),
                Name = details.GetValueOrDefault("friendlyName") ?? details.GetValueOrDefault("SERVER") ?? "",
                Url = details.GetValueOrDefault("presentationURL") ?? "",
                Manufacturer = details.GetValueOrDefault("manufacturer") ?? "",
                Model = details.GetValueOrDefault("modelName") ?? "",
                Serial = details.GetValueOrDefault("serialNumber") ?? "",
                Details = details,
            });
        }).ConfigureAwait(false);
        // one row per device: prefer the root device description per address/UDN
        return results.GroupBy(d => d.Details.GetValueOrDefault("UDN") ?? d.Address + d.Name).Select(g => g.First())
            .OrderBy(d => Core.Targets.AddressKey.From(d.Address)).ToList();
    }
}

/// <summary>mDNS / DNS-SD browsing (RFC 6762/6763) with QU questions from an ephemeral port (no port 5353 bind needed).</summary>
public sealed class MdnsDiscovery
{
    public async Task<IReadOnlyList<DiscoveredDevice>> DiscoverAsync(TimeSpan duration, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
        var group = new IPEndPoint(IPAddress.Parse("224.0.0.251"), 5353);
        await socket.SendToAsync(DnsMessage.Query([("_services._dns-sd._udp.local", DnsMessage.PtrType)]), SocketFlags.None, group, ct).ConfigureAwait(false);
        var records = new List<(DnsRecord Record, IPAddress From)>();
        foreach (var (data, from) in await UdpCollector.CollectAsync(socket, duration / 2, ct).ConfigureAwait(false))
        {
            records.AddRange(DnsMessage.Parse(data).Select(r => (r, from.Address)));
        }

        var types = records.Where(r => r.Record.Type == DnsMessage.PtrType && r.Record.Name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase))
            .Select(r => r.Record.Data).Distinct(StringComparer.OrdinalIgnoreCase).Take(64).ToList();
        if (types.Count > 0)
        {
            await socket.SendToAsync(DnsMessage.Query(types.Select(t => (t, DnsMessage.PtrType))), SocketFlags.None, group, ct).ConfigureAwait(false);
            foreach (var (data, from) in await UdpCollector.CollectAsync(socket, duration / 2, ct).ConfigureAwait(false))
            {
                records.AddRange(DnsMessage.Parse(data).Select(r => (r, from.Address)));
            }
        }

        return Build(records);
    }

    internal static IReadOnlyList<DiscoveredDevice> Build(IReadOnlyList<(DnsRecord Record, IPAddress From)> records)
    {
        var all = records.Select(r => r.Record).ToList();
        var instances = records.Where(r => r.Record.Type == DnsMessage.PtrType && !r.Record.Name.StartsWith("_services._dns-sd", StringComparison.OrdinalIgnoreCase))
            .DistinctBy(r => r.Record.Data, StringComparer.OrdinalIgnoreCase).ToList();
        var devices = new List<DiscoveredDevice>();
        foreach (var (ptr, from) in instances)
        {
            var instance = ptr.Data;
            var srv = all.FirstOrDefault(r => r.Type == DnsMessage.Srv && string.Equals(r.Name, instance, StringComparison.OrdinalIgnoreCase));
            var txt = all.FirstOrDefault(r => r.Type == DnsMessage.Txt && string.Equals(r.Name, instance, StringComparison.OrdinalIgnoreCase));
            var addr = srv is null ? null : all.FirstOrDefault(r => r.Type == DnsMessage.A && string.Equals(r.Name, srv.Data, StringComparison.OrdinalIgnoreCase))?.Address;
            addr ??= from;
            var serviceType = ptr.Name;
            var name = instance.EndsWith("." + serviceType, StringComparison.OrdinalIgnoreCase) ? instance[..^(serviceType.Length + 1)] : instance;
            var details = new Dictionary<string, string> { ["Instance"] = instance, ["Service"] = serviceType };
            if (srv is not null)
            {
                details["Host"] = srv.Data;
                details["Port"] = srv.Port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }

            foreach (var t in txt?.Text ?? [])
            {
                var eq = t.IndexOf('=', StringComparison.Ordinal);
                if (eq > 0) details["TXT " + t[..eq]] = t[(eq + 1)..];
            }

            var url = "";
            if (srv is not null && serviceType.StartsWith("_http._tcp", StringComparison.OrdinalIgnoreCase)) url = Core.Management.DeviceUrls.For("http", addr, srv.Port);
            else if (srv is not null && serviceType.StartsWith("_https._tcp", StringComparison.OrdinalIgnoreCase)) url = Core.Management.DeviceUrls.For("https", addr, srv.Port);
            else if (details.TryGetValue("TXT adminurl", out var admin)) url = admin;
            devices.Add(new DiscoveredDevice
            {
                Protocol = DiscoveryProtocol.Mdns,
                Address = addr,
                DeviceType = DnsMessage.ServiceLabel(serviceType),
                Name = name,
                Url = url,
                Model = details.GetValueOrDefault("TXT md") ?? details.GetValueOrDefault("TXT ty") ?? details.GetValueOrDefault("TXT model") ?? "",
                Details = details,
            });
        }

        return devices.OrderBy(d => Core.Targets.AddressKey.From(d.Address)).ThenBy(d => d.DeviceType, StringComparer.Ordinal).ToList();
    }
}

/// <summary>WS-Discovery probe (UDP 3702) plus WS-Transfer metadata; also the transport for ONVIF discovery.</summary>
public sealed class WsdDiscovery
{
    public static async Task<IReadOnlyList<(WsdMatch Match, IPAddress From)>> ProbeAsync(string types, TimeSpan duration, CancellationToken ct)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 1);
        var probe = WsDiscovery.Probe(types, Guid.NewGuid());
        await socket.SendToAsync(probe, SocketFlags.None, new IPEndPoint(IPAddress.Parse("239.255.255.250"), 3702), ct).ConfigureAwait(false);
        var list = new List<(WsdMatch, IPAddress)>();
        foreach (var (data, from) in await UdpCollector.CollectAsync(socket, duration, ct).ConfigureAwait(false))
        {
            try
            {
                list.AddRange(WsDiscovery.ParseProbeMatches(Encoding.UTF8.GetString(data)).Select(m => (m, from.Address)));
            }
            catch (System.Xml.XmlException)
            {
                // ignore malformed replies
            }
        }

        return list.DistinctBy(x => x.Item1.EndpointAddress + x.Item2).ToList();
    }

    public async Task<IReadOnlyList<DiscoveredDevice>> DiscoverAsync(TimeSpan duration, CancellationToken ct)
    {
        var matches = await ProbeAsync("wsdp:Device", duration, ct).ConfigureAwait(false);
        using var http = UdpCollector.NewHttp();
        var results = new ConcurrentBag<DiscoveredDevice>();
        await Parallel.ForEachAsync(matches, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (m, t) =>
        {
            var details = new Dictionary<string, string>
            {
                ["Endpoint"] = m.Match.EndpointAddress,
                ["Types"] = string.Join(" ", m.Match.Types),
                ["XAddrs"] = string.Join(" ", m.Match.XAddrs),
            };
            var xaddr = m.Match.XAddrs.FirstOrDefault(u => u.Scheme is "http" or "https");
            if (xaddr is not null)
            {
                using var content = new StringContent(WsDiscovery.TransferGet(xaddr, m.Match.EndpointAddress), Encoding.UTF8, "application/soap+xml");
                if (await UdpCollector.HttpTextAsync(http, xaddr, content, t).ConfigureAwait(false) is { } xml)
                {
                    try
                    {
                        foreach (var (k, v) in WsDiscovery.ParseMetadata(xml)) details[k] = v;
                    }
                    catch (System.Xml.XmlException)
                    {
                        details["error"] = "Invalid metadata.";
                    }
                }
            }

            results.Add(new DiscoveredDevice
            {
                Protocol = DiscoveryProtocol.Wsd,
                Address = m.From,
                DeviceType = string.Join(", ", m.Match.Types.Select(TypeLabel).Where(x => x.Length > 0).Distinct()),
                Name = details.GetValueOrDefault("FriendlyName") ?? "",
                Url = details.GetValueOrDefault("PresentationUrl") ?? xaddr?.ToString() ?? "",
                Manufacturer = details.GetValueOrDefault("Manufacturer") ?? "",
                Model = details.GetValueOrDefault("ModelName") ?? "",
                Serial = details.GetValueOrDefault("SerialNumber") ?? "",
                Firmware = details.GetValueOrDefault("FirmwareVersion") ?? "",
                Details = details,
            });
        }).ConfigureAwait(false);
        return results.OrderBy(d => Core.Targets.AddressKey.From(d.Address)).ToList();
    }

    internal static string TypeLabel(string qname)
    {
        var local = qname.Contains(':', StringComparison.Ordinal) ? qname[(qname.IndexOf(':', StringComparison.Ordinal) + 1)..] : qname;
        return local switch
        {
            "Device" => "",
            "PrintDeviceType" => "Printer",
            "ScanDeviceType" => "Scanner",
            "Computer" => "Computer",
            "NetworkVideoTransmitter" => "Video transmitter",
            _ => local,
        };
    }
}

/// <summary>ONVIF camera discovery: WS-Discovery for NetworkVideoTransmitter, scopes for name/hardware, then device
/// information and the first profile's RTSP stream URI (WS-UsernameToken digest when credentials are given).</summary>
public sealed class OnvifDiscovery
{
    public async Task<IReadOnlyList<DiscoveredDevice>> DiscoverAsync(string? user, string? password, TimeSpan duration, CancellationToken ct)
    {
        var matches = await WsdDiscovery.ProbeAsync("dn:NetworkVideoTransmitter", duration, ct).ConfigureAwait(false);
        using var http = UdpCollector.NewHttp();
        var results = new ConcurrentBag<DiscoveredDevice>();
        await Parallel.ForEachAsync(matches, new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ct }, async (m, t) =>
        {
            var scopes = WsDiscovery.OnvifScopes(m.Match.Scopes);
            var details = new Dictionary<string, string>(scopes.ToDictionary(p => "Scope " + p.Key, p => p.Value)) { ["XAddrs"] = string.Join(" ", m.Match.XAddrs) };
            string manufacturer = "", model = scopes.GetValueOrDefault("hardware") ?? "", firmware = "", serial = "", stream = "";
            var xaddr = m.Match.XAddrs.FirstOrDefault(u => u.Scheme is "http" or "https");
            if (xaddr is not null)
            {
                var info = await CallAsync(http, xaddr, OnvifSoap.GetDeviceInformation, user, password, t).ConfigureAwait(false);
                if (info.Doc is { } d)
                {
                    manufacturer = OnvifSoap.Value(d, "Manufacturer") ?? "";
                    model = OnvifSoap.Value(d, "Model") ?? model;
                    firmware = OnvifSoap.Value(d, "FirmwareVersion") ?? "";
                    serial = OnvifSoap.Value(d, "SerialNumber") ?? "";
                }
                else if (info.Auth)
                {
                    details["Device information"] = "authentication required";
                }

                var caps = await CallAsync(http, xaddr, OnvifSoap.GetCapabilities, user, password, t).ConfigureAwait(false);
                var media = caps.Doc is { } c && OnvifSoap.MediaXAddr(c) is { } mx && Uri.TryCreate(mx, UriKind.Absolute, out var mu) ? mu : xaddr;
                var profiles = await CallAsync(http, media, OnvifSoap.GetProfiles, user, password, t).ConfigureAwait(false);
                if (profiles.Doc is { } p && OnvifSoap.FirstProfileToken(p) is { } token)
                {
                    var uri = await CallAsync(http, media, OnvifSoap.GetStreamUri(token), user, password, t).ConfigureAwait(false);
                    stream = uri.Doc is { } u ? OnvifSoap.Value(u, "Uri") ?? "" : "";
                }
                else if (profiles.Auth)
                {
                    stream = "(authentication required)";
                }
            }

            results.Add(new DiscoveredDevice
            {
                Protocol = DiscoveryProtocol.Onvif,
                Address = m.From,
                DeviceType = "ONVIF camera",
                Name = scopes.GetValueOrDefault("name") ?? "",
                Manufacturer = manufacturer,
                Model = model,
                Firmware = firmware,
                Serial = serial,
                StreamUrl = stream,
                Url = stream.StartsWith("rtsp", StringComparison.OrdinalIgnoreCase) ? stream : xaddr?.ToString() ?? "",
                Details = details,
            });
        }).ConfigureAwait(false);
        return results.OrderBy(d => Core.Targets.AddressKey.From(d.Address)).ToList();
    }

    private static async Task<(System.Xml.Linq.XDocument? Doc, bool Auth)> CallAsync(HttpClient http, Uri uri, string body, string? user, string? password, CancellationToken ct)
    {
        using var content = new StringContent(OnvifSoap.Envelope(body, user, password, DateTimeOffset.UtcNow), Encoding.UTF8, "application/soap+xml");
        var xml = await UdpCollector.HttpTextAsync(http, uri, content, ct).ConfigureAwait(false);
        if (xml is null) return (null, false);
        if (OnvifSoap.IsAuthFault(xml)) return (null, true);
        try
        {
            var doc = SafeXml.Parse(xml);
            return doc.Descendants().Any(e => e.Name.LocalName == "Fault") ? (null, false) : (doc, false);
        }
        catch (System.Xml.XmlException)
        {
            return (null, false);
        }
    }
}
