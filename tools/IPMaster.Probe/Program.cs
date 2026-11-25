using IPMaster.Core.Discovery;
using IPMaster.Infrastructure.Discovery;
using IPMaster.Infrastructure.Network;

var what = args.Length > 0 ? args[0] : "all";
var t = TimeSpan.FromSeconds(4);
void Print(string title, IReadOnlyList<DiscoveredDevice> list)
{
    Console.WriteLine($"== {title}: {list.Count}");
    foreach (var d in list) Console.WriteLine($"  {d.Address,-16} {d.DeviceType,-24} {d.Name} | {d.Manufacturer} {d.Model} | {d.Url} {d.StreamUrl}");
}

if (what is "all" or "dhcp")
{
    var (offers, error) = await new DhcpDiscovery().DiscoverAsync([66, 67], t, CancellationToken.None);
    Console.WriteLine($"== DHCP: {offers.Count} {error}");
    foreach (var o in offers) Console.WriteLine($"  server {o.ServerDisplay} offers {o.OfferedAddress} gw {string.Join(",", o.Gateways)} dns {string.Join(",", o.DnsServers)} lease {o.LeaseTime}");
}

if (what is "all" or "ssdp") Print("SSDP/UPnP", await new SsdpDiscovery().DiscoverAsync(t, CancellationToken.None));
if (what is "all" or "mdns") Print("mDNS", await new MdnsDiscovery().DiscoverAsync(t, CancellationToken.None));
if (what is "all" or "wsd") Print("WSD", await new WsdDiscovery().DiscoverAsync(t, CancellationToken.None));
if (what is "all" or "onvif") Print("ONVIF", await new OnvifDiscovery().DiscoverAsync(null, null, t, CancellationToken.None));
if (what is "all" or "dup")
{
    var s = new DuplicateIpScanner(new PcapLibrary(new SystemNetworkAdapterProvider()));
    Console.WriteLine($"== Duplicate IP capability: {s.Capability.Available} {s.Capability.Description}");
}

// Phase 4 diagnostics (read-only): "snmp <ip> <community> [oid]" and "sshkey <ip> [port]".
if (what == "snmp" && args.Length >= 3)
{
    var target = new IPMaster.Infrastructure.Queries.SnmpTarget(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(args[1]), 161), IPMaster.Core.Queries.SnmpVersion.V2c,
        [args[2]], "", IPMaster.Core.Queries.SnmpSecurity.NoAuthNoPriv, IPMaster.Core.Queries.SnmpAuth.Sha256, "", IPMaster.Core.Queries.SnmpPriv.Aes128, "");
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
    try
    {
        var values = await IPMaster.Infrastructure.Queries.SnmpClient.RequestAsync(target, [args.Length > 3 ? args[3] : "1.3.6.1.2.1.1.1.0"],
            IPMaster.Infrastructure.Queries.SnmpPduKind.Get, cts.Token);
        foreach (var v in values) Console.WriteLine($"== SNMP {v.Oid} {v.Type}: {IPMaster.Infrastructure.Queries.SnmpQueryProvider.Render(v, IPMaster.Core.Queries.SnmpDisplay.Automatic)}");
    }
    catch (Exception ex) when (ex is IPMaster.Infrastructure.Queries.SnmpException or OperationCanceledException)
    {
        Console.WriteLine("== SNMP: " + ex.Message);
    }
}

if (what == "sshkey" && args.Length >= 2)
{
    var key = await IPMaster.Infrastructure.Queries.SshQueryProvider.ProbeHostKeyAsync(args[1], args.Length > 2 ? int.Parse(args[2], System.Globalization.CultureInfo.InvariantCulture) : 22, CancellationToken.None);
    Console.WriteLine(key is { } k ? $"== SSH host key {k.Algorithm} SHA256:{k.Fingerprint}" : "== SSH: no host key received");
}

// Wi-Fi (D-097, read-only): "wifi [fresh]" lists adapters, the connection and the BSS list.
if (what == "wifi" && OperatingSystem.IsWindows())
{
    var wifi = new IPMaster.Infrastructure.Wifi.WindowsWifiProvider();
    var adapters = await wifi.AdaptersAsync(CancellationToken.None);
    Console.WriteLine($"== Wi-Fi adapters: {adapters.State} {adapters.Detail}");
    foreach (var a in adapters.Value ?? [])
    {
        Console.WriteLine($"  {a.Id} {a.Description} [{a.State}] gw {a.Gateway} dns {string.Join(",", a.DnsServers)}");
        var c = await wifi.ConnectionAsync(a.Id, CancellationToken.None);
        Console.WriteLine($"  connection: {c.State} {c.Detail} {c.Value}");
        var scan = await wifi.ScanAsync(a.Id, args.Length > 1 && args[1] == "fresh", CancellationToken.None);
        Console.WriteLine($"  BSS list: {scan.State} {scan.Detail} {scan.Value?.Count}");
        foreach (var b in scan.Value ?? [])
            Console.WriteLine($"    {b.Ssid,-24} {IPMaster.Core.Wifi.WifiFormat.Bssid(b.Bssid)} {b.RssiDbm,4} dBm {b.FrequencyMhz} MHz ch {b.Channel} {b.WidthMhz?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "?"} MHz {b.Standard} | {b.Security} | k={b.Ies.RadioMeasurement} v={b.Ies.BssTransition} r={b.Ies.FastTransition} cc={b.Ies.Country} load={b.Ies.ChannelUtilizationPercent:0} ies={b.Ies.Count} bad={b.Ies.Malformed}");
    }
}
