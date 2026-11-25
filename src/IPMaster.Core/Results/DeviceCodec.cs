using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Xml.Linq;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Results;

/// <summary>Typed value encoder for XML (lossless, loadable) and JSON (export).</summary>
internal sealed record ValueCodec<T>(Action<XElement, T> WriteXml, Func<XElement, T> ReadXml, Action<Utf8JsonWriter, T> WriteJson);

internal interface IDeviceField
{
    string Name { get; }

    void WriteXml(XElement device, DeviceResult d, XNamespace ns);

    DeviceResult ReadXml(XElement device, DeviceResult d, XNamespace ns);

    void WriteJson(Utf8JsonWriter w, DeviceResult d);
}

internal sealed record DeviceField<T>(string Name, Func<DeviceResult, Observation<T>> Get, Func<DeviceResult, Observation<T>, DeviceResult> Set, ValueCodec<T> Codec)
    : IDeviceField
{
    public void WriteXml(XElement device, DeviceResult d, XNamespace ns)
    {
        var o = Get(d);
        if (o.State == ObservationState.NotRequested) return;
        device.Add(Codecs.ObservationToXml(ns + Name, o, Codec, ns));
    }

    public DeviceResult ReadXml(XElement device, DeviceResult d, XNamespace ns)
    {
        var e = device.Element(ns + Name);
        return e is null ? d : Set(d, Codecs.ObservationFromXml(e, Codec, ns));
    }

    public void WriteJson(Utf8JsonWriter w, DeviceResult d) => Codecs.ObservationToJson(w, Name, Get(d), Codec);
}

internal static class Codecs
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    public static string Iso(DateTimeOffset t) => t.ToString("O", Inv);

    public static DateTimeOffset ParseIso(string s) => DateTimeOffset.Parse(s, Inv, DateTimeStyles.RoundtripKind);

    private static string Attr(XElement e, string name) => (string?)e.Attribute(name) ?? throw new FormatException($"Missing attribute '{name}' on <{e.Name.LocalName}>.");

    private static string? OptAttr(XElement e, string name) => (string?)e.Attribute(name);

    private static void SetOpt(XElement e, string name, string? value)
    {
        if (value is not null) e.SetAttributeValue(name, value);
    }

    public static XElement ObservationToXml<T>(XName name, Observation<T> o, ValueCodec<T> codec, XNamespace ns)
    {
        var e = new XElement(name, new XAttribute("state", ObservationText.StateName(o.State)));
        if (o.ObservedAt is { } at) e.SetAttributeValue("at", Iso(at));
        if (o.Detail is not null) e.SetAttributeValue("detail", o.Detail);
        if (o.State == ObservationState.Success)
        {
            var v = new XElement(ns + "value");
            codec.WriteXml(v, o.Value!);
            e.Add(v);
        }

        return e;
    }

    public static Observation<T> ObservationFromXml<T>(XElement e, ValueCodec<T> codec, XNamespace ns)
    {
        var state = ObservationText.ParseState(OptAttr(e, "state"));
        var at = OptAttr(e, "at") is { } a ? ParseIso(a) : (DateTimeOffset?)null;
        var detail = OptAttr(e, "detail");
        if (state != ObservationState.Success) return new Observation<T>(state, default, detail, at);
        var v = e.Element(ns + "value") ?? throw new FormatException($"<{e.Name.LocalName}> has state success but no value.");
        return new Observation<T>(state, codec.ReadXml(v), detail, at);
    }

    public static void ObservationToJson<T>(Utf8JsonWriter w, string name, Observation<T> o, ValueCodec<T> codec)
    {
        if (o.State == ObservationState.NotRequested) return;
        w.WriteStartObject(name);
        w.WriteString("state", ObservationText.StateName(o.State));
        if (o.State == ObservationState.Success)
        {
            w.WritePropertyName("value");
            codec.WriteJson(w, o.Value!);
        }

        if (o.Detail is not null) w.WriteString("detail", o.Detail);
        w.WriteEndObject();
    }

    // ---- scalar codecs ----
    public static readonly ValueCodec<string> String = new((e, v) => e.Value = v, e => e.Value, (w, v) => w.WriteStringValue(v));

    public static readonly ValueCodec<int> Int = new((e, v) => e.Value = v.ToString(Inv), e => int.Parse(e.Value, Inv), (w, v) => w.WriteNumberValue(v));

    public static readonly ValueCodec<DateTimeOffset> Time = new((e, v) => e.Value = Iso(v), e => ParseIso(e.Value), (w, v) => w.WriteStringValue(v));

    public static readonly ValueCodec<PhysicalAddress> Mac = new((e, v) => e.Value = Formats.Mac(v, ":"),
        e => Formats.ParseMac(e.Value) ?? throw new FormatException($"Invalid MAC '{e.Value}'."), (w, v) => w.WriteStringValue(Formats.Mac(v, ":")));

    public static readonly ValueCodec<IPAddress> Ip = new((e, v) => e.Value = v.ToString(), e => IPAddress.Parse(e.Value), (w, v) => w.WriteStringValue(v.ToString()));

    public static readonly ValueCodec<HostNameInfo> HostName = new(
        (e, v) =>
        {
            e.SetAttributeValue("name", v.Name);
            if (v.ForwardConfirmed is { } f) e.SetAttributeValue("forwardConfirmed", f ? "true" : "false");
        },
        e => new HostNameInfo(Attr(e, "name"), OptAttr(e, "forwardConfirmed") is { } f ? f == "true" : null),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("name", v.Name);
            if (v.ForwardConfirmed is { } fc) w.WriteBoolean("forwardConfirmed", fc);
            w.WriteEndObject();
        });

    public static readonly ValueCodec<PingStatistics> Stats = new(
        (e, v) =>
        {
            e.SetAttributeValue("sent", v.Sent);
            e.SetAttributeValue("received", v.Received);
            if (v.Jitter is { } j) e.SetAttributeValue("jitterTicks", j.Ticks);
            if (v.AverageRoundTrip is { } a) e.SetAttributeValue("avgRttTicks", a.Ticks);
        },
        e => new PingStatistics(int.Parse(Attr(e, "sent"), Inv), int.Parse(Attr(e, "received"), Inv),
            OptAttr(e, "jitterTicks") is { } j ? TimeSpan.FromTicks(long.Parse(j, Inv)) : null,
            OptAttr(e, "avgRttTicks") is { } a ? TimeSpan.FromTicks(long.Parse(a, Inv)) : null),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteNumber("sent", v.Sent);
            w.WriteNumber("received", v.Received);
            w.WriteNumber("lossPercent", Math.Round(v.LossPercent, 2));
            if (v.Jitter is { } j) w.WriteNumber("jitterMs", Math.Round(j.TotalMilliseconds, 3));
            if (v.AverageRoundTrip is { } a) w.WriteNumber("avgRttMs", Math.Round(a.TotalMilliseconds, 3));
            w.WriteEndObject();
        });

    public static readonly ValueCodec<PortResult> Port = new(
        (e, v) =>
        {
            e.SetAttributeValue("protocol", v.Protocol == PortProtocol.Tcp ? "tcp" : "udp");
            e.SetAttributeValue("port", v.Port);
            e.SetAttributeValue("state", v.State.ToString());
            SetOpt(e, "service", v.Service);
            SetOpt(e, "detail", v.Detail);
        },
        e => new PortResult(Attr(e, "protocol") == "udp" ? PortProtocol.Udp : PortProtocol.Tcp, int.Parse(Attr(e, "port"), Inv),
            Enum.Parse<PortState>(Attr(e, "state")), OptAttr(e, "service"), OptAttr(e, "detail")),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("protocol", v.Protocol == PortProtocol.Tcp ? "tcp" : "udp");
            w.WriteNumber("port", v.Port);
            w.WriteString("state", v.State.ToString());
            if (v.Service is not null) w.WriteString("service", v.Service);
            if (v.Detail is not null) w.WriteString("detail", v.Detail);
            w.WriteEndObject();
        });

    public static readonly ValueCodec<ServiceBanner> Banner = new(
        (e, v) =>
        {
            e.SetAttributeValue("service", v.Service);
            e.SetAttributeValue("protocol", v.Protocol == PortProtocol.Tcp ? "tcp" : "udp");
            e.SetAttributeValue("port", v.Port);
            e.Value = v.Text;
        },
        e => new ServiceBanner(Attr(e, "service"), Attr(e, "protocol") == "udp" ? PortProtocol.Udp : PortProtocol.Tcp, int.Parse(Attr(e, "port"), Inv), e.Value),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("service", v.Service);
            w.WriteString("protocol", v.Protocol == PortProtocol.Tcp ? "tcp" : "udp");
            w.WriteNumber("port", v.Port);
            w.WriteString("text", v.Text);
            w.WriteEndObject();
        });

    public static readonly ValueCodec<TlsCertificateInfo> Tls = new(
        (e, v) =>
        {
            e.SetAttributeValue("port", v.Port);
            e.SetAttributeValue("subject", v.Subject);
            e.SetAttributeValue("issuer", v.Issuer);
            e.SetAttributeValue("notBefore", Iso(v.NotBefore));
            e.SetAttributeValue("notAfter", Iso(v.NotAfter));
            e.SetAttributeValue("serial", v.SerialNumber);
            e.SetAttributeValue("thumbprint", v.Thumbprint);
            e.SetAttributeValue("protocol", v.Protocol);
            e.SetAttributeValue("chainValid", v.ChainValid ? "true" : "false");
            SetOpt(e, "chainStatus", v.ChainStatus);
            foreach (var san in v.SubjectAlternativeNames) e.Add(new XElement(e.Name.Namespace + "san", san));
        },
        e => new TlsCertificateInfo(int.Parse(Attr(e, "port"), Inv), Attr(e, "subject"), Attr(e, "issuer"), ParseIso(Attr(e, "notBefore")),
            ParseIso(Attr(e, "notAfter")), Attr(e, "serial"), Attr(e, "thumbprint"), e.Elements(e.Name.Namespace + "san").Select(x => x.Value).ToList(),
            Attr(e, "protocol"), Attr(e, "chainValid") == "true", OptAttr(e, "chainStatus")),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteNumber("port", v.Port);
            w.WriteString("subject", v.Subject);
            w.WriteString("issuer", v.Issuer);
            w.WriteString("notBefore", v.NotBefore);
            w.WriteString("notAfter", v.NotAfter);
            w.WriteString("serialNumber", v.SerialNumber);
            w.WriteString("thumbprint", v.Thumbprint);
            w.WriteString("protocol", v.Protocol);
            w.WriteBoolean("chainValid", v.ChainValid);
            if (v.ChainStatus is not null) w.WriteString("chainStatus", v.ChainStatus);
            w.WriteStartArray("subjectAlternativeNames");
            foreach (var s in v.SubjectAlternativeNames) w.WriteStringValue(s);
            w.WriteEndArray();
            w.WriteEndObject();
        });

    public static readonly ValueCodec<NetBiosInfo> NetBios = new(
        (e, v) =>
        {
            SetOpt(e, "computer", v.ComputerName);
            SetOpt(e, "domain", v.Domain);
            SetOpt(e, "user", v.UserName);
            if (v.Mac is { } m) e.SetAttributeValue("mac", Formats.Mac(m, ":"));
            foreach (var n in v.Names)
            {
                e.Add(new XElement(e.Name.Namespace + "name", new XAttribute("suffix", n.Suffix.ToString("X2", Inv)),
                    new XAttribute("group", n.IsGroup ? "true" : "false"), n.Name));
            }
        },
        e => new NetBiosInfo(OptAttr(e, "computer"), OptAttr(e, "domain"), OptAttr(e, "user"), Formats.ParseMac(OptAttr(e, "mac")),
            e.Elements(e.Name.Namespace + "name").Select(n => new NetBiosName(n.Value, byte.Parse(Attr(n, "suffix"), NumberStyles.HexNumber, Inv),
                Attr(n, "group") == "true")).ToList()),
        (w, v) =>
        {
            w.WriteStartObject();
            if (v.ComputerName is not null) w.WriteString("computerName", v.ComputerName);
            if (v.Domain is not null) w.WriteString("domain", v.Domain);
            if (v.UserName is not null) w.WriteString("userName", v.UserName);
            if (v.Mac is { } m) w.WriteString("mac", Formats.Mac(m, ":"));
            w.WriteStartArray("names");
            foreach (var n in v.Names)
            {
                w.WriteStartObject();
                w.WriteString("name", n.Name);
                w.WriteNumber("suffix", n.Suffix);
                w.WriteBoolean("group", n.IsGroup);
                w.WriteEndObject();
            }

            w.WriteEndArray();
            w.WriteEndObject();
        });

    public static readonly ValueCodec<InstalledApplication> App = new(
        (e, v) =>
        {
            e.SetAttributeValue("name", v.Name);
            SetOpt(e, "version", v.Version);
            SetOpt(e, "publisher", v.Publisher);
        },
        e => new InstalledApplication(Attr(e, "name"), OptAttr(e, "version"), OptAttr(e, "publisher")),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("name", v.Name);
            if (v.Version is not null) w.WriteString("version", v.Version);
            if (v.Publisher is not null) w.WriteString("publisher", v.Publisher);
            w.WriteEndObject();
        });

    private static readonly ValueCodec<ShareAccess> Access = new(
        (e, v) =>
        {
            e.SetAttributeValue("readable", v.Readable ? "true" : "false");
            if (v.Writable is { } wr) e.SetAttributeValue("writable", wr ? "true" : "false");
        },
        e => new ShareAccess(Attr(e, "readable") == "true", OptAttr(e, "writable") is { } wr ? wr == "true" : null),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteBoolean("readable", v.Readable);
            if (v.Writable is { } wr) w.WriteBoolean("writable", wr);
            w.WriteEndObject();
        });

    private static readonly ValueCodec<DiskSpace> Disk = new(
        (e, v) =>
        {
            e.SetAttributeValue("total", v.TotalBytes);
            e.SetAttributeValue("free", v.FreeBytes);
        },
        e => new DiskSpace(long.Parse(Attr(e, "total"), Inv), long.Parse(Attr(e, "free"), Inv)),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteNumber("totalBytes", v.TotalBytes);
            w.WriteNumber("freeBytes", v.FreeBytes);
            w.WriteEndObject();
        });

    private static readonly ValueCodec<ShareAccessEntry> AclEntry = new(
        (e, v) =>
        {
            e.SetAttributeValue("account", v.Account);
            e.SetAttributeValue("rights", v.Rights);
            e.SetAttributeValue("allow", v.Allow ? "true" : "false");
        },
        e => new ShareAccessEntry(Attr(e, "account"), Attr(e, "rights"), Attr(e, "allow") == "true"),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("account", v.Account);
            w.WriteString("rights", v.Rights);
            w.WriteBoolean("allow", v.Allow);
            w.WriteEndObject();
        });

    public static readonly ValueCodec<ShareInfo> Share = new(
        (e, v) =>
        {
            var ns = e.Name.Namespace;
            e.SetAttributeValue("name", v.Name);
            e.SetAttributeValue("kind", v.Kind.ToString());
            e.SetAttributeValue("administrative", v.IsAdministrative ? "true" : "false");
            if (v.Remark.Length > 0) e.SetAttributeValue("remark", v.Remark);
            if (v.Access.State != ObservationState.NotRequested) e.Add(ObservationToXml(ns + "access", v.Access, Access, ns));
            if (v.Disk.State != ObservationState.NotRequested) e.Add(ObservationToXml(ns + "disk", v.Disk, Disk, ns));
            if (v.Permissions.State != ObservationState.NotRequested) e.Add(ObservationToXml(ns + "permissions", v.Permissions, ListOf(AclEntry), ns));
        },
        e =>
        {
            var ns = e.Name.Namespace;
            return new ShareInfo
            {
                Name = Attr(e, "name"),
                Kind = Enum.Parse<ShareKind>(Attr(e, "kind")),
                IsAdministrative = Attr(e, "administrative") == "true",
                Remark = OptAttr(e, "remark") ?? "",
                Access = e.Element(ns + "access") is { } a ? ObservationFromXml(a, Access, ns) : Observation<ShareAccess>.NotRequested,
                Disk = e.Element(ns + "disk") is { } d ? ObservationFromXml(d, Disk, ns) : Observation<DiskSpace>.NotRequested,
                Permissions = e.Element(ns + "permissions") is { } p ? ObservationFromXml(p, ListOf(AclEntry), ns) : Observation<IReadOnlyList<ShareAccessEntry>>.NotRequested,
            };
        },
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("name", v.Name);
            w.WriteString("kind", v.Kind.ToString().ToLowerInvariant());
            w.WriteBoolean("administrative", v.IsAdministrative);
            w.WriteString("remark", v.Remark);
            w.WriteString("typeLetters", v.TypeLetters);
            ObservationToJson(w, "access", v.Access, Access);
            ObservationToJson(w, "disk", v.Disk, Disk);
            ObservationToJson(w, "permissions", v.Permissions, ListOf(AclEntry));
            w.WriteEndObject();
        });

    public static readonly ValueCodec<GeoLocation> Geo = new(
        (e, v) =>
        {
            e.SetAttributeValue("city", v.City);
            e.SetAttributeValue("region", v.Region);
            e.SetAttributeValue("country", v.Country);
        },
        e => new GeoLocation((string?)e.Attribute("city") ?? "", (string?)e.Attribute("region") ?? "", (string?)e.Attribute("country") ?? ""),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("city", v.City);
            w.WriteString("region", v.Region);
            w.WriteString("country", v.Country);
            w.WriteEndObject();
        });

    public static ValueCodec<IReadOnlyList<T>> ListOf<T>(ValueCodec<T> item) => new(
        (e, list) =>
        {
            foreach (var v in list)
            {
                var i = new XElement(e.Name.Namespace + "item");
                item.WriteXml(i, v);
                e.Add(i);
            }
        },
        e => e.Elements(e.Name.Namespace + "item").Select(item.ReadXml).ToList(),
        (w, list) =>
        {
            w.WriteStartArray();
            foreach (var v in list) item.WriteJson(w, v);
            w.WriteEndArray();
        });
}

/// <summary>Field table: the single place that lists every serialised observation of a device.</summary>
internal static class DeviceFields
{
    public static readonly IReadOnlyList<IDeviceField> All =
    [
        new DeviceField<int>("ttl", d => d.Ttl, (d, o) => d with { Ttl = o }, Codecs.Int),
        new DeviceField<HostNameInfo>("hostName", d => d.HostName, (d, o) => d with { HostName = o }, Codecs.HostName),
        new DeviceField<PhysicalAddress>("mac", d => d.Mac, (d, o) => d with { Mac = o }, Codecs.Mac),
        new DeviceField<string>("vendor", d => d.Vendor, (d, o) => d with { Vendor = o }, Codecs.String),
        new DeviceField<PingStatistics>("pingStatistics", d => d.PingStats, (d, o) => d with { PingStats = o }, Codecs.Stats),
        new DeviceField<IReadOnlyList<IPAddress>>("ipv6Addresses", d => d.IPv6Addresses, (d, o) => d with { IPv6Addresses = o }, Codecs.ListOf(Codecs.Ip)),
        new DeviceField<NetBiosInfo>("netBios", d => d.NetBios, (d, o) => d with { NetBios = o }, Codecs.NetBios),
        new DeviceField<IReadOnlyList<PortResult>>("tcpPorts", d => d.TcpPorts, (d, o) => d with { TcpPorts = o }, Codecs.ListOf(Codecs.Port)),
        new DeviceField<IReadOnlyList<PortResult>>("udpPorts", d => d.UdpPorts, (d, o) => d with { UdpPorts = o }, Codecs.ListOf(Codecs.Port)),
        new DeviceField<IReadOnlyList<ServiceBanner>>("banners", d => d.Banners, (d, o) => d with { Banners = o }, Codecs.ListOf(Codecs.Banner)),
        new DeviceField<IReadOnlyList<string>>("rtspStreams", d => d.RtspStreams, (d, o) => d with { RtspStreams = o }, Codecs.ListOf(Codecs.String)),
        new DeviceField<TlsCertificateInfo>("tls", d => d.Tls, (d, o) => d with { Tls = o }, Codecs.Tls),
        new DeviceField<string>("workgroup", d => d.Workgroup, (d, o) => d with { Workgroup = o }, Codecs.String),
        new DeviceField<string>("osVersion", d => d.OsVersion, (d, o) => d with { OsVersion = o }, Codecs.String),
        new DeviceField<IReadOnlyList<string>>("accounts", d => d.Accounts, (d, o) => d with { Accounts = o }, Codecs.ListOf(Codecs.String)),
        new DeviceField<IReadOnlyList<string>>("loggedOnUsers", d => d.LoggedOnUsers, (d, o) => d with { LoggedOnUsers = o }, Codecs.ListOf(Codecs.String)),
        new DeviceField<IReadOnlyList<string>>("loggedOnSids", d => d.LoggedOnSids, (d, o) => d with { LoggedOnSids = o }, Codecs.ListOf(Codecs.String)),
        new DeviceField<DateTimeOffset>("remoteTime", d => d.RemoteTime, (d, o) => d with { RemoteTime = o }, Codecs.Time),
        new DeviceField<IReadOnlyList<InstalledApplication>>("installedApplications", d => d.InstalledApps, (d, o) => d with { InstalledApps = o }, Codecs.ListOf(Codecs.App)),
        new DeviceField<IReadOnlyList<ShareInfo>>("shares", d => d.Shares, (d, o) => d with { Shares = o }, Codecs.ListOf(Codecs.Share)),
        new DeviceField<GeoLocation>("location", d => d.Location, (d, o) => d with { Location = o }, Codecs.Geo),
        new DeviceField<IReadOnlyList<MonitorInfo>>("monitors", d => d.Monitors, (d, o) => d with { Monitors = o }, Codecs.ListOf(Phase4Codecs.Monitor)),
        new DeviceField<IReadOnlyList<TerminalSession>>("terminalSessions", d => d.TerminalSessions, (d, o) => d with { TerminalSessions = o }, Codecs.ListOf(Phase4Codecs.Session)),
        QueriesField.Instance,
    ];

    public static XElement ToXml(DeviceResult d, XNamespace ns)
    {
        var e = new XElement(ns + "device",
            new XAttribute("ip", d.Key.ToString()),
            new XAttribute("status", d.Status.ToString()),
            new XAttribute("respondedTo", d.RespondedTo.ToString()),
            new XAttribute("lastScanned", Codecs.Iso(d.LastScanned)));
        if (d.RoundTrip is { } rtt) e.SetAttributeValue("rttTicks", rtt.Ticks);
        if (d.LastSeen is { } ls) e.SetAttributeValue("lastSeen", Codecs.Iso(ls));
        if (d.MacSource != MacSource.None) e.SetAttributeValue("macSource", d.MacSource.ToString());
        if (!d.IsComplete) e.SetAttributeValue("complete", "false");
        foreach (var f in All) f.WriteXml(e, d, ns);
        return e;
    }

    public static DeviceResult FromXml(XElement e, XNamespace ns)
    {
        var ip = (string?)e.Attribute("ip") ?? throw new FormatException("<device> without ip.");
        if (!TargetParser.TryParseAddress(ip, out var key)) throw new FormatException($"Invalid device address '{ip}'.");
        var d = new DeviceResult
        {
            Key = key,
            Status = Enum.Parse<DeviceStatus>((string?)e.Attribute("status") ?? "Online"),
            RespondedTo = Enum.Parse<PingMethod>((string?)e.Attribute("respondedTo") ?? "None"),
            RoundTrip = e.Attribute("rttTicks") is { } r ? TimeSpan.FromTicks(long.Parse(r.Value, CultureInfo.InvariantCulture)) : null,
            LastScanned = Codecs.ParseIso((string?)e.Attribute("lastScanned") ?? throw new FormatException("<device> without lastScanned.")),
            LastSeen = e.Attribute("lastSeen") is { } ls ? Codecs.ParseIso(ls.Value) : null,
            MacSource = e.Attribute("macSource") is { } ms ? Enum.Parse<MacSource>(ms.Value) : MacSource.None,
            IsComplete = (string?)e.Attribute("complete") != "false",
            Revision = 0,
        };
        foreach (var f in All) d = f.ReadXml(e, d, ns);
        return d;
    }

    public static void ToJson(Utf8JsonWriter w, DeviceResult d)
    {
        w.WriteString("ip", d.Key.ToString());
        w.WriteString("family", d.Key.IsV6 ? "ipv6" : "ipv4");
        w.WriteString("status", d.Status.ToString().ToLowerInvariant());
        w.WriteString("respondedTo", d.RespondedTo.ToString().ToLowerInvariant());
        if (d.RoundTrip is { } rtt) w.WriteNumber("rttMs", Math.Round(rtt.TotalMilliseconds, 3));
        else w.WriteNull("rttMs");
        if (d.MacSource != MacSource.None) w.WriteString("macSource", d.MacSource.ToString().ToLowerInvariant());
        foreach (var f in All) f.WriteJson(w, d);
        w.WriteString("lastScanned", d.LastScanned);
        if (d.LastSeen is { } ls) w.WriteString("lastSeen", ls);
        else w.WriteNull("lastSeen");
    }
}

/// <summary>Remote query results: <c>&lt;queries&gt;&lt;query id="q:…" state=…&gt;&lt;value&gt;…</c> / <c>"queries": { "q:…": {…} }</c>.</summary>
internal sealed class QueriesField : IDeviceField
{
    public static readonly QueriesField Instance = new();

    public string Name => "queries";

    public void WriteXml(XElement device, DeviceResult d, XNamespace ns)
    {
        if (d.Queries.Count == 0) return;
        var e = new XElement(ns + Name);
        foreach (var (id, o) in d.Queries)
        {
            var q = Codecs.ObservationToXml(ns + "query", o, Codecs.String, ns);
            q.SetAttributeValue("id", id);
            e.Add(q);
        }

        device.Add(e);
    }

    public DeviceResult ReadXml(XElement device, DeviceResult d, XNamespace ns)
    {
        var e = device.Element(ns + Name);
        if (e is null) return d;
        var b = System.Collections.Immutable.ImmutableSortedDictionary.CreateBuilder<string, Observation<string>>(StringComparer.Ordinal);
        foreach (var q in e.Elements(ns + "query"))
        {
            var id = (string?)q.Attribute("id") ?? throw new FormatException("<query> without id.");
            b[id] = Codecs.ObservationFromXml(q, Codecs.String, ns);
        }

        return d with { Queries = b.ToImmutable() };
    }

    public void WriteJson(Utf8JsonWriter w, DeviceResult d)
    {
        if (d.Queries.Count == 0) return;
        w.WriteStartObject(Name);
        foreach (var (id, o) in d.Queries) Codecs.ObservationToJson(w, id, o, Codecs.String);
        w.WriteEndObject();
    }
}

internal static class Phase4Codecs
{
    public static readonly ValueCodec<MonitorInfo> Monitor = new(
        (e, v) =>
        {
            e.SetAttributeValue("manufacturer", v.Manufacturer);
            e.SetAttributeValue("model", v.Model);
            e.SetAttributeValue("serial", v.Serial);
            if (v.Year is { } y) e.SetAttributeValue("year", y);
        },
        e => new MonitorInfo((string?)e.Attribute("manufacturer") ?? "", (string?)e.Attribute("model") ?? "", (string?)e.Attribute("serial") ?? "", (int?)e.Attribute("year")),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteString("manufacturer", v.Manufacturer);
            w.WriteString("model", v.Model);
            w.WriteString("serial", v.Serial);
            if (v.Year is { } y) w.WriteNumber("year", y);
            w.WriteEndObject();
        });

    public static readonly ValueCodec<TerminalSession> Session = new(
        (e, v) =>
        {
            e.SetAttributeValue("id", v.Id);
            e.SetAttributeValue("user", v.User);
            e.SetAttributeValue("state", v.State);
            e.SetAttributeValue("clientName", v.ClientName);
            e.SetAttributeValue("clientAddress", v.ClientAddress);
        },
        e => new TerminalSession((int?)e.Attribute("id") ?? 0, (string?)e.Attribute("user") ?? "", (string?)e.Attribute("state") ?? "",
            (string?)e.Attribute("clientName") ?? "", (string?)e.Attribute("clientAddress") ?? ""),
        (w, v) =>
        {
            w.WriteStartObject();
            w.WriteNumber("id", v.Id);
            w.WriteString("user", v.User);
            w.WriteString("state", v.State);
            w.WriteString("clientName", v.ClientName);
            w.WriteString("clientAddress", v.ClientAddress);
            w.WriteEndObject();
        });
}
