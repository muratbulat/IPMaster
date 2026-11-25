using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Probes;

/// <summary>TCP connect probe. Sockets close with linger 0 (RST) so large scans do not pile up TIME_WAIT entries.</summary>
public sealed class TcpPortProbe : ITcpPortProbe
{
    public async Task<PortResult> ProbeAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        socket.LingerState = new LingerOption(true, 0);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token).ConfigureAwait(false);
            return new PortResult(PortProtocol.Tcp, port, PortState.Open);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new PortResult(PortProtocol.Tcp, port, PortState.Filtered, Detail: "No response.");
        }
        catch (SocketException ex)
        {
            var state = Classify(ex.SocketErrorCode);
            return new PortResult(PortProtocol.Tcp, port, state, Detail: state == PortState.Closed ? null : ex.SocketErrorCode.ToString());
        }
    }

    /// <summary>
    /// Refused = Closed; errors that come from the network path (unreachable, timed out, host down) = Filtered; anything else is
    /// a local failure (no buffer space, address in use, access denied…) that says nothing about the device (review C-10).
    /// </summary>
    public static PortState Classify(SocketError error) => error switch
    {
        SocketError.ConnectionRefused => PortState.Closed,
        SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.TimedOut or SocketError.HostDown
            or SocketError.ConnectionReset or SocketError.ConnectionAborted or SocketError.NetworkReset => PortState.Filtered,
        _ => PortState.Failed,
    };
}

/// <summary>Request/response exchange over a connected UDP socket. An ICMP port-unreachable surfaces as
/// ConnectionReset (Windows) or ConnectionRefused (Unix) and means Closed; silence means Open|Filtered.</summary>
internal static class UdpExchange
{
    public static async Task<(byte[]? Reply, PortState State, string? Detail)> RunAsync(IPAddress address, int port, byte[] request, TimeSpan timeout,
        CancellationToken ct)
    {
        using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token).ConfigureAwait(false);
            await socket.SendAsync(request, SocketFlags.None, cts.Token).ConfigureAwait(false);
            var buffer = new byte[8192];
            var n = await socket.ReceiveAsync(buffer, SocketFlags.None, cts.Token).ConfigureAwait(false);
            return (buffer[..n], PortState.Open, null);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (null, PortState.OpenOrFiltered, "No reply.");
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused)
        {
            return (null, PortState.Closed, "ICMP port unreachable.");
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostUnreachable or SocketError.NetworkUnreachable)
        {
            return (null, PortState.Filtered, ex.SocketErrorCode.ToString());
        }
    }
}

/// <summary>NetBIOS node-status (NBSTAT) query, RFC 1002 §4.2.18. Also yields the adapter MAC (unit ID).</summary>
public sealed class NetBiosProbe : INetBiosProbe
{
    public async Task<NetBiosInfo?> QueryAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != AddressFamily.InterNetwork) return null;
        var (reply, _, _) = await UdpExchange.RunAsync(address, 137, BuildRequest(), timeout, cancellationToken).ConfigureAwait(false);
        return reply is null ? null : Parse(reply);
    }

    internal static byte[] BuildRequest()
    {
        var p = new byte[50];
        BinaryPrimitives.WriteUInt16BigEndian(p, (ushort)RandomNumberGenerator.GetInt32(1, 65535));
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(4), 1); // QDCOUNT
        p[12] = 0x20;
        // "*" padded with NULs, first-level encoded: '*' (0x2A) → "CK", 0x00 → "AA"
        p[13] = (byte)'C';
        p[14] = (byte)'K';
        for (var i = 15; i < 45; i++) p[i] = (byte)'A';
        p[45] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(46), 0x21); // NBSTAT
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(48), 0x01); // IN
        return p;
    }

    internal static NetBiosInfo? Parse(ReadOnlySpan<byte> r)
    {
        if (r.Length < 12) return null;
        var answers = BinaryPrimitives.ReadUInt16BigEndian(r[6..]);
        var questions = BinaryPrimitives.ReadUInt16BigEndian(r[4..]);
        if (answers == 0) return null;
        var pos = 12;
        for (var q = 0; q < questions; q++)
        {
            pos = SkipName(r, pos);
            pos += 4;
        }

        pos = SkipName(r, pos);
        if (pos < 0 || pos + 10 > r.Length) return null;
        var type = BinaryPrimitives.ReadUInt16BigEndian(r[pos..]);
        if (type != 0x21) return null;
        pos += 10; // type, class, ttl, rdlength
        if (pos >= r.Length) return null;
        int count = r[pos++];
        var names = new List<NetBiosName>();
        for (var i = 0; i < count && pos + 18 <= r.Length; i++, pos += 18)
        {
            var name = Encoding.ASCII.GetString(r.Slice(pos, 15)).TrimEnd(' ', '\0');
            var suffix = r[pos + 15];
            var flags = BinaryPrimitives.ReadUInt16BigEndian(r[(pos + 16)..]);
            names.Add(new NetBiosName(name, suffix, (flags & 0x8000) != 0));
        }

        PhysicalAddress? mac = pos + 6 <= r.Length ? new PhysicalAddress(r.Slice(pos, 6).ToArray()) : null;
        var computer = names.FirstOrDefault(n => !n.IsGroup && n.Suffix == 0x00)?.Name ?? names.FirstOrDefault(n => !n.IsGroup && n.Suffix == 0x20)?.Name;
        var domain = names.FirstOrDefault(n => n.IsGroup && n.Suffix == 0x00)?.Name;
        var user = names.FirstOrDefault(n => !n.IsGroup && n.Suffix == 0x03 && !string.Equals(n.Name, computer, StringComparison.OrdinalIgnoreCase))?.Name;
        return new NetBiosInfo(computer, domain, user, mac, names);
    }

    private static int SkipName(ReadOnlySpan<byte> r, int pos)
    {
        while (pos >= 0 && pos < r.Length)
        {
            var len = r[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2;
            pos += 1 + len;
        }

        return -1;
    }
}

/// <summary>Protocol-specific UDP probes. Each sends a valid, read-only request; a reply proves the port is open.</summary>
public sealed class UdpServiceProbe : IUdpServiceProbe
{
    public async Task<(PortResult Port, ServiceBanner? Banner)> ProbeAsync(IPAddress address, UdpService service, string snmpCommunity,
        TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(service);
        var request = service.Id switch
        {
            "dns" => DnsVersionQuery(),
            "tftp" => TftpReadRequest(),
            "ntp" => NtpClientRequest(),
            "nbns" => NetBiosProbe.BuildRequest(),
            "snmp" => Snmp.GetRequest(snmpCommunity ?? "public", Snmp.SysDescr),
            "mssql" => [0x02],
            "radius" => RadiusAccessRequest(),
            _ => null,
        };
        if (request is null) return (new PortResult(PortProtocol.Udp, service.Port, PortState.Unsupported, service.Name, "No probe for this service."), null);

        var (reply, state, detail) = await UdpExchange.RunAsync(address, service.Port, request, timeout, cancellationToken).ConfigureAwait(false);
        var port = new PortResult(PortProtocol.Udp, service.Port, state, service.Name, detail);
        if (reply is null) return (port, null);
        var text = Describe(service.Id, reply);
        return (port, text is null ? null : new ServiceBanner(service.Name, PortProtocol.Udp, service.Port, text));
    }

    internal static string? Describe(string id, byte[] r)
    {
        try
        {
            return id switch
            {
                "dns" => DescribeDns(r),
                "tftp" => r.Length >= 4 && r[1] == 5 ? $"TFTP server (error {r[3]}: {Encoding.ASCII.GetString(r, 4, Math.Max(0, r.Length - 5)).TrimEnd('\0')})" : "TFTP server",
                "ntp" => r.Length >= 48 && (r[0] & 0x07) == 4 ? DescribeNtp(r) : "NTP (unexpected reply)",
                "nbns" => NetBiosProbe.Parse(r) is { } nb ? $"NetBIOS {nb.ComputerName}{(nb.Domain is null ? "" : $" ({nb.Domain})")}" : "NetBIOS name service",
                "snmp" => Snmp.ParseStringValue(r) is { } s ? s : "SNMP agent",
                "mssql" => r.Length > 3 && r[0] == 0x05 ? DescribeMssqlBrowser(Encoding.ASCII.GetString(r, 3, r.Length - 3)) : "SQL Server Browser",
                "radius" => r.Length > 0 ? $"RADIUS server (code {r[0]})" : null,
                _ => null,
            };
        }
        catch (Exception ex) when (ex is ArgumentException or IndexOutOfRangeException or FormatException)
        {
            return null;
        }
    }

    private static byte[] DnsVersionQuery()
    {
        var name = "\u0007version\u0004bind\0"u8;
        var q = new byte[12 + name.Length + 4];
        BinaryPrimitives.WriteUInt16BigEndian(q, (ushort)RandomNumberGenerator.GetInt32(1, 65535));
        BinaryPrimitives.WriteUInt16BigEndian(q.AsSpan(4), 1);
        name.CopyTo(q.AsSpan(12));
        BinaryPrimitives.WriteUInt16BigEndian(q.AsSpan(12 + name.Length), 16); // TXT
        BinaryPrimitives.WriteUInt16BigEndian(q.AsSpan(14 + name.Length), 3); // CHAOS
        return q;
    }

    private static string DescribeDns(byte[] r)
    {
        if (r.Length < 12) return "DNS server";
        var rcode = r[3] & 0x0F;
        var answers = BinaryPrimitives.ReadUInt16BigEndian(r.AsSpan(6));
        if (rcode != 0 || answers == 0) return $"DNS server (version hidden, rcode {rcode})";
        // skip question
        var pos = 12;
        while (pos < r.Length && r[pos] != 0) pos += (r[pos] & 0xC0) == 0xC0 ? 1 : r[pos] + 1;
        pos += 5;
        // answer: name (pointer or labels), type, class, ttl, rdlength, txt
        pos += (r[pos] & 0xC0) == 0xC0 ? 2 : SkipLabels(r, pos);
        pos += 10;
        if (pos >= r.Length) return "DNS server";
        var len = r[pos];
        return "DNS " + Encoding.ASCII.GetString(r, pos + 1, Math.Min(len, r.Length - pos - 1));
    }

    private static int SkipLabels(byte[] r, int pos)
    {
        var start = pos;
        while (pos < r.Length && r[pos] != 0) pos += r[pos] + 1;
        return pos - start + 1;
    }

    private static byte[] TftpReadRequest()
    {
        var file = $"ipmaster-probe-{RandomNumberGenerator.GetHexString(8, true)}";
        var b = new List<byte> { 0, 1 };
        b.AddRange(Encoding.ASCII.GetBytes(file));
        b.Add(0);
        b.AddRange("octet"u8.ToArray());
        b.Add(0);
        return b.ToArray();
    }

    private static byte[] NtpClientRequest()
    {
        var p = new byte[48];
        p[0] = 0x23; // LI 0, VN 4, mode 3 (client)
        return p;
    }

    private static string DescribeNtp(byte[] r)
    {
        var version = (r[0] >> 3) & 0x07;
        var stratum = r[1];
        var refid = stratum <= 1
            ? Encoding.ASCII.GetString(r, 12, 4).TrimEnd('\0')
            : new IPAddress(r.AsSpan(12, 4)).ToString();
        return string.Create(CultureInfo.InvariantCulture, $"NTP v{version}, stratum {stratum}, reference {refid}");
    }

    private static string DescribeMssqlBrowser(string s)
    {
        var instances = new List<string>();
        foreach (var block in s.Split(";;", StringSplitOptions.RemoveEmptyEntries))
        {
            var f = block.Split(';');
            string? Get(string key)
            {
                var i = Array.FindIndex(f, x => string.Equals(x, key, StringComparison.OrdinalIgnoreCase));
                return i >= 0 && i + 1 < f.Length ? f[i + 1] : null;
            }

            instances.Add($"{Get("InstanceName")} {Get("Version")}" + (Get("tcp") is { } tcp ? $" (tcp {tcp})" : ""));
        }

        return "SQL Server " + string.Join("; ", instances);
    }

    private static byte[] RadiusAccessRequest()
    {
        // Access-Request with only a User-Name attribute. Servers silently drop requests from unknown clients,
        // so silence is reported as open|filtered, never as open.
        var user = "ipmaster-probe"u8;
        var len = 20 + 2 + user.Length;
        var p = new byte[len];
        p[0] = 1;
        p[1] = (byte)RandomNumberGenerator.GetInt32(0, 256);
        BinaryPrimitives.WriteUInt16BigEndian(p.AsSpan(2), (ushort)len);
        RandomNumberGenerator.Fill(p.AsSpan(4, 16));
        p[20] = 1;
        p[21] = (byte)(2 + user.Length);
        user.CopyTo(p.AsSpan(22));
        return p;
    }
}

/// <summary>Minimal SNMPv1/v2c BER encoding for the sysDescr banner probe.</summary>
internal static class Snmp
{
    public static readonly byte[] SysDescr = [0x2B, 6, 1, 2, 1, 1, 1, 0]; // 1.3.6.1.2.1.1.1.0

    public static byte[] GetRequest(string community, byte[] oid)
    {
        var varbind = Tlv(0x30, [.. Tlv(0x06, oid), .. Tlv(0x05, [])]);
        var pdu = Tlv(0xA0, [.. Int(RandomNumberGenerator.GetInt32(1, int.MaxValue)), .. Int(0), .. Int(0), .. Tlv(0x30, varbind)]);
        return Tlv(0x30, [.. Int(1), .. Tlv(0x04, Encoding.UTF8.GetBytes(community)), .. pdu]);
    }

    private static byte[] Int(int v)
    {
        var bytes = new List<byte>();
        var x = v;
        do
        {
            bytes.Insert(0, (byte)(x & 0xFF));
            x >>= 8;
        }
        while (x != 0);
        if ((bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
        return Tlv(0x02, bytes.ToArray());
    }

    private static byte[] Tlv(byte tag, byte[] value)
    {
        var len = value.Length;
        byte[] lenBytes = len < 0x80 ? [(byte)len] : len < 0x100 ? [0x81, (byte)len] : [0x82, (byte)(len >> 8), (byte)len];
        return [tag, .. lenBytes, .. value];
    }

    /// <summary>Returns the first OCTET STRING varbind value of a GetResponse, or null.</summary>
    public static string? ParseStringValue(ReadOnlySpan<byte> r)
    {
        // Walk: SEQ { INT version, OCTET community, PDU { INT, INT errorStatus, INT, SEQ { SEQ { OID, value } } } }
        var pos = 0;
        if (!Enter(r, ref pos, 0x30)) return null;
        Skip(r, ref pos); // version
        Skip(r, ref pos); // community
        if (pos >= r.Length || r[pos] != 0xA2) return null;
        Enter(r, ref pos, 0xA2);
        Skip(r, ref pos);
        var errorStart = pos;
        Skip(r, ref pos);
        if (r[errorStart + 2] != 0) return null; // error-status
        Skip(r, ref pos);
        if (!Enter(r, ref pos, 0x30) || !Enter(r, ref pos, 0x30)) return null;
        Skip(r, ref pos); // oid
        if (pos >= r.Length || r[pos] != 0x04) return null;
        var (start, len) = Header(r, ref pos);
        return Encoding.UTF8.GetString(r.Slice(start, len)).Replace("\r", " ", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal).Trim();
    }

    private static (int Start, int Length) Header(ReadOnlySpan<byte> r, ref int pos)
    {
        pos++; // tag
        int len = r[pos++];
        if ((len & 0x80) != 0)
        {
            var n = len & 0x7F;
            len = 0;
            for (var i = 0; i < n; i++) len = (len << 8) | r[pos++];
        }

        return (pos, len);
    }

    private static bool Enter(ReadOnlySpan<byte> r, ref int pos, byte tag)
    {
        if (pos >= r.Length || r[pos] != tag) return false;
        Header(r, ref pos);
        return true;
    }

    private static void Skip(ReadOnlySpan<byte> r, ref int pos)
    {
        var (start, len) = Header(r, ref pos);
        pos = start + len;
    }
}
