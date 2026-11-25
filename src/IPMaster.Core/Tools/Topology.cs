using System.Globalization;
using System.Net;
using System.Text;

namespace IPMaster.Core.Tools;

/// <summary>One value of a MIB walk, library-neutral (D-092).</summary>
public sealed record MibValue(string Oid, string Text, byte[]? Octets = null, ulong? Number = null);

public enum NeighborProtocol
{
    Lldp,
    Cdp,
}

/// <summary>One neighbour entry as a device reports it: "on my port X I see device Y, port Z".</summary>
public sealed record NeighborEntry(NeighborProtocol Protocol, string LocalPort, string RemoteDeviceId, string RemoteName, string RemotePort, string RemotePortDescription,
    string RemoteDescription, IReadOnlyList<IPAddress> ManagementAddresses, string Capabilities);

/// <summary>What one queried device says about itself and its neighbours.</summary>
public sealed record DeviceReport(string Address, string Name, string ChassisId, IReadOnlyList<NeighborEntry> Neighbors, string? Error = null);

/// <summary>Parses LLDP-MIB (IEEE 802.1AB) and CISCO-CDP-MIB walk results (D-092). Malformed rows are skipped.</summary>
public static class NeighborParsers
{
    public const string LldpLocChassisId = "1.0.8802.1.1.2.1.3.2.0";
    public const string LldpLocChassisSubtype = "1.0.8802.1.1.2.1.3.1.0";
    public const string LldpLocSysName = "1.0.8802.1.1.2.1.3.3.0";
    public const string LldpLocPortTable = "1.0.8802.1.1.2.1.3.7.1";
    public const string LldpRemTable = "1.0.8802.1.1.2.1.4.1.1";
    public const string LldpRemManAddrTable = "1.0.8802.1.1.2.1.4.2.1";
    public const string CdpCacheTable = "1.3.6.1.4.1.9.9.23.1.2.1.1";
    public const string IfName = "1.3.6.1.2.1.31.1.1.1.1";
    public const string IfDescr = "1.3.6.1.2.1.2.2.1.2";

    /// <summary>LLDP neighbours; <paramref name="values"/> holds the local port table, the remote table and the management address table.</summary>
    public static IReadOnlyList<NeighborEntry> Lldp(IEnumerable<MibValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var list = values.ToList();
        // lldpLocPortTable: column.portNum → port id (3) / description (4)
        var localPorts = Rows(list, LldpLocPortTable, 1);
        var remote = Rows(list, LldpRemTable, 3); // index: timeMark.localPortNum.remIndex
        var manAddr = new Dictionary<string, List<IPAddress>>(StringComparer.Ordinal);
        foreach (var v in list.Where(v => v.Oid.StartsWith(LldpRemManAddrTable + ".", StringComparison.Ordinal)))
        {
            // index: column.timeMark.localPortNum.remIndex.addrSubtype.addrLen.addr...
            var arcs = v.Oid[(LldpRemManAddrTable.Length + 1)..].Split('.');
            if (arcs.Length < 6 || !int.TryParse(arcs[4], CultureInfo.InvariantCulture, out var subtype) || !int.TryParse(arcs[5], CultureInfo.InvariantCulture, out var len)) continue;
            if (arcs.Length < 6 + len) continue;
            var bytes = arcs.Skip(6).Take(len).Select(a => byte.TryParse(a, CultureInfo.InvariantCulture, out var b) ? b : (byte)0).ToArray();
            IPAddress? ip = (subtype, len) switch { (1, 4) => new IPAddress(bytes), (2, 16) => new IPAddress(bytes), _ => null };
            if (ip is null) continue;
            var key = string.Join('.', arcs[1..4]);
            if (!manAddr.TryGetValue(key, out var l)) manAddr[key] = l = [];
            if (!l.Contains(ip)) l.Add(ip);
        }

        var result = new List<NeighborEntry>();
        foreach (var (index, row) in remote)
        {
            var arcs = index.Split('.');
            if (arcs.Length != 3) continue;
            var localPortNum = arcs[1];
            var localPort = localPorts.TryGetValue(localPortNum, out var lp)
                ? FirstText(lp, 4) is { Length: > 0 } d ? d : PortId(lp.GetValueOrDefault("2"), lp.GetValueOrDefault("3"))
                : "port " + localPortNum;
            var chassis = ChassisId(row.GetValueOrDefault("4"), row.GetValueOrDefault("5"));
            var name = FirstText(row, 9);
            if (chassis.Length == 0 && name.Length == 0) continue;
            result.Add(new NeighborEntry(NeighborProtocol.Lldp, localPort, chassis, name, PortId(row.GetValueOrDefault("6"), row.GetValueOrDefault("7")), FirstText(row, 8),
                FirstText(row, 10), manAddr.GetValueOrDefault(index) ?? [], Capabilities(row.GetValueOrDefault("12"))));
        }

        return result;
    }

    /// <summary>CDP neighbours; <paramref name="ifNames"/> maps ifIndex to a local port name (ifName or ifDescr).</summary>
    public static IReadOnlyList<NeighborEntry> Cdp(IEnumerable<MibValue> values, IReadOnlyDictionary<string, string> ifNames)
    {
        ArgumentNullException.ThrowIfNull(values);
        ArgumentNullException.ThrowIfNull(ifNames);
        var result = new List<NeighborEntry>();
        foreach (var (index, row) in Rows(values.ToList(), CdpCacheTable, 2)) // index: ifIndex.deviceIndex
        {
            var ifIndex = index.Split('.')[0];
            var deviceId = FirstText(row, 6);
            if (deviceId.Length == 0) continue;
            var addresses = new List<IPAddress>();
            if (row.GetValueOrDefault("3")?.Number == 1 && row.GetValueOrDefault("4")?.Octets is { Length: 4 } a) addresses.Add(new IPAddress(a)); // cdpCacheAddressType ip(1)
            result.Add(new NeighborEntry(NeighborProtocol.Cdp, ifNames.GetValueOrDefault(ifIndex) ?? "ifIndex " + ifIndex, deviceId, deviceId, FirstText(row, 7), "",
                FirstText(row, 8), addresses, ""));
        }

        return result;
    }

    /// <summary>Chassis ID by subtype (LLDP-MIB LldpChassisIdSubtype): MAC address (4) as aa:bb:…, network address (5), else text.</summary>
    public static string ChassisId(MibValue? subtype, MibValue? id) => subtype?.Number switch
    {
        4 when id?.Octets is { Length: 6 } mac => Mac(mac),
        5 when id?.Octets is { Length: 5 or 17 } addr => new IPAddress(addr[1..]).ToString(),
        _ => Text(id),
    };

    /// <summary>Port ID by subtype (LldpPortIdSubtype): MAC (3) as aa:bb:…, network address (4), else text (ifName, ifAlias, local).</summary>
    public static string PortId(MibValue? subtype, MibValue? id) => subtype?.Number switch
    {
        3 when id?.Octets is { Length: 6 } mac => Mac(mac),
        4 when id?.Octets is { Length: 5 or 17 } addr => new IPAddress(addr[1..]).ToString(),
        _ => Text(id),
    };

    private static string Capabilities(MibValue? v)
    {
        if (v?.Octets is not { Length: > 0 } b) return "";
        string[] names = ["other", "repeater", "bridge", "WLAN AP", "router", "telephone", "DOCSIS", "station"];
        return string.Join(", ", names.Where((_, i) => (b[0] & (0x80 >> i)) != 0));
    }

    private static string Mac(byte[] b) => string.Join(':', b.Select(x => x.ToString("x2", CultureInfo.InvariantCulture)));

    private static string Text(MibValue? v)
    {
        if (v is null) return "";
        if (v.Octets is { } o && o.Any(c => c is < 0x20 and not (9 or 10 or 13) || c >= 0x7F)) return Convert.ToHexString(o); // binary
        return (v.Octets is { } t ? Encoding.UTF8.GetString(t) : v.Text).Trim('\0', ' ');
    }

    private static string FirstText(Dictionary<string, MibValue> row, int column) => Text(row.GetValueOrDefault(column.ToString(CultureInfo.InvariantCulture)));

    /// <summary>Table rows: index (the arcs after the column) → column → value.</summary>
    private static Dictionary<string, Dictionary<string, MibValue>> Rows(List<MibValue> values, string table, int indexArcs)
    {
        var rows = new Dictionary<string, Dictionary<string, MibValue>>(StringComparer.Ordinal);
        foreach (var v in values.Where(v => v.Oid.StartsWith(table + ".", StringComparison.Ordinal)))
        {
            var arcs = v.Oid[(table.Length + 1)..].Split('.');
            if (arcs.Length != indexArcs + 1) continue;
            var index = string.Join('.', arcs[1..]);
            if (!rows.TryGetValue(index, out var row)) rows[index] = row = new Dictionary<string, MibValue>(StringComparer.Ordinal);
            row[arcs[0]] = v;
        }

        return rows;
    }
}

public enum LinkEvidence
{
    /// <summary>Both devices list each other on these ports.</summary>
    BothEnds,

    /// <summary>One device lists the other; the other was queried but does not list this link (or was not queried).</summary>
    OneEnd,
}

public enum NodeState
{
    Queried,
    QueryFailed,

    /// <summary>Known only from a neighbour's table: not queried (no management address, outside the limit, or crawling off).</summary>
    Unresolved,
}

public sealed record TopologyNode(string Id, string Name, string ChassisId, IReadOnlyList<string> Addresses, NodeState State, string Detail)
{
    /// <summary>Name, else chassis ID, else first address.</summary>
    public string Label => Name.Length > 0 ? Name : ChassisId.Length > 0 ? ChassisId : Addresses.FirstOrDefault() ?? Id;
}

public sealed record TopologyLink(string FromNode, string FromPort, string ToNode, string ToPort, NeighborProtocol Protocol, LinkEvidence Evidence);

public sealed record TopologyGraph(IReadOnlyList<TopologyNode> Nodes, IReadOnlyList<TopologyLink> Links);

/// <summary>
/// Builds the topology from device reports (D-092). Nodes are reconciled by chassis ID, else by system name
/// (case-insensitive), else by management address; a link is drawn only where a device reported it. Links reported by
/// both devices are merged and marked <see cref="LinkEvidence.BothEnds"/>. Nothing is inferred beyond the tables.
/// </summary>
public static class TopologyBuilder
{
    public static TopologyGraph Build(IReadOnlyList<DeviceReport> reports)
    {
        ArgumentNullException.ThrowIfNull(reports);
        var nodes = new List<(string Id, string Name, string Chassis, HashSet<string> Addresses, NodeState State, string Detail)>();

        int Find(string chassis, string name, IEnumerable<string> addresses)
        {
            var addr = addresses.ToHashSet(StringComparer.Ordinal);
            var i = chassis.Length > 0 ? nodes.FindIndex(n => n.Chassis.Equals(chassis, StringComparison.OrdinalIgnoreCase)) : -1;
            // a shared name or address (VRRP, NAT, default names) never merges two devices with different known chassis IDs
            bool Compatible((string Id, string Name, string Chassis, HashSet<string> Addresses, NodeState State, string Detail) n) =>
                n.Chassis.Length == 0 || chassis.Length == 0 || n.Chassis.Equals(chassis, StringComparison.OrdinalIgnoreCase);
            if (i < 0 && name.Length > 0) i = nodes.FindIndex(n => Compatible(n) && n.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (i < 0 && addr.Count > 0) i = nodes.FindIndex(n => Compatible(n) && n.Addresses.Overlaps(addr));
            return i;
        }

        int Upsert(string chassis, string name, IEnumerable<string> addresses, NodeState state, string detail)
        {
            var i = Find(chassis, name, addresses);
            if (i < 0)
            {
                nodes.Add(($"n{nodes.Count + 1}", name, chassis, addresses.ToHashSet(StringComparer.Ordinal), state, detail));
                return nodes.Count - 1;
            }

            var n = nodes[i];
            n.Addresses.UnionWith(addresses);
            nodes[i] = (n.Id, n.Name.Length > 0 ? n.Name : name, n.Chassis.Length > 0 ? n.Chassis : chassis, n.Addresses,
                state == NodeState.Unresolved ? n.State : n.State == NodeState.Queried ? n.State : state, n.Detail.Length > 0 ? n.Detail : detail);
            return i;
        }

        // queried devices first, so their own identity wins
        var self = reports.Select(r => Upsert(r.ChassisId, r.Name, [r.Address], r.Error is null ? NodeState.Queried : NodeState.QueryFailed, r.Error ?? "")).ToList();
        var raw = new List<(int From, string FromPort, int To, string ToPort, NeighborProtocol Protocol)>();
        for (var k = 0; k < reports.Count; k++)
        {
            foreach (var e in reports[k].Neighbors)
            {
                var to = Upsert(e.RemoteDeviceId, e.RemoteName, e.ManagementAddresses.Select(a => a.ToString()), NodeState.Unresolved, e.RemoteDescription);
                if (to != self[k]) raw.Add((self[k], e.LocalPort, to, e.RemotePort, e.Protocol));
            }
        }

        var links = new List<TopologyLink>();
        var used = new bool[raw.Count];
        for (var i = 0; i < raw.Count; i++)
        {
            if (used[i]) continue;
            var a = raw[i];
            var back = -1;
            for (var j = i + 1; j < raw.Count && back < 0; j++)
            {
                var b = raw[j];
                if (!used[j] && b.From == a.To && b.To == a.From && Same(b.FromPort, a.ToPort) && Same(b.ToPort, a.FromPort)) back = j;
            }

            if (back >= 0) used[back] = true;
            var duplicate = links.Any(l => l.FromNode == nodes[a.From].Id && l.ToNode == nodes[a.To].Id && l.FromPort == a.FromPort && l.ToPort == a.ToPort);
            if (!duplicate) links.Add(new TopologyLink(nodes[a.From].Id, a.FromPort, nodes[a.To].Id, a.ToPort, a.Protocol, back >= 0 ? LinkEvidence.BothEnds : LinkEvidence.OneEnd));
        }

        return new TopologyGraph(nodes.Select(n => new TopologyNode(n.Id, n.Name, n.Chassis, n.Addresses.Order(StringComparer.Ordinal).ToList(), n.State, n.Detail)).ToList(), links);
    }

    /// <summary>Port names differ between ends (ifDescr "GigabitEthernet1/0/1" vs ifName "Gi1/0/1"); compare loosely.</summary>
    private static bool Same(string a, string b)
    {
        if (a.Equals(b, StringComparison.OrdinalIgnoreCase)) return true;
        static string Short(string s) => new string(s.Where(char.IsLetter).Take(2).ToArray()).ToLowerInvariant() + new string(s.SkipWhile(c => !char.IsDigit(c)).ToArray());
        return Short(a).Length > 2 && Short(a) == Short(b);
    }

    /// <summary>Graphviz DOT: solid = seen from both ends, dashed = one end; unresolved nodes dashed.</summary>
    public static string ToDot(TopologyGraph g)
    {
        ArgumentNullException.ThrowIfNull(g);
        static string E(string s) => s.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("\"", "\\\"", StringComparison.Ordinal);
        static string Q(string s) => "\"" + E(s) + "\"";
        var sb = new StringBuilder("graph topology {\n  node [shape=box];\n");
        foreach (var n in g.Nodes)
        {
            // parts escaped first, then joined with DOT's own line break
            var label = E(n.Label) + (n.Addresses.Count > 0 ? "\\n" + E(string.Join(", ", n.Addresses)) : "");
            sb.Append(CultureInfo.InvariantCulture, $"  {n.Id} [label=\"{label}\"{(n.State == NodeState.Queried ? "" : ", style=dashed")}];\n");
        }

        foreach (var l in g.Links)
        {
            sb.Append(CultureInfo.InvariantCulture, $"  {l.FromNode} -- {l.ToNode} [taillabel={Q(l.FromPort)}, headlabel={Q(l.ToPort)}{(l.Evidence == LinkEvidence.BothEnds ? "" : ", style=dashed")}];\n");
        }

        return sb.Append("}\n").ToString();
    }
}
