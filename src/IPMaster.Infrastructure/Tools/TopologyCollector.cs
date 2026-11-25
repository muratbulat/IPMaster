using System.Net;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Infrastructure.Tools;

/// <summary>
/// LLDP / CDP Topology Explorer data collection (D-092), read-only SNMP: per device sysName, the LLDP local identity and
/// the LLDP-MIB and CISCO-CDP-MIB neighbour tables. Exploration is breadth-first from the seeds, one device at a time,
/// at most <c>maxDevices</c>; neighbours' management addresses are followed only when asked.
/// </summary>
public static class TopologyCollector
{
    public const int MaxWalkItems = 5000;
    public const int MaxDevicesLimit = 200;
    private const string SysName = "1.3.6.1.2.1.1.5.0";

    public static async Task<DeviceReport> CollectAsync(SnmpTarget target, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        var address = target.Endpoint.Address.ToString();
        try
        {
            using var get = CancellationTokenSource.CreateLinkedTokenSource(ct);
            get.CancelAfter(timeout);
            var ids = await SnmpClient.RequestAsync(target, [SysName, NeighborParsers.LldpLocChassisSubtype, NeighborParsers.LldpLocChassisId, NeighborParsers.LldpLocSysName],
                SnmpPduKind.Get, get.Token).ConfigureAwait(false);
            MibValue? Id(string oid) => ids.FirstOrDefault(v => v.Oid == oid) is { IsMissing: false } v ? Mib(v) : null;
            var name = Id(SysName)?.Text.Trim() is { Length: > 0 } n ? n : Id(NeighborParsers.LldpLocSysName)?.Text.Trim() ?? "";
            var chassis = NeighborParsers.ChassisId(Id(NeighborParsers.LldpLocChassisSubtype), Id(NeighborParsers.LldpLocChassisId));

            async Task<List<MibValue>> Walk(string root)
            {
                using var w = CancellationTokenSource.CreateLinkedTokenSource(ct);
                w.CancelAfter(timeout * 10);
                return (await SnmpClient.WalkAsync(target, root, w.Token, MaxWalkItems).ConfigureAwait(false)).Where(v => !v.IsMissing).Select(Mib).ToList();
            }

            var lldp = new List<MibValue>();
            foreach (var root in new[] { NeighborParsers.LldpLocPortTable, NeighborParsers.LldpRemTable, NeighborParsers.LldpRemManAddrTable }) lldp.AddRange(await Walk(root).ConfigureAwait(false));
            var neighbors = NeighborParsers.Lldp(lldp).ToList();
            var cdp = await Walk(NeighborParsers.CdpCacheTable).ConfigureAwait(false);
            if (cdp.Count > 0)
            {
                var names = (await Walk(NeighborParsers.IfName).ConfigureAwait(false)).Concat(await Walk(NeighborParsers.IfDescr).ConfigureAwait(false))
                    .GroupBy(v => v.Oid[(v.Oid.LastIndexOf('.') + 1)..]).ToDictionary(g => g.Key, g => g.First().Text.Trim());
                neighbors.AddRange(NeighborParsers.Cdp(cdp, names));
            }

            return new DeviceReport(address, name, chassis, neighbors);
        }
        catch (Exception ex) when (ex is SnmpException || (ex is OperationCanceledException && !ct.IsCancellationRequested))
        {
            return new DeviceReport(address, "", "", [], SnmpInterfaceMonitor.Explain(ex, target, timeout));
        }
    }

    /// <summary>Queries the seeds and, when <paramref name="follow"/>, the IPv4 management addresses their neighbours advertise.</summary>
    public static async Task<IReadOnlyList<DeviceReport>> ExploreAsync(IReadOnlyList<IPAddress> seeds, Func<IPAddress, SnmpTarget> targetFor, bool follow, int maxDevices,
        TimeSpan timeout, Action<DeviceReport>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(seeds);
        ArgumentNullException.ThrowIfNull(targetFor);
        var limit = Math.Clamp(maxDevices, 1, MaxDevicesLimit);
        var queue = new Queue<IPAddress>(seeds.Distinct());
        var seen = new HashSet<IPAddress>(seeds);
        var reports = new List<DeviceReport>();
        while (queue.Count > 0 && reports.Count < limit)
        {
            ct.ThrowIfCancellationRequested();
            var report = await CollectAsync(targetFor(queue.Dequeue()), timeout, ct).ConfigureAwait(false);
            reports.Add(report);
            progress?.Invoke(report);
            if (!follow) continue;
            foreach (var a in report.Neighbors.SelectMany(n => n.ManagementAddresses).Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork))
            {
                if (seen.Add(a)) queue.Enqueue(a);
            }
        }

        return reports;
    }

    private static MibValue Mib(SnmpValue v) => new(v.Oid, v.Text, v.Octets, SnmpInterfaceMonitor.Number(v));
}
