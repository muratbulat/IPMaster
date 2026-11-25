using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;
using Lextm.SharpSnmpLib;

namespace IPMaster.Infrastructure.Tools;

/// <summary>One IF-MIB interface as discovered (D-091).</summary>
public sealed record SnmpInterface(int Index, string Name, string Description, string Alias, string Mac, ulong SpeedBitsPerSecond, string AdminStatus,
    string OperStatus, bool HighCapacity)
{
    public string Label => Name.Length > 0 ? Name : Description.Length > 0 ? Description : "if" + Index;
}

/// <summary>
/// SNMP Interface Monitor (D-091), read-only: walks IF-MIB (ifTable, ifXTable) and polls counters with GET through the
/// existing <see cref="SnmpClient"/> (v1, v2c, v3). 64-bit ifHC* counters where the agent has them (never on v1), else
/// the 32-bit ones. Every request carries sysUpTime.0 so rates use the agent's clock. Bounded: at most
/// <see cref="MaxInterfaces"/> interfaces, at most 31 values per request.
/// </summary>
public static class SnmpInterfaceMonitor
{
    public const int MaxInterfaces = 1024;
    private const string IfTable = "1.3.6.1.2.1.2.2.1";
    private const string IfX = "1.3.6.1.2.1.31.1.1.1";
    private const string SysUpTime = "1.3.6.1.2.1.1.3.0";
    private const int PerRequest = SnmpTester.MaxOidsPerRequest - 1; // + sysUpTime

    public static async Task<IReadOnlyList<SnmpInterface>> DiscoverAsync(SnmpTarget target, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        async Task<Dictionary<int, SnmpValue>> Column(string table, int column)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout * 10); // a walk is many requests
            var root = $"{table}.{column}";
            var values = await SnmpClient.WalkAsync(target, root, cts.Token, MaxInterfaces).ConfigureAwait(false);
            return values.Where(v => !v.IsMissing && v.Oid.StartsWith(root + ".", StringComparison.Ordinal))
                .Select(v => (Index: int.TryParse(v.Oid[(root.Length + 1)..], out var i) ? i : -1, v)).Where(x => x.Index >= 0)
                .GroupBy(x => x.Index).ToDictionary(g => g.Key, g => g.First().v);
        }

        var descr = await Column(IfTable, 2).ConfigureAwait(false);
        if (descr.Count == 0) throw new Queries.SnmpException("The agent returned no IF-MIB interfaces (ifTable is empty or not visible to this community/user).");
        var speed = await Column(IfTable, 5).ConfigureAwait(false);
        var mac = await Column(IfTable, 6).ConfigureAwait(false);
        var admin = await Column(IfTable, 7).ConfigureAwait(false);
        var oper = await Column(IfTable, 8).ConfigureAwait(false);
        var v1 = target.Version == Core.Queries.SnmpVersion.V1;
        var name = v1 ? [] : await Column(IfX, 1).ConfigureAwait(false);
        var highSpeed = v1 ? [] : await Column(IfX, 15).ConfigureAwait(false);
        var alias = v1 ? [] : await Column(IfX, 18).ConfigureAwait(false);
        var hc = v1 ? [] : await Column(IfX, 6).ConfigureAwait(false);
        return descr.Keys.Order().Take(MaxInterfaces).Select(i => new SnmpInterface(i,
            Text(name, i), Text(descr, i), Text(alias, i),
            mac.TryGetValue(i, out var m) && m.Octets is { Length: 6 } o ? Convert.ToHexString(o).Chunk(2).Select(c => new string(c)).Aggregate((a, b) => a + "-" + b) : "",
            Number(highSpeed.GetValueOrDefault(i)) is { } hs && hs > 0 ? hs * 1_000_000 : Number(speed.GetValueOrDefault(i)) ?? 0,
            Status(Number(admin.GetValueOrDefault(i))), Status(Number(oper.GetValueOrDefault(i))), hc.ContainsKey(i))).ToList();
    }

    /// <summary>One reading of every given interface. Values the agent does not return stay null.</summary>
    public static async Task<IReadOnlyList<InterfaceCounters>> PollAsync(SnmpTarget target, IReadOnlyList<SnmpInterface> interfaces, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(interfaces);
        var oids = interfaces.SelectMany(OidsFor).ToList();
        var values = new Dictionary<string, SnmpValue>(StringComparer.Ordinal);
        var upTimes = new Dictionary<string, uint?>(StringComparer.Ordinal);
        var arrived = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal);
        foreach (var batch in oids.Chunk(PerRequest))
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            var reply = await SnmpClient.RequestAsync(target, [SysUpTime, .. batch], SnmpPduKind.Get, cts.Token).ConfigureAwait(false);
            var now = DateTimeOffset.UtcNow;
            var up = reply.FirstOrDefault(v => v.Oid == SysUpTime) is { IsMissing: false } u ? (uint?)Number(u) : null;
            foreach (var v in reply.Where(v => v.Oid != SysUpTime))
            {
                values[v.Oid] = v;
                upTimes[v.Oid] = up;
                arrived[v.Oid] = now;
            }
        }

        ulong? Get(string oid) => values.TryGetValue(oid, out var v) && !v.IsMissing ? Number(v) : null;
        return interfaces.Select(i =>
        {
            var (inOct, outOct) = Octets(i);
            return new InterfaceCounters
            {
                Index = i.Index, At = arrived.GetValueOrDefault(inOct, DateTimeOffset.UtcNow), UpTime = upTimes.GetValueOrDefault(inOct), HighCapacity = i.HighCapacity,
                InOctets = Get(inOct), OutOctets = Get(outOct), InErrors = Get($"{IfTable}.14.{i.Index}"), OutErrors = Get($"{IfTable}.20.{i.Index}"),
                InDiscards = Get($"{IfTable}.13.{i.Index}"), OutDiscards = Get($"{IfTable}.19.{i.Index}"), SpeedBitsPerSecond = i.SpeedBitsPerSecond,
                OperStatus = Status(Get($"{IfTable}.8.{i.Index}")),
            };
        }).ToList();
    }

    private static (string In, string Out) Octets(SnmpInterface i) =>
        i.HighCapacity ? ($"{IfX}.6.{i.Index}", $"{IfX}.10.{i.Index}") : ($"{IfTable}.10.{i.Index}", $"{IfTable}.16.{i.Index}");

    /// <summary>The octet pair first, so one request carries both with the same sysUpTime.</summary>
    private static IEnumerable<string> OidsFor(SnmpInterface i)
    {
        var (inOct, outOct) = Octets(i);
        return [inOct, outOct, $"{IfTable}.14.{i.Index}", $"{IfTable}.20.{i.Index}", $"{IfTable}.13.{i.Index}", $"{IfTable}.19.{i.Index}", $"{IfTable}.8.{i.Index}"];
    }

    /// <summary>A failed request in words. No answer covers a timeout, a closed port and, on v1/v2c, a wrong community (agents stay silent).</summary>
    public static string Explain(Exception ex, SnmpTarget target, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(ex);
        ArgumentNullException.ThrowIfNull(target);
        if (ex is not (OperationCanceledException or Queries.SnmpException { State: Core.Scanning.ObservationState.NoResponse })) return ex.Message;
        var detail = ex is Queries.SnmpException { Message.Length: > 0 } s ? $" ({s.Message.TrimEnd('.')})" : "";
        return $"No answer from {target.Endpoint} within {timeout.TotalSeconds:0.#} s{detail}."
               + (target.Version == Core.Queries.SnmpVersion.V3 ? "" : " SNMPv1/v2c agents stay silent for a wrong community, so this can also mean the community is not accepted.");
    }

    public static ulong? Number(SnmpValue? v) => v?.Data switch
    {
        Counter64 c => c.ToUInt64(),
        Counter32 c => c.ToUInt32(),
        Gauge32 g => g.ToUInt32(),
        TimeTicks t => t.ToUInt32(),
        Integer32 i => i.ToInt32() >= 0 ? (ulong)i.ToInt32() : null,
        _ => null,
    };

    private static string Text(Dictionary<int, SnmpValue> column, int index) => column.TryGetValue(index, out var v) ? v.Text.Trim() : "";

    public static string Status(ulong? value) => value switch
    {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "notPresent",
        7 => "lowerLayerDown",
        null => "",
        _ => value.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };
}
