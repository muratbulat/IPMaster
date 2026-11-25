using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Queries;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Tools;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;

namespace IPMaster.Tests;

/// <summary>Scriptable SNMPv1/v2c agent on loopback that can misbehave (repeat or go backwards). Test-only.</summary>
public sealed class SnmpLabAgent : IAsyncDisposable
{
    public enum Fault
    {
        None,
        RepeatOid,
        GoBackwards,
        Silent,
    }

    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _cts = new();
    private readonly SortedDictionary<ObjectIdentifier, ISnmpData> _data;
    private readonly Task _loop;

    public SnmpLabAgent(string community, Dictionary<string, ISnmpData> data, Fault fault = Fault.None)
    {
        _data = new(data.ToDictionary(kv => new ObjectIdentifier(kv.Key), kv => kv.Value));
        _loop = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try
                {
                    r = await _udp.ReceiveAsync(_cts.Token);
                }
                catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
                {
                    return;
                }

                var m = MessageFactory.ParseMessages(r.Buffer, new UserRegistry())[0];
                Pdus.Enqueue(m.TypeCode());
                if (fault == Fault.Silent || m.Parameters.UserName.ToString() != community) continue;
                var vars = m.Pdu().Variables;
                IList<Variable> resp;
                switch (m.TypeCode())
                {
                    case SnmpType.GetRequestPdu:
                        resp = vars.Select(v => new Variable(v.Id, _data.TryGetValue(v.Id, out var d) ? d : new NoSuchObject())).ToList();
                        break;
                    case SnmpType.GetBulkRequestPdu:
                        var max = m.Pdu().ErrorIndex.ToInt32(); // SharpSnmpLib keeps max-repetitions here
                        MaxRepetitionsSeen.Enqueue(max);
                        resp = Next(vars[0].Id, max, fault);
                        break;
                    case SnmpType.GetNextRequestPdu:
                        resp = Next(vars[0].Id, 1, fault);
                        break;
                    default:
                        continue; // SET or anything else: never answered (and must never be sent)
                }

                var reply = new ResponseMessage(m.RequestId(), m.Version, m.Parameters.UserName, ErrorCode.NoError, 0, resp);
                await _udp.SendAsync(reply.ToBytes(), r.RemoteEndPoint);
            }
        });
    }

    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

    /// <summary>Changes a value between requests (counters that advance, reset or wrap). Call only while no request is in flight.</summary>
    public void Set(string oid, ISnmpData value) => _data[new ObjectIdentifier(oid)] = value;

    public ConcurrentQueue<SnmpType> Pdus { get; } = new();

    public ConcurrentQueue<int> MaxRepetitionsSeen { get; } = new();

    private List<Variable> Next(ObjectIdentifier after, int count, Fault fault)
    {
        if (fault == Fault.RepeatOid && _data.TryGetValue(after, out var same)) return [new Variable(after, same)];
        if (fault == Fault.GoBackwards && _data.Keys.FirstOrDefault(k => k.CompareTo(after) < 0 && k.ToString().StartsWith("1.3.6.1.2.1.2.2.1.2.", StringComparison.Ordinal)) is { } back)
        {
            return [new Variable(back, _data[back])]; // an earlier OID inside the walked subtree
        }
        var list = _data.Where(kv => kv.Key.CompareTo(after) > 0).Take(count).Select(kv => new Variable(kv.Key, kv.Value)).ToList();
        if (list.Count < count) list.Add(new Variable(list.Count > 0 ? list[^1].Id : after, new EndOfMibView()));
        return list;
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _udp.Dispose();
        await _loop;
    }
}

public class NetToolsSnmpTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static Dictionary<string, ISnmpData> Interfaces(int count)
    {
        var d = new Dictionary<string, ISnmpData>
        {
            ["1.3.6.1.2.1.1.1.0"] = new OctetString("Lab switch"),
            ["1.3.6.1.2.1.1.3.0"] = new TimeTicks(8_640_123),
            ["1.3.6.1.2.1.31.1.1.1.6.1"] = new Counter64(18_446_744_073_709_551_615UL),
            ["1.3.6.1.2.1.31.1.1.1.6.2"] = new Counter64(9_007_199_254_740_993UL), // 2^53 + 1: not representable as a double
            ["1.3.6.1.2.1.9.1.0"] = new Integer32(1), // after the walk subtree
        };
        for (var i = 1; i <= count; i++) d[$"1.3.6.1.2.1.2.2.1.2.{i}"] = new OctetString($"port{i}");
        return d;
    }

    private static SnmpTestRequest Req(SnmpLabAgent a, SnmpTestOperation op, string oid, string community = "lab-ro", Core.Queries.SnmpVersion v = Core.Queries.SnmpVersion.V2c) => new()
    {
        Target = new SnmpTarget(new IPEndPoint(IPAddress.Loopback, a.Port), v, [community], "", SnmpSecurity.NoAuthNoPriv, SnmpAuth.Sha1, "", SnmpPriv.Aes128, ""),
        Operation = op, Oids = [oid], Timeout = TimeSpan.FromSeconds(2), Retries = 0,
    };

    [Fact]
    public async Task Get_formats_types_and_keeps_counter64_exact()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(2));
        var r = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Get, "1.3.6.1.2.1.1.1.0") with { Oids = ["1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.31.1.1.1.6.1", "1.3.6.1.2.1.31.1.1.1.6.2"] }, null, Ct);
        Assert.Equal(SnmpTestOutcome.Success, r.Outcome);
        Assert.Equal(("Lab switch", "OCTET STRING"), (r.Rows[0].Value, r.Rows[0].Type));
        Assert.Equal("sysDescr.0", r.Rows[0].Name);
        Assert.Equal("ifHCInOctets.2", r.Rows[3].Name);
        Assert.Equal("8640123 (1d 00:00:01.23)", r.Rows[1].Value);
        Assert.Equal("18446744073709551615", r.Rows[2].Value);
        Assert.Equal("9007199254740993", r.Rows[3].Value);
        Assert.Equal("Counter64", r.Rows[3].Type);
    }

    [Fact]
    public async Task Missing_object_is_no_such_object_not_an_error()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(1));
        var r = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Get, "1.3.6.1.2.1.1.99.0"), null, Ct);
        Assert.Equal(SnmpTestOutcome.NoSuchObject, r.Outcome);
        Assert.Equal("noSuchObject", r.Rows.Single().Type);
    }

    [Fact]
    public async Task Walk_and_bulkwalk_stop_at_the_end_of_the_subtree()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(25));
        var walk = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Walk, "1.3.6.1.2.1.2.2.1.2"), null, Ct);
        Assert.Equal(25, walk.Rows.Count);
        Assert.Equal(SnmpWalkStop.EndOfSubtree, walk.WalkStop);
        Assert.Equal(26, walk.Requests);
        Assert.Equal("port25", walk.Rows[^1].Value);

        var bulk = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.BulkWalk, "1.3.6.1.2.1.2.2.1.2") with { MaxRepetitions = 10 }, null, Ct);
        Assert.Equal(25, bulk.Rows.Count);
        Assert.Equal(3, bulk.Requests);
        Assert.Equal(walk.Rows, bulk.Rows);
        Assert.All(a.MaxRepetitionsSeen, m => Assert.Equal(10, m));
    }

    [Fact]
    public async Task Walk_to_the_end_of_the_mib_and_empty_subtree()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(2));
        var all = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Walk, "1.3"), null, Ct);
        Assert.Equal(SnmpWalkStop.EndOfMibView, all.WalkStop);
        Assert.Equal(Interfaces(2).Count, all.Rows.Count);
        var none = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Walk, "1.3.6.1.2.1.5"), null, Ct);
        Assert.Equal(SnmpTestOutcome.NoSuchObject, none.Outcome);
        Assert.Empty(none.Rows);
    }

    [Fact]
    public async Task Item_limit_bounds_walks()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(50));
        var r = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.BulkWalk, "1.3.6.1.2.1.2.2.1.2") with { MaxItems = 12, MaxRepetitions = 5 }, null, Ct);
        Assert.Equal(12, r.Rows.Count);
        Assert.Equal(SnmpWalkStop.LimitReached, r.WalkStop);
        Assert.Equal([5, 5, 2], a.MaxRepetitionsSeen); // never asks for more than the remaining room
    }

    [Theory]
    [InlineData(SnmpLabAgent.Fault.RepeatOid, SnmpWalkStop.RepeatedOid)]
    [InlineData(SnmpLabAgent.Fault.GoBackwards, SnmpWalkStop.NonIncreasingOid)]
    public async Task Broken_agents_cannot_make_a_walk_loop(SnmpLabAgent.Fault fault, SnmpWalkStop expected)
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(5), fault);
        var r = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Walk, "1.3.6.1.2.1.2.2.1.2"), null, Ct);
        Assert.Equal(expected, r.WalkStop);
        Assert.Equal(SnmpTestOutcome.AgentError, r.Outcome);
        Assert.True(r.Requests < 10);
    }

    [Fact]
    public async Task Wrong_community_times_out_with_an_explanation_and_is_not_retried_with_others()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(1));
        var r = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Get, "1.3.6.1.2.1.1.1.0", community: "public") with { Timeout = TimeSpan.FromMilliseconds(400), Retries = 1 }, null, Ct);
        Assert.Equal(SnmpTestOutcome.Timeout, r.Outcome);
        Assert.Contains("wrong community", r.Detail, StringComparison.Ordinal);
        Assert.Equal(2, r.Requests); // one retry, same community
        Assert.DoesNotContain("public", SnmpTester.Report(Req(a, SnmpTestOperation.Get, "1.3.6.1.2.1.1.1.0", community: "public"), r), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inputs_are_validated_and_no_set_is_ever_sent()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(3));
        Assert.Equal(SnmpTestOutcome.InvalidInput, (await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Get, "sysDescr.0"), null, Ct)).Outcome);
        Assert.Equal(SnmpTestOutcome.InvalidInput, (await SnmpTester.RunAsync(Req(a, SnmpTestOperation.Get, "1.3.6.01"), null, Ct)).Outcome);
        var two = Req(a, SnmpTestOperation.Get, "1.3.6.1.2.1.1.1.0") with { Target = Req(a, SnmpTestOperation.Get, "1").Target with { Communities = ["a", "b"] } };
        Assert.Equal(SnmpTestOutcome.InvalidInput, (await SnmpTester.RunAsync(two, null, Ct)).Outcome);
        foreach (var op in Enum.GetValues<SnmpTestOperation>()) await SnmpTester.RunAsync(Req(a, op, "1.3.6.1.2.1.1"), null, Ct);
        Assert.DoesNotContain(SnmpType.SetRequestPdu, a.Pdus);
        Assert.False(Enum.IsDefined(typeof(SnmpTestOperation), "Set"));
    }

    [Fact]
    public async Task V1_bulk_falls_back_to_getnext_and_cancel_is_reported()
    {
        await using var a = new SnmpLabAgent("lab-ro", Interfaces(3));
        var r = await SnmpTester.RunAsync(Req(a, SnmpTestOperation.BulkWalk, "1.3.6.1.2.1.2.2.1.2", v: Core.Queries.SnmpVersion.V1), null, Ct);
        Assert.Equal(3, r.Rows.Count);
        Assert.DoesNotContain(SnmpType.GetBulkRequestPdu, a.Pdus);

        await using var silent = new SnmpLabAgent("lab-ro", Interfaces(1), SnmpLabAgent.Fault.Silent);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(150);
        var c = await SnmpTester.RunAsync(Req(silent, SnmpTestOperation.Get, "1.3.6.1.2.1.1.1.0") with { Timeout = TimeSpan.FromSeconds(10) }, null, cts.Token);
        Assert.Equal(SnmpTestOutcome.Cancelled, c.Outcome);
    }

    [Fact]
    public void Oid_order_and_walk_rules()
    {
        Assert.True(SnmpOid.Compare("1.3.6.1.2", "1.3.6.1.10") < 0); // numeric, not string order
        Assert.True(SnmpOid.Compare("1.3.6.1.2.1", "1.3.6.1.2") > 0);
        Assert.Equal(0, SnmpOid.Compare(".1.3.6", "1.3.6"));
        Assert.Null(SnmpOid.Check("1.3.6.1.2.1.2", "1.3.6.1.2.1.2.1.0", "1.3.6.1.2.1.2.2.1.1.1"));
        Assert.Equal(SnmpWalkStop.EndOfSubtree, SnmpOid.Check("1.3.6.1.2.1.2", "1.3.6.1.2.1.2.2.1.1.1", "1.3.6.1.2.1.20.1"));
        Assert.Equal(SnmpWalkStop.RepeatedOid, SnmpOid.Check("1.3", "1.3.6.1", "1.3.6.1"));
        Assert.Equal(SnmpWalkStop.NonIncreasingOid, SnmpOid.Check("1.3", "1.3.6.1.5", "1.3.6.1.4"));
        Assert.False(SnmpOid.TryParse("3.1", out _));
        Assert.False(SnmpOid.TryParse("1.40", out _));
        Assert.False(SnmpOid.TryParse("1", out _));
        Assert.True(SnmpOid.TryParse("2.999.1", out _));
    }

    [Fact]
    public void Mib_tree_places_every_builtin_object_under_its_parent()
    {
        var root = MibTree.Build();
        Assert.Equal("iso", root.Name);
        static IEnumerable<MibTreeNode> All(MibTreeNode n) => n.Children.SelectMany(All).Prepend(n);
        var all = All(root).ToList();
        Assert.Equal(Core.Queries.MibDatabase.Entries.Count, all.Count(n => n.Entry is not null));
        var system = all.Single(n => n.Name == "system");
        Assert.Equal(["sysDescr", "sysObjectID", "sysUpTime", "sysContact", "sysName", "sysLocation", "sysServices"], system.Children.Select(c => c.Name));
        Assert.All(all, n => Assert.All(n.Children, c => Assert.StartsWith(n.Oid + ".", c.Oid, StringComparison.Ordinal)));
    }
}
