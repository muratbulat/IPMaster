using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Network;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Tests;

/// <summary>Test-only fake ICMP probe. Hosts listed in <see cref="Alive"/> answer after <see cref="Latency"/>;
/// others are silent until the timeout. Tracks peak concurrency.</summary>
internal sealed class FakeIcmp : IIcmpProbe
{
    private int _current;
    private int _peak;
    private int _calls;

    public HashSet<string> Alive { get; } = [];

    public TimeSpan Latency { get; set; } = TimeSpan.FromMilliseconds(1);

    public TimeSpan? SilentDelay { get; set; }

    public Func<IPAddress, ProbeReply?>? Override { get; set; }

    public int Peak => Volatile.Read(ref _peak);

    /// <summary>Probes running right now.</summary>
    public int Current => Volatile.Read(ref _current);

    public int Calls => Volatile.Read(ref _calls);

    public CapabilityStatus Capability { get; set; } = CapabilityStatus.Yes("fake");

    public async Task<ProbeReply> PingAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        var now = Interlocked.Increment(ref _current);
        int peak;
        do
        {
            peak = Volatile.Read(ref _peak);
        }
        while (now > peak && Interlocked.CompareExchange(ref _peak, now, peak) != peak);

        try
        {
            if (Override?.Invoke(address) is { } o) return o;
            if (Alive.Contains(address.ToString()))
            {
                await Task.Delay(Latency, cancellationToken);
                return new ProbeReply(ObservationState.Success, Latency, 64);
            }

            await Task.Delay(SilentDelay ?? timeout, cancellationToken);
            return new ProbeReply(ObservationState.NoResponse, Detail: "timeout");
        }
        finally
        {
            Interlocked.Decrement(ref _current);
        }
    }
}

internal sealed class FakeArp : IArpProbe
{
    public CapabilityStatus Capability { get; set; } = CapabilityStatus.No("fake: unsupported");

    public HashSet<string> Alive { get; } = [];

    /// <summary>Time a silent address takes to report NoResponse (models SendARP giving up).</summary>
    public TimeSpan SilentDelay { get; set; }

    public async Task<ProbeReply> ArpAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (Alive.Contains(address.ToString()))
        {
            return new ProbeReply(ObservationState.Success, TimeSpan.FromMilliseconds(1), null, PhysicalAddress.Parse("00-11-22-33-44-55"));
        }

        await Task.Delay(SilentDelay, cancellationToken);
        return new ProbeReply(ObservationState.NoResponse);
    }
}

internal sealed class FakeDns : IHostNameResolver
{
    public ConcurrentDictionary<string, string> Names { get; } = new();

    public ConcurrentDictionary<string, IPAddress[]> Forward { get; } = new();

    public TimeSpan Delay { get; set; }

    /// <summary>Lookups never complete and ignore cancellation (models a stuck OS resolver).</summary>
    public bool Hang { get; set; }

    public int Started;

    public Task<string?> ReverseLookupAsync(IPAddress address, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Started);
        if (Hang) return new TaskCompletionSource<string?>().Task;
        return Impl();

        async Task<string?> Impl()
        {
            if (Delay > TimeSpan.Zero) await Task.Delay(Delay, cancellationToken);
            return Names.TryGetValue(address.ToString(), out var n) ? n : null;
        }
    }

    public Task<IPAddress[]> ForwardLookupAsync(string hostName, CancellationToken cancellationToken)
        => Task.FromResult(Forward.TryGetValue(hostName, out var a) ? a : []);
}

internal sealed class FakeAdapters(params NetworkAdapterInfo[] adapters) : INetworkAdapterProvider
{
    public IReadOnlyList<NetworkAdapterInfo> GetAdapters() => adapters;
}

internal sealed class ListSink : IScanResultSink
{
    private readonly ConcurrentDictionary<AddressKey, DeviceResult> _latest = new();
    private readonly ConcurrentQueue<(DeviceResult Result, DateTime At)> _events = new();

    public void OnDevice(DeviceResult result)
    {
        _events.Enqueue((result, DateTime.UtcNow));
        _latest.AddOrUpdate(result.Key, result, (_, old) => result.Revision >= old.Revision ? result : old);
    }

    public IReadOnlyCollection<(DeviceResult Result, DateTime At)> Events => _events;

    public DeviceResult Get(string ip) => _latest[AddressKey.From(IPAddress.Parse(ip))];

    public bool Has(string ip) => _latest.ContainsKey(AddressKey.From(IPAddress.Parse(ip)));

    public IReadOnlyDictionary<AddressKey, DeviceResult> Latest => _latest;

    public int Count => _latest.Count;
}

internal static class TestPlans
{
    public static TargetPlan Plan(params string[] targets) => Plan(new PlanOptions(), targets);

    public static TargetPlan Plan(PlanOptions options, params string[] targets)
    {
        var specs = targets.Select(t =>
        {
            Assert.True(TargetParser.TryParse(t, out var s, out var e), e);
            return s;
        });
        var r = TargetPlanBuilder.BuildAsync(specs, options with { Confirmed = true }, null).GetAwaiter().GetResult();
        return r.Plan;
    }

    public static List<string> Addresses(this TargetPlan plan) => plan.Enumerate().Select(a => a.ToString()).ToList();
}
