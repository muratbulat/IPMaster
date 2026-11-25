using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

// Synthetic scheduler benchmark (NFR-03). Probes are simulated: 20 % of addresses answer after 2-10 ms,
// the rest stay silent until the ping timeout. DNS answers after 5-50 ms. No packets are sent.
if (args.Length > 0 && args[0] == "results") return await ResultsBench.RunAsync(args[1..]);

var targets = args.Length > 0 ? args[0] : "10.0.0.0/18";      // 16,382 hosts
var concurrency = args.Length > 1 ? int.Parse(args[1], CultureInfo.InvariantCulture) : 256;
var timeoutMs = args.Length > 2 ? int.Parse(args[2], CultureInfo.InvariantCulture) : 200;

Console.WriteLine($"IPMaster scheduler benchmark — SYNTHETIC probes, no network traffic");
Console.WriteLine($"Runtime {Environment.Version}, {Environment.ProcessorCount} logical CPUs, {Environment.OSVersion}");
Console.WriteLine($"targets={targets} concurrency={concurrency} pingTimeout={timeoutMs} ms");

if (!TargetParser.TryParse(targets, out var spec, out var err)) { Console.Error.WriteLine(err); return 1; }
var plan = (await TargetPlanBuilder.BuildAsync([spec], new PlanOptions { Confirmed = true, Limits = new PlanLimits { MaxTargets = 1UL << 26 } }, null)).Plan;
var sw = Stopwatch.StartNew();
var count = plan.CountExact();
Console.WriteLine($"plan: {count:N0} addresses, exact count in {sw.ElapsedMilliseconds} ms");

GC.Collect();
var allocBefore = GC.GetTotalAllocatedBytes(true);
var sink = new Sink();
var engine = new ScanEngine(new SyntheticIcmp(), new NoArp(), new SyntheticDns());
sw.Restart();
using var session = engine.Start(new ScanRequest
{
    Plan = plan,
    ExactCount = count,
    Settings = new ScanSettings { MaxConcurrency = concurrency, PingTimeoutMs = timeoutMs, PingAttempts = 1, DnsTimeoutMs = 1000, DeviceDeadlineSeconds = 10 },
}, sink);

long peakWs = 0;
var maxWorkers = 0;
while (!session.Completion.IsCompleted)
{
    await Task.WhenAny(session.Completion, Task.Delay(100));
    using var proc = Process.GetCurrentProcess();
    peakWs = Math.Max(peakWs, proc.WorkingSet64);
    maxWorkers = Math.Max(maxWorkers, session.Progress.ActiveWorkers);
}

var summary = await session.Completion;
sw.Stop();
var alloc = GC.GetTotalAllocatedBytes(true) - allocBefore;
var ideal = Math.Ceiling(count * 0.8 / concurrency) * timeoutMs / 1000.0;
Console.WriteLine($"result: {summary.State}, {summary.Processed:N0} processed, {summary.Online:N0} online, {sink.Updates:N0} sink updates");
Console.WriteLine($"elapsed: {sw.Elapsed.TotalSeconds:0.00} s  throughput: {summary.Processed / sw.Elapsed.TotalSeconds:N0} addr/s  (lower bound from silent hosts ≈ {ideal:0.0} s)");
Console.WriteLine($"peak active workers: {maxWorkers} (limit {concurrency})");
Console.WriteLine($"peak working set: {peakWs / 1048576.0:0.0} MB  managed allocations during scan: {alloc / 1048576.0:0.0} MB");

// Lazy enumeration check on a 16M-address plan
var big = (await TargetPlanBuilder.BuildAsync([Parse("2001:db8::/104")], new PlanOptions { Confirmed = true }, null)).Plan;
var before = GC.GetAllocatedBytesForCurrentThread();
sw.Restart();
ulong n = 0;
foreach (var _ in big.Enumerate(randomOrder: true, seed: 1)) { if (++n == 1_000_000) break; }
Console.WriteLine($"lazy IPv6 /104 plan (16.8M raw): first 1M random-order addresses in {sw.ElapsedMilliseconds} ms, {(GC.GetAllocatedBytesForCurrentThread() - before) / 1024.0:0} KB allocated");
return 0;

static TargetSpec Parse(string s) => TargetParser.TryParse(s, out var t, out _) ? t : throw new ArgumentException(s);

sealed class SyntheticIcmp : IIcmpProbe
{
    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("synthetic");

    public async Task<ProbeReply> PingAsync(IPAddress address, TimeSpan timeout, CancellationToken ct)
    {
        var h = (uint)address.GetHashCode();
        if (h % 5 == 0)
        {
            var ms = 2 + (int)(h % 9);
            await Task.Delay(ms, ct);
            return new ProbeReply(ObservationState.Success, TimeSpan.FromMilliseconds(ms), 64);
        }

        await Task.Delay(timeout, ct);
        return new ProbeReply(ObservationState.NoResponse);
    }
}

sealed class NoArp : IArpProbe
{
    public CapabilityStatus Capability { get; } = CapabilityStatus.No("synthetic");
    public Task<ProbeReply> ArpAsync(IPAddress a, TimeSpan t, CancellationToken c) => Task.FromResult(new ProbeReply(ObservationState.Unsupported));
}

sealed class SyntheticDns : IHostNameResolver
{
    public async Task<string?> ReverseLookupAsync(IPAddress address, CancellationToken ct)
    {
        await Task.Delay(5 + (int)((uint)address.GetHashCode() % 45), ct);
        return "host-" + address.ToString().Replace('.', '-') + ".bench.invalid";
    }

    public Task<IPAddress[]> ForwardLookupAsync(string hostName, CancellationToken ct) => Task.FromResult(Array.Empty<IPAddress>());
}

sealed class Sink : IScanResultSink
{
    private readonly ConcurrentDictionary<AddressKey, DeviceResult> _d = new();
    private long _updates;
    public long Updates => Interlocked.Read(ref _updates);
    public void OnDevice(DeviceResult r) { Interlocked.Increment(ref _updates); _d[r.Key] = r; }
}
