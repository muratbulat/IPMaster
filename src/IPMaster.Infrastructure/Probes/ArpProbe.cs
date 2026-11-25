using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Probes;

/// <summary>
/// ARP "ping" for local IPv4 subnets. Windows: iphlpapi <c>SendARP</c>, which also returns the MAC.
/// Limitation (D-009): SendARP may answer from a still-valid neighbour cache entry. Other platforms need
/// raw sockets (Phase 2) and report Unsupported.
/// </summary>
public sealed partial class ArpProbe : IArpProbe
{
    private const int ErrorBadNetName = 67;
    private const int ErrorGenFailure = 31;
    private static readonly SemaphoreSlim OutstandingCalls = new(128, 128);
    private static readonly TimeSpan MinWait = TimeSpan.FromSeconds(3);

    public CapabilityStatus Capability { get; } = OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes("ARP via Windows SendARP.")
        : CapabilityStatus.No("ARP ping is not implemented on this platform yet; use ICMP.");

    public async Task<ProbeReply> ArpAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!OperatingSystem.IsWindows()) return new ProbeReply(ObservationState.Unsupported, Detail: Capability.Description);
        if (address.AddressFamily != AddressFamily.InterNetwork) return new ProbeReply(ObservationState.Unsupported, Detail: "ARP is IPv4 only.");

        // SendARP blocks and has no timeout parameter (Windows gives up after ~1–3 s). Our wait is bounded by
        // the ping timeout; outstanding blocking calls, including abandoned ones, are capped by a semaphore so
        // they cannot exhaust the thread pool.
        // SendARP retries for ~3 s by itself and cannot be cancelled; giving up sooner drops slow replies (a /24 at 1 s
        // found 5 of 8 hosts) without freeing the slot any earlier (D-084).
        if (timeout < MinWait) timeout = MinWait;
        if (!await OutstandingCalls.WaitAsync(timeout, cancellationToken).ConfigureAwait(false))
        {
            return new ProbeReply(ObservationState.Failed, Detail: "ARP capacity saturated"); // local, not the device (review C-03)
        }

        // LongRunning = a dedicated thread: up to 128 calls blocking pool threads for ~3 s starved the thread pool,
        // which injects threads slowly, so a /24 with ARP took ~45 s instead of ~4 s (D-084).
        var call = Task.Factory.StartNew(() =>
        {
            try
            {
                return OperatingSystem.IsWindows() ? SendArpBlocking(address) : default;
            }
            finally
            {
                OutstandingCalls.Release();
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        try
        {
            return await call.WaitAsync(timeout, cancellationToken).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            return new ProbeReply(ObservationState.NoResponse, Detail: "No ARP reply.");
        }
    }

    [SupportedOSPlatform("windows")]
    private static ProbeReply SendArpBlocking(IPAddress address)
    {
        var dest = BitConverter.ToUInt32(address.GetAddressBytes(), 0);
        var mac = new byte[8];
        uint len = (uint)mac.Length;
        var sw = Stopwatch.StartNew();
        var rc = SendARP(dest, 0, mac, ref len);
        sw.Stop();
        if (rc == 0 && len >= 6)
        {
            var bytes = mac.AsSpan(0, (int)Math.Min(len, 6u)).ToArray();
            if (bytes.All(b => b == 0)) return new ProbeReply(ObservationState.NoResponse, Detail: "Incomplete ARP entry.");
            return new ProbeReply(ObservationState.Success, sw.Elapsed, null, new PhysicalAddress(bytes));
        }

        return rc is ErrorBadNetName or ErrorGenFailure
            ? new ProbeReply(ObservationState.NoResponse, Detail: "No ARP reply.")
            : new ProbeReply(ObservationState.Failed, Detail: $"SendARP error {rc}.");
    }

    [LibraryImport("iphlpapi.dll")]
    [SupportedOSPlatform("windows")]
    private static partial int SendARP(uint destIp, uint srcIp, [Out] byte[] macAddr, ref uint physicalAddrLen);
}
