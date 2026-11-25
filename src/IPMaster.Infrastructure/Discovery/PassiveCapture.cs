using IPMaster.Core.Discovery;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Discovery;

/// <summary>
/// Passive discovery on one adapter (D-090): captures ARP, IPv4 and IPv6 frames (DHCP included) through
/// <see cref="PcapLibrary"/> and reports what they reveal. Never sends a frame; not promiscuous. A silent device with a
/// static address sends nothing and cannot be found this way: use active discovery.
/// </summary>
public sealed class PassiveCapture(PcapLibrary pcap)
{
    public CapabilityStatus Capability => pcap.Capability;

    public IReadOnlyList<CaptureInterface> Interfaces() => pcap.Interfaces();

    /// <summary>Captures until <paramref name="ct"/> is cancelled; the callback runs on the capture thread.</summary>
    public Task RunAsync(CaptureInterface iface, Action<DiscoveryObservation> onObservation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(iface);
        ArgumentNullException.ThrowIfNull(onObservation);
        if (!pcap.Capability.Available) throw new InvalidOperationException(pcap.Capability.Description);
        return Task.Factory.StartNew(() =>
        {
            using var handle = pcap.Open(iface.PcapName, "arp or ip or ip6", snapLength: 600);
            while (!ct.IsCancellationRequested)
            {
                handle.Drain(frame =>
                {
                    foreach (var o in FrameObservations.FromFrame(frame, DateTimeOffset.UtcNow)) onObservation(o);
                });
            }
        }, ct, TaskCreationOptions.LongRunning, TaskScheduler.Default);
    }
}
