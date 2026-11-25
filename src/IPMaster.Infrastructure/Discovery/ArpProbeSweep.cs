using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Discovery;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Discovery;

/// <summary>Raw frame access; <see cref="PcapHandle"/> in production, a fake device in tests.</summary>
public interface IFrameLink
{
    void Send(ReadOnlySpan<byte> frame);

    /// <summary>Hands every frame waiting now to <paramref name="onFrame"/> and returns (bounded wait).</summary>
    int Drain(ReadOnlySpanAction<byte> onFrame);
}

/// <summary>
/// Active discovery by ARP probe (D-090): a who-has request with sender address 0.0.0.0 (RFC 5227) for each candidate.
/// A device answers for its own address whatever the laptop's subnet, so this finds a static management controller on
/// an unknown subnet without first giving the laptop an address there. Firmware that ignores probes is not found; a
/// device behind a router never is (ARP is link-local). Only the given candidates are probed.
/// </summary>
public sealed class ArpProbeSweep(PcapLibrary pcap)
{
    public CapabilityStatus Capability => pcap.Capability;

    public async Task<IReadOnlyList<DiscoveryObservation>> RunAsync(CaptureInterface iface, IReadOnlyList<IPAddress> candidates, TimeSpan listen,
        IProgress<int>? progress, Action<DiscoveryObservation>? onObservation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(iface);
        if (!pcap.Capability.Available) throw new InvalidOperationException(pcap.Capability.Description);
        var mac = Core.Results.Formats.ParseMac(iface.Adapter.MacAddress) ?? throw new InvalidOperationException("The adapter has no MAC address.");
        return await Task.Factory.StartNew(() =>
        {
            using var link = pcap.Open(iface.PcapName, "arp");
            return Sweep(link, mac, candidates, listen, progress, onObservation, ct);
        }, ct, TaskCreationOptions.LongRunning, TaskScheduler.Default).ConfigureAwait(false);
    }

    /// <summary>The sweep itself, on any <see cref="IFrameLink"/>. Paced: replies are read after every 32 probes.</summary>
    public static IReadOnlyList<DiscoveryObservation> Sweep(IFrameLink link, PhysicalAddress source, IReadOnlyList<IPAddress> candidates, TimeSpan listen,
        IProgress<int>? progress, Action<DiscoveryObservation>? onObservation, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(link);
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(candidates);
        if (candidates.Count > CandidateList.MaxAddresses) throw new ArgumentException($"At most {CandidateList.MaxAddresses} candidates.", nameof(candidates));
        var wanted = candidates.ToHashSet();
        var found = new Dictionary<(PhysicalAddress, IPAddress), DiscoveryObservation>();
        void Read() => link.Drain(frame =>
        {
            if (ArpFrame.ParseReply(frame) is not { } r || !wanted.Contains(r.SenderIp) || r.SenderMac.Equals(source)) return;
            if (found.ContainsKey((r.SenderMac, r.SenderIp))) return;
            var o = new DiscoveryObservation(DateTimeOffset.UtcNow, r.SenderMac, r.SenderIp, DiscoverySource.ActiveArp, IpAssignment.Observed,
                $"Answered an ARP probe for {r.SenderIp}");
            found[(r.SenderMac, r.SenderIp)] = o;
            onObservation?.Invoke(o);
        });

        for (var i = 0; i < candidates.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            link.Send(ArpFrame.Request(source, IPAddress.Any, candidates[i]));
            if ((i + 1) % 32 == 0)
            {
                Read();
                progress?.Report(100 * (i + 1) / candidates.Count);
            }
        }

        var until = DateTime.UtcNow + listen;
        do
        {
            Read();
        }
        while (DateTime.UtcNow < until && !ct.IsCancellationRequested);
        progress?.Report(100);
        return found.Values.ToList();
    }
}
