using System.Net.NetworkInformation;
using IPMaster.Core.Discovery;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Infrastructure.Discovery;

/// <summary>
/// Duplicate IP detection (DSC-06/07): sends a raw ARP request for every address of the selected IPv4 subnet through
/// libpcap (<see cref="PcapLibrary"/>) and groups the replies. Without the capture library or the required privileges
/// the capability is reported as unavailable with guidance and nothing is sent.
/// </summary>
public sealed class DuplicateIpScanner(PcapLibrary pcap)
{
    public const int MaxAddresses = 4096;

    public CapabilityStatus Capability => pcap.Capability;

    /// <summary>IPv4 adapters that libpcap can open.</summary>
    public IReadOnlyList<CaptureInterface> Interfaces() => pcap.Interfaces();

    public async Task<DuplicateIpReport> ScanAsync(CaptureInterface iface, TimeSpan listen, IProgress<int>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(iface);
        if (!pcap.Capability.Available) throw new InvalidOperationException(pcap.Capability.Description);
        var mask = AddressKey.MaskFor(iface.Address.PrefixLength, false);
        var local = AddressKey.From(iface.Address.Address);
        var net = local.Value & mask;
        var count = (ulong)((~mask) & uint.MaxValue) - 1;
        if (count > MaxAddresses) throw new InvalidOperationException($"The subnet has {count:N0} addresses; at most {MaxAddresses:N0} are checked. Use a smaller prefix.");
        var srcMac = Core.Results.Formats.ParseMac(iface.Adapter.MacAddress)!;
        return await Task.Run(() => ScanBlocking(iface, net, count, srcMac, listen, progress, ct), ct).ConfigureAwait(false);
    }

    private DuplicateIpReport ScanBlocking(CaptureInterface iface, UInt128 net, ulong count, PhysicalAddress srcMac, TimeSpan listen,
        IProgress<int>? progress, CancellationToken ct)
    {
        using var handle = pcap.Open(iface.PcapName, "arp");
        var replies = new List<ArpReply>();
        void Drain() => handle.Drain(frame =>
        {
            if (ArpFrame.ParseReply(frame) is { } r) replies.Add(r);
        });

        for (ulong i = 1; i <= count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var target = AddressKey.FromIPv4((uint)(net + i)).ToIPAddress();
            handle.Send(ArpFrame.Request(srcMac, iface.Address.Address, target));
            if (i % 64 == 0)
            {
                Drain();
                progress?.Report((int)(100 * i / count));
            }
        }

        var until = DateTime.UtcNow + listen;
        while (DateTime.UtcNow < until && !ct.IsCancellationRequested) Drain();
        progress?.Report(100);
        var gw = iface.Adapter.Gateways.FirstOrDefault();
        var gatewayMac = gw is null ? null : replies.FirstOrDefault(r => r.SenderIp.Equals(gw))?.SenderMac;
        return DuplicateIpAnalyzer.Analyze(replies, gatewayMac);
    }
}
