using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Discovery;
using IPMaster.Infrastructure.Discovery;

namespace IPMaster.Tests;

/// <summary>Active discovery (D-090): candidate limits and the ARP-probe sweep against a fake link. Nothing is sent.</summary>
public class ActiveDiscoveryTests
{
    private static readonly PhysicalAddress Laptop = PhysicalAddress.Parse("00-00-00-AA-BB-CC");

    /// <summary>A static device on the cable: answers ARP probes for its own address only, like Linux-based BMC firmware.</summary>
    private sealed class FakeDevice(PhysicalAddress mac, IPAddress address) : IFrameLink
    {
        private readonly Queue<byte[]> _replies = new();

        public List<byte[]> Sent { get; } = [];

        public void Send(ReadOnlySpan<byte> frame)
        {
            Sent.Add(frame.ToArray());
            if (new IPAddress(frame.Slice(38, 4)).Equals(address))
            {
                var reply = ArpFrame.Request(mac, address, IPAddress.Any);
                BinaryPrimitives.WriteUInt16BigEndian(reply.AsSpan(20), 2);
                _replies.Enqueue(reply);
            }
        }

        public int Drain(ReadOnlySpanAction<byte> onFrame)
        {
            var n = 0;
            while (_replies.TryDequeue(out var f))
            {
                onFrame(f);
                n++;
            }

            return n;
        }
    }

    [Fact]
    public void Candidates_parse_ranges_and_cidr_without_network_and_broadcast()
    {
        var list = CandidateList.Parse("192.168.0.120, 192.168.70.0/30\n10.0.0.1-10.0.0.3; 192.168.0.120", out var error)!;
        Assert.Equal("", error);
        Assert.Equal(["192.168.0.120", "192.168.70.1", "192.168.70.2", "10.0.0.1", "10.0.0.2", "10.0.0.3"], list.Select(a => a.ToString()));
    }

    [Theory]
    [InlineData("10.0.0.0/16", "More than")]
    [InlineData("server.example", "no host names")]
    [InlineData("fe80::1", "no IPv6")]
    [InlineData("", "at least one")]
    [InlineData("300.1.1.1", "'300.1.1.1'")]
    public void Unbounded_or_unusable_candidates_are_refused(string text, string expected)
    {
        Assert.Null(CandidateList.Parse(text, out var error));
        Assert.Contains(expected, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Probes_use_sender_0_0_0_0_and_find_the_static_device()
    {
        var bmc = PhysicalAddress.Parse("94-40-C9-12-34-56");
        var device = new FakeDevice(bmc, IPAddress.Parse("192.168.0.120"));
        var candidates = CandidateList.Parse("192.168.0.100-192.168.0.140", out _)!;
        var live = new List<DiscoveryObservation>();
        var found = ArpProbeSweep.Sweep(device, Laptop, candidates, TimeSpan.Zero, null, live.Add, CancellationToken.None);

        var o = Assert.Single(found);
        Assert.Equal((bmc, IPAddress.Parse("192.168.0.120"), DiscoverySource.ActiveArp, IpAssignment.Observed), (o.Mac, o.Address, o.Source, o.Assignment));
        Assert.Single(live);
        Assert.Equal(candidates.Count, device.Sent.Count); // one probe per candidate, nothing else
        Assert.All(device.Sent, f => Assert.Equal(IPAddress.Any, new IPAddress(f.AsSpan(28, 4)))); // RFC 5227 probe
        Assert.All(device.Sent, f => Assert.Equal(Laptop, new PhysicalAddress(f.AsSpan(6, 6).ToArray())));
    }

    [Fact]
    public void Sweep_is_cancellable_and_bounded()
    {
        var device = new FakeDevice(PhysicalAddress.Parse("94-40-C9-12-34-56"), IPAddress.Parse("192.168.0.120"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.Throws<OperationCanceledException>(() => ArpProbeSweep.Sweep(device, Laptop, [IPAddress.Parse("192.168.0.120")], TimeSpan.Zero, null, null, cts.Token));
        Assert.Empty(device.Sent);
        var tooMany = Enumerable.Range(0, CandidateList.MaxAddresses + 1).Select(i => IPAddress.Parse($"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}")).ToList();
        Assert.Throws<ArgumentException>(() => ArpProbeSweep.Sweep(device, Laptop, tooMany, TimeSpan.Zero, null, null, CancellationToken.None));
    }

    [Fact]
    public void Vendor_defaults_are_parseable_candidates()
    {
        foreach (var (_, candidates) in ManagementDefaults.All.Where(d => char.IsDigit(d.Candidates[0])))
        {
            Assert.NotNull(CandidateList.Parse(candidates, out _));
        }
    }
}
