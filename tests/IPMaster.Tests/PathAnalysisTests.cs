using System.Net;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Tools;

namespace IPMaster.Tests;

/// <summary>Continuous traceroute statistics and path MTU search (D-093). Synthetic traces and probes only.</summary>
public class PathAnalysisTests
{
    private static readonly DateTimeOffset T = new(2026, 11, 24, 12, 0, 0, TimeSpan.Zero);
    private static readonly IPAddress Dest = IPAddress.Parse("198.51.100.10");

    private static RouteHop H(int ttl, string? ip, double? ms) => new(ttl, ip is null ? null : IPAddress.Parse(ip), ms);

    [Fact]
    public void Rate_limited_middle_hop_is_not_forwarding_loss()
    {
        var t = new PathTracker(Dest);
        for (var i = 0; i < 10; i++)
        {
            // hop 2 answers only every other time; the destination always answers
            t.Add([H(1, "10.0.0.1", 1), H(2, "192.0.2.1", i % 2 == 0 ? 5 : null), H(3, "198.51.100.10", 9 + i % 3)], T.AddSeconds(i));
        }

        var hops = t.Hops;
        Assert.Equal(50, hops[1].LossPercent);
        Assert.Contains("rate limiting", hops[1].Note, StringComparison.Ordinal);
        Assert.Equal(0, t.EndToEndLossPercent);
        Assert.Equal((9d, 11d), (hops[2].MinMs!.Value, hops[2].MaxMs!.Value));
        Assert.Equal(10, t.EndToEnd.Count);
    }

    [Fact]
    public void Loss_continuing_to_the_destination_is_flagged_at_its_first_hop()
    {
        var t = new PathTracker(Dest);
        for (var i = 0; i < 10; i++)
        {
            var lost = i % 4 == 0;
            t.Add([H(1, "10.0.0.1", 1), H(2, lost ? null : "192.0.2.1", lost ? null : 5), H(3, lost ? null : "198.51.100.10", lost ? null : 9)], T.AddSeconds(i));
        }

        Assert.Contains("possible forwarding loss", t.Hops[1].Note, StringComparison.Ordinal);
        Assert.Contains("end-to-end loss", t.Hops[2].Note, StringComparison.Ordinal);
        Assert.Equal(30, t.EndToEndLossPercent);
    }

    [Fact]
    public void Filtered_router_that_never_answers_is_explained()
    {
        var t = new PathTracker(Dest);
        for (var i = 0; i < 3; i++) t.Add([H(1, "10.0.0.1", 1), H(2, null, null), H(3, "198.51.100.10", 9)], T.AddSeconds(i));
        Assert.Contains("ICMP filtered", t.Hops[1].Note, StringComparison.Ordinal);
    }

    [Fact]
    public void New_address_is_a_change_but_alternating_ecmp_addresses_are_reported_once()
    {
        var t = new PathTracker(Dest);
        t.Add([H(1, "10.0.0.1", 1), H(2, "192.0.2.1", 5), H(3, "198.51.100.10", 9)], T);
        t.Add([H(1, "10.0.0.1", 1), H(2, "192.0.2.2", 5), H(3, "198.51.100.10", 9)], T.AddSeconds(1));
        t.Add([H(1, "10.0.0.1", 1), H(2, "192.0.2.1", 5), H(3, "198.51.100.10", 9)], T.AddSeconds(2));
        t.Add([H(1, "10.0.0.1", 1), H(2, "192.0.2.2", 5), H(3, "198.51.100.10", 9)], T.AddSeconds(3));
        var change = Assert.Single(t.Changes);
        Assert.Equal((2, IPAddress.Parse("192.0.2.1"), IPAddress.Parse("192.0.2.2")), (change.Ttl, change.Before, change.After));
        Assert.Contains("2 addresses", t.Hops[1].Note, StringComparison.Ordinal);
    }

    [Fact]
    public void Shorter_trace_does_not_count_missing_hops_as_lost()
    {
        var t = new PathTracker(Dest);
        t.Add([H(1, "10.0.0.1", 1), H(2, "192.0.2.1", 5), H(3, "198.51.100.10", 9)], T);
        t.Add([H(1, "10.0.0.1", 1), H(2, "198.51.100.10", 6)], T.AddSeconds(1)); // route got shorter
        Assert.Equal(1, t.Hops[2].Sent);
        Assert.Equal(0, t.Hops[2].Lost);
    }

    [Fact]
    public void Bounded_history()
    {
        var t = new PathTracker(Dest);
        for (var i = 0; i < PathTracker.MaxSamples + 10; i++) t.Add([H(1, "198.51.100.10", 1)], T.AddSeconds(i));
        Assert.Equal(PathTracker.MaxSamples, t.EndToEnd.Count);
    }

    private static Func<int, CancellationToken, Task<MtuProbe>> Path(int mtu, MtuProbe tooLarge, List<int>? sizes = null) => (size, _) =>
    {
        sizes?.Add(size);
        return Task.FromResult(size <= mtu ? MtuProbe.Reply : tooLarge);
    };

    [Fact]
    public async Task Mtu_is_found_by_binary_search_with_fragmentation_needed()
    {
        var sizes = new List<int>();
        var r = await PathMtu.DiscoverAsync(Path(1420, MtuProbe.TooBig, sizes), 1500, CancellationToken.None);
        Assert.Equal((1420, false), (r.Mtu, r.AtLeast));
        Assert.Contains("fragmentation needed", r.Evidence, StringComparison.Ordinal);
        Assert.Contains("payload 1392", r.Evidence, StringComparison.Ordinal);
        Assert.True(sizes.Count < 15, $"{sizes.Count} probes");
    }

    [Fact]
    public async Task Silent_drops_suggest_a_black_hole_and_full_mtu_is_a_lower_bound()
    {
        var hole = await PathMtu.DiscoverAsync(Path(1400, MtuProbe.NoReply), 1500, CancellationToken.None);
        Assert.Equal(1400, hole.Mtu);
        Assert.Contains("black hole", hole.Evidence, StringComparison.Ordinal);
        var full = await PathMtu.DiscoverAsync(Path(1500, MtuProbe.TooBig), 1500, CancellationToken.None);
        Assert.Equal((1500, true), (full.Mtu, full.AtLeast));
    }

    [Fact]
    public async Task No_answer_at_all_is_unknown_not_a_number()
    {
        var r = await PathMtu.DiscoverAsync((_, _) => Task.FromResult(MtuProbe.NoReply), 1500, CancellationToken.None);
        Assert.Null(r.Mtu);
        Assert.Contains("does not answer pings", r.Evidence, StringComparison.Ordinal);
        var e = await PathMtu.DiscoverAsync((_, _) => Task.FromResult(MtuProbe.Error), 1500, CancellationToken.None);
        Assert.Null(e.Mtu);
    }

    [Fact]
    public async Task Real_dont_fragment_ping_on_loopback()
    {
        // loopback only: nothing leaves the computer
        var r = await IPMaster.Infrastructure.Tools.PathProbes.MtuProbeAsync(IPAddress.Loopback, 1500, TimeSpan.FromSeconds(2), CancellationToken.None);
        if (r == MtuProbe.Error) return; // platform without raw ICMP (unprivileged Linux/macOS)
        Assert.Equal(MtuProbe.Reply, r);
        Assert.Equal(MtuProbe.Error, await IPMaster.Infrastructure.Tools.PathProbes.MtuProbeAsync(IPAddress.IPv6Loopback, 1500, TimeSpan.FromSeconds(2), CancellationToken.None));
    }

    [Fact]
    public async Task One_lost_probe_is_retried_and_does_not_shrink_the_mtu()
    {
        var lostOnce = new HashSet<int>();
        Task<MtuProbe> Flaky(int size, CancellationToken _)
        {
            if (size <= 1500 && size > 1000 && lostOnce.Add(size)) return Task.FromResult(MtuProbe.NoReply); // first try of each large size is lost
            return Task.FromResult(size <= 1500 ? MtuProbe.Reply : MtuProbe.TooBig);
        }

        Assert.Equal(1500, (await PathMtu.DiscoverAsync(Flaky, 1500, CancellationToken.None)).Mtu);
    }
}
