using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Configuration;
using IPMaster.Core.Network;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Scanning;

/// <summary>Application service shared by the GUI and CLI: turns settings + targets into a validated plan.</summary>
public sealed class ScanPlanner
{
    private static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");
    private readonly INetworkAdapterProvider _adapters;
    private readonly IHostNameResolver _dns;
    private readonly IIcmpProbe? _icmp;
    private readonly INeighborTable? _neighbors;

    public ScanPlanner(INetworkAdapterProvider adapters, IHostNameResolver dns, IIcmpProbe? icmp = null, INeighborTable? neighbors = null)
    {
        _adapters = adapters ?? throw new ArgumentNullException(nameof(adapters));
        _dns = dns ?? throw new ArgumentNullException(nameof(dns));
        _icmp = icmp;
        _neighbors = neighbors;
    }

    /// <summary>How long responders get to answer the multicast echo before the neighbour cache is read.</summary>
    public TimeSpan DiscoveryWait { get; init; } = TimeSpan.FromSeconds(2);

    public IReadOnlyList<LocalSubnet> LocalSubnets() => Network.LocalNetworks.Subnets(_adapters.GetAdapters());

    public IReadOnlyList<long> LinkLocalScopes() => _adapters.GetAdapters().SelectMany(a => a.Addresses)
        .Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6 && a.Address.IsIPv6LinkLocal && a.Address.ScopeId != 0)
        .Select(a => a.Address.ScopeId).Distinct().ToList();

    /// <summary>IPv6 neighbour discovery (manual: multicast ping to ff02::1, then scan each responder). Responders
    /// resolve our address before replying, which creates neighbour-cache entries we can read afterwards.</summary>
    public async Task<IReadOnlyList<IPAddress>> DiscoverIPv6NeighborsAsync(long scopeId, CancellationToken cancellationToken)
    {
        if (_icmp is null || _neighbors is null || !_neighbors.Capability.Available) return [];
        var target = new IPAddress(AllNodes.GetAddressBytes(), scopeId);
        for (var i = 0; i < 2; i++)
        {
            try
            {
                await _icmp.PingAsync(target, TimeSpan.FromSeconds(1), cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // the multicast echo may fail locally while neighbours still answer
            }
        }

        await Task.Delay(DiscoveryWait, cancellationToken).ConfigureAwait(false);
        var entries = await _neighbors.SnapshotAsync(cancellationToken).ConfigureAwait(false);
        return entries.Where(e => e.Address.AddressFamily == AddressFamily.InterNetworkV6 && !e.Address.IsIPv6Multicast
                                  && (e.InterfaceIndex == scopeId || e.Address.ScopeId == scopeId))
            .Select(e => e.Address.IsIPv6LinkLocal && e.Address.ScopeId == 0 ? new IPAddress(e.Address.GetAddressBytes(), scopeId) : e.Address)
            .DistinctBy(a => a.ToString())
            .ToList();
    }

    public async Task<PlanBuildResult> PlanAsync(IEnumerable<TargetSpec> specs, AppSettings settings, bool confirmed,
        IReadOnlySet<AddressKey>? exclude = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var ignoreLines = settings.IgnoredAddresses.AsEnumerable();
        var options = new PlanOptions
        {
            PingNetworkAndBroadcast = settings.Scan.PingNetworkAndBroadcast,
            LocalSubnets = LocalSubnets(),
            Ignore = new IgnoreList(ignoreLines),
            Limits = settings.Limits,
            Confirmed = confirmed,
            Discover = DiscoverIPv6NeighborsAsync,
            Exclude = exclude,
        };
        var timeout = TimeSpan.FromMilliseconds(Math.Max(500, settings.Scan.DnsTimeoutMs));
        return await TargetPlanBuilder.BuildAsync(specs, options, ResolveTargetAsync, cancellationToken).ConfigureAwait(false);

        async Task<IPAddress?> ResolveTargetAsync(string host, CancellationToken ct)
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout * 2);
            IPAddress[] addrs;
            try
            {
                addrs = await _dns.ForwardLookupAsync(host, cts.Token).WaitAsync(cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException("lookup timed out");
            }
            catch (SocketException)
            {
                return null;
            }

            // Prefer IPv4 (D-011): host-name targets are treated as one device.
            return addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addrs.FirstOrDefault();
        }
    }

    /// <summary>Resolves a host name for "Detect IP Range from Host Name" (all addresses, IPv4 first).</summary>
    public async Task<IReadOnlyList<IPAddress>> ResolveHostAsync(string host, CancellationToken cancellationToken)
    {
        var addrs = await _dns.ForwardLookupAsync(host, cancellationToken).ConfigureAwait(false);
        return addrs.OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).ToList();
    }
}
