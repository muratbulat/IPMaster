using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Targets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace IPMaster.Core.Scanning;

/// <summary>Receives device snapshots (new or updated, keyed by <see cref="DeviceResult.Key"/>).
/// Called concurrently from worker threads; implementations must be thread-safe and must not block.</summary>
public interface IScanResultSink
{
    void OnDevice(DeviceResult result);
}

public sealed record ScanRequest
{
    public required TargetPlan Plan { get; init; }

    public required ScanSettings Settings { get; init; }

    public IReadOnlyList<LocalSubnet> LocalSubnets { get; init; } = [];

    /// <summary>Interface scope IDs of local IPv6 link-local addresses (used to warm the neighbour cache).</summary>
    public IReadOnlyList<long> IPv6ScopeIds { get; init; } = [];

    /// <summary>Addresses already listed in the results; offline results for them are always published (rescans).</summary>
    public IReadOnlySet<AddressKey>? KnownAddresses { get; init; }

    /// <summary>Number of addresses that will be scanned when known; otherwise <see cref="TargetPlan.RawCount"/> is the upper bound.</summary>
    public ulong? ExactCount { get; init; }

    /// <summary>Seed for random order; 0 = random.</summary>
    public ulong Seed { get; init; }

    /// <summary>Remote queries to run for analysed devices (Phase 4); null = none.</summary>
    public Queries.QueryPlan? Queries { get; init; }

    /// <summary>Routers for the Router MIB MAC method (default gateways + configured routers).</summary>
    public IReadOnlyList<IPAddress> Routers { get; init; } = [];

    /// <summary>Resolved Workstation-tab credential (WKS-07); null = current account.</summary>
    public Security.ResolvedCredential? WorkstationCredential { get; init; }

    /// <summary>Resolved Shares-tab credential; null = current account.</summary>
    public Security.ResolvedCredential? SharesCredential { get; init; }
}

/// <summary>All probes used by a scan. Optional probes default to <see cref="UnavailableProbes"/>, which report
/// Unsupported with a reason — never fake data.</summary>
public sealed record ScanProbes(IIcmpProbe Icmp, IArpProbe Arp, IHostNameResolver Dns)
{
    public ITcpPortProbe Tcp { get; init; } = UnavailableProbes.Instance;

    public IUdpServiceProbe Udp { get; init; } = UnavailableProbes.Instance;

    public INetBiosProbe NetBios { get; init; } = UnavailableProbes.Instance;

    public INeighborTable Neighbors { get; init; } = UnavailableProbes.Instance;

    public IVendorLookup Vendors { get; init; } = UnavailableProbes.Instance;

    public IServiceProbe Service { get; init; } = UnavailableProbes.Instance;

    public IWindowsHostProbe Windows { get; init; } = UnavailableProbes.Instance;

    public IGeoLocator? Geo { get; init; }

    public IWindowsExtras? WindowsExtras { get; init; }

    public IRouterArpSource? RouterArp { get; init; }
}

/// <summary>Creates scan sessions. Stateless and thread-safe; one engine can run several sessions.</summary>
public sealed class ScanEngine
{
    private readonly ScanProbes _probes;
    private readonly TimeProvider _time;
    private readonly ILogger _logger;

    public ScanEngine(ScanProbes probes, TimeProvider? time = null, ILogger<ScanEngine>? logger = null)
    {
        _probes = probes ?? throw new ArgumentNullException(nameof(probes));
        _time = time ?? TimeProvider.System;
        _logger = (ILogger?)logger ?? NullLogger.Instance;
    }

    public ScanEngine(IIcmpProbe icmp, IArpProbe arp, IHostNameResolver dns, TimeProvider? time = null, ILogger<ScanEngine>? logger = null)
        : this(new ScanProbes(icmp, arp, dns), time, logger)
    {
    }

    public ScanProbes Probes => _probes;

    public ScanSession Start(ScanRequest request, IScanResultSink sink, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(sink);
        var session = new ScanSession(request with { Settings = request.Settings.Normalize() }, sink, _probes, _time, _logger, cancellationToken);
        session.Begin();
        return session;
    }
}

/// <summary>Stand-in for probes that are not available on this host or build. Every call reports Unsupported.</summary>
public sealed class UnavailableProbes : ITcpPortProbe, IUdpServiceProbe, INetBiosProbe, INeighborTable, IVendorLookup, IServiceProbe, IWindowsHostProbe
{
    private const string Reason = "Not available in this configuration.";

    private UnavailableProbes()
    {
    }

    public static UnavailableProbes Instance { get; } = new();

    public CapabilityStatus Capability { get; } = CapabilityStatus.No(Reason);

    public Task<PortResult> ProbeAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
        => Task.FromResult(new PortResult(PortProtocol.Tcp, port, PortState.Unsupported, Detail: Reason));

    public Task<(PortResult Port, ServiceBanner? Banner)> ProbeAsync(IPAddress address, UdpService service, string snmpCommunity, TimeSpan timeout,
        CancellationToken cancellationToken)
        => Task.FromResult<(PortResult, ServiceBanner?)>((new PortResult(PortProtocol.Udp, service.Port, PortState.Unsupported, service.Name, Reason), null));

    public Task<NetBiosInfo?> QueryAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken) => Task.FromResult<NetBiosInfo?>(null);

    public Task<IReadOnlyList<NeighborEntry>> SnapshotAsync(CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<NeighborEntry>>([]);

    public string? Lookup(PhysicalAddress mac) => null;

    public Task<ServiceBanner?> GrabTcpBannerAsync(IPAddress address, BannerService service, int port, TimeSpan timeout, CancellationToken cancellationToken)
        => Task.FromResult<ServiceBanner?>(null);

    public Task<TlsCertificateInfo?> GetCertificateAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
        => Task.FromResult<TlsCertificateInfo?>(null);

    public Task<IReadOnlyList<string>> FindRtspStreamsAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
        => Task.FromResult<IReadOnlyList<string>>([]);

    private static Observation<T> No<T>(DateTimeOffset now) => Observation<T>.Of(ObservationState.Unsupported, now, Reason);

    public Observation<string> GetWorkgroup(string host, DateTimeOffset now) => No<string>(now);

    public Observation<string> GetWindowsVersion(string host, DateTimeOffset now) => No<string>(now);

    public Observation<IReadOnlyList<string>> GetAccounts(string host, DateTimeOffset now) => No<IReadOnlyList<string>>(now);

    public Observation<IReadOnlyList<string>> GetLoggedOnUsers(string host, DateTimeOffset now) => No<IReadOnlyList<string>>(now);

    public Observation<IReadOnlyList<string>> GetLoggedOnSids(string host, DateTimeOffset now) => No<IReadOnlyList<string>>(now);

    public Observation<DateTimeOffset> GetRemoteTime(string host, DateTimeOffset now) => No<DateTimeOffset>(now);

    public Observation<IReadOnlyList<InstalledApplication>> GetInstalledApplications(string host, DateTimeOffset now) => No<IReadOnlyList<InstalledApplication>>(now);

    public Observation<IReadOnlyList<ShareInfo>> GetShares(string host, ShareTypeSelection types, bool diskSpace, bool security, bool writeCheck,
        DateTimeOffset now, CancellationToken cancellationToken) => No<IReadOnlyList<ShareInfo>>(now);
}

/// <summary>Wildcard matching with <c>*</c> and <c>?</c> (ignored addresses, account exclusions).</summary>
public static class Wildcard
{
    public static bool IsMatch(string pattern, string text, bool ignoreCase = false)
    {
        ArgumentNullException.ThrowIfNull(pattern);
        ArgumentNullException.ThrowIfNull(text);
        return ignoreCase
            ? Match(pattern.ToUpperInvariant(), text.ToUpperInvariant())
            : Match(pattern, text);
    }

    private static bool Match(ReadOnlySpan<char> pattern, ReadOnlySpan<char> text)
    {
        int p = 0, t = 0, star = -1, mark = 0;
        while (t < text.Length)
        {
            if (p < pattern.Length && (pattern[p] == '?' || pattern[p] == text[t]))
            {
                p++;
                t++;
            }
            else if (p < pattern.Length && pattern[p] == '*')
            {
                star = p++;
                mark = t;
            }
            else if (star >= 0)
            {
                p = star + 1;
                t = ++mark;
            }
            else
            {
                return false;
            }
        }

        while (p < pattern.Length && pattern[p] == '*') p++;
        return p == pattern.Length;
    }
}
