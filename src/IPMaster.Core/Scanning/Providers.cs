using System.Net;
using System.Net.NetworkInformation;

namespace IPMaster.Core.Scanning;

public enum PingMethod
{
    None,
    Icmp,
    Arp,
}

public enum PingMethodSetting
{
    Icmp,
    Arp,
    Both,
}

public readonly record struct ProbeReply(
    ObservationState State,
    TimeSpan? RoundTrip = null,
    int? Ttl = null,
    PhysicalAddress? Mac = null,
    string? Detail = null)
{
    public bool IsAlive => State == ObservationState.Success;
}

/// <summary>Single ICMP echo request.</summary>
public interface IIcmpProbe
{
    /// <summary>Whether ICMP echo is usable on this host (privileges, ping utility).</summary>
    CapabilityStatus Capability { get; }

    Task<ProbeReply> PingAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>ARP request on a local IPv4 subnet ("ARP ping"); also yields the MAC address.</summary>
public interface IArpProbe
{
    CapabilityStatus Capability { get; }

    Task<ProbeReply> ArpAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken);
}

public interface IHostNameResolver
{
    /// <summary>Reverse lookup. Returns null when the address has no name.</summary>
    Task<string?> ReverseLookupAsync(IPAddress address, CancellationToken cancellationToken);

    Task<IPAddress[]> ForwardLookupAsync(string hostName, CancellationToken cancellationToken);
}

public sealed record CapabilityStatus(bool Available, string Description)
{
    public static CapabilityStatus Yes(string description) => new(true, description);

    public static CapabilityStatus No(string description) => new(false, description);
}

/// <summary>TCP connect probe.</summary>
public interface ITcpPortProbe
{
    Task<PortResult> ProbeAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Protocol-specific UDP probes. Returns Open only when the service answered.</summary>
public interface IUdpServiceProbe
{
    Task<(PortResult Port, ServiceBanner? Banner)> ProbeAsync(IPAddress address, UdpService service, string snmpCommunity,
        TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>NetBIOS node-status (NBSTAT) query on UDP 137.</summary>
public interface INetBiosProbe
{
    Task<NetBiosInfo?> QueryAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Read-only view of the OS neighbour cache (ARP/NDP).</summary>
public interface INeighborTable
{
    CapabilityStatus Capability { get; }

    Task<IReadOnlyList<NeighborEntry>> SnapshotAsync(CancellationToken cancellationToken);
}

/// <summary>Offline OUI (IEEE MA-L/MA-M/MA-S) vendor lookup.</summary>
public interface IVendorLookup
{
    CapabilityStatus Capability { get; }

    string? Lookup(PhysicalAddress mac);
}

/// <summary>TCP banner/TLS/RTSP probes.</summary>
public interface IServiceProbe
{
    Task<ServiceBanner?> GrabTcpBannerAsync(IPAddress address, BannerService service, int port, TimeSpan timeout, CancellationToken cancellationToken);

    Task<TlsCertificateInfo?> GetCertificateAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken);

    /// <summary>Returns stream URLs that answered DESCRIBE, each suffixed with "(open)" or "(authentication required)".</summary>
    Task<IReadOnlyList<string>> FindRtspStreamsAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken);
}

/// <summary>Remote Windows management (NetApi, remote registry, SMB shares). Calls may block; the engine bounds them.</summary>
public interface IWindowsHostProbe
{
    CapabilityStatus Capability { get; }

    Observation<string> GetWorkgroup(string host, DateTimeOffset now);

    Observation<string> GetWindowsVersion(string host, DateTimeOffset now);

    Observation<IReadOnlyList<string>> GetAccounts(string host, DateTimeOffset now);

    Observation<IReadOnlyList<string>> GetLoggedOnUsers(string host, DateTimeOffset now);

    Observation<IReadOnlyList<string>> GetLoggedOnSids(string host, DateTimeOffset now);

    Observation<DateTimeOffset> GetRemoteTime(string host, DateTimeOffset now);

    Observation<IReadOnlyList<InstalledApplication>> GetInstalledApplications(string host, DateTimeOffset now);

    Observation<IReadOnlyList<ShareInfo>> GetShares(string host, ShareTypeSelection types, bool diskSpace, bool security, bool writeCheck,
        DateTimeOffset now, CancellationToken cancellationToken);
}

/// <summary>Optional geolocation of public addresses through a user-configured HTTP JSON endpoint (ENG-10).</summary>
public interface IGeoLocator
{
    CapabilityStatus Capability(ScanSettings settings);

    Task<GeoLocation?> LocateAsync(IPAddress address, ScanSettings settings, CancellationToken cancellationToken);
}
