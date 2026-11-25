using System.Collections.Immutable;
using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Scanning;

public enum DeviceStatus
{
    /// <summary>Responded to a liveness probe.</summary>
    Online,

    /// <summary>Did not respond to any liveness probe.</summary>
    Offline,

    /// <summary>Scan stopped before the device finished.</summary>
    Cancelled,

    /// <summary>The per-device deadline expired.</summary>
    TimedOut,

    /// <summary>No usable liveness method (e.g. ARP only, not supported here).</summary>
    Unsupported,
}

public sealed record HostNameInfo(string Name, bool? ForwardConfirmed);

public sealed record PingStatistics(int Sent, int Received, TimeSpan? Jitter, TimeSpan? AverageRoundTrip)
{
    public double LossPercent => Sent == 0 ? 0 : 100.0 * (Sent - Received) / Sent;
}

/// <summary>Immutable snapshot of what is known about one scanned address.</summary>
public sealed record DeviceResult
{
    public required AddressKey Key { get; init; }

    public IPAddress Address => Key.ToIPAddress();

    public required DeviceStatus Status { get; init; }

    public PingMethod RespondedTo { get; init; }

    public TimeSpan? RoundTrip { get; init; }

    public Observation<int> Ttl { get; init; } = Observation<int>.NotRequested;

    public Observation<HostNameInfo> HostName { get; init; } = Observation<HostNameInfo>.NotRequested;

    public Observation<PhysicalAddress> Mac { get; init; } = Observation<PhysicalAddress>.NotRequested;

    public Observation<PingStatistics> PingStats { get; init; } = Observation<PingStatistics>.NotRequested;

    public MacSource MacSource { get; init; }

    public Observation<string> Vendor { get; init; } = Observation<string>.NotRequested;

    public Observation<IReadOnlyList<IPAddress>> IPv6Addresses { get; init; } = Observation<IReadOnlyList<IPAddress>>.NotRequested;

    public Observation<NetBiosInfo> NetBios { get; init; } = Observation<NetBiosInfo>.NotRequested;

    public Observation<IReadOnlyList<PortResult>> TcpPorts { get; init; } = Observation<IReadOnlyList<PortResult>>.NotRequested;

    public Observation<IReadOnlyList<PortResult>> UdpPorts { get; init; } = Observation<IReadOnlyList<PortResult>>.NotRequested;

    public Observation<IReadOnlyList<ServiceBanner>> Banners { get; init; } = Observation<IReadOnlyList<ServiceBanner>>.NotRequested;

    public Observation<IReadOnlyList<string>> RtspStreams { get; init; } = Observation<IReadOnlyList<string>>.NotRequested;

    public Observation<TlsCertificateInfo> Tls { get; init; } = Observation<TlsCertificateInfo>.NotRequested;

    public Observation<string> Workgroup { get; init; } = Observation<string>.NotRequested;

    public Observation<string> OsVersion { get; init; } = Observation<string>.NotRequested;

    public Observation<IReadOnlyList<string>> Accounts { get; init; } = Observation<IReadOnlyList<string>>.NotRequested;

    public Observation<IReadOnlyList<string>> LoggedOnUsers { get; init; } = Observation<IReadOnlyList<string>>.NotRequested;

    public Observation<IReadOnlyList<string>> LoggedOnSids { get; init; } = Observation<IReadOnlyList<string>>.NotRequested;

    public Observation<DateTimeOffset> RemoteTime { get; init; } = Observation<DateTimeOffset>.NotRequested;

    public Observation<IReadOnlyList<InstalledApplication>> InstalledApps { get; init; } = Observation<IReadOnlyList<InstalledApplication>>.NotRequested;

    public Observation<IReadOnlyList<ShareInfo>> Shares { get; init; } = Observation<IReadOnlyList<ShareInfo>>.NotRequested;

    public Observation<GeoLocation> Location { get; init; } = Observation<GeoLocation>.NotRequested;

    public Observation<IReadOnlyList<MonitorInfo>> Monitors { get; init; } = Observation<IReadOnlyList<MonitorInfo>>.NotRequested;

    public Observation<IReadOnlyList<TerminalSession>> TerminalSessions { get; init; } = Observation<IReadOnlyList<TerminalSession>>.NotRequested;

    /// <summary>Remote query results keyed by query column id (<c>q:&lt;guid&gt;</c>).</summary>
    public IReadOnlyDictionary<string, Observation<string>> Queries { get; init; } = NoQueries;

    public static readonly IReadOnlyDictionary<string, Observation<string>> NoQueries =
        System.Collections.Immutable.ImmutableSortedDictionary<string, Observation<string>>.Empty;

    /// <summary>States of every enrichment observation (used for completeness checks and finalisation).</summary>
    public IEnumerable<ObservationState> EnrichmentStates =>
    [
        HostName.State, PingStats.State, Mac.State, Vendor.State, IPv6Addresses.State, NetBios.State, TcpPorts.State,
        UdpPorts.State, Banners.State, RtspStreams.State, Tls.State, Workgroup.State, OsVersion.State, Accounts.State,
        LoggedOnUsers.State, LoggedOnSids.State, RemoteTime.State, InstalledApps.State, Shares.State, Location.State, Monitors.State, TerminalSessions.State,
        .. Queries.Values.Select(q => q.State),
    ];

    public bool HasPending => EnrichmentStates.Any(s => s == ObservationState.Pending);

    /// <summary>Replaces every still-pending observation with <paramref name="state"/>.</summary>
    public DeviceResult FinalizePending(ObservationState state, DateTimeOffset at, string? detail = null)
    {
        static Observation<T> F<T>(Observation<T> o, ObservationState s, DateTimeOffset t, string? d)
            => o.State == ObservationState.Pending ? Observation<T>.Of(s, t, d) : o;
        return this with
        {
            HostName = F(HostName, state, at, detail),
            PingStats = F(PingStats, state, at, detail),
            Mac = F(Mac, state, at, detail),
            Vendor = F(Vendor, state, at, detail),
            IPv6Addresses = F(IPv6Addresses, state, at, detail),
            NetBios = F(NetBios, state, at, detail),
            TcpPorts = F(TcpPorts, state, at, detail),
            UdpPorts = F(UdpPorts, state, at, detail),
            Banners = F(Banners, state, at, detail),
            RtspStreams = F(RtspStreams, state, at, detail),
            Tls = F(Tls, state, at, detail),
            Workgroup = F(Workgroup, state, at, detail),
            OsVersion = F(OsVersion, state, at, detail),
            Accounts = F(Accounts, state, at, detail),
            LoggedOnUsers = F(LoggedOnUsers, state, at, detail),
            LoggedOnSids = F(LoggedOnSids, state, at, detail),
            RemoteTime = F(RemoteTime, state, at, detail),
            InstalledApps = F(InstalledApps, state, at, detail),
            Shares = F(Shares, state, at, detail),
            Location = F(Location, state, at, detail),
            Monitors = F(Monitors, state, at, detail),
            TerminalSessions = F(TerminalSessions, state, at, detail),
            Queries = Queries.Values.Any(q => q.State == ObservationState.Pending)
                ? Queries.ToDictionary(kv => kv.Key, kv => F(kv.Value, state, at, detail)).ToImmutableSortedDictionary(StringComparer.Ordinal)
                : Queries,
        };
    }

    /// <summary>Merges a rescan result into a previous one: a device that is now offline keeps its last-seen time.</summary>
    public static DeviceResult MergeRescan(DeviceResult previous, DeviceResult current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        return current.LastSeen is null && previous.LastSeen is not null ? current with { LastSeen = previous.LastSeen } : current;
    }

    /// <summary>
    /// Continuous operation: an answered round replaces the row (as <see cref="MergeRescan"/>); an unanswered one keeps what is
    /// known and only updates status and scan time. Clearing offline fields is a separate, configured step (BKG-02, review C-05).
    /// </summary>
    public static DeviceResult MergeBackground(DeviceResult previous, DeviceResult current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);
        return current.Status == DeviceStatus.Online
            ? MergeRescan(previous, current)
            : previous with { Status = current.Status, LastScanned = current.LastScanned, Revision = current.Revision, IsComplete = current.IsComplete };
    }

    public required DateTimeOffset LastScanned { get; init; }

    public DateTimeOffset? LastSeen { get; init; }

    /// <summary>True when all requested enrichment for this scan pass has finished.</summary>
    public bool IsComplete { get; init; }

    /// <summary>Monotonic per-session revision; consumers drop out-of-order snapshots.</summary>
    public long Revision { get; init; }
}
