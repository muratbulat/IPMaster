using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Scanning;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Infrastructure.Probes;

/// <summary>
/// Reverse lookups ask the system's DNS server directly first (D-083): a definite answer (a name, NXDOMAIN or empty
/// NOERROR) takes milliseconds, where the OS resolver spends ~3 s per unnamed address on fallbacks. Only when no server
/// answers definitely is the OS resolver (getnameinfo: hosts file, other servers, NetBIOS) used. Timeouts and
/// concurrency are enforced by the scan engine.
/// </summary>
public sealed class DnsHostNameResolver(Func<IReadOnlyList<IPEndPoint>>? servers = null) : IHostNameResolver
{
    private static readonly DnsQueryOptions Direct = new() { Timeout = TimeSpan.FromMilliseconds(800), Retries = 1, Transport = DnsTransport.Udp };
    private readonly Func<IReadOnlyList<IPEndPoint>> _servers = servers ?? (() => DnsClient.SystemServers().Select(a => new IPEndPoint(a, 53)).ToList());
    private readonly object _lock = new();
    private IReadOnlyList<IPEndPoint>? _list;
    private long _at;

    public DnsHostNameResolver()
        : this(null)
    {
    }

    public async Task<string?> ReverseLookupAsync(IPAddress address, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (Servers().FirstOrDefault() is { } server)
        {
            var r = await DnsClient.QueryAsync(server, DnsWire.PtrName(address), (ushort)DnsType.PTR, Direct, cancellationToken).ConfigureAwait(false);
            if (r.Outcome == DnsOutcome.Reply && r.Message!.Rcode is 0 or 3)
            {
                var ptr = r.Records.Select(x => x.Data.TrimEnd('.')).FirstOrDefault(n => n.Length > 0);
                if (ptr is not null || !IsOwnAddress(address)) return ptr;
                // the OS knows its own name even when DNS has no PTR record (D-085)
            }
        }

        var entry = await Dns.GetHostEntryAsync(address).WaitAsync(cancellationToken).ConfigureAwait(false);
        var name = entry.HostName;
        return string.IsNullOrWhiteSpace(name) || IPAddress.TryParse(name, out _) ? null : name;
    }

    public Task<IPAddress[]> ForwardLookupAsync(string hostName, CancellationToken cancellationToken)
        => Dns.GetHostAddressesAsync(hostName, cancellationToken);

    private static bool IsOwnAddress(IPAddress address)
        => IPAddress.IsLoopback(address) || NetworkInterface.GetAllNetworkInterfaces()
            .Any(n => n.GetIPProperties().UnicastAddresses.Any(u => u.Address.Equals(address)));

    /// <summary>The configured servers, re-read at most every 30 s (adapters change; a scan asks hundreds of times).</summary>
    private IReadOnlyList<IPEndPoint> Servers()
    {
        lock (_lock)
        {
            if (_list is null || Environment.TickCount64 - _at > 30_000)
            {
                // IPv4 first: link-local IPv6 servers without a scope often cannot be reached directly
                _list = _servers().OrderBy(e => e.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 0 : 1).ToList();
                _at = Environment.TickCount64;
            }

            return _list;
        }
    }
}
