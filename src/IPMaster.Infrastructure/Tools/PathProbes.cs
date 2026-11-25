using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

/// <summary>Don't-fragment ICMP echo for path MTU discovery (D-093). IPv4 only; on platforms where .NET can only use the
/// system ping utility with its default payload (unprivileged Linux/macOS, D-067) the probe reports <see cref="MtuProbe.Error"/>.</summary>
public static class PathProbes
{
    public static async Task<MtuProbe> MtuProbeAsync(IPAddress destination, int packetSize, TimeSpan timeout, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(destination);
        if (destination.AddressFamily != AddressFamily.InterNetwork || packetSize < PathMtu.IcmpOverhead) return MtuProbe.Error;
        using var ping = new Ping();
        try
        {
            var reply = await ping.SendPingAsync(destination, timeout, new byte[packetSize - PathMtu.IcmpOverhead], new PingOptions(128, dontFragment: true), ct).ConfigureAwait(false);
            return reply.Status switch
            {
                IPStatus.Success => MtuProbe.Reply,
                IPStatus.PacketTooBig => MtuProbe.TooBig,
                _ => MtuProbe.NoReply,
            };
        }
        catch (Exception ex) when (ex is PingException or PlatformNotSupportedException or InvalidOperationException)
        {
            return MtuProbe.Error;
        }
    }
}
