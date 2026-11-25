using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Probes;

/// <summary>
/// ICMP echo via <see cref="Ping"/>. On Windows this uses IcmpSendEcho2 (no elevation needed); on Linux and
/// macOS .NET uses raw/datagram ICMP sockets when permitted and otherwise falls back to the system
/// <c>ping</c> utility, in which case TTL may be unavailable.
/// </summary>
public sealed class IcmpProbe : IIcmpProbe
{
    private static readonly byte[] Payload = "IPMaster-echo-req"u8.ToArray();
    private static volatile bool _defaultPayload;

    public CapabilityStatus Capability { get; } = OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes("ICMP echo (Windows ICMP API).")
        : CapabilityStatus.Yes("ICMP echo (ICMP socket or system ping utility).");

    public async Task<ProbeReply> PingAsync(IPAddress address, TimeSpan timeout, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(address);
        using var ping = new Ping();
        PingReply reply;
        try
        {
            try
            {
                reply = await ping.SendPingAsync(address, timeout, _defaultPayload ? null : Payload, new PingOptions(128, dontFragment: false), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (PlatformNotSupportedException) when (!_defaultPayload)
            {
                // Linux/macOS without CAP_NET_RAW: .NET falls back to the system ping utility, which only sends the
                // default payload. Use it from now on (D-067).
                _defaultPayload = true;
                reply = await ping.SendPingAsync(address, timeout, null, new PingOptions(128, dontFragment: false), cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (PingException ex)
        {
            return new ProbeReply(ObservationState.Failed, Detail: ex.InnerException?.Message ?? ex.Message);
        }
        catch (PlatformNotSupportedException ex)
        {
            return new ProbeReply(ObservationState.Failed, Detail: ex.Message);
        }

        return reply.Status switch
        {
            IPStatus.Success => new ProbeReply(ObservationState.Success, TimeSpan.FromMilliseconds(reply.RoundtripTime),
                reply.Options?.Ttl is > 0 and var ttl ? ttl : null),
            IPStatus.TimedOut => new ProbeReply(ObservationState.NoResponse, Detail: "Request timed out."),
            _ => new ProbeReply(ObservationState.NoResponse, Detail: reply.Status.ToString()),
        };
    }
}
