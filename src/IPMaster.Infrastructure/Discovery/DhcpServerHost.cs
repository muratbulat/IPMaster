using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Discovery;

namespace IPMaster.Infrastructure.Discovery;

/// <summary>
/// Runs <see cref="DhcpServerEngine"/> on one UDP socket bound to the server address of the selected adapter (D-090).
/// Started only by an explicit user action; never binds to all interfaces. One receive loop, one packet at a time
/// (bounded by design). <see cref="StopAsync"/> closes the socket and completes when the loop has ended.
/// </summary>
public sealed class DhcpServerHost : IAsyncDisposable
{
    private readonly Socket _socket;
    private readonly DhcpServerEngine? _engine;
    private readonly Action<DhcpMessage>? _onClientMessage;
    private readonly IPAddress _broadcast;
    private readonly int _clientPort;
    private readonly CancellationTokenSource _stop = new();
    private readonly object _lock = new();
    private readonly Task _loop;

    private DhcpServerHost(Socket socket, DhcpServerEngine? engine, IPAddress broadcast, int clientPort, Action<DhcpEvent>? onEvent, Action<DhcpMessage>? onClientMessage)
    {
        _socket = socket;
        _engine = engine;
        _onClientMessage = onClientMessage;
        _broadcast = broadcast;
        _clientPort = clientPort;
        Event = onEvent;
        _loop = Task.Run(LoopAsync);
    }

    /// <summary>Called on the receive loop for every handled or ignored message; never after <see cref="StopAsync"/>.</summary>
    private Action<DhcpEvent>? Event { get; }

    public IPEndPoint LocalEndPoint => (IPEndPoint)_socket.LocalEndPoint!;

    /// <summary>Completes when the server stopped; faulted when the socket failed (e.g. the adapter went away).</summary>
    public Task Completion => _loop;

    public IReadOnlyList<DhcpLease> Leases
    {
        get
        {
            lock (_lock) return _engine?.Leases ?? [];
        }
    }

    /// <summary>
    /// Validates <paramref name="config"/> and binds UDP <paramref name="serverPort"/> on <paramref name="bindAddress"/>.
    /// Throws <see cref="ArgumentException"/> for an invalid configuration and <see cref="InvalidOperationException"/>
    /// when the port cannot be bound (in use, or not permitted). Ports other than 67/68 are for loopback tests.
    /// </summary>
    public static DhcpServerHost Start(DhcpServerConfig config, IPAddress bindAddress, Action<DhcpEvent>? onEvent,
        int serverPort = 67, int clientPort = 68, IPAddress? broadcast = null, TimeProvider? time = null, Action<DhcpMessage>? onClientMessage = null)
    {
        ArgumentNullException.ThrowIfNull(config);
        ArgumentNullException.ThrowIfNull(bindAddress);
        var engine = new DhcpServerEngine(config, time);
        return new DhcpServerHost(Bind(bindAddress, serverPort), engine, broadcast ?? IPAddress.Broadcast, clientPort, onEvent, onClientMessage);
    }

    /// <summary>
    /// Passive DHCP listening (D-090): receives client DISCOVER/REQUEST/INFORM broadcasts on the selected address and
    /// never sends anything. Needs no packet capture driver; needs UDP 67 to be free.
    /// </summary>
    public static DhcpServerHost Listen(IPAddress bindAddress, Action<DhcpMessage> onClientMessage, int serverPort = 67)
    {
        ArgumentNullException.ThrowIfNull(bindAddress);
        ArgumentNullException.ThrowIfNull(onClientMessage);
        return new DhcpServerHost(Bind(bindAddress, serverPort), null, IPAddress.Broadcast, 68, null, onClientMessage);
    }

    private static Socket Bind(IPAddress bindAddress, int serverPort)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            if (OperatingSystem.IsWindows()) socket.ExclusiveAddressUse = true; // never share port 67 with another server
            socket.EnableBroadcast = true;
            socket.Bind(new IPEndPoint(bindAddress, serverPort));
        }
        catch (SocketException ex)
        {
            socket.Dispose();
            throw new InvalidOperationException(ex.SocketErrorCode switch
            {
                SocketError.AddressAlreadyInUse => $"UDP port {serverPort} on {bindAddress} is already in use: another DHCP server (for example Internet Connection Sharing) runs on this computer.",
                SocketError.AccessDenied => $"Binding UDP port {serverPort} was denied: run IPMaster as administrator (root on Linux/macOS).",
                SocketError.AddressNotAvailable => $"{bindAddress} is not an address of this computer: assign it to the adapter first.",
                _ => $"UDP port {serverPort} on {bindAddress} cannot be used: {ex.Message}",
            }, ex);
        }

        return socket;
    }

    private async Task LoopAsync()
    {
        var ct = _stop.Token;
        var buffer = new byte[1500];
        while (!ct.IsCancellationRequested)
        {
            SocketReceiveFromResult r;
            try
            {
                r = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, new IPEndPoint(IPAddress.Any, 0), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ct.IsCancellationRequested && ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                continue; // Windows reports an earlier ICMP port-unreachable here; not a server failure
            }

            var from = (IPEndPoint)r.RemoteEndPoint;
            var message = DhcpMessage.Parse(buffer.AsSpan(0, r.ReceivedBytes));
            if (message is null)
            {
                Raise(new DhcpEvent(DateTimeOffset.UtcNow, DhcpEventKind.Ignored, System.Net.NetworkInformation.PhysicalAddress.None, from.Address,
                    $"Malformed or non-Ethernet DHCP packet ({r.ReceivedBytes} bytes) from {from.Address} ignored."));
                continue;
            }

            if (message.Op == 1 && !_stop.IsCancellationRequested) _onClientMessage?.Invoke(message);
            if (_engine is null) continue; // listen only

            DhcpResult result;
            lock (_lock) result = _engine.Handle(message);
            if (result.Reply is { } reply)
            {
                var to = DhcpServerEngine.ReplyTarget(message, reply, _broadcast);
                if (to.Port == 68) to = new IPEndPoint(to.Address, _clientPort);
                try
                {
                    await _socket.SendToAsync(reply.Serialize(), SocketFlags.None, to, ct).ConfigureAwait(false);
                }
                catch (Exception ex) when (ct.IsCancellationRequested && ex is OperationCanceledException or SocketException or ObjectDisposedException)
                {
                    return;
                }
            }

            Raise(result.Event);
        }
    }

    private void Raise(DhcpEvent e)
    {
        if (!_stop.IsCancellationRequested) Event?.Invoke(e);
    }

    /// <summary>Stops receiving, releases the port and waits for the loop. Safe to call repeatedly.</summary>
    public async Task StopAsync()
    {
        if (!_stop.IsCancellationRequested) await _stop.CancelAsync().ConfigureAwait(false);
        _socket.Dispose(); // also ends a pending receive on platforms that ignore the token
        try
        {
            await _loop.ConfigureAwait(false);
        }
        catch (SocketException)
        {
            // the loop already faulted (adapter gone); Completion carries it
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        _stop.Dispose();
    }
}
