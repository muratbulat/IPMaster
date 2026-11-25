using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

public sealed record SyslogListenOptions
{
    public IPAddress Address { get; init; } = IPAddress.Any;

    public bool EnableUdp { get; init; } = true;

    public bool EnableTcp { get; init; } = true;

    /// <summary>0 = any free port (tests).</summary>
    public int UdpPort { get; init; } = 514;

    /// <summary>0 = any free port (tests).</summary>
    public int TcpPort { get; init; } = 514;

    public int QueueCapacity { get; init; } = 10_000;

    public int MaxTcpConnections { get; init; } = 32;

    public int MaxMessageBytes { get; init; } = 64 * 1024;

    /// <summary>A TCP connection that sends nothing for this long is closed.</summary>
    public TimeSpan TcpIdleTimeout { get; init; } = TimeSpan.FromMinutes(10);
}

public sealed record SyslogStats(long Received, long Dropped, long Oversized, int TcpConnections, long RejectedConnections);

/// <summary>
/// Syslog Receiver (D-079): UDP and TCP (RFC 6587 octet counting or newline framing) listeners feeding one bounded
/// queue; when the consumer falls behind, new messages are dropped and counted. Stopping closes every socket so the
/// ports are released immediately. Nothing is forwarded, stored or answered.
/// </summary>
public sealed class SyslogReceiver : IAsyncDisposable
{
    private readonly SyslogListenOptions _o;
    private readonly Channel<SyslogMessage> _queue;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<Task> _loops = [];
    private readonly Dictionary<TcpClient, Task?> _clients = [];
    private readonly Lock _gate = new();
    private Socket? _udp;
    private TcpListener? _tcp;
    private long _received;
    private long _dropped;
    private long _oversized;
    private long _rejected;

    private SyslogReceiver(SyslogListenOptions o)
    {
        _o = o;
        _queue = Channel.CreateBounded<SyslogMessage>(new BoundedChannelOptions(Math.Max(1, o.QueueCapacity)) { SingleReader = true, FullMode = BoundedChannelFullMode.Wait });
    }

    public ChannelReader<SyslogMessage> Messages => _queue.Reader;

    public int UdpPort => (_udp?.LocalEndPoint as IPEndPoint)?.Port ?? 0;

    public int TcpPort => (_tcp?.LocalEndpoint as IPEndPoint)?.Port ?? 0;

    public SyslogStats Stats
    {
        get
        {
            int connections;
            lock (_gate) connections = _clients.Count;
            return new SyslogStats(Interlocked.Read(ref _received), Interlocked.Read(ref _dropped), Interlocked.Read(ref _oversized), connections, Interlocked.Read(ref _rejected));
        }
    }

    /// <summary>Binds the requested listeners; throws <see cref="SocketException"/> (e.g. AddressAlreadyInUse, AccessDenied) with nothing left bound.</summary>
    public static SyslogReceiver Start(SyslogListenOptions o)
    {
        ArgumentNullException.ThrowIfNull(o);
        if (!o.EnableUdp && !o.EnableTcp) throw new ArgumentException("Enable UDP, TCP or both.", nameof(o));
        var r = new SyslogReceiver(o);
        try
        {
            if (o.EnableUdp)
            {
                r._udp = new Socket(o.Address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                if (o.Address.Equals(IPAddress.IPv6Any)) r._udp.DualMode = true;
                r._udp.ExclusiveAddressUse = OperatingSystem.IsWindows();
                r._udp.Bind(new IPEndPoint(o.Address, o.UdpPort));
                r._loops.Add(Task.Run(r.UdpLoopAsync));
            }

            if (o.EnableTcp)
            {
                r._tcp = new TcpListener(o.Address, o.TcpPort) { ExclusiveAddressUse = OperatingSystem.IsWindows() };
                if (o.Address.Equals(IPAddress.IPv6Any)) r._tcp.Server.DualMode = true;
                r._tcp.Start(16);
                r._loops.Add(Task.Run(r.AcceptLoopAsync));
            }

            return r;
        }
        catch
        {
            r._udp?.Dispose();
            r._tcp?.Stop();
            throw;
        }
    }

    private void Enqueue(ReadOnlySpan<byte> frame, EndPoint? from, string transport)
    {
        Interlocked.Increment(ref _received);
        var source = from is IPEndPoint ep ? (ep.Address.IsIPv4MappedToIPv6 ? ep.Address.MapToIPv4() : ep.Address).ToString() : "?";
        var m = SyslogParser.Parse(frame, DateTime.UtcNow, source, transport);
        if (!_queue.Writer.TryWrite(m)) Interlocked.Increment(ref _dropped);
    }

    private async Task UdpLoopAsync()
    {
        var buffer = new byte[65_535];
        EndPoint any = _o.Address.AddressFamily == AddressFamily.InterNetworkV6 ? new IPEndPoint(IPAddress.IPv6Any, 0) : new IPEndPoint(IPAddress.Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            SocketReceiveFromResult r;
            try
            {
                r = await _udp!.ReceiveFromAsync(buffer, SocketFlags.None, any, _cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                if (ex.SocketErrorCode == SocketError.MessageSize) Interlocked.Increment(ref _oversized);
                continue; // ICMP from an earlier datagram, or one larger than the buffer
            }

            if (r.ReceivedBytes > _o.MaxMessageBytes)
            {
                Interlocked.Increment(ref _oversized);
                continue;
            }

            Enqueue(buffer.AsSpan(0, r.ReceivedBytes), r.RemoteEndPoint, "UDP");
        }
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _tcp!.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            lock (_gate)
            {
                if (_clients.Count >= _o.MaxTcpConnections)
                {
                    Interlocked.Increment(ref _rejected);
                    client.Dispose();
                    continue;
                }

                _clients.Add(client, null);
            }

            var task = Task.Run(() => ConnectionAsync(client));
            lock (_gate)
            {
                if (_clients.ContainsKey(client)) _clients[client] = task; // removed again when the connection ends: the set stays bounded
            }
        }
    }

    private async Task ConnectionAsync(TcpClient client)
    {
        var decoder = new SyslogStreamDecoder(_o.MaxMessageBytes);
        var from = client.Client.RemoteEndPoint;
        var buffer = new byte[16 * 1024];
        try
        {
            var stream = client.GetStream();
            while (!_cts.IsCancellationRequested)
            {
                using var idle = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                idle.CancelAfter(_o.TcpIdleTimeout);
                var n = await stream.ReadAsync(buffer, idle.Token).ConfigureAwait(false);
                if (n == 0) break;
                var before = decoder.Oversized;
                foreach (var frame in decoder.Push(buffer.AsSpan(0, n))) Enqueue(frame, from, "TCP");
                Interlocked.Add(ref _oversized, decoder.Oversized - before);
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or SocketException)
        {
        }
        finally
        {
            lock (_gate) _clients.Remove(client);
            client.Dispose();
        }
    }

    /// <summary>Stops the listeners, closes all connections and waits for every loop; the ports are free when this returns.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_cts.IsCancellationRequested) return;
        await _cts.CancelAsync().ConfigureAwait(false);
        _udp?.Dispose();
        _tcp?.Stop();
        Task[] loops;
        lock (_gate)
        {
            foreach (var c in _clients.Keys) c.Dispose();
            loops = [.. _loops, .. _clients.Values.OfType<Task>()];
        }

        await Task.WhenAll(loops).ConfigureAwait(false);
        _queue.Writer.TryComplete();
        _cts.Dispose();
    }
}
