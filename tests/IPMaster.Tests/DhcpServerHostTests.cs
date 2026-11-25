using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using IPMaster.Core.Discovery;
using IPMaster.Infrastructure.Discovery;

namespace IPMaster.Tests;

/// <summary>
/// The DHCP server socket host on loopback with ephemeral ports (D-090). Never binds UDP 67/68 and never sends to a
/// real network: replies go to 127.0.0.1 instead of the broadcast address.
/// </summary>
public class DhcpServerHostTests
{
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(10);

    private static readonly DhcpServerConfig Config = new()
    {
        ServerAddress = IPAddress.Parse("192.168.88.1"),
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        PoolStart = IPAddress.Parse("192.168.88.100"),
        PoolEnd = IPAddress.Parse("192.168.88.110"),
    };

    private static byte[] Packet(DhcpMessageType type, IPAddress? requested = null) => new DhcpMessage
    {
        Op = 1,
        TransactionId = 0xCAFE,
        Flags = 0x8000,
        ClientMac = PhysicalAddress.Parse("00-11-22-33-44-55"),
        Options = requested is null
            ? new Dictionary<byte, byte[]> { [53] = [(byte)type], [12] = "XCC-7X06"u8.ToArray() }
            : new Dictionary<byte, byte[]> { [53] = [(byte)type], [50] = requested.GetAddressBytes(), [54] = Config.ServerAddress.GetAddressBytes() },
    }.Serialize();

    private static async Task<DhcpMessage> ReceiveAsync(UdpClient client)
    {
        var r = await client.ReceiveAsync(TestContext.Current.CancellationToken).AsTask().WaitAsync(Wait);
        return DhcpMessage.Parse(r.Buffer)!;
    }

    [Fact]
    public async Task Discover_to_ack_over_udp_on_loopback()
    {
        using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var events = new ConcurrentQueue<DhcpEvent>();
        await using var host = DhcpServerHost.Start(Config, IPAddress.Loopback, events.Enqueue, serverPort: 0,
            clientPort: ((IPEndPoint)client.Client.LocalEndPoint!).Port, broadcast: IPAddress.Loopback);

        await client.SendAsync(Packet(DhcpMessageType.Discover), host.LocalEndPoint, TestContext.Current.CancellationToken);
        var offer = await ReceiveAsync(client);
        Assert.Equal((DhcpMessageType.Offer, 0xCAFEu), (offer.Type!.Value, offer.TransactionId));

        await client.SendAsync(Packet(DhcpMessageType.Request, offer.YourAddress), host.LocalEndPoint, TestContext.Current.CancellationToken);
        var ack = await ReceiveAsync(client);
        Assert.Equal(DhcpMessageType.Ack, ack.Type);
        var lease = Assert.Single(host.Leases);
        Assert.Equal((DhcpLeaseState.Bound, "XCC-7X06"), (lease.State, lease.HostName));
        Assert.Contains(events, e => e.Kind == DhcpEventKind.Acknowledged);
    }

    [Fact]
    public async Task Malformed_packet_is_reported_and_the_server_keeps_running()
    {
        using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var events = new ConcurrentQueue<DhcpEvent>();
        await using var host = DhcpServerHost.Start(Config, IPAddress.Loopback, events.Enqueue, 0, ((IPEndPoint)client.Client.LocalEndPoint!).Port, IPAddress.Loopback);
        await client.SendAsync(new byte[] { 1, 2, 3 }, host.LocalEndPoint, TestContext.Current.CancellationToken);
        await client.SendAsync(Packet(DhcpMessageType.Discover), host.LocalEndPoint, TestContext.Current.CancellationToken);
        Assert.Equal(DhcpMessageType.Offer, (await ReceiveAsync(client)).Type);
        Assert.Contains(events, e => e.Kind == DhcpEventKind.Ignored && e.Text.Contains("Malformed", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Port_in_use_is_reported_and_stop_releases_the_port()
    {
        var first = DhcpServerHost.Start(Config, IPAddress.Loopback, null, serverPort: 0);
        var port = first.LocalEndPoint.Port;
        var ex = Assert.Throws<InvalidOperationException>(() => DhcpServerHost.Start(Config, IPAddress.Loopback, null, serverPort: port));
        Assert.Contains("already in use", ex.Message, StringComparison.Ordinal);

        await first.StopAsync().WaitAsync(Wait);
        await first.StopAsync().WaitAsync(Wait); // idempotent
        Assert.True(first.Completion.IsCompletedSuccessfully);
        await using var second = DhcpServerHost.Start(Config, IPAddress.Loopback, null, serverPort: port); // port is free again
        await first.DisposeAsync();
    }

    [Fact]
    public async Task No_events_after_stop()
    {
        using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var events = new ConcurrentQueue<DhcpEvent>();
        var host = DhcpServerHost.Start(Config, IPAddress.Loopback, events.Enqueue, 0, ((IPEndPoint)client.Client.LocalEndPoint!).Port, IPAddress.Loopback);
        var target = host.LocalEndPoint;
        await host.DisposeAsync();
        await client.SendAsync(Packet(DhcpMessageType.Discover), target, TestContext.Current.CancellationToken);
        await Task.Delay(200, TestContext.Current.CancellationToken);
        Assert.Empty(events);
    }

    [Fact]
    public async Task Listen_only_reports_clients_and_never_replies()
    {
        using var client = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var seen = new TaskCompletionSource<DhcpMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var listener = DhcpServerHost.Listen(IPAddress.Loopback, m => seen.TrySetResult(m), serverPort: 0);
        await client.SendAsync(Packet(DhcpMessageType.Discover), listener.LocalEndPoint, TestContext.Current.CancellationToken);
        var m = await seen.Task.WaitAsync(Wait, TestContext.Current.CancellationToken);
        Assert.Equal("XCC-7X06", m.HostName);
        var o = Assert.Single(FrameObservations.FromDhcp(m, DateTimeOffset.UtcNow));
        Assert.Equal(PhysicalAddress.Parse("00-11-22-33-44-55"), o.Mac);
        await Task.Delay(300, TestContext.Current.CancellationToken);
        Assert.Equal(0, client.Available); // nothing was sent back
        Assert.Empty(listener.Leases);
    }

    [Fact]
    public void Invalid_configuration_never_binds()
    {
        var bad = Config with { PoolStart = IPAddress.Parse("10.0.0.1") };
        Assert.Throws<ArgumentException>(() => DhcpServerHost.Start(bad, IPAddress.Loopback, null, serverPort: 0));
    }
}
