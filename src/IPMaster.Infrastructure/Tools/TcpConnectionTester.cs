using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

public delegate Task<IPAddress[]> HostResolver(string host, CancellationToken ct);

public delegate Task TcpConnector(Socket socket, IPEndPoint endpoint, CancellationToken ct);

public enum DnsRefresh
{
    EveryAttempt,
    OncePerRun,
}

public sealed record TcpRunOptions
{
    /// <summary>Bind the local side to this address (port 0). The OS still chooses the route; a mismatch fails as BindFailure or Unreachable.</summary>
    public IPAddress? Source { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    public int Concurrency { get; init; } = 16;

    public bool Continuous { get; init; }

    public TimeSpan Interval { get; init; } = TimeSpan.FromSeconds(5);

    public DnsRefresh DnsRefresh { get; init; } = DnsRefresh.EveryAttempt;
}

/// <summary>
/// TCP Connection Tester (D-074): connect, measure, close (no payload). Attempts for one target:port never overlap; the
/// scheduler skips a target whose previous attempt is still running instead of piling up work.
/// </summary>
public sealed class TcpConnectionTester(HostResolver? resolver = null, TcpConnector? connector = null)
{
    private readonly HostResolver _resolver = resolver ?? ((h, ct) => Dns.GetHostAddressesAsync(h, ct));
    private readonly TcpConnector _connector = connector ?? ((s, ep, ct) => s.ConnectAsync(ep, ct).AsTask());

    public async Task<TcpAttempt> AttemptAsync(TcpTarget target, TcpRunOptions o, ConcurrentDictionary<string, IPAddress[]>? dnsCache, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(o);
        var at = DateTimeOffset.Now;
        TimeSpan? dnsTime = null;
        IPAddress[] addresses;
        if (IPAddress.TryParse(target.Host, out var literal))
        {
            addresses = [literal];
        }
        else if (dnsCache is not null && dnsCache.TryGetValue(target.Host, out var cached))
        {
            addresses = cached;
        }
        else
        {
            var sw = Stopwatch.StartNew();
            try
            {
                using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dnsCts.CancelAfter(o.Timeout);
                addresses = await _resolver(target.Host, dnsCts.Token).ConfigureAwait(false);
                dnsTime = sw.Elapsed;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return new TcpAttempt(target, at, null, null, sw.Elapsed, null, TcpOutcome.Cancelled, null, "Cancelled.");
            }
            catch (OperationCanceledException)
            {
                return new TcpAttempt(target, at, null, null, sw.Elapsed, null, TcpOutcome.DnsFailure, null, "Name resolution timed out.");
            }
            catch (SocketException ex)
            {
                return new TcpAttempt(target, at, null, null, sw.Elapsed, null, TcpOutcome.DnsFailure, ex.SocketErrorCode.ToString(), ex.Message);
            }

            if (addresses.Length == 0) return new TcpAttempt(target, at, null, null, dnsTime, null, TcpOutcome.DnsFailure, null, "The name has no addresses.");
            dnsCache?.TryAdd(target.Host, addresses);
        }

        // with a source address, use an address of the same family
        var address = o.Source is { } src ? addresses.FirstOrDefault(a => a.AddressFamily == src.AddressFamily) : addresses[0];
        if (address is null)
        {
            return new TcpAttempt(target, at, null, null, dnsTime, null, TcpOutcome.BindFailure, null,
                $"The source address {o.Source} is {o.Source!.AddressFamily}, but {target.Host} has no address of that family.");
        }

        var endpoint = new IPEndPoint(address, target.Port);
        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        if (o.Source is not null)
        {
            try
            {
                socket.Bind(new IPEndPoint(o.Source, 0));
            }
            catch (SocketException ex)
            {
                return new TcpAttempt(target, at, endpoint.ToString(), null, dnsTime, null, TcpOutcome.BindFailure, ex.SocketErrorCode.ToString(),
                    $"Cannot use {o.Source} as the source address: {ex.Message}");
            }
        }

        var connectWatch = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(o.Timeout);
        try
        {
            await _connector(socket, endpoint, cts.Token).ConfigureAwait(false);
            var elapsed = connectWatch.Elapsed;
            var local = socket.LocalEndPoint?.ToString();
            socket.Close(); // no application payload is ever sent
            return new TcpAttempt(target, at, endpoint.ToString(), local, dnsTime, elapsed, TcpOutcome.Connected, null, "");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return new TcpAttempt(target, at, endpoint.ToString(), null, dnsTime, null, TcpOutcome.Cancelled, null, "Cancelled.");
        }
        catch (OperationCanceledException)
        {
            return new TcpAttempt(target, at, endpoint.ToString(), null, dnsTime, null, TcpOutcome.Timeout, null,
                $"No answer within {o.Timeout.TotalMilliseconds:0} ms (filtered, host down, or path dropped).");
        }
        catch (SocketException ex)
        {
            var outcome = ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => TcpOutcome.Refused,
                SocketError.TimedOut => TcpOutcome.Timeout,
                SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.NetworkDown or SocketError.HostDown => TcpOutcome.Unreachable,
                SocketError.AddressNotAvailable => TcpOutcome.BindFailure,
                _ => TcpOutcome.Error,
            };
            return new TcpAttempt(target, at, endpoint.ToString(), null, dnsTime, connectWatch.Elapsed, outcome, ex.SocketErrorCode.ToString(), ex.Message);
        }
    }

    /// <summary>
    /// Single pass (every target once) or continuous rounds every <see cref="TcpRunOptions.Interval"/>. Concurrency is
    /// bounded; a target still in flight when its next round comes is skipped (reported through <paramref name="skipped"/>).
    /// </summary>
    public async Task RunAsync(IReadOnlyList<TcpTarget> targets, TcpRunOptions o, Action<TcpAttempt> onResult, Action<TcpTarget>? skipped, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(targets);
        ArgumentNullException.ThrowIfNull(onResult);
        using var gate = new SemaphoreSlim(Math.Clamp(o.Concurrency, 1, 256));
        var inFlight = new ConcurrentDictionary<string, byte>();
        var cache = o.DnsRefresh == DnsRefresh.OncePerRun ? new ConcurrentDictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase) : null;
        var running = new List<Task>();
        do
        {
            foreach (var t in targets)
            {
                if (!inFlight.TryAdd(t.Key, 0))
                {
                    skipped?.Invoke(t);
                    continue;
                }

                running.Add(Task.Run(async () =>
                {
                    try
                    {
                        await gate.WaitAsync(ct).ConfigureAwait(false);
                        try
                        {
                            var a = await AttemptAsync(t, o, cache, ct).ConfigureAwait(false);
                            if (a.Outcome != TcpOutcome.Cancelled) onResult(a);
                        }
                        finally
                        {
                            gate.Release();
                        }
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        // stopping
                    }
                    finally
                    {
                        inFlight.TryRemove(t.Key, out _);
                    }
                }, CancellationToken.None));
            }

            running.RemoveAll(x => x.IsCompleted);
            if (!o.Continuous) break;
            try
            {
                await Task.Delay(o.Interval, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
        while (!ct.IsCancellationRequested);

        await Task.WhenAll(running).ConfigureAwait(false);
    }
}
