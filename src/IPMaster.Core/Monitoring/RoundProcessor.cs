using System.Threading.Channels;

namespace IPMaster.Core.Monitoring;

/// <summary>
/// Single-consumer work queue for background rounds (review C-06). At most <c>capacity</c> items wait while another is
/// processed; when a newer item arrives the oldest waiting one is dropped and reported, so slow processing (e.g.
/// notifications to an unreachable SMTP server) can never build an unbounded backlog. A handler fault is reported through
/// <c>failed</c> at once and the queue keeps going (D-086); without <c>failed</c> it ends the loop. Stopping cancels the
/// running handler and waits for it.
/// </summary>
public sealed class RoundProcessor<T> : IDisposable
{
    private readonly Channel<T> _channel;
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _loop;

    public RoundProcessor(Func<T, CancellationToken, Task> handler, Action<T> dropped, int capacity = 1, Action<T, Exception>? failed = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(dropped);
        _channel = Channel.CreateBounded<T>(new BoundedChannelOptions(Math.Max(1, capacity)) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true }, dropped);
        _loop = Task.Run(async () =>
        {
            try
            {
                await foreach (var item in _channel.Reader.ReadAllAsync(_stop.Token).ConfigureAwait(false))
                {
                    try
                    {
                        await handler(item, _stop.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (_stop.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (Exception ex) when (failed is not null)
                    {
                        failed(item, ex);
                    }
                }
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                // stopping
            }
        });
    }

    /// <summary>Queues an item; ignored after <see cref="StopAsync"/>.</summary>
    public void Post(T item) => _channel.Writer.TryWrite(item);

    /// <summary>Processes what is queued unless <paramref name="cancelRunning"/>; then waits for the consumer to finish.</summary>
    public async Task StopAsync(bool cancelRunning = true)
    {
        _channel.Writer.TryComplete();
        if (cancelRunning) await _stop.CancelAsync().ConfigureAwait(false);
        await _loop.ConfigureAwait(false);
    }

    public void Dispose()
    {
        _channel.Writer.TryComplete();
        _stop.Cancel();
        _loop.Wait(TimeSpan.FromSeconds(5));
        _stop.Dispose();
    }
}
