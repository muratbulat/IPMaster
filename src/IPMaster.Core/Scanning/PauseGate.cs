namespace IPMaster.Core.Scanning;

/// <summary>Async gate: open = running, closed = paused. Work already in flight is not interrupted.</summary>
public sealed class PauseGate
{
    private readonly object _lock = new();
    private TaskCompletionSource _open = CreateOpen();

    public bool IsPaused
    {
        get
        {
            lock (_lock) return !_open.Task.IsCompleted;
        }
    }

    public void Pause()
    {
        lock (_lock)
        {
            if (_open.Task.IsCompleted) _open = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    public void Resume()
    {
        lock (_lock) _open.TrySetResult();
    }

    public Task WaitAsync(CancellationToken cancellationToken)
    {
        Task t;
        lock (_lock) t = _open.Task;
        return t.IsCompleted ? Task.CompletedTask : t.WaitAsync(cancellationToken);
    }

    private static TaskCompletionSource CreateOpen()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        tcs.SetResult();
        return tcs;
    }
}
