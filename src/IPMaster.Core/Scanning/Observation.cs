namespace IPMaster.Core.Scanning;

/// <summary>
/// Outcome of one probe/enrichment. Keeps "no data" cases distinguishable instead of collapsing them
/// into empty strings.
/// </summary>
public enum ObservationState
{
    /// <summary>Feature disabled or not applicable for this device.</summary>
    NotRequested,

    /// <summary>Requested, not finished yet.</summary>
    Pending,

    /// <summary>Completed with a value.</summary>
    Success,

    /// <summary>Completed successfully, but there is no value (e.g. no PTR record).</summary>
    Empty,

    /// <summary>Target did not respond.</summary>
    NoResponse,

    Timeout,
    AccessDenied,

    /// <summary>The scanner platform, privileges or target do not support this probe.</summary>
    Unsupported,

    Cancelled,
    Failed,
}

public readonly record struct Observation<T>(ObservationState State, T? Value, string? Detail, DateTimeOffset? ObservedAt)
{
    public static Observation<T> NotRequested => new(ObservationState.NotRequested, default, null, null);

    public static Observation<T> Pending => new(ObservationState.Pending, default, null, null);

    public bool HasValue => State == ObservationState.Success;

    public static Observation<T> Ok(T value, DateTimeOffset at) => new(ObservationState.Success, value, null, at);

    public static Observation<T> Of(ObservationState state, DateTimeOffset at, string? detail = null)
        => new(state, default, detail, at);
}
