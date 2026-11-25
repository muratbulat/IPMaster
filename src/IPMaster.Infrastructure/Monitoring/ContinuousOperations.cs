using System.Net;
using IPMaster.Core.Configuration;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Network;
using IPMaster.Core.Queries;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Export;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Security;

namespace IPMaster.Infrastructure.Monitoring;

/// <summary>
/// Background scanning with history, notifications and per-round file output (BKG-01..06, HIS-01..03), shared by the
/// desktop app and <c>/live</c>. The merged state of all rounds is kept in <see cref="Current"/>.
/// </summary>
public sealed class ContinuousOperations : IDisposable
{
    private readonly ScanEngine _engine;
    private readonly ScanPlanner _planner;
    private readonly QueryServices _queries;
    private readonly CredentialVault _vault;
    private readonly INetworkAdapterProvider _adapters;
    private readonly NetworkIdentifier _identifier;
    private readonly Dictionary<AddressKey, DeviceResult> _current = [];
    private readonly object _gate = new();
    private Task _stopping = Task.CompletedTask;
    private RoundProcessor<BackgroundRound>? _rounds;
    private RoundProcessor<BackgroundRound>? _notify;

    /// <summary>Rounds that may wait for recording; rounds are minutes apart, so a drop means recording is stuck.</summary>
    public const int EssentialQueue = 16;

    /// <summary>Time one round may spend sending notifications before the rest are skipped (review C-06).</summary>
    public static readonly TimeSpan NotificationBudget = TimeSpan.FromMinutes(2);
    private BackgroundScanner? _scanner;
    private QueryPlan? _queryPlan;
    private Func<AppSettings> _settings = () => new AppSettings();

    public ContinuousOperations(ScanEngine engine, ScanPlanner planner, QueryServices queries, CredentialVault vault, INetworkAdapterProvider adapters,
        IHistoryStore history, NetworkIdentifier identifier, NotificationDispatcher notifier)
    {
        _engine = engine;
        _planner = planner;
        _queries = queries;
        _vault = vault;
        _adapters = adapters;
        History = history;
        _identifier = identifier;
        Notifier = notifier;
    }

    public IHistoryStore History { get; }

    public NotificationDispatcher Notifier { get; }

    public BackgroundLog Log { get; } = new();

    public HistoryView HistoryView { get; } = new();

    public bool IsRunning => _scanner?.IsRunning == true;

    public int Round => _scanner?.Round ?? 0;

    public DateTimeOffset? NextRoundAt => _scanner?.NextRoundAt;

    /// <summary>Optional overrides for <c>/live</c>: output file instead of the Browsing setting.</summary>
    public string? OutputOverride { get; set; }

    /// <summary>After each round (thread pool): round, merged results, events.</summary>
    public event EventHandler<BackgroundRound>? RoundFinished;

    /// <summary>After a session is torn down: by <see cref="StopAsync"/> or because its loop ended by itself (thread pool).</summary>
    public event EventHandler? Stopped;

    public IReadOnlyList<DeviceResult> Current
    {
        get
        {
            lock (_current) return _current.Values.OrderBy(d => d.Key).ToList();
        }
    }

    /// <summary>
    /// Starts a session. Ignored while one is running or a previous one is still being torn down (await
    /// <see cref="StopAsync"/> first), so two sessions never overlap.
    /// </summary>
    public void Start(Func<AppSettings> settings, IEnumerable<DeviceResult>? baseline, IScanResultSink? live)
    {
        ArgumentNullException.ThrowIfNull(settings);
        BackgroundScanner scanner;
        lock (_gate)
        {
            if (_scanner is not null || !_stopping.IsCompleted) return;
            _settings = settings;
            var s = settings();
            lock (_current)
            {
                _current.Clear();
                foreach (var d in baseline ?? []) _current[d.Key] = d;
            }

            _queryPlan = _queries.Plan(s);
            scanner = _scanner = new BackgroundScanner(_engine, BuildRequestAsync) { Settings = s.Background, LiveSink = live };
            // Essential work (state, event log, history, file output) has its own deeper queue, so slow notifications can
            // only drop notifications, never history (D-086). Both queues stay bounded and log every drop and fault.
            var rounds = _rounds = new RoundProcessor<BackgroundRound>(OnRoundAsync, dropped => Log.Add(DateTimeOffset.Now,
                    $"Round {dropped.Number} was not recorded: {EssentialQueue} later rounds were already waiting. Its history samples and file output are missing."),
                EssentialQueue, (r, ex) => Log.Add(DateTimeOffset.Now, $"Processing round {r.Number} failed: {ex.Message}"));
            var notify = _notify = new RoundProcessor<BackgroundRound>(NotifyRoundAsync, dropped => Log.Add(DateTimeOffset.Now,
                    $"{dropped.Events.Count} event(s) of round {dropped.Number} were not notified: the previous round was still sending notifications."),
                failed: (r, ex) => Log.Add(DateTimeOffset.Now, $"Notifications of round {r.Number} failed: {ex.Message}"));
            scanner.RoundCompleted += (_, r) =>
            {
                rounds.Post(r);
                notify.Post(r);
            };
            Log.Add(DateTimeOffset.Now, $"Background scanning started ({s.Background.Mode}, every {s.Background.RoundDelayMinutes:0.#} min).");
            scanner.Start(baseline);
        }

        // A loop that ends without a Stop request (no plan, fault) still releases the session and reports it.
        scanner.Completion.ContinueWith(_ =>
        {
            lock (_gate)
            {
                if (_scanner == scanner) _ = StopAsync();
            }
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
    }

    /// <summary>
    /// Cancels the session and completes only when its round loop, round processing and query plan are finished and
    /// released ("stopped" means stopped). Safe to call concurrently or repeatedly: every caller awaits the same teardown.
    /// </summary>
    public Task StopAsync()
    {
        lock (_gate)
        {
            if (_scanner is null) return _stopping;
            var (scanner, rounds, notify, plan) = (_scanner, _rounds, _notify, _queryPlan);
            (_scanner, _rounds, _notify, _queryPlan) = (null, null, null, null); // before teardown starts, so re-entrant calls see no session
            return _stopping = TeardownAsync(scanner, rounds, notify, plan);
        }
    }

    private async Task TeardownAsync(BackgroundScanner scanner, RoundProcessor<BackgroundRound>? rounds, RoundProcessor<BackgroundRound>? notify, QueryPlan? plan)
    {
        try
        {
            await scanner.StopAsync().ConfigureAwait(false);
        }
        catch (Exception ex) // an unexpected loop fault is reported in the log; teardown must still finish
        {
            Log.Add(DateTimeOffset.Now, "Background scanning failed: " + ex.Message);
        }

        try
        {
            if (notify is not null) await notify.StopAsync().ConfigureAwait(false);
            if (rounds is not null) await rounds.StopAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Log.Add(DateTimeOffset.Now, "Background round processing failed: " + ex.Message);
        }
        finally
        {
            notify?.Dispose();
            rounds?.Dispose();
            plan?.Dispose();
            scanner.Dispose();
        }

        Log.Add(DateTimeOffset.Now, "Background scanning stopped.");
        Stopped?.Invoke(this, EventArgs.Empty);
    }

    private async Task<ScanRequest?> BuildRequestAsync(BackgroundMode mode, IReadOnlySet<AddressKey> known, CancellationToken ct)
    {
        var s = _settings();
        var (specs, errors) = AppSettings.ParseRanges(s.Ranges);
        IReadOnlySet<AddressKey>? exclude = null;
        if (mode == BackgroundMode.Known && known.Count == 0)
        {
            // Nothing is known yet: a baseline round over the ranges is the only way to learn the devices (review C-17, D-071).
            Log.Add(DateTimeOffset.Now, "Known-devices mode: no known devices yet, so this round scans the configured ranges to find them.");
        }
        else if (mode == BackgroundMode.Known)
        {
            (specs, errors) = AppSettings.ParseRanges(known.Select(k => new RangeEntry { Target = k.ToString() }));
        }
        else if (mode == BackgroundMode.New)
        {
            exclude = known;
        }

        foreach (var e in errors) Log.Add(DateTimeOffset.Now, "Range error: " + e);
        var built = await _planner.PlanAsync(specs, s, confirmed: true, exclude, ct).ConfigureAwait(false);
        if (!built.CanStart)
        {
            Log.Add(DateTimeOffset.Now, "Background round not started: " + string.Join("; ", built.Errors.DefaultIfEmpty(built.Status.ToString())));
            return null;
        }

        var ctx = ScanContext.Resolve(s, _vault, _adapters);
        return new ScanRequest
        {
            Plan = built.Plan,
            Settings = Security.ScanSecrets.Reveal(s.Scan, _vault),
            LocalSubnets = _planner.LocalSubnets(),
            KnownAddresses = mode == BackgroundMode.New ? null : known,
            Queries = _queryPlan,
            Routers = ctx.Routers,
            WorkstationCredential = ctx.WorkstationCredential,
            SharesCredential = ctx.SharesCredential,
        };
    }

    private async Task OnRoundAsync(BackgroundRound round, CancellationToken stop)
    {
        {
            var s = _settings();
            var leaving = round.Events.Where(e => e.Type == BackgroundEventType.Leave).Select(e => e.Address).ToHashSet();
            lock (_current)
            {
                foreach (var d in round.Results) _current[d.Key] = _current.TryGetValue(d.Key, out var old) ? DeviceResult.MergeBackground(old, d) : d;
                foreach (var key in leaving)
                {
                    if (!_current.TryGetValue(key, out var d)) continue;
                    d = d with { Status = DeviceStatus.Offline };
                    _current[key] = s.Background.ClearOffline ? OfflineClearer.Clear(d, s.Background.KeepOnOffline) : d;
                }
            }

            Log.Add(DateTimeOffset.Now, $"Round {round.Number} {(round.Complete ? "completed" : "incomplete")}: {round.Results.Count(r => r.Status == DeviceStatus.Online)} online in {round.Elapsed.TotalSeconds:0.#} s.");
            var columns = s.DisplayColumns;
            var format = s.Format;
            foreach (var e in round.Events.Where(e => s.Background.For(e.Type).Enabled)) Log.Add(e.At, $"{BackgroundEvent.Code(e.Type)}: {e.Message}");

            if (s.History.Enabled) await RecordHistoryAsync(s, round.Results, round.StartedAt, round.StartedAt + round.Elapsed, round.Complete, round.Plan).ConfigureAwait(false);

            var output = OutputOverride ?? (s.Background.SaveAfterRound ? s.Background.OutputFile : null);
            if (round.Complete && !string.IsNullOrWhiteSpace(output))
            {
                try
                {
                    var path = FileNameTokens.Expand(output, DateTime.Now);
                    await ResultExport.ExportAsync(new ExportRequest { Path = path, Columns = columns, Devices = Current, Format = format }, stop).ConfigureAwait(false);
                    Log.Add(DateTimeOffset.Now, "Saved " + path);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or OperationCanceledException)
                {
                    Log.Add(DateTimeOffset.Now, "File output failed: " + ex.Message);
                }
            }

            RoundFinished?.Invoke(this, round);
        }
    }

    private async Task NotifyRoundAsync(BackgroundRound round, CancellationToken stop)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(stop);
        budget.CancelAfter(NotificationBudget);
        var s = _settings();
        var columns = s.DisplayColumns;
        var format = s.Format;
        var skipped = 0;
        foreach (var e in round.Events)
        {
            if (!s.Background.For(e.Type).Enabled) continue;
            if (budget.IsCancellationRequested)
            {
                skipped++;
                continue;
            }

            try
            {
                foreach (var err in await Notifier.DispatchAsync(e, s.Background, columns, format, budget.Token).ConfigureAwait(false))
                {
                    Log.Add(DateTimeOffset.Now, "Notification failed — " + err);
                }
            }
            catch (OperationCanceledException) when (budget.IsCancellationRequested)
            {
                skipped++;
            }
        }

        if (skipped > 0) Log.Add(DateTimeOffset.Now, $"{skipped} notification(s) of round {round.Number} were skipped: " + (stop.IsCancellationRequested ? "background scanning was stopped." : $"the round exceeded its {NotificationBudget.TotalMinutes:0}-minute notification budget."));
    }

    /// <summary>Records a session in history (also called after interactive scans) and refreshes <see cref="HistoryView"/>.</summary>
    public async Task RecordHistoryAsync(AppSettings s, IReadOnlyCollection<DeviceResult> results, DateTimeOffset started, DateTimeOffset finished, bool complete,
        TargetPlan? plan)
    {
        ArgumentNullException.ThrowIfNull(s);
        try
        {
            var network = await _identifier.IdentifyAsync(CancellationToken.None).ConfigureAwait(false);
            var covered = plan;
            if (covered is null)
            {
                var built = await _planner.PlanAsync(AppSettings.ParseRanges(s.Ranges).Specs, s, confirmed: true).ConfigureAwait(false);
                covered = built.CanStart ? built.Plan : null;
            }

            bool Eligible(string ip) => covered is not null && TargetParser.TryParseAddress(ip, out var k) && covered.Contains(k);
            var newcomers = History.RecordSession(network, started, finished, complete, results, Eligible);
            HistoryView.Network = network;
            HistoryView.Devices = History.Devices(network);
            HistoryView.Newcomers = newcomers;
            if (newcomers.Count > 0) Log.Add(DateTimeOffset.Now, $"History: {newcomers.Count} new device(s) on {network.Name}.");
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or InvalidOperationException)
        {
            Log.Add(DateTimeOffset.Now, "History not recorded: " + ex.Message);
        }
    }

    /// <summary>Loads the history of the current network for the results columns (start-up).</summary>
    public async Task RefreshHistoryAsync()
    {
        try
        {
            var network = await _identifier.IdentifyAsync(CancellationToken.None).ConfigureAwait(false);
            HistoryView.Network = network;
            HistoryView.Devices = History.Devices(network);
        }
        catch (Exception ex) when (ex is Microsoft.Data.Sqlite.SqliteException or IOException or InvalidOperationException)
        {
            Log.Add(DateTimeOffset.Now, "History unavailable: " + ex.Message);
        }
    }

    public void Dispose()
    {
        _scanner?.Dispose();
        _notify?.Dispose();
        _rounds?.Dispose();
        _queryPlan?.Dispose();
    }
}
