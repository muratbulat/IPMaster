using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using IPMaster.Core.Configuration;
using IPMaster.Core.Management;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Export;
using IPMaster.Infrastructure.Network;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Security;
using IPMaster.Core.Queries;
using IPMaster.Core.Security;

namespace IPMaster.Desktop.ViewModels;

public interface IDialogs
{
    Task<bool> ConfirmAsync(string title, string message);

    Task ShowMessageAsync(string title, string message);
}

public enum RescanMode
{
    /// <summary>Every device currently listed.</summary>
    Listed,

    /// <summary>Addresses in the ranges that were not discovered.</summary>
    Undiscovered,

    Both,
}

public enum LoadMode
{
    LoadOnly,
    RescanListed,
    RescanUndiscovered,
    RescanBoth,
}

/// <summary>One condition row in the advanced filter panel.</summary>
public sealed partial class FilterConditionViewModel : ObservableObject
{
    public FilterConditionViewModel(IReadOnlyList<ResultColumn> columns) => Columns = columns;

    public IReadOnlyList<ResultColumn> Columns { get; }

    public static IReadOnlyList<string> OperationNames { get; } =
        ["contains", "does not contain", "equals", "not equal", "starts with", "ends with", "less than", "greater than", "regex", "is empty", "is not empty"];

    [ObservableProperty] public partial ResultColumn? Column { get; set; }

    [ObservableProperty] public partial int OperationIndex { get; set; }

    [ObservableProperty] public partial string Value { get; set; } = "";

    public FilterCondition ToModel() => new() { ColumnId = Column?.Id ?? "ip", Operation = (FilterOperation)OperationIndex, Value = Value };
}

public sealed partial class MainWindowViewModel : ObservableObject, IScanResultSink
{
    private const int MaxUpdatesPerTick = 20_000;

    private readonly ScanEngine _engine;
    private readonly ScanPlanner _planner;
    private readonly SettingsStore _store;
    private readonly ConcurrentQueue<(DeviceResult Result, bool Background)> _incoming = new();
    private readonly DispatcherTimer _timer;
    private readonly bool _settingsReadOnly;
    private ScanSession? _session;
    private bool _mergeIncoming;
    private DateTime _lastRebuild = DateTime.MinValue;
    private IReadOnlyList<string> _lastTargets = [];

    public MainWindowViewModel(ScanEngine engine, ScanPlanner planner, SettingsStore store, INetworkAdapterProvider adapters, OuiDatabase oui,
        IServiceProvider services)
    {
        Services = services;
        _engine = engine;
        _planner = planner;
        _store = store;
        Adapters = adapters;
        Oui = oui;

        var load = store.Load();
        Settings = load.Settings;
        _settingsReadOnly = load.Status == SettingsLoadStatus.NewerSchemaReadOnly;
        NeedsMasterPassword = load.Status == SettingsLoadStatus.PasswordRequired;
        StartupMessage = NeedsMasterPassword ? null : load.Message;
        Queries = services.GetService(typeof(QueryServices)) as QueryServices ?? throw new InvalidOperationException("Query services are not registered.");
        Queries.KnownHosts.Load(Settings.Queries.KnownHosts);
        Queries.KnownHosts.Trusted += (_, _) => Dispatcher.UIThread.Post(async () =>
        {
            Settings = Settings with { Queries = Settings.Queries with { KnownHosts = Queries.KnownHosts.All } };
            await PersistAsync();
        });
        foreach (var r in Settings.Ranges) Ranges.Add(RangeEntryViewModel.From(r));
        if (Ranges.Count == 0) Ranges.Add(new RangeEntryViewModel());
        ApplyTheme();
        if (Avalonia.Application.Current is { } app) app.ActualThemeVariantChanged += (_, _) => IsDarkMode = App.IsDark; // OS switched while following it
        ApplyViewSettings();

        _timer = new DispatcherTimer(TimeSpan.FromMilliseconds(150), DispatcherPriority.Background, (_, _) => Drain());
        _timer.Start();
    }

    public IDialogs? Dialogs { get; set; }

    public IServiceProvider Services { get; }

    public QueryServices Queries { get; }

    public CredentialVault Vault => Queries.Vault;

    /// <summary>The settings file is encrypted and has not been unlocked yet (SEC-02).</summary>
    public bool NeedsMasterPassword { get; private set; }

    public INetworkAdapterProvider Adapters { get; }

    public OuiDatabase Oui { get; }

    public ScanProbes Probes => _engine.Probes;

    public ScanPlanner Planner => _planner;

    public AppSettings Settings { get; private set; }

    public string? StartupMessage { get; }

    public string ConfigPath => _store.FilePath;

    public ObservableCollection<RangeEntryViewModel> Ranges { get; } = [];

    public ResultsView Results { get; } = new();

    public ObservableCollection<FilterConditionViewModel> FilterConditions { get; } = [];

    /// <summary>Raised when columns, view options or the grid layout must be re-applied.</summary>
    public event EventHandler? ViewChanged;

    /// <summary>Raised after menus that list settings (bookmarks, recent files, saved filters) changed.</summary>
    public event EventHandler? MenusChanged;

    /// <summary>Raised for every device update on the UI thread (properties windows follow their device).</summary>
    public event EventHandler<DeviceResult>? DeviceUpdated;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(StartButtonText))]
    [NotifyCanExecuteChangedFor(nameof(PauseCommand))]
    public partial bool IsScanning { get; set; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PauseButtonText))]
    public partial bool IsPaused { get; set; }

    [ObservableProperty] public partial bool IsDarkMode { get; set; }

    [ObservableProperty] public partial string StatusText { get; set; } = "Ready";

    [ObservableProperty] public partial double ProgressPercent { get; set; }

    /// <summary>The interactive scan's phase (D-100); background scans and monitoring have their own status.</summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(StartStopCommand))]
    public partial ScanPhase ScanPhase { get; set; }

    /// <summary>The bar shows only while a scan is working; finished, stopped and failed scans say so in words.</summary>
    [ObservableProperty] public partial bool ProgressVisible { get; set; }

    /// <summary>Incremented per scan: work that finishes after a newer scan started must not write to the status bar.</summary>
    private int _scanGeneration;

    private void Show(ScanPhase phase, ScanView view)
    {
        ScanPhase = phase;
        StatusText = view.Status;
        ProgressVisible = view.ProgressVisible;
        ProgressIndeterminate = view.Indeterminate;
        ProgressPercent = view.Percent;
    }

    private bool CanStartStop() => ScanPhase is not (ScanPhase.Preparing or ScanPhase.AwaitingConfirmation);

    [ObservableProperty] public partial bool ProgressIndeterminate { get; set; }

    [ObservableProperty] public partial string WorkersText { get; set; } = "Workers 0";

    [ObservableProperty] public partial string DevicesText { get; set; } = "Devices 0 / 0";

    [ObservableProperty] public partial bool FilterPanelVisible { get; set; }

    [ObservableProperty] public partial bool FilterMatchAll { get; set; } = true;

    [ObservableProperty] public partial bool FilterShowOnlyMatching { get; set; }

    [ObservableProperty] public partial string FilterError { get; set; } = "";

    [ObservableProperty] public partial bool SharesFilterVisible { get; set; }

    [ObservableProperty] public partial bool SharesAnyType { get; set; } = true;

    [ObservableProperty] public partial bool OnlySharedFolders { get; set; }

    [ObservableProperty] public partial bool FindVisible { get; set; }

    [ObservableProperty] public partial string FindText { get; set; } = "";

    public string StartButtonText => IsScanning ? "Stop" : "Start Scanning";

    public string PauseButtonText => IsPaused ? "Resume" : "Pause";

    public ColumnFormat Format => Settings.Format with { DuplicateMacs = Settings.Scan.DetectDuplicateMacs ? DuplicateMacs.Find(Results.Nodes.Select(n => n.Result)) : null };

    public IReadOnlyList<ResultColumn> EnabledColumns => Settings.AvailableColumns;

    public IReadOnlyList<ResultColumn> DisplayColumns => ColumnCatalog.Arrange(Settings.AvailableColumns.Concat(RuntimeColumns()).ToList(), Settings.View.Columns);

    // ---------------- view settings ----------------
    public void ApplyViewSettings()
    {
        if (_monitor is not null) _monitor.Settings = Settings.Monitoring;
        Results.Columns = DisplayColumns;
        Results.Format = Format;
        Results.CaseInsensitiveSort = Settings.View.CaseInsensitiveSort;
        Results.RepeatedValues = Settings.View.RepeatedValues;
        Results.AutoExpand = Settings.View.AutoExpand;
        Results.Styles.Clear();
        foreach (var s in Settings.ColumnStyles) Results.Styles[s.ColumnId] = s;
        SharesFilterVisible = SharesFilterVisible && Settings.Scan.ScanShares;
        ApplyFilter();
        ViewChanged?.Invoke(this, EventArgs.Empty);
    }

    partial void OnFilterMatchAllChanged(bool value) => ApplyFilter();

    partial void OnFilterShowOnlyMatchingChanged(bool value) => ApplyFilter();

    partial void OnOnlySharedFoldersChanged(bool value)
    {
        Results.OnlyWithSharedFolders = value;
        Results.Rebuild();
        UpdateDeviceCount();
    }

    partial void OnSharesAnyTypeChanged(bool value)
    {
        if (value) Results.ShareCategories.Clear();
        Results.Rebuild();
    }

    public void SetShareCategory(ShareCategory category, bool on)
    {
        if (on) Results.ShareCategories.Add(category);
        else Results.ShareCategories.Remove(category);
        SharesAnyType = Results.ShareCategories.Count == 0;
        Results.Rebuild();
        UpdateDeviceCount();
    }

    /// <summary>Compiles the advanced filter panel and refreshes the view (live search).</summary>
    public void ApplyFilter()
    {
        var def = CurrentFilterDefinition("");
        var compiled = CompiledFilter.Compile(def, out var errors, DisplayColumns);
        FilterError = errors.Count > 0 ? errors[0] : "";
        Results.SetFilter(FilterPanelVisible ? compiled : null, def.Mode);
        Results.Rebuild();
        UpdateDeviceCount();
    }

    public FilterDefinition CurrentFilterDefinition(string name) => new()
    {
        Name = name,
        Conditions = FilterConditions.Where(c => c.Column is not null && (c.Value.Length > 0 || c.OperationIndex >= (int)FilterOperation.IsEmpty)).Select(c => c.ToModel()).ToList(),
        MatchAll = FilterMatchAll,
        Mode = FilterShowOnlyMatching ? FilterMode.ShowOnlyMatching : FilterMode.Highlight,
    };

    public FilterConditionViewModel AddFilterCondition(string? columnId = null, FilterOperation op = FilterOperation.Contains, string value = "")
    {
        var vm = new FilterConditionViewModel(DisplayColumns)
        {
            Column = DisplayColumns.FirstOrDefault(c => c.Id == columnId) ?? DisplayColumns.FirstOrDefault(),
            OperationIndex = (int)op,
            Value = value,
        };
        vm.PropertyChanged += (_, _) => ApplyFilter();
        FilterConditions.Add(vm);
        FilterPanelVisible = true;
        ApplyFilter();
        return vm;
    }

    public void RemoveFilterCondition(FilterConditionViewModel c)
    {
        FilterConditions.Remove(c);
        ApplyFilter();
    }

    public void LoadFilter(FilterDefinition f)
    {
        FilterConditions.Clear();
        FilterMatchAll = f.MatchAll;
        FilterShowOnlyMatching = f.Mode == FilterMode.ShowOnlyMatching;
        foreach (var c in f.Conditions) AddFilterCondition(c.ColumnId, c.Operation, c.Value);
        FilterPanelVisible = true;
        ApplyFilter();
    }

    [RelayCommand]
    private void ToggleFilterPanel()
    {
        FilterPanelVisible = !FilterPanelVisible;
        if (FilterPanelVisible && FilterConditions.Count == 0) AddFilterCondition();
        else ApplyFilter();
    }

    [RelayCommand]
    private void ClearFilter()
    {
        FilterConditions.Clear();
        AddFilterCondition();
    }

    public async Task SaveFilterAsync(string name)
    {
        var def = CurrentFilterDefinition(name);
        Settings = Settings with { SavedFilters = Settings.SavedFilters.Where(f => f.Name != name).Append(def).ToList() };
        await PersistAsync();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task SetSavedFiltersAsync(IReadOnlyList<FilterDefinition> filters)
    {
        Settings = Settings with { SavedFilters = filters };
        await PersistAsync();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    [RelayCommand]
    private void ToggleSharesFilter()
    {
        if (!Settings.Scan.ScanShares)
        {
            OnlySharedFolders = !OnlySharedFolders;
            return;
        }

        SharesFilterVisible = !SharesFilterVisible;
        OnlySharedFolders = SharesFilterVisible;
    }

    // ---------------- results sink ----------------
    public void OnDevice(DeviceResult result) => _incoming.Enqueue((result, false));

    /// <summary>Results of continuous-operation rounds (see <see cref="BackgroundSink"/>).</summary>
    public void OnBackgroundDevice(DeviceResult result) => _incoming.Enqueue((result, true));

    /// <summary>Live sink for background rounds: merged so an unanswered round never blanks a row (review C-05b).</summary>
    public sealed class BackgroundSink(MainWindowViewModel owner) : IScanResultSink
    {
        public void OnDevice(DeviceResult result) => owner.OnBackgroundDevice(result);
    }

    private void Drain()
    {
        var n = 0;
        var newDevices = false;
        var enrolled = false;
        while (n < MaxUpdatesPerTick && _incoming.TryDequeue(out var item))
        {
            n++;
            var r = item.Result;
            newDevices |= Results.Upsert(r, _mergeIncoming, item.Background);
            enrolled |= OnArrived(r);
            DeviceUpdated?.Invoke(this, Results.Find(r.Key)?.Result ?? r);
        }

        // Throttled rebuild when incremental insertion is not possible (sorted, filtered or expanded views).
        if (Results.IsDirty && (DateTime.UtcNow - _lastRebuild > TimeSpan.FromSeconds(IsScanning ? 1 : 0)))
        {
            if (Settings.Scan.DetectDuplicateMacs && newDevices) Results.Format = Format;
            Results.Rebuild();
            _lastRebuild = DateTime.UtcNow;
        }

        if (enrolled) UpdateTally(); // Monitor All enrolled devices: the monitoring state shows it at once
        if (_session is { } s) UpdateProgress(s.Progress);
        else if (n > 0) UpdateDeviceCount();
    }

    public void UpdateDeviceCount()
    {
        var total = Results.Count;
        var online = Results.Nodes.Count(r => r.Result.Status == DeviceStatus.Online);
        var c = CultureInfo.CurrentCulture;
        DevicesText = Settings.View.StatusStatistic switch
        {
            StatusStatistic.Offline => string.Create(c, $"Offline {total - online:N0} / {total:N0}"),
            StatusStatistic.Filtered => string.Create(c, $"Filtered {Results.FilteredCount:N0} / {total:N0}"),
            _ => string.Create(c, $"Devices {online:N0} / {total:N0}"),
        };
    }

    public async Task SetStatusStatisticAsync(StatusStatistic statistic)
    {
        Settings = Settings with { View = Settings.View with { StatusStatistic = statistic } };
        UpdateDeviceCount();
        await PersistAsync();
    }

    private void UpdateProgress(ScanProgress p)
    {
        // a session reports Completed/Cancelled before RunScanCoreAsync takes over: only the finishing code shows a terminal state
        if (ScanPresentation.IsTerminal(ScanPresentation.FromEngine(p.State))) return;
        WorkersText = $"Workers {p.ActiveWorkers}" + (p.PendingEnrichment > 0 ? $" · enrich {p.PendingEnrichment}" : "");
        UpdateDeviceCount();
        Show(ScanPresentation.FromEngine(p.State), ScanPresentation.During(p));
    }

    // ---------------- scanning ----------------
    // AllowConcurrentExecutions: the start task lasts the whole scan, and a second execution is the Stop request; without
    // it the toolkit disables the command while it runs, so Stop and Ctrl+Enter were greyed out during every scan (D-100)
    [RelayCommand(CanExecute = nameof(CanStartStop), AllowConcurrentExecutions = true)]
    private async Task StartStopAsync()
    {
        if (!CanStartStop()) return; // preparing or awaiting confirmation: no second scan
        if (IsScanning)
        {
            _session?.Stop();
            return;
        }

        foreach (var r in Ranges) r.Validate();
        var (specs, errors) = AppSettings.ParseRanges(Ranges.Select(r => r.ToModel()));
        if (errors.Count > 0)
        {
            await ShowAsync("Invalid range", string.Join(Environment.NewLine, errors));
            return;
        }

        await PersistAsync();
        ClearResults();
        _lastTargets = specs.Select(s => s.Original).ToList();
        await RunScanAsync(specs, null, known: null, merge: false);
    }

    /// <summary>Manual: Rescan All Displayed Devices (full / previously undiscovered / both) and Rescan Device.</summary>
    public async Task RescanAsync(RescanMode mode, IReadOnlyList<DeviceNode>? only = null)
    {
        if (ScanPresentation.IsBusy(ScanPhase)) return;
        var listed = (only ?? Results.Rows.Where(r => !r.IsShare).Select(r => r.Node).ToList()).Select(n => n.Result.Key).ToList();
        var specs = new List<TargetSpec>();
        HashSet<AddressKey>? exclude = null;
        if (mode is RescanMode.Listed or RescanMode.Both)
        {
            specs.AddRange(listed.Select(k => new TargetSpec { Kind = TargetKind.SingleAddress, Start = k, End = k, Original = k.ToString() }));
        }

        if (mode is RescanMode.Undiscovered or RescanMode.Both)
        {
            var ranges = _lastTargets.Count > 0 ? _lastTargets : Ranges.Where(r => r.Enabled).Select(r => r.Target).ToList();
            foreach (var t in ranges)
            {
                if (TargetParser.TryParse(t, out var spec, out _)) specs.Add(spec);
            }

            if (mode == RescanMode.Undiscovered)
            {
                exclude = Results.Nodes.Where(n => n.Result.Status == DeviceStatus.Online).Select(n => n.Result.Key).ToHashSet();
            }
        }

        if (specs.Count == 0)
        {
            await ShowAsync("Rescan", "There is nothing to rescan.");
            return;
        }

        await RunScanAsync(specs, exclude, Results.Nodes.Select(n => n.Result.Key).ToHashSet(), merge: true);
    }

    /// <summary>The running scan, history included: shutdown waits for it (D-086).</summary>
    private Task _scanRun = Task.CompletedTask;

    private bool _shuttingDown;

    private Task RunScanAsync(List<TargetSpec> specs, IReadOnlySet<AddressKey>? exclude, IReadOnlySet<AddressKey>? known, bool merge)
        => _shuttingDown ? Task.CompletedTask : _scanRun = RunScanCoreAsync(specs, exclude, known, merge);

    private async Task RunScanCoreAsync(List<TargetSpec> specs, IReadOnlySet<AddressKey>? exclude, IReadOnlySet<AddressKey>? known, bool merge)
    {
        var generation = ++_scanGeneration;
        Show(ScanPhase.Preparing, ScanPresentation.Before(ScanPhase.Preparing));
        PlanBuildResult built;
        try
        {
            built = await _planner.PlanAsync(specs, Settings, confirmed: false, exclude);
            if (built.Status == PlanStatus.NeedsConfirmation)
            {
                Show(ScanPhase.AwaitingConfirmation, ScanPresentation.Before(ScanPhase.AwaitingConfirmation));
                var ok = Dialogs is not null && await Dialogs.ConfirmAsync("Large scan",
                    $"The ranges contain {built.RawCount:N0} addresses, more than the confirmation threshold of {Settings.ConfirmationThreshold:N0}.\n\nScan them anyway?");
                if (!ok)
                {
                    ResetStatus("Scan not started (large scan cancelled).");
                    return;
                }

                Show(ScanPhase.Preparing, ScanPresentation.Before(ScanPhase.Preparing));
                built = await _planner.PlanAsync(specs, Settings, confirmed: true, exclude);
            }
        }
        catch (Exception ex)
        {
            ResetStatus("Ready");
            await ShowAsync("Cannot start scan", ex.Message);
            return;
        }

        if (!built.CanStart)
        {
            ResetStatus("Ready");
            await ShowAsync("Cannot start scan", string.Join(Environment.NewLine, built.Errors));
            return;
        }

        var plan = built.Plan;
        ulong? exact = plan.RawCount <= 4_000_000 ? await Task.Run(() => plan.CountExact()) : null;
        _mergeIncoming = merge;
        IsScanning = true;
        IsPaused = false;
        Show(ScanPhase.Scanning, new ScanView("Scanning…", true, exact is null, 0));
        using var queryPlan = Queries.Plan(Settings);
        var scanContext = ScanContext.Resolve(Settings, Vault, Adapters);
        if (scanContext.Warnings.Count > 0) StatusText = string.Join(" ", scanContext.Warnings);
        var started = DateTimeOffset.Now;
        _session = _engine.Start(new ScanRequest
        {
            Plan = plan,
            Settings = ScanSecrets.Reveal(Settings.Scan, Vault),
            Queries = queryPlan,
            LocalSubnets = _planner.LocalSubnets(),
            IPv6ScopeIds = _planner.LinkLocalScopes(),
            KnownAddresses = known,
            ExactCount = exact,
            Routers = scanContext.Routers,
            WorkstationCredential = scanContext.WorkstationCredential,
            SharesCredential = scanContext.SharesCredential,
        }, this);

        var warnings = built.Errors.Concat(built.Warnings).ToList();
        var summary = await _session.Completion;
        Drain();
        _session.Dispose();
        _session = null;
        IsScanning = false;
        IsPaused = false;
        WorkersText = "Workers 0";
        Results.Format = Format;
        Results.Rebuild();
        UpdateDeviceCount();
        var historyTask = RecordInteractiveHistoryAsync(started, summary.State == ScanState.Completed, plan, generation);
        var dup = Results.Format.DuplicateMacs?.Count ?? 0;
        var view = ScanPresentation.After(summary);
        Show(ScanPresentation.FromEngine(summary.State), view with
        {
            Status = view.Status + string.Create(CultureInfo.CurrentCulture, $" (started {started:HH:mm:ss})")
                     + (dup > 0 ? $" · {dup} duplicate MAC address(es)" : "")
                     + (warnings.Count > 0 ? $" · {warnings.Count} warning(s): {warnings[0]}" : ""),
        });
        await historyTask;
    }

    private void ResetStatus(string text) => Show(ScanPhase.Idle, ScanPresentation.Before(ScanPhase.Idle) with { Status = text });

    private bool CanPause() => IsScanning;

    [RelayCommand(CanExecute = nameof(CanPause))]
    private void Pause()
    {
        if (_session is null) return;
        if (_session.IsPaused) _session.Resume();
        else _session.Pause();
        IsPaused = _session.IsPaused;
    }

    [RelayCommand]
    private void ClearResults()
    {
        _incoming.Clear();
        Results.Clear();
        if (!ScanPresentation.IsBusy(ScanPhase)) ResetStatus("Ready"); // a finished scan's summary no longer describes the (empty) results
        UpdateDeviceCount();
    }

    public void DeleteDevices(IEnumerable<DeviceNode> nodes)
    {
        Results.Remove(nodes);
        Results.Rebuild();
        UpdateDeviceCount();
    }

    public IReadOnlyList<DeviceNode> InactiveDevices() => Results.Nodes.Where(n => n.Result.Status != DeviceStatus.Online).ToList();

    // ---------------- ranges ----------------
    [RelayCommand]
    private void AddRange() => Ranges.Add(new RangeEntryViewModel());

    [RelayCommand]
    private void RemoveRange(RangeEntryViewModel range)
    {
        Ranges.Remove(range);
        if (Ranges.Count == 0) Ranges.Add(new RangeEntryViewModel());
    }

    [RelayCommand]
    private async Task ConvertCidrAsync(RangeEntryViewModel range)
    {
        if (CidrConverter.TryConvert(range.Target, out var converted, out var error)) range.Target = converted;
        else await ShowAsync("CIDR conversion", error);
    }

    public void SetRanges(IEnumerable<RangeEntryViewModel> ranges, bool append)
    {
        if (!append) Ranges.Clear();
        foreach (var r in ranges)
        {
            if (append && Ranges.Count == 1 && string.IsNullOrWhiteSpace(Ranges[0].Target)) Ranges.Clear();
            Ranges.Add(r);
        }

        if (Ranges.Count == 0) Ranges.Add(new RangeEntryViewModel());
    }

    /// <summary>Manual "Paste": as-is, or expanded to the class A/B/C range around an IPv4 address.</summary>
    public static string? ExpandPasted(string text, int prefix)
    {
        if (!TargetParser.TryParseAddress(text.Trim(), out var key)) return null;
        if (key.IsV6 || prefix >= 32) return key.ToString();
        var mask = AddressKey.MaskFor(prefix, false);
        var start = AddressKey.FromIPv4((uint)(key.Value & mask));
        var end = AddressKey.FromIPv4((uint)((key.Value & mask) | (uint.MaxValue & ~mask)));
        return $"{start}-{end}";
    }

    // ---------------- bookmarks ----------------
    public async Task AddBookmarkAsync(string name)
    {
        var b = new Bookmark { Name = name, Ranges = Ranges.Where(r => r.Target.Trim().Length > 0).Select(r => r.ToModel()).ToList() };
        Settings = Settings with { Bookmarks = Settings.Bookmarks.Where(x => x.Name != name).Append(b).ToList() };
        await PersistAsync();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task SetBookmarksAsync(IReadOnlyList<Bookmark> bookmarks)
    {
        Settings = Settings with { Bookmarks = bookmarks };
        await PersistAsync();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    public void OpenBookmark(Bookmark b, bool append) => SetRanges(b.Ranges.Select(RangeEntryViewModel.From), append);

    // ---------------- load / save ----------------
    public async Task ExportAsync(string path)
    {
        var rows = Results.Rows.Where(r => !r.IsShare).Select(r => r.Result).ToList();
        await ResultExport.ExportAsync(new ExportRequest
        {
            Path = path,
            Columns = DisplayColumns,
            Devices = rows,
            Format = Format,
            Csv = Settings.Csv,
            Metadata = new ScanMetadata { Targets = _lastTargets },
        });
        await RememberRecentAsync(path);
        StatusText = $"Saved {rows.Count:N0} devices to {path}";
    }

    public async Task LoadAsync(string path, LoadMode mode, bool append)
    {
        ResultDocument doc;
        try
        {
            doc = await ResultsXml.LoadAsync(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or System.Xml.XmlException)
        {
            await ShowAsync("Load Results", $"Cannot load {path}: {ex.Message}");
            return;
        }

        if (!append) ClearResults();
        foreach (var d in doc.Devices) Results.Upsert(d, mergeRescan: false);
        Results.Format = Format;
        Results.Rebuild();
        UpdateDeviceCount();
        if (doc.Metadata.Targets.Count > 0) _lastTargets = doc.Metadata.Targets;
        await RememberRecentAsync(path);
        StatusText = $"Loaded {doc.Devices.Count:N0} devices from {path}";
        switch (mode)
        {
            case LoadMode.RescanListed:
                await RescanAsync(RescanMode.Listed, Results.Nodes.Where(n => doc.Devices.Any(d => d.Key == n.Result.Key)).ToList());
                break;
            case LoadMode.RescanUndiscovered:
                await RescanAsync(RescanMode.Undiscovered);
                break;
            case LoadMode.RescanBoth:
                await RescanAsync(RescanMode.Both);
                break;
        }
    }

    private async Task RememberRecentAsync(string path)
    {
        if (!path.EndsWith(".xml", StringComparison.OrdinalIgnoreCase)) return;
        Settings = Settings.WithRecentFile(Path.GetFullPath(path));
        await PersistAsync();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task SetAutoLoadSaveAsync(bool on)
    {
        Settings = Settings with { AutoLoadSaveRecent = on };
        await PersistAsync();
    }

    /// <summary>Started through File → New Window (UI-21): no auto load/save of the most recent results file.</summary>
    public bool IsSecondaryWindow { get; set; }

    /// <summary>Manual: Auto Load/Save to Most Recent File.</summary>
    public async Task AutoLoadAsync()
    {
        if (IsSecondaryWindow) return; // only the first window owns the most-recent results file (D-064)
        if (Settings.AutoLoadSaveRecent && Settings.RecentFiles.FirstOrDefault() is { } f && File.Exists(f)) await LoadAsync(f, LoadMode.LoadOnly, append: false);
    }

    // ---------------- configuration ----------------
    public async Task SaveConfigAsync(string path)
    {
        await PersistAsync();
        await ConfigXml.SaveAsync(path, Settings);
        StatusText = "Configuration saved to " + path;
    }

    public async Task LoadConfigAsync(string path)
    {
        try
        {
            var r = ConfigXml.Load(path, _store);
            if (r.Status == SettingsLoadStatus.NewerSchemaReadOnly)
            {
                await ShowAsync("Load Configuration", r.Message ?? "Unsupported configuration version.");
                return;
            }

            await ReplaceSettingsAsync(r.Settings);
            StatusText = "Configuration loaded from " + path;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or System.Xml.XmlException or System.Text.Json.JsonException)
        {
            await ShowAsync("Load Configuration", ex.Message);
        }
    }

    public async Task ResetConfigAsync() => await ReplaceSettingsAsync(new AppSettings());

    private async Task ReplaceSettingsAsync(AppSettings s)
    {
        Settings = s;
        Ranges.Clear();
        foreach (var r in s.Ranges) Ranges.Add(RangeEntryViewModel.From(r));
        if (Ranges.Count == 0) Ranges.Add(new RangeEntryViewModel());
        ApplyTheme();
        await PersistAsync();
        ApplyViewSettings();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    // ---------------- management (Phase 3) ----------------
    /// <summary>Manual Browsing tab: check that a device answers before connecting to it. True when any enabled check
    /// succeeds or no check is enabled.</summary>
    public async Task<bool> IsReachableAsync(DeviceResult device)
    {
        var b = Settings.Browsing;
        if (!b.CheckIcmp && !b.CheckArp && !b.CheckNetBios) return true;
        var address = device.Address;
        var timeout = TimeSpan.FromMilliseconds(Math.Max(500, Settings.Scan.PingTimeoutMs));
        try
        {
            if (b.CheckIcmp && (await Probes.Icmp.PingAsync(address, timeout, CancellationToken.None)).IsAlive) return true;
            if (b.CheckArp && Probes.Arp.Capability.Available && !device.Key.IsV6 && (await Probes.Arp.ArpAsync(address, timeout, CancellationToken.None)).IsAlive) return true;
            if (b.CheckNetBios && await Probes.NetBios.QueryAsync(address, timeout, CancellationToken.None) is not null) return true;
        }
        catch (Exception ex) when (ex is System.Net.NetworkInformation.PingException or System.Net.Sockets.SocketException)
        {
            return false;
        }

        return false;
    }

    public string ExpandApplication(ExternalApplication app, DeviceResult device, IReadOnlyDictionary<string, string> prompts) =>
        CommandTemplate.Expand(app.CommandLine, device.Key.ToString(), device.HostName.Value?.Name ?? device.Key.ToString(),
            device.Mac.HasValue ? Formats.Mac(device.Mac.Value!, Settings.View.MacFormat) : "", prompts, Settings.Applications.Variables);

    public async Task UpdateSettingsAsync(Func<AppSettings, AppSettings> change)
    {
        Settings = change(Settings);
        await PersistAsync();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    // ---------------- credentials and remote queries (Phase 4) ----------------
    public async Task<bool> UnlockAsync(string password)
    {
        var r = _store.Unlock(password);
        if (r.Status == SettingsLoadStatus.WrongPassword) return false;
        NeedsMasterPassword = false;
        Queries.KnownHosts.Load(r.Settings.Queries.KnownHosts);
        await ReplaceSettingsAsync(r.Settings);
        return true;
    }

    public async Task SetMasterPasswordAsync(string password)
    {
        Settings = Vault.SetMasterPassword(Settings, password);
        await PersistAsync();
    }

    public async Task RemoveMasterPasswordAsync()
    {
        Settings = Vault.RemoveMasterPassword(Settings);
        await PersistAsync();
    }

    /// <summary>Creates the vault key on first use (Windows: DPAPI). Throws with guidance elsewhere without a master password.</summary>
    public void EnsureVaultKey() => Settings = Vault.EnsureKey(Settings);

    /// <summary>SNMP communities of the scan settings are stored vault-protected (review C-14); without a possible key they stay as typed.</summary>
    private AppSettings ProtectScanSecrets(AppSettings settings)
    {
        try
        {
            if (!Vault.CanReveal) settings = Vault.EnsureKey(settings);
        }
        catch (InvalidOperationException)
        {
            return settings; // no OS key store and no master password: nothing to protect with
        }

        return settings with { Scan = ScanSecrets.Protect(settings.Scan, Vault) };
    }

    /// <summary>Settings for the Options dialog: secrets revealed for editing.</summary>
    public AppSettings SettingsForEditing() => Settings with { Scan = ScanSecrets.Reveal(Settings.Scan, Vault) };

    public async Task SaveCredentialsAsync(IReadOnlyList<StoredCredential> credentials)
    {
        Settings = Settings with { Credentials = credentials };
        Vault.Attach(Settings);
        await PersistAsync();
    }

    public async Task SaveQueriesAsync(QuerySettings queries)
    {
        Settings = Settings with { Queries = queries };
        await PersistAsync();
        ApplyViewSettings();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    public string SuggestedTestTarget() =>
        Results.Rows.FirstOrDefault(r => !r.IsShare && r.Result.Status == DeviceStatus.Online)?.Result.Key.ToString() ?? "127.0.0.1";

    /// <summary>Rescan Device → one query column (SCN-04).</summary>
    public async Task RescanColumnAsync(IReadOnlyList<DeviceResult> devices, Guid queryId)
    {
        var q = Settings.Queries.Items.FirstOrDefault(x => x.Id == queryId);
        StatusText = $"Rescanning {q?.Name} for {devices.Count} device(s)…";
        foreach (var d in devices)
        {
            var updated = await Queries.RescanColumnAsync(Settings, d, queryId, CancellationToken.None);
            OnDevice(updated with { Revision = d.Revision + 1 });
        }

        StatusText = $"{q?.Name}: rescanned {devices.Count} device(s).";
    }

    // ---------------- customisation ----------------
    public FriendlyEntry? FriendlyEntryFor(DeviceNode node) => new FriendlyNameMap(Settings.FriendlyNames).Find(node.Result);

    public string? FriendlyKeyFor(DeviceNode node) => FriendlyNameMap.KeyOf(node.Result, Settings.FriendlyNames.IdentifyBy);

    public async Task AssignFriendlyNameAsync(FriendlyEntry entry)
    {
        var fn = Settings.FriendlyNames;
        await SetFriendlyNamesAsync(fn with { Entries = FriendlyNameMap.Upsert(fn.Entries, entry) });
    }

    public async Task SetFriendlyNamesAsync(FriendlyNameSettings friendly)
    {
        Settings = Settings with { FriendlyNames = friendly };
        await PersistAsync();
        ApplyViewSettings();
    }

    public async Task SetVirtualColumnsAsync(IReadOnlyList<VirtualColumnDefinition> columns)
    {
        Settings = Settings with { VirtualColumns = columns };
        await PersistAsync();
        ApplyViewSettings();
    }

    public async Task SetColumnStyleAsync(string columnId, ColumnStyle? style)
    {
        var list = Settings.ColumnStyles.Where(s => s.ColumnId != columnId).ToList();
        if (style is not null) list.Add(style with { ColumnId = columnId });
        Settings = Settings with { ColumnStyles = list };
        await PersistAsync();
        ApplyViewSettings();
    }

    // ---------------- misc ----------------
    [RelayCommand]
    private async Task ToggleDarkModeAsync()
    {
        // an explicit choice stops following the system
        Settings = Settings with { View = Settings.View with { FollowSystemTheme = false, DarkMode = !IsDarkMode } };
        ApplyTheme();
        await PersistAsync();
    }

    [RelayCommand]
    private async Task ToggleSystemThemeAsync()
    {
        // turning it off keeps the theme currently shown
        Settings = Settings with { View = Settings.View with { FollowSystemTheme = !Settings.View.FollowSystemTheme, DarkMode = IsDarkMode } };
        ApplyTheme();
        await PersistAsync();
    }

    [ObservableProperty] public partial bool IsSystemTheme { get; set; }

    private void ApplyTheme()
    {
        IsSystemTheme = Settings.View.FollowSystemTheme;
        App.ApplyTheme(IsSystemTheme ? null : Settings.View.DarkMode);
        IsDarkMode = App.IsDark;
    }

    public async Task ApplySettingsAsync(AppSettings settings)
    {
        Settings = ProtectScanSecrets(settings);
        await PersistAsync();
        ApplyViewSettings();
        MenusChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task SetSortAsync(string? columnId, bool descending)
    {
        Results.SetSort(columnId, descending);
        Results.Rebuild();
        await Task.CompletedTask;
    }

    /// <summary>Finds the next row (after <paramref name="start"/>) whose visible cells contain the text.</summary>
    public int FindNext(int start, bool backwards)
    {
        if (string.IsNullOrEmpty(FindText) || Results.Rows.Count == 0) return -1;
        var n = Results.Rows.Count;
        for (var i = 1; i <= n; i++)
        {
            var idx = ((backwards ? start - i : start + i) % n + n) % n;
            var row = Results.Rows[idx];
            if (Results.Columns.Any(c => row[c.Id].Contains(FindText, StringComparison.CurrentCultureIgnoreCase))) return idx;
        }

        return -1;
    }

    public async Task PersistAsync()
    {
        Settings = Settings with { Ranges = Ranges.Where(r => r.Target.Trim().Length > 0).Select(r => r.ToModel()).ToList() };
        if (_settingsReadOnly || _store.IsLocked) return;
        try
        {
            var ours = Settings;
            var saved = await _store.SaveSharedAsync(ours);
            if (!ReferenceEquals(saved, ours))
            {
                // another window changed the shared configuration: take its changes (ranges stay per window)
                Settings = saved with { Ranges = ours.Ranges };
                ApplyTheme();

                ApplyViewSettings();
                MenusChanged?.Invoke(this, EventArgs.Empty);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            StatusText = "Settings could not be saved: " + ex.Message;
        }
    }

    /// <summary>
    /// Stops the scan, background scanning and monitoring and waits for them, then saves settings and the auto-save
    /// results file. Returns why saving failed, or null (D-086). No new scan or background session starts afterwards.
    /// </summary>
    public async Task<string?> ShutdownAsync(IReadOnlyList<ColumnLayout>? layout)
    {
        _shuttingDown = true;
        _session?.Stop();
        try
        {
            await _scanRun; // the scan finishes its results and history before anything is disposed
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            StatusText = "Scan ended with an error: " + ex.Message; // the scan reports its own errors; saving still proceeds
        }

        _timer.Stop();
        if (_ops is not null) await _ops.StopAsync();
        if (_monitor is not null) await _monitor.StopAsync();
        var hookErrors = new List<string>();
        foreach (var hook in _shutdownHooks.ToList())
        {
            if (await hook() is { Length: > 0 } e) hookErrors.Add(e); // e.g. a temporary adapter address that could not be removed
        }
        Settings = Settings with { Ranges = Ranges.Where(r => r.Target.Trim().Length > 0).Select(r => r.ToModel()).ToList() };
        if (layout is not null) Settings = Settings with { View = Settings.View with { Columns = layout } };
        var hookText = hookErrors.Count > 0 ? string.Join('\n', hookErrors) : null;
        if (_settingsReadOnly) return hookText;
        var settings = Settings;
        var autoSave = !IsSecondaryWindow && settings.AutoLoadSaveRecent && settings.RecentFiles.FirstOrDefault() is { } f ? f : null;
        var devices = Results.Nodes.Select(n => n.Result).OrderBy(d => d.Key).ToList();
        try
        {
            await Task.Run(async () =>
            {
                await _store.SaveSharedAsync(settings).ConfigureAwait(false);
                if (autoSave is not null && devices.Count > 0)
                {
                    await ResultsXml.ExportAsync(autoSave, settings.DisplayColumns, devices,
                        new ScanMetadata { Targets = _lastTargets }).ConfigureAwait(false);
                }
            });
            return hookText;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return (hookText is null ? "" : hookText + '\n') + (autoSave is null ? "The settings could not be saved: " : "The settings or the auto-save results file could not be saved: ") + ex.Message;
        }
    }

    private readonly List<Func<Task<string?>>> _shutdownHooks = [];

    /// <summary>
    /// Work that must finish before the app exits (D-090: stop a DHCP server or capture, remove temporary addresses). The hook
    /// returns an error to show, or null. Remove it with the returned action when its window closes.
    /// </summary>
    public Action AddShutdownHook(Func<Task<string?>> hook)
    {
        _shutdownHooks.Add(hook);
        return () => _shutdownHooks.Remove(hook);
    }

    /// <summary>The user kept the window open after a failed save: scanning works again (stopped sessions stay stopped).</summary>
    public void ResumeAfterCancelledClose()
    {
        _shuttingDown = false;
        _timer.Start();
    }

    private Task ShowAsync(string title, string message) => Dialogs?.ShowMessageAsync(title, message) ?? Task.CompletedTask;
}
