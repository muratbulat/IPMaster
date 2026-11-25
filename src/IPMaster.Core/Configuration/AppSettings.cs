using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Configuration;

/// <summary>One address-bar entry (manual: each range has its own enable toggle and optional comment).</summary>
public sealed record RangeEntry
{
    public string Target { get; set; } = "";

    public bool Enabled { get; set; } = true;

    public bool OctetMode { get; set; }

    public string Comment { get; set; } = "";
}

public sealed record ViewSettings
{
    public bool DarkMode { get; set; }

    /// <summary>Follow the operating system's light/dark setting, live (D-082); <see cref="DarkMode"/> applies only when off.</summary>
    public bool FollowSystemTheme { get; set; } = true;

    public char? CsvDelimiter { get; set; } = ',';

    public CsvEncoding CsvEncoding { get; set; } = CsvEncoding.Utf8Bom;

    public bool CsvProtectFormulas { get; set; } = true;

    /// <summary>Separator between multiple values in one cell.</summary>
    public string CellSeparator { get; set; } = ", ";

    public bool GridLines { get; set; } = true;

    public bool MultiLineCells { get; set; }

    public RepeatedValueMode RepeatedValues { get; set; } = RepeatedValueMode.ShowAll;

    public MacFormat MacFormat { get; set; } = MacFormat.Dashes;

    public RowSpacing RowSpacing { get; set; } = RowSpacing.Standard;

    /// <summary>Row colours as #RRGGBB; empty = theme default.</summary>
    public string OddRowColor { get; set; } = "";

    public string EvenRowColor { get; set; } = "";

    public string HighlightColor { get; set; } = "#FFF3B0";

    public string FontFamily { get; set; } = "";

    public double FontSize { get; set; }

    public bool CaseInsensitiveSort { get; set; } = true;

    public bool AutoExpand { get; set; } = true;

    public IReadOnlyList<ColumnLayout> Columns { get; set; } = [];

    public int FrozenColumns { get; set; }

    /// <summary>Which device count the status bar shows.</summary>
    public StatusStatistic StatusStatistic { get; set; } = StatusStatistic.Online;

    /// <summary>Shortcut overrides (UI-18): command id → gesture text; an empty gesture removes the default.</summary>
    public IReadOnlyList<ShortcutBinding> Shortcuts { get; set; } = [];

    /// <summary>Toolbar buttons hidden via View → Toolbar Settings (UI-23), by button name.</summary>
    public IReadOnlyList<string> HiddenToolbarButtons { get; set; } = [];

    /// <summary>General › Minimise to the notification area (UI-19).</summary>
    public bool MinimizeToTray { get; set; }

    public ColumnFormat Format(ScanSettings scan) => new()
    {
        MacFormat = MacFormat,
        Separator = string.IsNullOrEmpty(CellSeparator) ? ", " : CellSeparator,
        ShowServiceNames = scan?.ShowServiceNames ?? false,
    };
}

public sealed record ShortcutBinding
{
    public string CommandId { get; set; } = "";

    public string Gesture { get; set; } = "";
}

public enum RepeatedValueMode
{
    ShowAll,

    /// <summary>Consecutive duplicates show a ditto mark (D-032).</summary>
    Fold,

    /// <summary>Consecutive duplicates are blank.</summary>
    Hide,
}

public enum RowSpacing
{
    Compact,
    Standard,
    Expanded,
}

public enum StatusStatistic
{
    Online,
    Offline,
    Filtered,
}

/// <summary>Saved address-bar contents. Names may contain '|' to create submenus ("London | Subnet 1").</summary>
public sealed record Bookmark
{
    public string Name { get; set; } = "";

    public IReadOnlyList<RangeEntry> Ranges { get; set; } = [];

    public string RangeInfo => string.Join(", ", Ranges.Where(r => r.Enabled).Select(r => r.Target + (r.OctetMode ? " #N" : "")));
}

/// <summary>Persisted application configuration (transient scan results are never stored here).
/// Persisted models use <c>set</c> accessors: the System.Text.Json source generator assigns every <c>init</c>
/// property at construction, which would replace defaults of members missing from the file (D-016).</summary>
public sealed record AppSettings
{
    public const int CurrentSchemaVersion = 1;

    public int SchemaVersion { get; set; } = CurrentSchemaVersion;

    public ScanSettings Scan { get; set; } = new();

    public ViewSettings View { get; set; } = new();

    public IReadOnlyList<RangeEntry> Ranges { get; set; } = [];

    public IReadOnlyList<string> IgnoredAddresses { get; set; } = [];

    public ulong MaxTargets { get; set; } = new PlanLimits().MaxTargets;

    public ulong ConfirmationThreshold { get; set; } = new PlanLimits().ConfirmationThreshold;

    public IReadOnlyList<Bookmark> Bookmarks { get; set; } = [];

    /// <summary>Saved filters (manual: Quick Host Filter → Settings).</summary>
    public IReadOnlyList<FilterDefinition> SavedFilters { get; set; } = [];

    public IReadOnlyList<string> RecentFiles { get; set; } = [];

    /// <summary>Reload the most recent results file at start-up and save it on exit.</summary>
    public bool AutoLoadSaveRecent { get; set; }

    public IReadOnlyList<VirtualColumnDefinition> VirtualColumns { get; set; } = [];

    public IReadOnlyList<ColumnStyle> ColumnStyles { get; set; } = [];

    public FriendlyNameSettings FriendlyNames { get; set; } = new();

    public Management.WolSettings Wol { get; set; } = new();

    public Management.ApplicationSettings Applications { get; set; } = new();

    public Management.BrowsingSettings Browsing { get; set; } = new();

    /// <summary>Custom DHCP option codes requested by DHCP discovery (e.g. "160, 66, 67").</summary>
    public string DhcpCustomOptions { get; set; } = "";

    public string LastBatchTemplate { get; set; } = "";

    public Queries.QuerySettings Queries { get; set; } = new();

    /// <summary>Tools menu utilities (SMTP Client Tester profiles).</summary>
    public Tools.ToolSettings Tools { get; set; } = new();

    public IReadOnlyList<Security.StoredCredential> Credentials { get; set; } = [];

    public Security.VaultSettings Vault { get; set; } = new();

    public Monitoring.MonitoringSettings Monitoring { get; set; } = new();

    public Monitoring.BackgroundSettings Background { get; set; } = new();

    public Monitoring.HistorySettings History { get; set; } = new();

    /// <summary>All columns available with the current options: built-in, friendly-name and virtual columns.</summary>
    public IReadOnlyList<ResultColumn> AvailableColumns => ColumnSet.Build(Scan, FriendlyNames, VirtualColumns, Queries);

    /// <summary>Available columns in the saved order without hidden ones.</summary>
    public IReadOnlyList<ResultColumn> DisplayColumns => ColumnCatalog.Arrange(AvailableColumns, View.Columns);

    public const int MaxRecentFiles = 10;

    public AppSettings WithRecentFile(string path) => this with
    {
        RecentFiles = new[] { path }.Concat(RecentFiles.Where(p => !string.Equals(p, path, StringComparison.OrdinalIgnoreCase))).Take(MaxRecentFiles).ToList(),
    };

    public ColumnFormat Format => View.Format(Scan);

    public PlanLimits Limits => new() { MaxTargets = MaxTargets, ConfirmationThreshold = ConfirmationThreshold };

    public CsvOptions Csv => new()
    {
        Delimiter = View.CsvDelimiter,
        Encoding = View.CsvEncoding,
        ProtectFormulas = View.CsvProtectFormulas,
    };

    /// <summary>Parses enabled range entries. Invalid entries are returned as errors (never silently skipped).</summary>
    public static (List<TargetSpec> Specs, List<string> Errors) ParseRanges(IEnumerable<RangeEntry> ranges)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        var specs = new List<TargetSpec>();
        var errors = new List<string>();
        foreach (var r in ranges.Where(r => r.Enabled))
        {
            foreach (var part in r.Target.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (TargetParser.TryParse(part, r.OctetMode, out var spec, out var error)) specs.Add(spec);
                else errors.Add(r.Comment.Length > 0 ? $"{r.Comment}: {error}" : error);
            }
        }

        return (specs, errors);
    }
}
