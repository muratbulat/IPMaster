using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Desktop.ViewModels;

/// <summary>ObservableCollection with a single Reset notification for bulk replacement.</summary>
public sealed class RangeObservableCollection<T> : ObservableCollection<T>
{
    public void ReplaceAll(IEnumerable<T> items)
    {
        Items.Clear();
        foreach (var i in items) Items.Add(i);
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}

/// <summary>One device and its share child rows.</summary>
public sealed class DeviceNode
{
    public DeviceNode(DeviceResult result, ResultsView owner)
    {
        Result = result;
        Row = new ResultRow(this, null, owner);
    }

    public DeviceResult Result { get; set; }

    public ResultRow Row { get; }

    public List<ResultRow> ShareRows { get; } = [];

    public bool Expanded { get; set; }

    public bool UserHighlighted { get; set; }

    public bool Visible { get; set; }
}

/// <summary>A grid row: a device or one of its shares. Cells are read through the string indexer (column id).</summary>
public sealed class ResultRow : INotifyPropertyChanged
{
    private readonly ResultsView _owner;
    private Dictionary<string, string>? _cache;

    public ResultRow(DeviceNode node, ShareInfo? share, ResultsView owner)
    {
        Node = node;
        Share = share;
        _owner = owner;
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public DeviceNode Node { get; }

    public ShareInfo? Share { get; }

    public bool IsShare => Share is not null;

    public DeviceResult Result => Node.Result;

    /// <summary>Repeated-value display overrides (per column id), set by the view after sorting.</summary>
    public Dictionary<string, string>? Overrides { get; set; }

    public bool IsFilterMatch { get; set; }

    public string Glyph => IsShare ? "" : Node.ShareRows.Count == 0 ? "" : Node.Expanded ? "−" : "+";

    public double Indent => IsShare ? 18 : 0;

    public bool IsOnline => Node.Result.Status == DeviceStatus.Online;

    /// <summary>Category for the Device Type glyph (D-072); Unknown shows no glyph.</summary>
    public IPMaster.Core.Results.DeviceCategory DeviceCategory => IsShare ? IPMaster.Core.Results.DeviceCategory.Unknown : IPMaster.Core.Results.DeviceTypes.Describe(Node.Result).Category;

    /// <summary>Device Type tooltip: the text and the evidence behind it (D-089); null when there is nothing to explain.</summary>
    public string? DeviceTypeTip => IsShare || IPMaster.Core.Results.DeviceTypes.Describe(Node.Result) is not { Text.Length: > 0 } t
        ? null
        : t.Source.Length > 0 ? $"{t.Text}\n{t.Source}" : t.Text;

    public string this[string key]
    {
        get
        {
            var (columnId, part) = _owner.Resolve(key);
            if (part is not null) return _owner.StyleValue(this, columnId, part);
            if (Overrides is not null && Overrides.TryGetValue(columnId, out var o)) return o;
            _cache ??= [];
            if (!_cache.TryGetValue(columnId, out var v))
            {
                v = _owner.CellText(this, columnId);
                _cache[columnId] = v;
            }

            return v;
        }
    }

    public string RawText(string columnId)
    {
        _cache ??= [];
        if (!_cache.TryGetValue(columnId, out var v))
        {
            v = _owner.CellText(this, columnId);
            _cache[columnId] = v;
        }

        return v;
    }

    public void Invalidate()
    {
        _cache = null;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Glyph)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsFilterMatch)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsOnline)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DeviceCategory)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(DeviceTypeTip)));
    }
}

/// <summary>Share columns shown in the grid next to device columns (device rows leave them blank).</summary>
public static class ShareGridColumns
{
    public static readonly (string Id, string Header, Func<ShareInfo, string> Text)[] All =
    [
        ("share.type", "Share Type", Formats.ShareKind),
        ("share.access", "Share Access", Formats.ShareAccessText),
        ("share.disk", "Disk Space", s => ShareColumns.All.First(c => c.Id == "disk").Text(s)),
        ("share.permissions", "Permissions", s => ShareColumns.All.First(c => c.Id == "permissions").Text(s)),
        ("share.remark", "Share Remark", s => s.Remark),
    ];
}

/// <summary>
/// UI-independent results tree: master list of device nodes, typed sorting, filters (highlight or hide), share-type
/// filtering, expand/collapse and repeated-value display. Produces the flat <see cref="Rows"/> list for the grid.
/// </summary>
public sealed class ResultsView
{
    private readonly Dictionary<AddressKey, DeviceNode> _nodes = [];
    private CompiledFilter? _filter;
    private FilterMode _filterMode = FilterMode.Highlight;

    public RangeObservableCollection<ResultRow> Rows { get; } = [];

    public IReadOnlyCollection<DeviceNode> Nodes => _nodes.Values;

    public int Count => _nodes.Count;

    private IReadOnlyList<ResultColumn> _columns = [];
    private readonly Dictionary<string, string> _keyToId = [];
    private readonly Dictionary<string, string> _idToKey = [];

    public IReadOnlyList<ResultColumn> Columns
    {
        get => _columns;
        set
        {
            _columns = value;
            _keyToId.Clear();
            _idToKey.Clear();
            var ids = value.Select(c => c.Id).Concat(ShareGridColumns.All.Select(s => s.Id)).ToList();
            for (var i = 0; i < ids.Count; i++)
            {
                _keyToId["k" + i.ToString(System.Globalization.CultureInfo.InvariantCulture)] = ids[i];
                _idToKey[ids[i]] = "k" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            }
        }
    }

    /// <summary>Column styles (manual "Change Column View") by column id.</summary>
    public Dictionary<string, ColumnStyle> Styles { get; } = new(StringComparer.Ordinal);

    /// <summary>Binding-safe key for a column id (ids may contain spaces or colons).</summary>
    public string KeyFor(string columnId) => _idToKey.GetValueOrDefault(columnId) ?? columnId;

    /// <summary>Resolves a grid key ("k3", "k3_fg" ...) to a column id and an optional style part.</summary>
    public (string Id, string? Part) Resolve(string key)
    {
        var us = key.IndexOf('_', StringComparison.Ordinal);
        if (us > 0 && _keyToId.TryGetValue(key[..us], out var styled)) return (styled, key[(us + 1)..]);
        return (_keyToId.GetValueOrDefault(key) ?? key, null);
    }

    public ColumnFormat Format { get; set; } = ColumnFormat.Default;

    public string? SortColumn { get; private set; }

    public bool SortDescending { get; private set; }

    public bool CaseInsensitiveSort { get; set; } = true;

    public RepeatedValueMode RepeatedValues { get; set; } = RepeatedValueMode.ShowAll;

    public bool AutoExpand { get; set; } = true;

    public bool OnlyWithSharedFolders { get; set; }

    /// <summary>Share categories to show; empty = any type.</summary>
    public HashSet<ShareCategory> ShareCategories { get; } = [];

    public bool IsDirty { get; private set; }

    public bool HasHidingFilter => OnlyWithSharedFolders || (_filter is { IsEmpty: false } && _filterMode == FilterMode.ShowOnlyMatching) || ShareCategories.Count > 0;

    public int FilteredCount => _nodes.Values.Count(n => n.Visible && (_filter is null || _filter.IsEmpty || n.Row.IsFilterMatch));

    public void SetFilter(CompiledFilter? filter, FilterMode mode)
    {
        _filter = filter is { IsEmpty: false } ? filter : null;
        _filterMode = mode;
        IsDirty = true;
    }

    public void SetSort(string? columnId, bool descending)
    {
        SortColumn = columnId;
        SortDescending = descending;
        IsDirty = true;
    }

    public DeviceNode? Find(AddressKey key) => _nodes.GetValueOrDefault(key);

    public void Clear()
    {
        _nodes.Clear();
        Rows.ReplaceAll([]);
        IsDirty = false;
    }

    public void Remove(IEnumerable<DeviceNode> nodes)
    {
        foreach (var n in nodes.ToList()) _nodes.Remove(n.Result.Key);
        IsDirty = true;
    }

    /// <summary>Adds or updates a device. Returns true when the node is new. <paramref name="background"/>: a continuous-operation
    /// round, merged with <see cref="DeviceResult.MergeBackground"/> so an unanswered round keeps the known fields (review C-05b).</summary>
    public bool Upsert(DeviceResult result, bool mergeRescan, bool background = false)
    {
        if (_nodes.TryGetValue(result.Key, out var node))
        {
            if (result.Revision != 0 && result.Revision < node.Result.Revision) return false;
            var sharesBefore = node.Result.Shares;
            node.Result = background ? DeviceResult.MergeBackground(node.Result, result) : mergeRescan ? DeviceResult.MergeRescan(node.Result, result) : result;
            if (!Equals(sharesBefore, node.Result.Shares)) RebuildShareRows(node);
            Evaluate(node);
            node.Row.Invalidate();
            foreach (var s in node.ShareRows) s.Invalidate();
            // Position or visibility may have changed: cheap path only for the default view.
            if (SortColumn is not null || HasHidingFilter || node.ShareRows.Count > 0) IsDirty = true;
            return false;
        }

        node = new DeviceNode(result, this);
        _nodes[result.Key] = node;
        RebuildShareRows(node);
        Evaluate(node);
        if (SortColumn is null && !HasHidingFilter && node.ShareRows.Count == 0 && !_nodes.Values.Any(n => n.Expanded))
        {
            // Incremental insert in address order (no expanded nodes: rows map 1:1 to devices).
            var lo = 0;
            var hi = Rows.Count;
            while (lo < hi)
            {
                var mid = (lo + hi) / 2;
                if (Rows[mid].Result.Key.CompareTo(result.Key) < 0) lo = mid + 1;
                else hi = mid;
            }

            node.Visible = true;
            Rows.Insert(lo, node.Row);
        }
        else
        {
            IsDirty = true;
        }

        return true;
    }

    private void RebuildShareRows(DeviceNode node)
    {
        node.ShareRows.Clear();
        if (!node.Result.Shares.HasValue) return;
        foreach (var s in node.Result.Shares.Value!.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase))
        {
            node.ShareRows.Add(new ResultRow(node, s, this));
        }

        if (AutoExpand && node.ShareRows.Count > 0) node.Expanded = true;
    }

    private void Evaluate(DeviceNode node) => node.Row.IsFilterMatch = _filter is not null && _filter.Matches(node.Result, Format);

    public void ToggleExpand(DeviceNode node)
    {
        if (node.ShareRows.Count == 0) return;
        node.Expanded = !node.Expanded;
        Rebuild();
    }

    public void ExpandAll(bool expand)
    {
        foreach (var n in _nodes.Values) n.Expanded = expand && n.ShareRows.Count > 0;
        Rebuild();
    }

    private bool ShareVisible(ShareInfo s) => Format.ShareMatches(s) && ShareFilters.MatchesAny(s, ShareCategories);

    /// <summary>Full rebuild: filter, sort, expand, repeated values.</summary>
    public void Rebuild()
    {
        var list = new List<DeviceNode>(_nodes.Count);
        foreach (var n in _nodes.Values)
        {
            Evaluate(n);
            var visible = true;
            if (OnlyWithSharedFolders && !ShareFilters.HasSharedFolders(n.Result)) visible = false;
            if (visible && ShareCategories.Count > 0 && !(n.Result.Shares.HasValue && n.Result.Shares.Value!.Any(ShareVisible))) visible = false;
            if (visible && _filter is not null && _filterMode == FilterMode.ShowOnlyMatching && !n.Row.IsFilterMatch) visible = false;
            n.Visible = visible;
            if (visible) list.Add(n);
        }

        list.Sort(Compare);
        var rows = new List<ResultRow>(list.Count);
        foreach (var n in list)
        {
            n.Row.Overrides = null;
            rows.Add(n.Row);
            if (!n.Expanded) continue;
            foreach (var s in n.ShareRows)
            {
                if (ShareVisible(s.Share!)) rows.Add(s);
            }
        }

        ApplyRepeatedValues(rows);
        Rows.ReplaceAll(rows);
        foreach (var r in rows) r.Invalidate();
        IsDirty = false;
    }

    private int Compare(DeviceNode a, DeviceNode b)
    {
        if (SortColumn is not null && Columns.FirstOrDefault(c => c.Id == SortColumn) is { } col)
        {
            var va = col.SortValue(a.Result, Format);
            var vb = col.SortValue(b.Result, Format);
            int c;
            if (va is null && vb is null) c = 0;
            else if (va is null) c = 1; // empty values last in either direction
            else if (vb is null) c = -1;
            else
            {
                c = va is string sa && vb is string sb
                    ? (CaseInsensitiveSort ? string.Compare(sa, sb, StringComparison.CurrentCultureIgnoreCase) : string.Compare(sa, sb, StringComparison.CurrentCulture))
                    : va.GetType() == vb.GetType() ? va.CompareTo(vb) : string.CompareOrdinal(va.ToString(), vb.ToString());
                if (SortDescending) c = -c;
            }

            if (c != 0) return c;
        }

        return a.Result.Key.CompareTo(b.Result.Key);
    }

    private void ApplyRepeatedValues(List<ResultRow> rows)
    {
        if (RepeatedValues == RepeatedValueMode.ShowAll) return;
        var marker = RepeatedValues == RepeatedValueMode.Fold ? "〃" : "";
        ResultRow? previous = null;
        foreach (var r in rows.Where(r => !r.IsShare))
        {
            if (previous is not null)
            {
                foreach (var c in Columns)
                {
                    if (c.Id == "ip") continue;
                    var text = r.RawText(c.Id);
                    if (text.Length > 0 && text == previous.RawText(c.Id))
                    {
                        r.Overrides ??= [];
                        r.Overrides[c.Id] = marker;
                    }
                }
            }

            previous = r;
        }
    }

    public string CellText(ResultRow row, string columnId)
    {
        if (row.Share is { } share)
        {
            if (columnId == "ip") return share.Name;
            var sc = ShareGridColumns.All.FirstOrDefault(c => c.Id == columnId);
            return sc.Text is null ? "" : sc.Text(share);
        }

        if (columnId.StartsWith("share.", StringComparison.Ordinal)) return "";
        var col = Columns.FirstOrDefault(c => c.Id == columnId) ?? ColumnCatalog.Find(columnId);
        if (col is null) return "";
        var r = row.Result;
        // Pending enrichment shows an ellipsis in the grid (exports leave it blank, D-024).
        if (col.Id == "hostName" && r.HostName.State == ObservationState.Pending) return "…";
        return Styles.TryGetValue(col.Id, out var style) ? ColumnStyles.Transform(style, col.Text(r, Format)) : col.Text(r, Format);
    }

    /// <summary>Style values for template cells: colour strings, "Bold", "Italic", "Underline"/"Strikethrough"; empty = default.</summary>
    /// <summary>Rows rendered bold in the IP column (history newcomers, HIS-02).</summary>
    public Func<DeviceResult, bool>? IsBold { get; set; }

    public string StyleValue(ResultRow row, string columnId, string part)
    {
        if (part == "fw" && columnId == "ip" && !row.IsShare && IsBold?.Invoke(row.Result) == true) return "Bold";
        if (row.IsShare || !Styles.TryGetValue(columnId, out var s)) return "";
        var col = Columns.FirstOrDefault(c => c.Id == columnId);
        if (col is null || !ColumnStyles.Applies(s, col.Text(row.Result, Format))) return "";
        return part switch
        {
            "fg" => s.Foreground,
            "bg" => s.Background,
            "fw" => s.Bold ? "Bold" : "",
            "fs" => s.Italic ? "Italic" : "",
            "td" => s.Underline && s.Strikethrough ? "Underline,Strikethrough" : s.Underline ? "Underline" : s.Strikethrough ? "Strikethrough" : "",
            _ => "",
        };
    }
}
