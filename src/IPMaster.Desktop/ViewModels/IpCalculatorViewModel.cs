using System.Collections.ObjectModel;
using System.Globalization;
using System.Numerics;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;

namespace IPMaster.Desktop.ViewModels;

/// <summary>Tools → IP Calculator. All arithmetic is in <see cref="IpCalculator"/> (Core); this class only keeps the fields in step.</summary>
public sealed partial class IpCalculatorViewModel : ObservableObject, IDisposable
{
    private static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    /// <summary>Set while the view-model writes one of the linked fields, so the change handlers do not recurse.</summary>
    private bool _syncing;

    private int _prefix = 24;
    private CancellationTokenSource? _exportCts;

    public IpCalculatorViewModel()
    {
        UpdateMaskText();
        Recalculate();
        RecalculateSplit();
    }

    public static IReadOnlyList<string> Examples => IpCalculator.Examples;

    // ================================================================ calculator input

    [ObservableProperty] public partial int FamilyIndex { get; set; }
    [ObservableProperty] public partial string AddressText { get; set; } = "";
    [ObservableProperty] public partial decimal? PrefixNumber { get; set; } = 24;
    [ObservableProperty] public partial double PrefixSlider { get; set; } = 24;
    [ObservableProperty] public partial string MaskText { get; set; } = "";
    [ObservableProperty] public partial string Validation { get; set; } = "";
    [ObservableProperty] public partial IpCalcResult? Result { get; set; }
    [ObservableProperty] public partial string Headline { get; set; } = "";
    [ObservableProperty] public partial string NotesText { get; set; } = "";
    [ObservableProperty] public partial bool ShowBinary { get; set; }
    [ObservableProperty] public partial bool InputEmpty { get; set; } = true;
    [ObservableProperty] public partial string Status { get; set; } = "";

    public bool IsV4 => FamilyIndex == 0;

    public bool IsV6 => FamilyIndex == 1;

    public int MaxPrefix => IsV6 ? 128 : 32;

    public int Prefix => _prefix;

    public bool HasResult => Result is not null;

    public ObservableCollection<IpField> PrimaryFields { get; } = [];

    public ObservableCollection<IpField> AdvancedFields { get; } = [];

    partial void OnFamilyIndexChanged(int value)
    {
        OnPropertyChanged(nameof(IsV4));
        OnPropertyChanged(nameof(IsV6));
        OnPropertyChanged(nameof(MaxPrefix));
        if (_syncing) return;
        ApplyFamilyChange();
    }

    /// <summary>A prefix typed with the address wins (switching family is how the user fixes a family mismatch); otherwise the family default.</summary>
    private void ApplyFamilyChange()
    {
        if (IpCalculator.TryParseInput(AddressText, Family, out _, out var p, out _) && p is { } typed) SetPrefix(typed, rewriteAddress: false);
        else SetPrefix(IsV6 ? 64 : 24, rewriteAddress: true);
        Recalculate();
    }

    partial void OnAddressTextChanged(string value)
    {
        if (_syncing) return;
        // A prefix or mask typed with the address drives the other fields; an address alone uses the prefix field.
        if (IpCalculator.TryParseInput(value, Family, out _, out var p, out _) && p is { } typed) SetPrefix(typed, rewriteAddress: false);
        Recalculate();
    }

    partial void OnPrefixNumberChanged(decimal? value)
    {
        if (_syncing) return;
        if (value is null)
        {
            // a cleared box shows the prefix still in use instead of staying blank
            SetPrefix(_prefix, rewriteAddress: false);
            return;
        }

        SetPrefix((int)Math.Clamp(Math.Truncate(value.Value), 0, MaxPrefix), rewriteAddress: true);
        Recalculate();
    }

    partial void OnPrefixSliderChanged(double value)
    {
        if (_syncing) return;
        var p = (int)Math.Round(Math.Clamp(value, 0, MaxPrefix));
        if (p == _prefix) return;
        SetPrefix(p, rewriteAddress: true);
        Recalculate();
    }

    partial void OnMaskTextChanged(string value)
    {
        if (_syncing || !IsV4) return;
        if (IpCalculator.TryParseMask(value, out var p, out _)) SetPrefix(p, rewriteAddress: true);
        Recalculate();
    }

    partial void OnShowBinaryChanged(bool value) => OnPropertyChanged(nameof(Result));

    private IpFamily Family => IsV6 ? IpFamily.IPv6 : IpFamily.IPv4;

    /// <summary>Writes the prefix into every linked field once. The address keeps its own form; a "/n" or mask it carries is rewritten.</summary>
    private void SetPrefix(int prefix, bool rewriteAddress)
    {
        _syncing = true;
        try
        {
            _prefix = Math.Clamp(prefix, 0, MaxPrefix);
            PrefixNumber = _prefix;
            PrefixSlider = _prefix;
            UpdateMaskText();
            // only an address of the selected family gets the new suffix (never "/66" on an IPv4 address)
            if (rewriteAddress && IpCalculator.TryParseAddress(AddressToken(AddressText), out var a, out _) && a.IsV6 == IsV6) AddressText = WithPrefix(AddressText, _prefix);
        }
        finally
        {
            _syncing = false;
        }

        OnPropertyChanged(nameof(Prefix));
    }

    private void UpdateMaskText() => MaskText = IsV4 ? IpText.Format(IpBlock.Containing(0, Math.Min(_prefix, 32), false).Mask, false) : "";

    /// <summary>"a/24", "a 255.255.255.0" and "a/24 255.255.255.0" become "a/{prefix}"; a bare address is left alone.</summary>
    internal static string WithPrefix(string text, int prefix)
    {
        var t = text.Trim();
        var parts = t.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return text;
        var first = parts[0];
        var slash = first.LastIndexOf('/');
        if (slash < 0 && parts.Length == 1) return text;
        if (slash >= 0) first = first[..slash];
        return string.Create(Inv, $"{first}/{prefix}");
    }

    /// <summary>The address token as typed, without "/prefix" or "%zone".</summary>
    private static string AddressToken(string text)
    {
        var first = text.Trim().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "";
        var slash = first.LastIndexOf('/');
        if (slash >= 0) first = first[..slash];
        first = first.TrimStart('[').TrimEnd(']');
        var pct = first.IndexOf('%', StringComparison.Ordinal);
        return pct >= 0 ? first[..pct] : first;
    }

    private void Recalculate()
    {
        string error;
        var maskPrefix = 0;
        IpCalcResult? result = null;
        if (AddressText.Trim().Length == 0)
        {
            error = "";
        }
        else if (!IpCalculator.TryParseInput(AddressText, Family, out var a, out var typed, out error))
        {
            // shown inline; previous results are cleared so nothing stale is on screen
        }
        else if (IsV4 && !IpCalculator.TryParseMask(MaskText, out maskPrefix, out var maskError))
        {
            error = "Subnet Mask: " + maskError;
        }
        else if (IsV4 && maskPrefix != (typed ?? _prefix))
        {
            error = $"The prefix /{typed ?? _prefix} and the subnet mask {MaskText.Trim()} (/{maskPrefix}) disagree.";
        }
        else
        {
            result = IpCalculator.Calculate(a, typed ?? _prefix, AddressToken(AddressText));
        }

        Validation = error;
        Result = result;
        InputEmpty = AddressText.Trim().Length == 0;
        OnPropertyChanged(nameof(HasResult));
        PrimaryFields.Clear();
        AdvancedFields.Clear();
        if (result is null)
        {
            Headline = "";
            NotesText = "";
            return;
        }

        foreach (var f in result.Primary) PrimaryFields.Add(f);
        foreach (var f in result.Advanced) AdvancedFields.Add(f);
        Headline = result.IsV6
            ? $"{result.Block}  ·  {IpText.Readable(result.Total)} addresses"
            : $"{result.Block}  ·  {IpText.Readable(result.Usable)} usable of {IpText.Readable(result.Total)}";
        NotesText = string.Join(Environment.NewLine, result.Notes.Select(n => "• " + n));
    }

    public void UseExample(string example)
    {
        _syncing = true;
        try
        {
            FamilyIndex = example.Contains(':', StringComparison.Ordinal) ? 1 : 0;
        }
        finally
        {
            _syncing = false;
        }

        _syncing = true;
        try
        {
            AddressText = example; // may be unchanged (same example again): recalculate explicitly below
        }
        finally
        {
            _syncing = false;
        }

        ApplyFamilyChange();
    }

    public void Reset()
    {
        _syncing = true;
        try
        {
            FamilyIndex = 0;
            AddressText = "";
            ShowBinary = false;
        }
        finally
        {
            _syncing = false;
        }

        SetPrefix(24, rewriteAddress: false);
        Recalculate();
        Status = "Reset.";
    }

    public string SummaryText() => Result?.Summary() ?? "";

    // ================================================================ split subnet

    [ObservableProperty] public partial string SplitParent { get; set; } = "";
    [ObservableProperty] public partial int SplitModeIndex { get; set; }
    [ObservableProperty] public partial decimal? SplitPrefix { get; set; } = 26;
    [ObservableProperty] public partial string SplitHosts { get; set; } = "50";
    [ObservableProperty] public partial bool AllowPointToPoint { get; set; }
    [ObservableProperty] public partial string SplitError { get; set; } = "";
    [ObservableProperty] public partial string SplitNote { get; set; } = "";
    [ObservableProperty] public partial SubnetSplit? Split { get; set; }
    [ObservableProperty] public partial IReadOnlyList<SubnetRow> SplitRows { get; set; } = [];
    [ObservableProperty] public partial string PageText { get; set; } = "";
    [ObservableProperty] public partial string GoToPage { get; set; } = "1";
    [ObservableProperty] public partial bool IsExporting { get; set; }

    private BigInteger _page;

    public ObservableCollection<IpField> SplitFields { get; } = [];

    public bool ByHosts => SplitModeIndex == 1;

    public bool ByPrefix => SplitModeIndex == 0;

    public bool CanExportAll => Split is { } s && s.SubnetCount <= SubnetSplit.MaxExportRows;

    public bool HasSplit => Split is not null;

    partial void OnSplitParentChanged(string value) => RecalculateSplit();

    partial void OnSplitModeIndexChanged(int value)
    {
        OnPropertyChanged(nameof(ByHosts));
        OnPropertyChanged(nameof(ByPrefix));
        RecalculateSplit();
    }

    partial void OnSplitPrefixChanged(decimal? value) => RecalculateSplit();

    partial void OnSplitHostsChanged(string value) => RecalculateSplit();

    partial void OnAllowPointToPointChanged(bool value) => RecalculateSplit();

    partial void OnSplitChanged(SubnetSplit? value)
    {
        OnPropertyChanged(nameof(CanExportAll));
        OnPropertyChanged(nameof(HasSplit));
    }

    public void UseCalculatorNetwork()
    {
        if (Result is { } r) SplitParent = r.Block.ToString();
    }

    private void RecalculateSplit()
    {
        SplitFields.Clear();
        SplitError = "";
        var notes = new List<string>();
        Split = null;
        SplitRows = [];
        PageText = "";
        if (SplitParent.Trim().Length == 0)
        {
            SplitNote = "Enter a parent network, or use the calculator's network.";
            return;
        }

        if (!IpCalculator.TryParseNetwork(SplitParent, null, out var parent, out var normalized, out var error))
        {
            SplitError = error;
            SplitNote = "";
            return;
        }

        if (normalized) notes.Add($"The entered address has host bits set; it was normalised to its containing network {parent}.");
        int newPrefix;
        if (ByHosts)
        {
            if (parent.IsV6)
            {
                SplitError = "Host-count planning is for IPv4. For IPv6 choose a prefix length (LANs normally use /64).";
                SplitNote = string.Join(" ", notes);
                return;
            }

            if (!BigInteger.TryParse(SplitHosts.Trim().Replace(",", "", StringComparison.Ordinal), NumberStyles.None, Inv, out var hosts))
            {
                SplitError = "Enter the number of usable hosts each subnet needs, e.g. 50.";
                SplitNote = string.Join(" ", notes);
                return;
            }

            if (!IpCalculator.TryPrefixForHosts(hosts, AllowPointToPoint, out newPrefix, out var hostNote))
            {
                SplitError = hostNote;
                SplitNote = string.Join(" ", notes);
                return;
            }

            notes.Add(hostNote);
        }
        else
        {
            newPrefix = (int)(SplitPrefix ?? parent.Prefix);
        }

        if (newPrefix < parent.Prefix || newPrefix > parent.Bits)
        {
            SplitError = newPrefix < parent.Prefix
                ? $"The new prefix /{newPrefix} is shorter than the parent /{parent.Prefix}. Subnets must be at least as specific as the parent (/{parent.Prefix}–/{parent.Bits})."
                : $"The prefix must be at most /{parent.Bits}.";
            SplitNote = string.Join(" ", notes);
            return;
        }

        var split = new SubnetSplit(parent, newPrefix);
        Split = split;
        SplitNote = string.Join(" ", notes);
        SplitFields.Add(new IpField("Parent Network", parent.ToString(), parent.ToString()));
        SplitFields.Add(new IpField("Resulting Prefix", $"/{newPrefix}", $"/{newPrefix}"));
        if (!parent.IsV6) SplitFields.Add(new IpField("Subnet Mask", IpText.Format(split.Mask, false), IpText.Format(split.Mask, false)));
        SplitFields.Add(new IpField("Number of Subnets", IpText.Readable(split.SubnetCount), IpText.Exact(split.SubnetCount)));
        SplitFields.Add(new IpField("Addresses per Subnet", IpText.Readable(split.AddressesPerSubnet), IpText.Exact(split.AddressesPerSubnet)));
        if (!parent.IsV6) SplitFields.Add(new IpField("Usable per Subnet", IpText.Readable(split.UsablePerSubnet), IpText.Exact(split.UsablePerSubnet)));
        ShowPage(0);
    }

    public void ShowPage(BigInteger page)
    {
        if (Split is not { } s) return;
        page = BigInteger.Clamp(page, 0, s.PageCount - 1);
        _page = page;
        SplitRows = s.Page(page);
        var first = (page * SubnetSplit.PageSize) + 1;
        PageText = $"Page {IpText.Grouped(page + 1)} of {IpText.Grouped(s.PageCount)}  ·  showing subnets {IpText.Grouped(first)}–{IpText.Grouped(first + SplitRows.Count - 1)} of {IpText.Grouped(s.SubnetCount)} in total";
        _syncing = true;
        GoToPage = IpText.Exact(page + 1);
        _syncing = false;
    }

    public void FirstPage() => ShowPage(0);

    public void PreviousPage() => ShowPage(_page - 1);

    public void NextPage() => ShowPage(_page + 1);

    public void LastPage()
    {
        if (Split is { } s) ShowPage(s.PageCount - 1);
    }

    public void GoTo()
    {
        if (BigInteger.TryParse(GoToPage.Trim().Replace(",", "", StringComparison.Ordinal), NumberStyles.None, Inv, out var p) && p >= 1) ShowPage(p - 1);
        else Status = "Enter a page number.";
    }

    /// <summary>Exports the current page or (bounded) the complete set; runs off the UI thread and can be cancelled.</summary>
    public async Task ExportSplitAsync(string path, bool json, bool complete)
    {
        if (Split is not { } s || IsExporting) return;
        if (complete && !CanExportAll)
        {
            Status = $"The complete set has {IpText.Readable(s.SubnetCount)} subnets, more than the export limit of {IpText.Grouped(SubnetSplit.MaxExportRows)}. Export pages instead, or choose a shorter prefix.";
            return;
        }

        var first = complete ? BigInteger.Zero : _page * SubnetSplit.PageSize;
        var count = complete ? (int)s.SubnetCount : SplitRows.Count;
        var scope = SubnetSplit.ScopeText(complete, _page, s.PageCount, count, s.SubnetCount);
        _exportCts = new CancellationTokenSource();
        var ct = _exportCts.Token;
        IsExporting = true;
        Status = $"Exporting {scope}…";
        try
        {
            await Task.Run(() => AtomicFile.WriteAsync(path, async stream =>
            {
                if (json)
                {
                    await s.WriteJsonAsync(stream, first, count, scope, complete, ct).ConfigureAwait(false);
                }
                else
                {
                    await using var w = new StreamWriter(stream, SubnetSplit.Utf8, 64 * 1024, leaveOpen: true);
                    await s.WriteCsvAsync(w, first, count, scope, ct).ConfigureAwait(false);
                    await w.FlushAsync(ct).ConfigureAwait(false);
                }
            }, ct), ct);
            Status = $"Exported {scope} to {Path.GetFileName(path)}.";
        }
        catch (OperationCanceledException)
        {
            Status = "Export cancelled; no file was written.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            Status = "Export failed: " + ex.Message;
        }
        finally
        {
            IsExporting = false;
            _exportCts.Dispose();
            _exportCts = null;
        }
    }

    public void CancelExport()
    {
        try
        {
            _exportCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    public async Task ExportSummaryAsync(string path, bool json)
    {
        if (Result is not { } r) return;
        try
        {
            await AtomicFile.WriteAsync(path, async stream =>
            {
                if (json)
                {
                    r.WriteJson(stream);
                }
                else
                {
                    await using var w = new StreamWriter(stream, SubnetSplit.Utf8, 4096, leaveOpen: true);
                    await w.WriteAsync(r.Summary()).ConfigureAwait(false);
                }
            });
            Status = $"Summary exported to {Path.GetFileName(path)}.";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            Status = "Export failed: " + ex.Message;
        }
    }

    // ================================================================ range and membership utilities

    [ObservableProperty] public partial string ContainsNetwork { get; set; } = "";
    [ObservableProperty] public partial string ContainsAddress { get; set; } = "";
    [ObservableProperty] public partial string ContainsResult { get; set; } = "";
    [ObservableProperty] public partial bool ContainsError { get; set; }
    [ObservableProperty] public partial string CompareA { get; set; } = "";
    [ObservableProperty] public partial string CompareB { get; set; } = "";
    [ObservableProperty] public partial string CompareResult { get; set; } = "";
    [ObservableProperty] public partial bool CompareError { get; set; }
    [ObservableProperty] public partial string RangeStart { get; set; } = "";
    [ObservableProperty] public partial string RangeEnd { get; set; } = "";
    [ObservableProperty] public partial string RangeResult { get; set; } = "";
    [ObservableProperty] public partial string RangeCidrs { get; set; } = "";
    [ObservableProperty] public partial bool RangeError { get; set; }

    public bool HasRangeCidrs => RangeCidrs.Length > 0;

    partial void OnRangeCidrsChanged(string value) => OnPropertyChanged(nameof(HasRangeCidrs));

    partial void OnContainsNetworkChanged(string value) => UpdateContains();

    partial void OnContainsAddressChanged(string value) => UpdateContains();

    partial void OnCompareAChanged(string value) => UpdateCompare();

    partial void OnCompareBChanged(string value) => UpdateCompare();

    partial void OnRangeStartChanged(string value) => UpdateRange();

    partial void OnRangeEndChanged(string value) => UpdateRange();

    private void UpdateContains()
    {
        if (ContainsNetwork.Trim().Length == 0 || ContainsAddress.Trim().Length == 0)
        {
            (ContainsResult, ContainsError) = ("", false);
            return;
        }

        if (IpCalculator.TryContains(ContainsNetwork, ContainsAddress, out var r, out var error))
        {
            ContainsResult = r.Text + (r.Normalized ? $" (The subnet was normalised to {r.Network}.)" : "");
            ContainsError = false;
        }
        else
        {
            (ContainsResult, ContainsError) = (error, true);
        }
    }

    private void UpdateCompare()
    {
        if (CompareA.Trim().Length == 0 || CompareB.Trim().Length == 0)
        {
            (CompareResult, CompareError) = ("", false);
            return;
        }

        if (IpCalculator.TryCompare(CompareA, CompareB, out var r, out var error)) (CompareResult, CompareError) = ($"{r.Text}\nA = {r.A.Label}\nB = {r.B.Label}", false);
        else (CompareResult, CompareError) = (error, true);
    }

    private void UpdateRange()
    {
        RangeCidrs = "";
        if (RangeStart.Trim().Length == 0 || RangeEnd.Trim().Length == 0)
        {
            (RangeResult, RangeError) = ("", false);
            return;
        }

        if (IpCalculator.TryRangeToCidr(RangeStart, RangeEnd, out var blocks, out var total, out var error))
        {
            RangeCidrs = string.Join(Environment.NewLine, blocks.Select(b => b.ToString()));
            RangeResult = blocks.Count == 1
                ? $"Exactly one CIDR block covers the {IpText.Readable(total)} addresses."
                : $"{blocks.Count} CIDR blocks exactly cover the {IpText.Readable(total)} addresses (the smallest exact set).";
            RangeError = false;
        }
        else
        {
            (RangeResult, RangeError) = (error, true);
        }
    }

    public void Dispose() => CancelExport();
}
