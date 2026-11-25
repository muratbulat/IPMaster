using System.Globalization;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Network;

namespace IPMaster.Desktop.ViewModels;

public enum AdapterFilter
{
    All,
    Physical,
    Virtual,
    Vpn,
    Ethernet,
    WiFi,
}

/// <summary>A range chosen in the picker: the target text the range list takes, and where it came from.</summary>
public sealed record AdapterRange(string Adapter, AdapterAddress Address, string Range, UInt128 Count);

/// <summary>One address of an adapter: a scan range, IPv6 neighbour discovery, or disabled with the reason.</summary>
public sealed partial class AdapterAddressItem : ObservableObject
{
    public AdapterAddressItem(string adapterId, AdapterAddress address)
    {
        Address = address;
        Key = adapterId + "|" + address;
        var spec = address.ToSubnetSpec();
        if (spec is not null)
        {
            Range = $"{spec.Start}/{address.PrefixLength}";
            Count = spec.RawCount;
            Detail = string.Create(CultureInfo.CurrentCulture, $"scan range {spec.Start} – {spec.End} ({(decimal)spec.RawCount:N0} addresses)");
        }
        else if (address.IsLinkLocal && address.Address.ScopeId != 0)
        {
            // manual: a link-local address selects IPv6 neighbour discovery (multicast ping to ff02::1 on that link)
            Range = $"ff02::1%{address.Address.ScopeId}";
            Count = 1;
            Detail = $"IPv6 neighbour discovery ({Range})";
        }
        else
        {
            Detail = "subnet too large to sweep (select the adapter's link-local address for IPv6 neighbour discovery)";
        }
    }

    /// <summary>Stable identity: the adapter's OS id and the address, never the display name.</summary>
    public string Key { get; }

    public AdapterAddress Address { get; }

    public string? Range { get; }

    public UInt128 Count { get; }

    public bool Eligible => Range is not null;

    public string Detail { get; }

    public string Text => $"{Address}   {Detail}";

    [ObservableProperty] public partial bool IsSelected { get; set; }

    /// <summary>False while the IPv4/IPv6 filter hides it (a hidden selection stays selected and is counted).</summary>
    [ObservableProperty] public partial bool IsShown { get; set; } = true;
}

/// <summary>One adapter with its addresses.</summary>
public sealed partial class AdapterGroupItem : ObservableObject
{
    public AdapterGroupItem(NetworkAdapterInfo adapter)
    {
        Adapter = adapter;
        Class = AdapterClassifier.Classify(adapter);
        Addresses = [.. adapter.Addresses.Select(a => new AdapterAddressItem(adapter.Id, a))];
        foreach (var a in Addresses) a.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(AdapterAddressItem.IsSelected)) OnPropertyChanged(nameof(GroupChecked));
        };
        SearchText = string.Join(' ', new[] { adapter.Name, adapter.Description, adapter.MacAddress ?? "", Class.Label, adapter.Type }
            .Concat(adapter.Addresses.Select(a => a.ToString())).Concat(adapter.Gateways.Select(g => g.ToString()))).ToLowerInvariant();
    }

    public NetworkAdapterInfo Adapter { get; }

    public AdapterClass Class { get; }

    public IReadOnlyList<AdapterAddressItem> Addresses { get; }

    public string SearchText { get; }

    public string Title => Adapter.Name;

    public string Subtitle => $"{Class.Label} · {Adapter.Description}";

    public string Details => string.Join("   ", new[]
    {
        Adapter.MacAddress is { Length: > 0 } m ? "MAC " + m : null,
        Adapter.Gateways.Count > 0 ? "Gateway " + string.Join(", ", Adapter.Gateways) : "No gateway",
        "Type: " + Class.Label + " (" + Class.Evidence + ")",
        Adapter.SpeedBitsPerSecond > 0 ? string.Create(CultureInfo.CurrentCulture, $"{Adapter.SpeedBitsPerSecond / 1e6:0.#} Mbit/s") : null,
    }.OfType<string>());

    [ObservableProperty] public partial bool IsExpanded { get; set; }

    [ObservableProperty] public partial bool IsShown { get; set; } = true;

    /// <summary>All shown eligible addresses selected (true), none (false) or some (null); setting it selects or clears them.</summary>
    public bool? GroupChecked
    {
        get
        {
            var eligible = Addresses.Where(a => a.Eligible && a.IsShown).ToList();
            if (eligible.Count == 0 || eligible.All(a => !a.IsSelected)) return false;
            return eligible.All(a => a.IsSelected) ? true : null;
        }
        set
        {
            foreach (var a in Addresses.Where(a => a.Eligible && a.IsShown)) a.IsSelected = value == true;
            OnPropertyChanged();
        }
    }

    internal void RaiseGroupChecked() => OnPropertyChanged(nameof(GroupChecked));
}

/// <summary>
/// The Auto Detect Local IP Range picker (D-101): search, kind and IP-family filters, grouped adapters, selection that
/// survives filtering and refresh (keyed by adapter id and address), deduplicated ranges and a large-range warning.
/// Range semantics are unchanged: IPv4 subnets, small IPv6 subnets, IPv6 neighbour discovery on link-local addresses.
/// </summary>
public sealed partial class AdapterPickerViewModel : ObservableObject
{
    private readonly UInt128 _largeThreshold;

    public AdapterPickerViewModel(IReadOnlyList<NetworkAdapterInfo> adapters, ulong largeThreshold = 65_536)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        _largeThreshold = largeThreshold;
        Groups = Build(adapters);
        DefaultNote = SelectDefaults();
        foreach (var g in Groups) g.IsExpanded = Groups.Count <= 3 || g.Addresses.Any(a => a.IsSelected);
        Apply();
    }

    public IReadOnlyList<AdapterGroupItem> Groups { get; private set; }

    /// <summary>Why something was (or was not) preselected.</summary>
    public string DefaultNote { get; }

    [ObservableProperty] public partial string Search { get; set; } = "";

    [ObservableProperty] public partial AdapterFilter Filter { get; set; }

    [ObservableProperty] public partial bool ShowIPv4 { get; set; } = true;

    [ObservableProperty] public partial bool ShowIPv6 { get; set; }

    [ObservableProperty] public partial string Summary { get; set; } = "";

    [ObservableProperty] public partial string Warning { get; set; } = "";

    [ObservableProperty] public partial string RefreshNote { get; set; } = "";

    [ObservableProperty] public partial bool CanSubmit { get; set; }

    /// <summary>The chosen ranges exceed the large-scan threshold: the dialog asks before adding them.</summary>
    public bool IsLarge { get; private set; }

    partial void OnSearchChanged(string value) => Apply();

    partial void OnFilterChanged(AdapterFilter value) => Apply();

    partial void OnShowIPv4Changed(bool value) => Apply();

    partial void OnShowIPv6Changed(bool value) => Apply();

    private List<AdapterGroupItem> Build(IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        var groups = adapters.Select(a => new AdapterGroupItem(a)).ToList();
        foreach (var g in groups)
        {
            foreach (var a in g.Addresses) a.PropertyChanged += (_, e) =>
            {
                if (e.PropertyName == nameof(AdapterAddressItem.IsSelected)) UpdateSummary();
            };
        }

        return groups;
    }

    /// <summary>
    /// Preselects only when one adapter is clearly the primary one: a likely physical Ethernet or Wi-Fi adapter with a
    /// gateway. Several such adapters, or only virtual/VPN/unknown ones, leave the choice to the user.
    /// </summary>
    private string SelectDefaults()
    {
        var primary = Groups.Where(g => g.Class.Physical == true && g.Class.Kind is AdapterKind.Ethernet or AdapterKind.WiFi && g.Adapter.Gateways.Count > 0
                                        && g.Addresses.Any(a => a.Eligible && !a.Address.IsV6)).ToList();
        if (primary.Count == 1)
        {
            foreach (var a in primary[0].Addresses.Where(a => a.Eligible && !a.Address.IsV6)) a.IsSelected = true;
            return $"Preselected: {primary[0].Adapter.Name} ({primary[0].Class.Label} with a gateway). Virtual and VPN adapters are never preselected.";
        }

        return primary.Count > 1
            ? "Several connected adapters could be the main one: choose the networks to scan."
            : Groups.Count == 0 ? "" : "No physical adapter with a gateway was found: choose the networks to scan.";
    }

    private bool Matches(AdapterGroupItem g)
    {
        var kindOk = Filter switch
        {
            AdapterFilter.Physical => g.Class.Physical == true,
            AdapterFilter.Virtual => g.Class.Kind == AdapterKind.Virtual,
            AdapterFilter.Vpn => g.Class.Kind == AdapterKind.Vpn,
            AdapterFilter.Ethernet => g.Class.Kind == AdapterKind.Ethernet,
            AdapterFilter.WiFi => g.Class.Kind == AdapterKind.WiFi,
            _ => true,
        };
        var q = Search.Trim().ToLowerInvariant();
        return kindOk && (q.Length == 0 || q.Split(' ', StringSplitOptions.RemoveEmptyEntries).All(t => g.SearchText.Contains(t, StringComparison.Ordinal)));
    }

    /// <summary>Applies search and filters by visibility only: no selection changes and no controls rebuilt.</summary>
    private void Apply()
    {
        foreach (var g in Groups)
        {
            foreach (var a in g.Addresses) a.IsShown = a.Address.IsV6 ? ShowIPv6 : ShowIPv4;
            g.IsShown = Matches(g) && g.Addresses.Any(a => a.IsShown);
            g.RaiseGroupChecked();
        }

        UpdateSummary();
    }

    public IEnumerable<AdapterAddressItem> Shown => Groups.Where(g => g.IsShown).SelectMany(g => g.Addresses).Where(a => a.IsShown);

    /// <summary>Selects the eligible addresses that are visible now; hidden selections are left as they are.</summary>
    public void SelectVisible()
    {
        foreach (var a in Shown.Where(a => a.Eligible)) a.IsSelected = true;
        foreach (var g in Groups) g.RaiseGroupChecked();
    }

    public void ClearVisible()
    {
        foreach (var a in Shown) a.IsSelected = false;
        foreach (var g in Groups) g.RaiseGroupChecked();
    }

    public void ClearAll()
    {
        foreach (var a in Groups.SelectMany(g => g.Addresses)) a.IsSelected = false;
        foreach (var g in Groups) g.RaiseGroupChecked();
    }

    /// <summary>Re-reads the adapters; selections whose adapter and address still exist are kept, the others reported.</summary>
    public void Refresh(IReadOnlyList<NetworkAdapterInfo> adapters)
    {
        ArgumentNullException.ThrowIfNull(adapters);
        var selected = Groups.SelectMany(g => g.Addresses).Where(a => a.IsSelected).Select(a => a.Key).ToHashSet(StringComparer.Ordinal);
        var expanded = Groups.Where(g => g.IsExpanded).Select(g => g.Adapter.Id).ToHashSet(StringComparer.Ordinal);
        var oldNames = Groups.ToDictionary(g => g.Adapter.Id, g => g.Adapter.Name, StringComparer.Ordinal);
        Groups = Build(adapters);
        foreach (var a in Groups.SelectMany(g => g.Addresses)) a.IsSelected = selected.Contains(a.Key) && a.Eligible;
        foreach (var g in Groups) g.IsExpanded = expanded.Contains(g.Adapter.Id) || g.Addresses.Any(a => a.IsSelected);
        var now = Groups.SelectMany(g => g.Addresses).Select(a => a.Key).ToHashSet(StringComparer.Ordinal);
        var gone = selected.Where(k => !now.Contains(k)).Select(k => k.Split('|') is [var id, var addr] ? $"{oldNames.GetValueOrDefault(id, id)} {addr}" : k).ToList();
        var goneAdapters = oldNames.Keys.Where(id => Groups.All(g => g.Adapter.Id != id)).Select(id => oldNames[id]).ToList();
        RefreshNote = (gone.Count > 0 ? "No longer present (deselected): " + string.Join(", ", gone) + ". " : "")
                      + (goneAdapters.Count > 0 ? "Adapters gone: " + string.Join(", ", goneAdapters) + "." : "")
                      + (gone.Count == 0 && goneAdapters.Count == 0 ? $"Refreshed: {Groups.Count} adapter(s)." : "");
        OnPropertyChanged(nameof(Groups));
        Apply();
    }

    /// <summary>The chosen ranges, deduplicated (two adapters on one subnet give one range).</summary>
    public IReadOnlyList<AdapterRange> Result() => Groups
        .SelectMany(g => g.Addresses.Where(a => a.IsSelected && a.Eligible).Select(a => new AdapterRange(g.Adapter.Name, a.Address, a.Range!, a.Count)))
        .GroupBy(r => r.Range, StringComparer.OrdinalIgnoreCase).Select(x => x.First()).ToList();

    private void UpdateSummary()
    {
        var chosen = Groups.SelectMany(g => g.Addresses.Where(a => a.IsSelected && a.Eligible).Select(a => (g, a))).ToList();
        var hidden = chosen.Count(x => !x.a.IsShown || !x.g.IsShown);
        var ranges = Result();
        var total = ranges.Aggregate(UInt128.Zero, (s, r) => s + r.Count);
        var c = CultureInfo.CurrentCulture;
        Summary = chosen.Count == 0 ? "Nothing selected."
            : string.Create(c, $"Selected: {chosen.Count} address(es) from {chosen.Select(x => x.g).Distinct().Count()} adapter(s) → {ranges.Count} range(s), {(decimal)total:N0} addresses")
              + (ranges.Count < chosen.Count ? $" ({chosen.Count - ranges.Count} duplicate subnet(s) merged)" : "")
              + (hidden > 0 ? $" · {hidden} selected address(es) hidden by the filters" : "");
        IsLarge = total > _largeThreshold;
        Warning = IsLarge ? string.Create(c, $"Large scan: {(decimal)total:N0} addresses (more than {(decimal)_largeThreshold:N0}). You will be asked to confirm.") : "";
        CanSubmit = ranges.Count > 0;
    }
}
