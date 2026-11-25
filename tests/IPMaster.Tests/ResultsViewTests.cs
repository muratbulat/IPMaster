using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

public class ResultsViewTests
{
    private static ResultsView View() => new() { Columns = [ColumnCatalog.IpAddress, ColumnCatalog.HostName, ColumnCatalog.ResponseTime, ColumnCatalog.Shares] };

    private static DeviceResult D(string ip, string? host = null, double rttMs = 1) => Samples.Device(ip, host) with { RoundTrip = TimeSpan.FromMilliseconds(rttMs), Revision = 1 };

    private static List<string> Ips(ResultsView v) => v.Rows.Select(r => r.IsShare ? "  " + r.Share!.Name : r.Result.Key.ToString()).ToList();

    [Fact]
    public void Incremental_insert_keeps_address_order()
    {
        var v = View();
        foreach (var ip in new[] { "10.0.0.10", "10.0.0.2", "10.0.0.9" }) v.Upsert(D(ip), false);
        Assert.False(v.IsDirty);
        Assert.Equal(["10.0.0.2", "10.0.0.9", "10.0.0.10"], Ips(v));
    }

    [Fact]
    public void Typed_sort_and_case_insensitive_text_sort()
    {
        var v = View();
        v.Upsert(D("10.0.0.1", "beta", 30), false);
        v.Upsert(D("10.0.0.2", "Alpha", 4), false);
        v.Upsert(D("10.0.0.3", "gamma", 200), false);
        v.SetSort("rtt", descending: false);
        v.Rebuild();
        Assert.Equal(["10.0.0.2", "10.0.0.1", "10.0.0.3"], Ips(v)); // 4 < 30 < 200 numerically, not as text
        v.SetSort("hostName", descending: true);
        v.Rebuild();
        Assert.Equal(["10.0.0.3", "10.0.0.1", "10.0.0.2"], Ips(v));
        v.SetSort(null, false);
        v.Rebuild();
        Assert.Equal(["10.0.0.1", "10.0.0.2", "10.0.0.3"], Ips(v));
    }

    [Fact]
    public void Highlight_filter_keeps_rows_and_hide_filter_removes_them()
    {
        var v = View();
        v.Upsert(D("10.0.0.1", "printer"), false);
        v.Upsert(D("10.0.0.2", "server"), false);
        var f = CompiledFilter.Compile(new FilterDefinition { Conditions = [new FilterCondition { ColumnId = "hostName", Value = "print" }] }, out _);
        v.SetFilter(f, FilterMode.Highlight);
        v.Rebuild();
        Assert.Equal(2, v.Rows.Count);
        Assert.True(v.Rows[0].IsFilterMatch);
        Assert.False(v.Rows[1].IsFilterMatch);
        Assert.Equal(1, v.FilteredCount);
        v.SetFilter(f, FilterMode.ShowOnlyMatching);
        v.Rebuild();
        Assert.Equal(["10.0.0.1"], Ips(v));
    }

    [Fact]
    public void Shares_tree_expand_collapse_and_category_filter()
    {
        var v = View();
        v.Upsert(RichSamples.Full("10.0.0.2") with { Revision = 1 }, false);
        v.Upsert(D("10.0.0.3"), false);
        v.Rebuild();
        Assert.Equal(["10.0.0.2", "  C$", "  Printer1", "  Public", "  Secret", "10.0.0.3"], Ips(v)); // auto-expanded
        Assert.Equal("Public", v.Rows[3]["ip"]);
        Assert.Equal("Read/Write", v.Rows[3]["share.access"]);
        Assert.Equal("", v.Rows[0]["share.access"]);
        v.ToggleExpand(v.Find(v.Rows[0].Result.Key)!);
        Assert.Equal(["10.0.0.2", "10.0.0.3"], Ips(v));
        v.ExpandAll(true);
        v.ShareCategories.Add(ShareCategory.Writable);
        v.Rebuild();
        Assert.Equal(["10.0.0.2", "  Public"], Ips(v)); // device without matching shares hidden, other shares filtered
        v.ShareCategories.Clear();
        v.OnlyWithSharedFolders = true;
        v.Rebuild();
        Assert.Equal("10.0.0.2", Ips(v)[0]);
        Assert.DoesNotContain("10.0.0.3", Ips(v));
    }

    [Fact]
    public void Repeated_values_fold_and_hide()
    {
        var v = View();
        v.RepeatedValues = RepeatedValueMode.Fold;
        v.Upsert(D("10.0.0.1", "same"), false);
        v.Upsert(D("10.0.0.2", "same"), false);
        v.Upsert(D("10.0.0.3", "other"), false);
        v.Rebuild();
        Assert.Equal("same", v.Rows[0]["hostName"]);
        Assert.Equal("〃", v.Rows[1]["hostName"]);
        Assert.Equal("other", v.Rows[2]["hostName"]);
        Assert.Equal("10.0.0.2", v.Rows[1]["ip"]); // the key column is never folded
        v.RepeatedValues = RepeatedValueMode.Hide;
        v.Rebuild();
        Assert.Equal("", v.Rows[1]["hostName"]);
    }

    [Fact]
    public void Older_revisions_are_ignored_and_rescans_keep_last_seen()
    {
        var v = View();
        v.Upsert(D("10.0.0.1", "new") with { Revision = 5 }, false);
        v.Upsert(D("10.0.0.1", "stale") with { Revision = 3 }, false);
        Assert.Equal("new", v.Rows[0]["hostName"]);
        v.Upsert(D("10.0.0.1") with { Revision = 9, Status = DeviceStatus.Offline, LastSeen = null }, mergeRescan: true);
        Assert.Equal(Samples.T, v.Find(v.Rows[0].Result.Key)!.Result.LastSeen);
    }

    [Fact]
    public void Paste_expansion_to_class_ranges()
    {
        Assert.Equal("10.0.1.0-10.0.1.255", MainWindowViewModel.ExpandPasted("10.0.1.50", 24));
        Assert.Equal("10.0.0.0-10.0.255.255", MainWindowViewModel.ExpandPasted("10.0.1.50", 16));
        Assert.Equal("10.0.0.0-10.255.255.255", MainWindowViewModel.ExpandPasted("10.0.1.50", 8));
        Assert.Equal("10.0.1.50", MainWindowViewModel.ExpandPasted("10.0.1.50", 32));
        Assert.Equal("2001:db8::1", MainWindowViewModel.ExpandPasted("2001:db8::1", 24)); // IPv6: as-is only
        Assert.Null(MainWindowViewModel.ExpandPasted("not an ip", 24));
    }
}
