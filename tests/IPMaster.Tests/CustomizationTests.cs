using System.Net.NetworkInformation;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

public class VirtualColumnTests
{
    private static readonly ScanSettings Scan = new() { ResolveHostNames = true, ResolveMac = true };

    [Fact]
    public void Combines_columns_and_applies_regex()
    {
        var defs = new[]
        {
            new VirtualColumnDefinition { Name = "Label", Source = "[Host Name] ([MAC Address])" },
            new VirtualColumnDefinition { Name = "Gen", Source = "[Host Name]", Regex = @"i[0-9]-(\d+)K?", Replacement = "$1" },
            new VirtualColumnDefinition { Name = "Chained", Source = "<[Label]>" },
        };
        var cols = ColumnSet.Build(Scan, new FriendlyNameSettings(), defs);
        var d = Samples.Device("10.0.0.2", "Intel Core i7-12700K");
        Assert.Equal("Intel Core i7-12700K (AA-BB-CC-00-11-22)", cols.Single(c => c.Header == "Label").Text(d));
        Assert.Equal("Intel Core 12700", cols.Single(c => c.Header == "Gen").Text(d));
        Assert.Equal("<Intel Core i7-12700K (AA-BB-CC-00-11-22)>", cols.Single(c => c.Header == "Chained").Text(d));
    }

    [Fact]
    public void Validation_rejects_self_forward_and_unknown_references_and_bad_regex()
    {
        var available = ColumnSet.Build(Scan, new FriendlyNameSettings(), []);
        Assert.NotNull(ColumnSet.Validate(new VirtualColumnDefinition { Name = "A", Source = "[A]" }, available));
        Assert.NotNull(ColumnSet.Validate(new VirtualColumnDefinition { Name = "A", Source = "[Later]" }, available));
        Assert.NotNull(ColumnSet.Validate(new VirtualColumnDefinition { Name = "A", Source = "[Host Name]", Regex = "(" }, available));
        Assert.NotNull(ColumnSet.Validate(new VirtualColumnDefinition { Name = "", Source = "x" }, available));
        Assert.Null(ColumnSet.Validate(new VirtualColumnDefinition { Name = "A", Source = "[host name] [ip]" }, available));
    }

    [Fact]
    public void Catastrophic_regex_is_bounded()
    {
        var text = new string('a', 30) + "!";
        Assert.Equal("[regex timeout]", SafeRegex.Replace(text, "^(a+)+$", "x"));
    }
}

public class ColumnStyleTests
{
    [Theory]
    [InlineData(StyleCondition.None, "", "anything", true)]
    [InlineData(StyleCondition.Contains, "win", "Windows 11", true)]
    [InlineData(StyleCondition.NotContains, "win", "Linux", true)]
    [InlineData(StyleCondition.Equal, "online", "Online", true)]
    [InlineData(StyleCondition.LessThan, "10", "9 ms", true)]      // numeric, not text
    [InlineData(StyleCondition.GreaterThan, "100", "90 ms", false)]
    [InlineData(StyleCondition.Regex, "^10\\.0\\.", "10.0.0.5", true)]
    public void Conditions(StyleCondition condition, string value, string text, bool expected) =>
        Assert.Equal(expected, ColumnStyles.Applies(new ColumnStyle { Condition = condition, ConditionValue = value }, text));

    [Fact]
    public void Display_transform_and_grid_style_values()
    {
        Assert.Equal("Win", ColumnStyles.Transform(new ColumnStyle { Regex = "^(.{3}).*", Replacement = "$1" }, "Windows"));
        var v = new ResultsView { Columns = [ColumnCatalog.IpAddress, ColumnCatalog.HostName] };
        v.Styles["hostName"] = new ColumnStyle { ColumnId = "hostName", Background = "#FF0000", Bold = true, Condition = StyleCondition.Contains, ConditionValue = "srv", Regex = "\\..*", Replacement = "" };
        v.Upsert(Samples.Device("10.0.0.1", "srv1.corp") with { Revision = 1 }, false);
        v.Upsert(Samples.Device("10.0.0.2", "pc2.corp") with { Revision = 1 }, false);
        var key = v.KeyFor("hostName");
        Assert.Equal("srv1", v.Rows[0][key]);           // regex transform for display
        Assert.Equal("#FF0000", v.Rows[0][key + "_bg"]); // condition matches the original value
        Assert.Equal("Bold", v.Rows[0][key + "_fw"]);
        Assert.Equal("", v.Rows[1][key + "_bg"]);        // condition does not match
        Assert.Equal("pc2", v.Rows[1][key]);
    }
}

public class FriendlyNameTests
{
    private static DeviceResult WithMac(string ip, string mac) => Samples.Device(ip) with { Mac = Observation<PhysicalAddress>.Ok(PhysicalAddress.Parse(mac), Samples.T) };

    [Fact]
    public void Names_follow_the_mac_across_ip_changes_and_any_mac_spelling()
    {
        var fn = new FriendlyNameSettings
        {
            IdentifyBy = ["mac"],
            Parameters = ["Location"],
            Entries = [new FriendlyEntry { Key = "00:11:22:33:44:55", Name = "Reception printer", Data = new() { ["Location"] = "Lobby" } }],
        };
        var cols = ColumnSet.Build(new ScanSettings(), fn, []);
        Assert.Equal("Reception printer", cols.Single(c => c.Id == ColumnSet.FriendlyNameId).Text(WithMac("10.0.0.5", "00-11-22-33-44-55")));
        Assert.Equal("Reception printer", cols.Single(c => c.Id == ColumnSet.FriendlyNameId).Text(WithMac("10.0.0.99", "00-11-22-33-44-55")));
        Assert.Equal("Lobby", cols.Single(c => c.Header == "Location").Text(WithMac("10.0.0.99", "00-11-22-33-44-55")));
        Assert.Equal("", cols.Single(c => c.Id == ColumnSet.FriendlyNameId).Text(Samples.Device("10.0.0.7") with { Mac = Observation<PhysicalAddress>.NotRequested }));
    }

    [Fact]
    public void Composite_keys_and_no_mapping()
    {
        var d = WithMac("10.0.0.5", "00-11-22-33-44-55");
        Assert.Equal("00-11-22-33-44-55 | 10.0.0.5", FriendlyNameMap.KeyOf(d, ["mac", "ip"]));
        Assert.DoesNotContain(ColumnSet.Build(new ScanSettings(), new FriendlyNameSettings { IdentifyBy = [], Entries = [new FriendlyEntry { Key = "x", Name = "y" }] }, []),
            c => c.Id == ColumnSet.FriendlyNameId);
    }

    [Fact]
    public void Csv_round_trip_with_append_merge_replace()
    {
        var s = new FriendlyNameSettings
        {
            IdentifyBy = ["ip"],
            Parameters = ["Asset tag"],
            Entries = [new FriendlyEntry { Key = "10.0.0.1", Name = "=evil()", Data = new() { ["Asset tag"] = "A-1, \"x\"" } }],
        };
        var csv = FriendlyNameMap.ExportCsv(s);
        Assert.Contains("'=evil()", csv, StringComparison.Ordinal); // formula protection on export
        var back = FriendlyNameMap.ImportCsv(s with { Entries = [] }, csv, ImportMode.Replace, out var n);
        Assert.Equal(1, n);
        Assert.Equal("=evil()", back.Entries[0].Name);           // protection removed on import
        Assert.Equal("A-1, \"x\"", back.Entries[0].Data["Asset tag"]);

        const string update = "Key;Friendly Name;Asset tag;Owner\n10.0.0.1;Updated;A-2;Ann\n10.0.0.2;New;B-1;Bob\n";
        var appended = FriendlyNameMap.ImportCsv(back, update, ImportMode.Append, out var na);
        Assert.Equal(1, na);
        Assert.Equal("=evil()", appended.Entries.Single(e => e.Key == "10.0.0.1").Name);
        Assert.Contains("Owner", appended.Parameters);
        var merged = FriendlyNameMap.ImportCsv(back, update, ImportMode.Merge, out var nm);
        Assert.Equal(2, nm);
        Assert.Equal("Updated", merged.Entries.Single(e => e.Key == "10.0.0.1").Name);
        Assert.Equal(2, merged.Entries.Count);
    }

    [Fact]
    public void Upsert_removes_entry_when_cleared()
    {
        var list = FriendlyNameMap.Upsert([], new FriendlyEntry { Key = "aa-bb-cc-dd-ee-ff", Name = "PC" });
        Assert.Equal("AA-BB-CC-DD-EE-FF", list[0].Key);
        Assert.Empty(FriendlyNameMap.Upsert(list, new FriendlyEntry { Key = "AA:BB:CC:DD:EE:FF", Name = "" }));
    }

    [Fact]
    public void Cli_exports_friendly_and_virtual_columns()
    {
        var s = new AppSettings
        {
            Scan = new ScanSettings { ResolveHostNames = false, ShowTimestamps = false, ResolveMac = false, ShowDeviceType = false },
            FriendlyNames = new FriendlyNameSettings { IdentifyBy = ["ip"], Entries = [new FriendlyEntry { Key = "10.0.0.1", Name = "Router" }] },
            VirtualColumns = [new VirtualColumnDefinition { Name = "Tag", Source = "[Friendly Name]@[IP Address]" }],
        };
        var cols = s.DisplayColumns;
        Assert.Equal(["ip", "friendly", "rtt", "v:Tag"], cols.Select(c => c.Id));
        Assert.Equal("Router@10.0.0.1", cols[3].Text(Samples.Device("10.0.0.1")));
        var (selected, unknown) = ColumnCatalog.Select(["Tag", "friendly name"], s.AvailableColumns);
        Assert.Empty(unknown);
        Assert.Equal(2, selected.Count);
    }
}
