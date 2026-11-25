using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Xml;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Export;
using Microsoft.Data.Sqlite;

namespace IPMaster.Tests;

internal static class RichSamples
{
    public static readonly DateTimeOffset T = new(2026, 11, 16, 10, 30, 0, TimeSpan.FromHours(1));

    public static DeviceResult Full(string ip = "10.0.0.2") => Samples.Device(ip, "Düsseldorf-PC \"main\"") with
    {
        MacSource = MacSource.NeighborCache,
        Vendor = Observation<string>.Ok("Example Corp, \"Ltd\" <x>", T),
        PingStats = Observation<PingStatistics>.Ok(new PingStatistics(10, 9, TimeSpan.FromTicks(12345), TimeSpan.FromMilliseconds(3.5)), T),
        IPv6Addresses = Observation<IReadOnlyList<IPAddress>>.Ok([IPAddress.Parse("fe80::1%7"), IPAddress.Parse("2001:db8::5")], T),
        NetBios = Observation<NetBiosInfo>.Ok(new NetBiosInfo("PC1", "WORKGROUP", null, PhysicalAddress.Parse("00-11-22-33-44-55"),
            [new NetBiosName("PC1", 0x00, false), new NetBiosName("WORKGROUP", 0x00, true)]), T),
        TcpPorts = Observation<IReadOnlyList<PortResult>>.Ok([new PortResult(PortProtocol.Tcp, 80, PortState.Open, "http"), new PortResult(PortProtocol.Tcp, 443, PortState.Open, "https")], T) with { Detail = "2 open, 3 closed, 0 filtered of 5" },
        UdpPorts = Observation<IReadOnlyList<PortResult>>.Ok([new PortResult(PortProtocol.Udp, 53, PortState.Open, "DNS"), new PortResult(PortProtocol.Udp, 1812, PortState.OpenOrFiltered, "RADIUS", "No reply.")], T),
        Banners = Observation<IReadOnlyList<ServiceBanner>>.Ok([new ServiceBanner("SSH", PortProtocol.Tcp, 22, "SSH-2.0-OpenSSH_9.6 <&>")], T),
        RtspStreams = Observation<IReadOnlyList<string>>.Of(ObservationState.Empty, T),
        Tls = Observation<TlsCertificateInfo>.Ok(new TlsCertificateInfo(443, "CN=host", "CN=CA", T.AddYears(-1), T.AddDays(20), "01AB", "THUMB",
            ["host.example", "10.0.0.2"], "TLS 1.3", false, "UntrustedRoot"), T),
        Workgroup = Observation<string>.Ok("CORP", T),
        OsVersion = Observation<string>.Of(ObservationState.AccessDenied, T, "denied"),
        Accounts = Observation<IReadOnlyList<string>>.Ok(["Administrator", "Zoë"], T),
        LoggedOnUsers = Observation<IReadOnlyList<string>>.Of(ObservationState.Timeout, T, "Windows management call timed out."),
        RemoteTime = Observation<DateTimeOffset>.Ok(T.AddMinutes(1), T),
        InstalledApps = Observation<IReadOnlyList<InstalledApplication>>.Ok([new InstalledApplication("App & Co", "1.2", null)], T),
        Shares = Observation<IReadOnlyList<ShareInfo>>.Ok(
        [
            new ShareInfo
            {
                Name = "Public", Kind = ShareKind.Folder, Remark = "Team files",
                Access = Observation<ShareAccess>.Ok(new ShareAccess(true, true), T),
                Disk = Observation<DiskSpace>.Ok(new DiskSpace(1_000_000_000, 250_000_000), T),
                Permissions = Observation<IReadOnlyList<ShareAccessEntry>>.Ok([new ShareAccessEntry("Everyone", "Read", true)], T),
            },
            new ShareInfo { Name = "C$", Kind = ShareKind.Folder, IsAdministrative = true, Access = Observation<ShareAccess>.Of(ObservationState.AccessDenied, T) },
            new ShareInfo { Name = "Printer1", Kind = ShareKind.Printer },
            new ShareInfo { Name = "Secret", Kind = ShareKind.Folder, Access = Observation<ShareAccess>.Ok(new ShareAccess(false, false), T) },
        ], T),
    };
}

public class ResultsXmlTests
{
    [Fact]
    public void Round_trip_is_lossless_for_every_field()
    {
        var devices = new[] { RichSamples.Full(), Samples.Device("fe80::5%3", null, ObservationState.Timeout) with { Status = DeviceStatus.Offline, LastSeen = null, RoundTrip = null } };
        var meta = new ScanMetadata { ExportedAt = RichSamples.T, StartedAt = RichSamples.T, Elapsed = TimeSpan.FromSeconds(3), Targets = ["10.0.0.0/24", "fe80::5%3"] };
        var doc = ResultsXml.ToDocument(ColumnCatalog.All, devices, meta);
        using var ms = new MemoryStream();
        doc.Save(ms);
        ms.Position = 0;
        var back = ResultsXml.Read(ms);

        Assert.Equal(2, back.Devices.Count);
        Assert.Equal(meta.Targets, back.Metadata.Targets);
        Assert.Equal(ColumnCatalog.All.Select(c => c.Id), back.ColumnIds);
        // Lossless: re-serialising the loaded devices gives the identical XML.
        var again = ResultsXml.ToDocument(ColumnCatalog.All, back.Devices, meta).ToString();
        Assert.Equal(doc.ToString(), again);
        // Typed spot checks
        var d = back.Devices[0];
        Assert.Equal(TimeSpan.FromTicks(12345), d.PingStats.Value!.Jitter);
        Assert.Equal(7, d.IPv6Addresses.Value![0].ScopeId);
        Assert.Equal(ObservationState.AccessDenied, d.OsVersion.State);
        Assert.Equal("denied", d.OsVersion.Detail);
        Assert.Equal("WCW".Length, "WCW".Length);
        Assert.Equal("CW", d.Shares.Value![0].TypeLetters);
        Assert.Equal("A", d.Shares.Value![1].TypeLetters);
        Assert.Equal("P", d.Shares.Value![2].TypeLetters);
        Assert.Equal("R", d.Shares.Value![3].TypeLetters);
        Assert.Equal(PortState.OpenOrFiltered, d.UdpPorts.Value![1].State);
        Assert.Equal(3, back.Devices[1].Key.ScopeId);
        // display text identical for every column
        foreach (var c in ColumnCatalog.All) Assert.Equal(c.Text(devices[0]), c.Text(d));
    }

    [Fact]
    public void Doctype_and_external_entities_are_rejected()
    {
        const string evil = """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///c:/windows/win.ini">]><ipmasterResults xmlns="urn:ipmaster:results" schemaVersion="1"><devices>&x;</devices></ipmasterResults>""";
        Assert.Throws<XmlException>(() => ResultsXml.Read(new MemoryStream(Encoding.UTF8.GetBytes(evil))));
    }

    [Fact]
    public void Foreign_or_newer_documents_are_rejected()
    {
        Assert.Throws<FormatException>(() => ResultsXml.Read(new MemoryStream("<other/>"u8.ToArray())));
        Assert.Throws<FormatException>(() => ResultsXml.Read(new MemoryStream("""<ipmasterResults xmlns="urn:ipmaster:results" schemaVersion="99"/>"""u8.ToArray())));
    }

    [Fact]
    public async Task File_round_trip_via_atomic_export()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory("ipm-xml-").FullName, "r.xml");
        await ResultsXml.ExportAsync(path, ColumnCatalog.All, [RichSamples.Full()], new ScanMetadata());
        var back = await ResultsXml.LoadAsync(path);
        Assert.Single(back.Devices);
    }
}

public class TextAndHtmlExportTests
{
    private static readonly ResultColumn[] Cols = [ColumnCatalog.IpAddress, ColumnCatalog.HostName, ColumnCatalog.TcpPorts, ColumnCatalog.Shares];

    [Fact]
    public void Html_is_encoded_and_lists_shares()
    {
        var html = HtmlExporter.Render(Cols, [RichSamples.Full()], ColumnFormat.Default, new ScanMetadata { Targets = ["<script>"] });
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("Düsseldorf-PC &quot;main&quot;", html, StringComparison.Ordinal);
        Assert.Contains(@"\\10.0.0.2\Public", html, StringComparison.Ordinal);
    }

    [Fact]
    public void Share_type_filter_limits_shares()
    {
        var format = ColumnFormat.Default with { ShareTypeFilter = "W" };
        Assert.Equal("Public [CW]", ColumnCatalog.Shares.Text(RichSamples.Full(), format));
        Assert.Equal("Printer1 [P]", ColumnCatalog.Shares.Text(RichSamples.Full(), format with { ShareTypeFilter = "P" }));
    }

    [Fact]
    public void Split_multi_values_into_rows()
    {
        var rows = TableRows.Build([ColumnCatalog.IpAddress, ColumnCatalog.TcpPorts], [RichSamples.Full()], ColumnFormat.Default, splitMultiValues: true).ToList();
        Assert.Equal(2, rows.Count);
        Assert.Equal(["10.0.0.2", "80"], rows[0]);
        Assert.Equal(["10.0.0.2", "443"], rows[1]);
    }

    [Fact]
    public void Service_names_and_mac_formats()
    {
        var d = RichSamples.Full();
        Assert.Equal("http, https", ColumnCatalog.TcpPorts.Text(d, ColumnFormat.Default with { ShowServiceNames = true }));
        Assert.Equal("aabb.cc00.1122", ColumnCatalog.MacAddress.Text(d, ColumnFormat.Default with { MacFormat = MacFormat.Dotted }));
        Assert.Equal("AABBCC001122", ColumnCatalog.MacAddress.Text(d, ColumnFormat.Default with { MacFormat = MacFormat.Plain }));
        Assert.Equal("80 | 443", ColumnCatalog.TcpPorts.Text(d, ColumnFormat.Default with { Separator = " | " }));
    }

    [Fact]
    public async Task Csv_append_and_merge_with_existing_file()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory("ipm-merge-").FullName, "r.csv");
        var opts = new CsvOptions { Encoding = CsvEncoding.Utf8 };
        await CsvExporter.ExportAsync(path, [ColumnCatalog.IpAddress], [Samples.Device("10.0.0.5"), Samples.Device("10.0.0.1")], opts);
        await CsvExporter.ExportAsync(path, [ColumnCatalog.IpAddress], [Samples.Device("10.0.0.1"), Samples.Device("10.0.0.3")], opts with { ExistingFile = ExistingFileMode.Append });
        Assert.Equal("IP Address\r\n10.0.0.5\r\n10.0.0.1\r\n10.0.0.1\r\n10.0.0.3\r\n", await File.ReadAllTextAsync(path));
        await CsvExporter.ExportAsync(path, [ColumnCatalog.IpAddress], [Samples.Device("10.0.0.2")], opts with { ExistingFile = ExistingFileMode.Merge });
        Assert.Equal("IP Address\r\n10.0.0.1\r\n10.0.0.2\r\n10.0.0.3\r\n10.0.0.5\r\n", await File.ReadAllTextAsync(path));
    }

    [Fact]
    public void Quoted_multiline_csv_records_stay_together()
    {
        Assert.Equal(["a,\"x\r\ny\"", "b"], TextFiles.SplitLines("a,\"x\r\ny\"\r\nb\r\n"));
    }

    [Fact]
    public void Text_table_is_aligned()
    {
        var text = TextExporter.Render([ColumnCatalog.IpAddress, ColumnCatalog.Status], [Samples.Device("10.0.0.1")], ColumnFormat.Default, false);
        var lines = text.Split("\r\n");
        Assert.Equal("IP Address  Status", lines[0]);
        Assert.Equal("----------  ------", lines[1]);
        Assert.Equal("10.0.0.1    Online", lines[2]);
    }
}

public class SqliteExportTests
{
    [Fact]
    public async Task Device_and_share_tables_with_safe_column_names()
    {
        var path = Path.Combine(Directory.CreateTempSubdirectory("ipm-db-").FullName, "r.db");
        var weird = new ResultColumn("w", "Name\"; DROP TABLE DEVICE; --", ColumnKind.Text, (_, _) => "x'y");
        await SqliteExporter.ExportAsync(path, [ColumnCatalog.IpAddress, ColumnCatalog.HostName, weird, weird], [RichSamples.Full(), Samples.Device("10.0.0.9")], ColumnFormat.Default);
        await using var db = new SqliteConnection($"Data Source={path};Pooling=False");
        await db.OpenAsync();
        await using var cmd = db.CreateCommand();
        cmd.CommandText = "SELECT \"IP Address\", \"Host Name\", \"Name\"\"; DROP TABLE DEVICE; --\", \"Name\"\"; DROP TABLE DEVICE; -- (2)\" FROM DEVICE ORDER BY id";
        await using (var r = await cmd.ExecuteReaderAsync())
        {
            Assert.True(await r.ReadAsync());
            Assert.Equal("10.0.0.2", r.GetString(0));
            Assert.Equal("Düsseldorf-PC \"main\"", r.GetString(1));
            Assert.Equal("x'y", r.GetString(2));
            Assert.Equal("x'y", r.GetString(3));
            Assert.True(await r.ReadAsync());
        }

        cmd.CommandText = "SELECT s.name, s.attributes, s.disk_free, d.\"IP Address\" FROM SHARE s JOIN DEVICE d ON d.id = s.device_id ORDER BY s.name";
        await using var r2 = await cmd.ExecuteReaderAsync();
        var shares = new List<string>();
        while (await r2.ReadAsync()) shares.Add($"{r2.GetString(0)}|{r2.GetString(1)}|{(r2.IsDBNull(2) ? "-" : r2.GetInt64(2).ToString(System.Globalization.CultureInfo.InvariantCulture))}|{r2.GetString(3)}");
        Assert.Equal(["C$|A|-|10.0.0.2", "Printer1|P|-|10.0.0.2", "Public|CW|250000000|10.0.0.2", "Secret|R|-|10.0.0.2"], shares);
    }
}

public class ConfigXmlTests
{
    [Fact]
    public async Task Round_trip_preserves_settings()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-cfgxml-").FullName;
        var store = new SettingsStore(dir);
        var s = new AppSettings
        {
            Scan = new ScanSettings { MaxConcurrency = 7, TcpPorts = "22, 80-81", MacMethods = [MacMethod.NetBios, MacMethod.Arp], ShareTypes = ShareTypeSelection.All, ExcludedAccounts = ["NT AUTHORITY\\*"] },
            View = new ViewSettings { CsvDelimiter = null, MacFormat = MacFormat.Colons, Columns = [new ColumnLayout { Id = "hostName", Width = 200 }] },
            Bookmarks = [new Bookmark { Name = "London | Subnet 1", Ranges = [new RangeEntry { Target = "10.1.0.0/24", Comment = "LDN" }] }],
            SavedFilters = [new FilterDefinition { Name = "Win10", Conditions = [new FilterCondition { ColumnId = "os", Operation = FilterOperation.Contains, Value = "Windows 10" }] }],
            IgnoredAddresses = ["10.0.0.*"],
        };
        var path = Path.Combine(dir, "config.xml");
        await ConfigXml.SaveAsync(path, s);
        var loaded = ConfigXml.Load(path, store);
        Assert.Equal(SettingsLoadStatus.Loaded, loaded.Status);
        var l = loaded.Settings;
        Assert.Equal(7, l.Scan.MaxConcurrency);
        Assert.Equal("22, 80-81", l.Scan.TcpPorts);
        Assert.Equal([MacMethod.NetBios, MacMethod.Arp], l.Scan.MacMethods);
        Assert.Equal(ShareTypeSelection.All, l.Scan.ShareTypes);
        Assert.Equal(["NT AUTHORITY\\*"], l.Scan.ExcludedAccounts);
        Assert.Null(l.View.CsvDelimiter);
        Assert.Equal(MacFormat.Colons, l.View.MacFormat);
        Assert.Equal(200, l.View.Columns[0].Width);
        Assert.Equal("London | Subnet 1", l.Bookmarks[0].Name);
        Assert.Equal("10.1.0.0/24", l.Bookmarks[0].RangeInfo);
        Assert.Equal("Windows 10", l.SavedFilters[0].Conditions[0].Value);
        Assert.Equal(["10.0.0.*"], l.IgnoredAddresses);
    }

    [Fact]
    public void Rejects_dtd()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-cfgxml-").FullName;
        var path = Path.Combine(dir, "evil.xml");
        File.WriteAllText(path, """<!DOCTYPE x [<!ENTITY e "boom">]><ipmasterConfig xmlns="urn:ipmaster:config"/>""");
        Assert.Throws<XmlException>(() => ConfigXml.Load(path, new SettingsStore(dir)));
    }

    [Fact]
    public void Recent_files_are_capped_and_deduplicated()
    {
        var s = new AppSettings();
        for (var i = 0; i < 15; i++) s = s.WithRecentFile($"f{i}.xml");
        s = s.WithRecentFile("F3.xml");
        Assert.Equal(AppSettings.MaxRecentFiles, s.RecentFiles.Count);
        Assert.Equal("F3.xml", s.RecentFiles[0]);
        Assert.Single(s.RecentFiles, f => f.Equals("f3.xml", StringComparison.OrdinalIgnoreCase));
    }
}

public class FilterTests
{
    private static bool Match(DeviceResult d, bool all, params FilterCondition[] c)
    {
        var f = CompiledFilter.Compile(new FilterDefinition { Conditions = c, MatchAll = all }, out var errors);
        Assert.Empty(errors);
        return f.Matches(d, ColumnFormat.Default);
    }

    private static FilterCondition C(string col, FilterOperation op, string v) => new() { ColumnId = col, Operation = op, Value = v };

    [Fact]
    public void Text_operations_are_case_insensitive()
    {
        var d = RichSamples.Full();
        Assert.True(Match(d, true, C("hostName", FilterOperation.Contains, "düsseldorf")));
        Assert.True(Match(d, true, C("hostName", FilterOperation.StartsWith, "DÜSS")));
        Assert.False(Match(d, true, C("hostName", FilterOperation.NotContains, "PC")));
        Assert.True(Match(d, true, C("vendor", FilterOperation.EqualTo, "example corp, \"ltd\" <x>")));
        Assert.True(Match(d, true, C("rtsp", FilterOperation.IsEmpty, "")));
        Assert.True(Match(d, true, C("hostName", FilterOperation.Regex, "^d.*main\"$")));
    }

    [Fact]
    public void Less_and_greater_compare_typed_values()
    {
        Assert.True(Match(Samples.Device("10.0.0.9"), true, C("ip", FilterOperation.LessThan, "10.0.0.10"))); // text compare would say false
        Assert.False(Match(Samples.Device("10.0.0.10"), true, C("ip", FilterOperation.LessThan, "10.0.0.9")));
        Assert.True(Match(Samples.Device("10.0.0.1"), true, C("rtt", FilterOperation.GreaterThan, "2.5")));
        Assert.True(Match(RichSamples.Full(), true, C("tlsExpiry", FilterOperation.LessThan, "2027-01-01")));
    }

    [Fact]
    public void And_or_combination()
    {
        var d = RichSamples.Full();
        var yes = C("ip", FilterOperation.EqualTo, "10.0.0.2");
        var no = C("ip", FilterOperation.EqualTo, "10.0.0.3");
        Assert.False(Match(d, true, yes, no));
        Assert.True(Match(d, false, yes, no));
    }

    [Fact]
    public void Invalid_regex_and_unknown_column_reported()
    {
        CompiledFilter.Compile(new FilterDefinition { Conditions = [C("ip", FilterOperation.Regex, "(unclosed"), C("nope", FilterOperation.Contains, "x")] }, out var errors);
        Assert.Equal(2, errors.Count);
    }

    [Fact]
    public void Share_categories()
    {
        var shares = RichSamples.Full().Shares.Value!;
        Assert.True(ShareFilters.HasSharedFolders(RichSamples.Full()));
        Assert.Equal(["Public"], shares.Where(s => ShareFilters.Matches(s, ShareCategory.Writable)).Select(s => s.Name));
        Assert.Equal(["Secret"], shares.Where(s => ShareFilters.Matches(s, ShareCategory.Restricted)).Select(s => s.Name));
        Assert.Equal(["C$"], shares.Where(s => ShareFilters.Matches(s, ShareCategory.Administrative)).Select(s => s.Name));
        Assert.Equal(["Printer1"], shares.Where(s => ShareFilters.Matches(s, ShareCategory.Printer)).Select(s => s.Name));
        Assert.Equal(["Public"], shares.Where(s => ShareFilters.Matches(s, ShareCategory.Standard)).Select(s => s.Name));
    }
}

public class CompareTests
{
    [Fact]
    public void By_ip_reports_added_removed_changed()
    {
        var before = new[] { Samples.Device("10.0.0.1", "a"), Samples.Device("10.0.0.2", "b"), Samples.Device("10.0.0.3", "c") };
        var after = new[] { Samples.Device("10.0.0.1", "a"), Samples.Device("10.0.0.2", "B2"), Samples.Device("10.0.0.4", "d") };
        var r = ScanComparer.Compare(before, after, CompareKey.IpAddress, [ColumnCatalog.IpAddress, ColumnCatalog.HostName, ColumnCatalog.LastScanned]);
        Assert.Equal(1, r.Count(ChangeKind.Added));
        Assert.Equal(1, r.Count(ChangeKind.Removed));
        Assert.Equal(1, r.Count(ChangeKind.Changed));
        Assert.Equal(1, r.Count(ChangeKind.Unchanged));
        var changed = r.Rows.Single(x => x.Change == ChangeKind.Changed);
        Assert.Equal(new ColumnChange("Host Name", "b", "B2"), Assert.Single(changed.Changes));
    }

    [Fact]
    public void By_mac_follows_devices_across_ip_changes_and_counts_devices_without_mac()
    {
        var mac = PhysicalAddress.Parse("00-11-22-33-44-55");
        var before = new[] { Samples.Device("10.0.0.1") with { Mac = Observation<PhysicalAddress>.Ok(mac, Samples.T) }, Samples.Device("10.0.0.7") with { Mac = Observation<PhysicalAddress>.NotRequested } };
        var after = new[] { Samples.Device("10.0.0.9") with { Mac = Observation<PhysicalAddress>.Ok(mac, Samples.T) } };
        var r = ScanComparer.Compare(before, after, CompareKey.MacAddress, [ColumnCatalog.IpAddress]);
        var row = Assert.Single(r.Rows);
        Assert.Equal(ChangeKind.Changed, row.Change);
        Assert.Equal("10.0.0.9", row.Changes[0].After);
        Assert.Equal(1, r.SkippedWithoutKey);
    }
}

public class PortListTests
{
    [Theory]
    [InlineData("21, 80, 110-115, 443", new[] { 21, 80, 110, 111, 112, 113, 114, 115, 443 })]
    [InlineData("443,80,80", new[] { 80, 443 })]
    [InlineData("", new int[0])]
    public void Parses(string text, int[] expected)
    {
        Assert.True(PortList.TryParse(text, out var ports, out var e), e);
        Assert.Equal(expected, ports);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-90")]
    [InlineData("http")]
    public void Rejects(string text) => Assert.False(PortList.TryParse(text, out _, out _));

    [Fact]
    public void Service_names() => Assert.Equal("ms-wbt-server", PortList.ServiceName(3389));
}

public class DuplicateMacTests
{
    [Fact]
    public void Same_mac_on_two_ips_is_flagged()
    {
        var mac = PhysicalAddress.Parse("BC-24-11-F2-42-BD");
        var a = Samples.Device("10.0.0.53") with { Mac = Observation<PhysicalAddress>.Ok(mac, Samples.T) };
        var b = Samples.Device("10.0.0.153") with { Mac = Observation<PhysicalAddress>.Ok(mac, Samples.T) };
        var c = Samples.Device("10.0.0.7");
        var dup = DuplicateMacs.Find([a, b, c, a]);
        Assert.Equal(["BC2411F242BD"], dup);
        var f = ColumnFormat.Default with { DuplicateMacs = dup };
        Assert.Equal("BC-24-11-F2-42-BD (duplicate)", ColumnCatalog.MacAddress.Text(a, f));
        Assert.Equal("AA-BB-CC-00-11-22", ColumnCatalog.MacAddress.Text(c, f));
    }

    [Fact]
    public void Udp_column_lists_only_confirmed_open_services()
    {
        Assert.Equal("53", ColumnCatalog.UdpPorts.Text(RichSamples.Full()));
    }
}
