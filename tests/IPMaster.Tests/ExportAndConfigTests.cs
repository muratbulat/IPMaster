using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using IPMaster.Cli;
using IPMaster.Core.Configuration;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure;
using IPMaster.Infrastructure.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Tests;

internal static class Samples
{
    public static readonly DateTimeOffset T = new(2026, 11, 16, 10, 30, 0, TimeSpan.Zero);

    public static DeviceResult Device(string ip, string? host = null, ObservationState hostState = ObservationState.Empty) => new()
    {
        Key = AddressKey.From(IPAddress.Parse(ip)),
        Status = DeviceStatus.Online,
        RespondedTo = PingMethod.Icmp,
        RoundTrip = TimeSpan.FromMilliseconds(3),
        Ttl = Observation<int>.Ok(64, T),
        HostName = host is null ? Observation<HostNameInfo>.Of(hostState, T) : Observation<HostNameInfo>.Ok(new HostNameInfo(host, null), T),
        Mac = Observation<PhysicalAddress>.Ok(PhysicalAddress.Parse("AA-BB-CC-00-11-22"), T),
        LastScanned = T,
        LastSeen = T,
        IsComplete = true,
    };
}

public class CsvExporterTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("line1\nline2", "\"line1\nline2\"")]
    [InlineData("=1+2", "'=1+2")]
    [InlineData("@SUM(A1)", "'@SUM(A1)")]
    [InlineData("+cmd", "'+cmd")]
    [InlineData("-5", "-5")] // numbers are not formulas
    [InlineData("Zürich 東京", "Zürich 東京")]
    public void Escapes_cells(string input, string expected) => Assert.Equal(expected, CsvExporter.Escape(input, ',', true));

    [Fact]
    public void Formula_protection_can_be_disabled() => Assert.Equal("=1+2", CsvExporter.Escape("=1+2", ',', false));

    [Fact]
    public async Task Unicode_round_trip_with_quotes_and_newlines()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-csv-").FullName;
        var path = Path.Combine(dir, "r.csv");
        var devices = new[] { Samples.Device("10.0.0.2", "Düsseldorf \"main\",\nfloor 2"), Samples.Device("10.0.0.10", "=HYPERLINK(\"x\")") };
        await CsvExporter.ExportAsync(path, [ColumnCatalog.IpAddress, ColumnCatalog.HostName, ColumnCatalog.MacAddress], devices,
            new CsvOptions { Delimiter = ';', Encoding = CsvEncoding.Utf8Bom });

        var bytes = await File.ReadAllBytesAsync(path);
        Assert.Equal([0xEF, 0xBB, 0xBF], bytes[..3]);
        var text = Encoding.UTF8.GetString(bytes[3..]);
        Assert.Equal(
            "IP Address;Host Name;MAC Address\r\n" +
            "10.0.0.2;\"Düsseldorf \"\"main\"\",\nfloor 2\";AA-BB-CC-00-11-22\r\n" +
            "10.0.0.10;\"'=HYPERLINK(\"\"x\"\")\";AA-BB-CC-00-11-22\r\n", text);
        Assert.Empty(Directory.GetFiles(dir, "*.tmp")); // atomic write leaves no temp files
    }

    [Fact]
    public void Failure_states_rendered_distinctly()
    {
        Assert.Equal("[timeout]", ColumnCatalog.HostName.Text(Samples.Device("10.0.0.1", null, ObservationState.Timeout)));
        Assert.Equal("", ColumnCatalog.HostName.Text(Samples.Device("10.0.0.1", null, ObservationState.Empty)));
        Assert.Equal("[unsupported]", ColumnCatalog.HostName.Text(Samples.Device("10.0.0.1", null, ObservationState.Unsupported)));
    }

    [Fact]
    public void Utf16_encoding_writes_bom()
    {
        var enc = CsvExporter.ToEncoding(CsvEncoding.Utf16LittleEndian);
        Assert.Equal([0xFF, 0xFE], enc.GetPreamble());
    }

    [Fact]
    public void Columns_selected_by_header_or_id_case_insensitively()
    {
        var (cols, unknown) = ColumnCatalog.Select(["host name", "MAC Address", "rtt", "Nope"]);
        Assert.Equal(["hostName", "mac", "rtt"], cols.Select(c => c.Id));
        Assert.Equal(["Nope"], unknown);
    }
}

public class JsonExporterTests
{
    [Fact]
    public void Writes_versioned_typed_document()
    {
        using var ms = new MemoryStream();
        var devices = new[] { Samples.Device("10.0.0.2", "host.example"), Samples.Device("2001:db8::1", null, ObservationState.Timeout) };
        JsonExporter.Write(ms, ColumnCatalog.All, devices, new ScanMetadata { ExportedAt = Samples.T, Targets = ["10.0.0.0/24"] });
        using var doc = JsonDocument.Parse(ms.ToArray());
        var root = doc.RootElement;
        Assert.Equal("ipmaster.results", root.GetProperty("schema").GetString());
        Assert.Equal(2, root.GetProperty("schemaVersion").GetInt32());
        var d0 = root.GetProperty("devices")[0];
        Assert.Equal("10.0.0.2", d0.GetProperty("ip").GetString());
        Assert.Equal("success", d0.GetProperty("hostName").GetProperty("state").GetString());
        Assert.Equal("host.example", d0.GetProperty("hostName").GetProperty("value").GetProperty("name").GetString());
        Assert.Equal(64, d0.GetProperty("ttl").GetProperty("value").GetInt32());
        Assert.Equal("AA:BB:CC:00:11:22", d0.GetProperty("mac").GetProperty("value").GetString());
        var d1 = root.GetProperty("devices")[1];
        Assert.Equal("ipv6", d1.GetProperty("family").GetString());
        Assert.Equal("timeout", d1.GetProperty("hostName").GetProperty("state").GetString());
        Assert.False(d1.GetProperty("hostName").TryGetProperty("value", out _));
    }
}

public class FileNameTokenTests
{
    private static readonly DateTime D = new(2026, 3, 7, 9, 5, 4);

    [Theory]
    [InlineData("scan_%yyyy%%mm%%dd%_time_%hh%%nn%.csv", "scan_20260307_time_0905.csv")]
    [InlineData("%y%-%m%-%d% %h%.%n%.%s%", "26-3-7 9.5.4")]
    [InlineData("%mmm% %mmmm% %ddd% %dddd%", "Mar March Sat Saturday")]
    [InlineData("%ss%", "04")]
    [InlineData("100%_%unknown%_%", "100%_%unknown%_%")]
    [InlineData("C:\\Reports\\inventory_%yyyy%%mm%%dd%.csv", "C:\\Reports\\inventory_20260307.csv")]
    public void Expands(string pattern, string expected) => Assert.Equal(expected, FileNameTokens.Expand(pattern, D));
}

public class SettingsStoreTests
{
    private static SettingsStore NewStore() => new(Directory.CreateTempSubdirectory("ipm-cfg-").FullName);

    [Fact]
    public async Task Round_trips_settings()
    {
        var store = NewStore();
        var s = new AppSettings
        {
            Scan = new ScanSettings { MaxConcurrency = 12, PingMethod = PingMethodSetting.Both, HostNameMode = HostNameMode.ShortName },
            View = new ViewSettings { DarkMode = true, CsvDelimiter = null },
            Ranges = [new RangeEntry { Target = "10.0.0.0/24", Comment = "Office", OctetMode = true, Enabled = false }],
            IgnoredAddresses = ["10.0.0.*"],
        };
        await store.SaveAsync(s);
        var loaded = store.Load();
        Assert.Equal(SettingsLoadStatus.Loaded, loaded.Status);
        Assert.Equal(12, loaded.Settings.Scan.MaxConcurrency);
        Assert.Equal(PingMethodSetting.Both, loaded.Settings.Scan.PingMethod);
        Assert.True(loaded.Settings.View.DarkMode);
        Assert.Null(loaded.Settings.View.CsvDelimiter);
        Assert.Equal(s.Ranges[0], loaded.Settings.Ranges[0]);
        Assert.Equal(["10.0.0.*"], loaded.Settings.IgnoredAddresses);
        Assert.Contains("\"pingMethod\": \"Both\"", await File.ReadAllTextAsync(store.FilePath), StringComparison.Ordinal);
    }

    [Fact]
    public void Missing_file_gives_defaults()
    {
        var r = NewStore().Load();
        Assert.Equal(SettingsLoadStatus.Defaults, r.Status);
        Assert.Equal(256, r.Settings.Scan.MaxConcurrency);
    }

    [Fact]
    public async Task Unversioned_file_is_migrated()
    {
        var store = NewStore();
        await File.WriteAllTextAsync(store.FilePath, """{ "scan": { "maxConcurrency": 5 } }""");
        var r = store.Load();
        Assert.Equal(SettingsLoadStatus.Migrated, r.Status);
        Assert.Equal(5, r.Settings.Scan.MaxConcurrency);
    }

    [Fact]
    public async Task Newer_schema_is_never_overwritten()
    {
        var store = NewStore();
        const string future = """{ "schemaVersion": 99, "scan": {} }""";
        await File.WriteAllTextAsync(store.FilePath, future);
        var r = store.Load();
        Assert.Equal(SettingsLoadStatus.NewerSchemaReadOnly, r.Status);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.SaveAsync(r.Settings));
        Assert.Equal(future, await File.ReadAllTextAsync(store.FilePath));
    }

    [Fact]
    public async Task Corrupt_file_is_backed_up_and_defaults_used()
    {
        var store = NewStore();
        await File.WriteAllTextAsync(store.FilePath, "{ not json");
        var r = store.Load();
        Assert.Equal(SettingsLoadStatus.RecoveredFromCorruption, r.Status);
        Assert.Single(Directory.GetFiles(store.Directory, "*.corrupt-*"));
    }

    [Fact]
    public async Task Out_of_range_values_are_clamped()
    {
        var store = NewStore();
        await File.WriteAllTextAsync(store.FilePath, """{ "schemaVersion": 1, "scan": { "maxConcurrency": 100000, "pingAttempts": 0 } }""");
        var s = store.Load().Settings.Scan;
        Assert.Equal(1024, s.MaxConcurrency);
        Assert.Equal(1, s.PingAttempts);
    }
}

public class NetworkAdapterDetectorTests
{
    private static NetworkAdapterInfo Adapter(params (string Ip, int Prefix)[] addrs) => new("id", "Ethernet", "NIC", "Ethernet", "00-11-22-33-44-55",
        addrs.Select(a => new AdapterAddress(IPAddress.Parse(a.Ip), a.Prefix)).ToList(), [IPAddress.Parse("192.168.1.1")], 1_000_000_000);

    [Fact]
    public void Auto_detect_v4_and_v6()
    {
        var a = Adapter(("192.168.1.20", 24), ("fe80::1234%3", 64), ("fd00::10", 120));
        var skipped = new List<string>();
        var v4 = LocalNetworks.AutoDetect([a], v4: true, v6: false, skipped);
        Assert.Single(v4);
        Assert.Equal("192.168.1.0", v4[0].Start.ToString());
        Assert.Equal(24, v4[0].PrefixLength);

        var v6 = LocalNetworks.AutoDetect([a], v4: false, v6: true, skipped);
        Assert.Single(v6); // fd00::/120 only; the /64 is skipped with a reason
        Assert.Single(skipped);
        Assert.Contains("neighbour discovery", skipped[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Local_subnets_for_network_broadcast_rules()
    {
        var subnets = LocalNetworks.Subnets([Adapter(("10.1.2.3", 16))]);
        Assert.Single(subnets);
        Assert.Equal(16, subnets[0].PrefixLength);
    }
}

public class CommandLineParserTests
{
    [Fact]
    public void Parses_manual_examples()
    {
        var o = CommandLineParser.Parse(["/hide", "/auto:c:\\desktop\\result.csv", "/range:192.168.0.1-192.168.10.254,10.64.1.1-10.64.5.10#N", "/cols:Host Name;MAC Address"]);
        Assert.Empty(o.Errors);
        Assert.True(o.Hide);
        Assert.True(o.Auto);
        Assert.Equal("c:\\desktop\\result.csv", o.AutoPath);
        Assert.Equal(2, o.Ranges.Count);
        Assert.False(o.Ranges[0].OctetMode);
        Assert.True(o.Ranges[1].OctetMode);
        Assert.Equal(["Host Name", "MAC Address"], o.Columns);
    }

    [Theory]
    [InlineData("/range:all", AutoDetectKind.All)]
    [InlineData("/range:v4", AutoDetectKind.V4)]
    [InlineData("/range:V6", AutoDetectKind.V6)]
    public void Range_autodetect(string arg, AutoDetectKind kind) => Assert.Equal(kind, CommandLineParser.Parse([arg]).AutoDetect);

    [Fact]
    public void Auto_without_file_and_alternative_prefixes()
    {
        var o = CommandLineParser.Parse(["--auto", "-range=10.0.0.1", "/file:\"list.txt\""]);
        Assert.Empty(o.Errors);
        Assert.True(o.Auto);
        Assert.Null(o.AutoPath);
        Assert.Single(o.Ranges);
        Assert.Equal("list.txt", o.FilePath);
    }

    [Fact]
    public void All_manual_switches_are_implemented_and_mpass_redacted()
    {
        var o = CommandLineParser.Parse(["/mpass:hunter2", "/live:x.csv"]);
        Assert.Empty(o.NotImplemented);
        Assert.True(o.Live);
        Assert.Equal("x.csv", o.LivePath);
        Assert.Equal("hunter2", o.MasterPassword);
        Assert.DoesNotContain(o.Redacted, r => r.Contains("hunter2", StringComparison.Ordinal));
    }

    [Fact]
    public void Errors_for_unknown_and_bad_values()
    {
        var o = CommandLineParser.Parse(["/bogus", "/range:10.0.0.300", "positional"]);
        Assert.Equal(3, o.Errors.Count);
    }
}

public class CliExitCodeTests
{
    private static (CliApp App, StringWriter Out, StringWriter Err, string Dir) Create(FakeIcmp? icmp = null)
    {
        var dir = Directory.CreateTempSubdirectory("ipm-cli-").FullName;
        var services = new ServiceCollection().AddIPMaster(dir);
        services.AddSingleton<IIcmpProbe>(icmp ?? new FakeIcmp());
        services.AddSingleton<IArpProbe>(new FakeArp());
        services.AddSingleton<IHostNameResolver>(new FakeDns());
        services.AddSingleton<INetworkAdapterProvider>(new FakeAdapters(new NetworkAdapterInfo("1", "eth0", "fake", "Ethernet", null,
            [new AdapterAddress(IPAddress.Parse("10.9.0.5"), 29)], [], 0)));
        var sp = services.BuildServiceProvider();
        var o = new StringWriter();
        var e = new StringWriter();
        return (new CliApp(sp, o, e, () => new DateTime(2026, 1, 2, 3, 4, 5)), o, e, dir);
    }

    [Fact]
    public async Task Scan_to_csv_with_tokens_and_cols()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        var (app, _, err, dir) = Create(icmp);
        var path = Path.Combine(dir, "out_%yyyy%%mm%%dd%.csv");
        var code = await app.RunAsync(["/auto:" + path, "/range:10.0.0.1-10.0.0.3", "/cols:IP Address;Status", "/quiet"], CancellationToken.None);
        Assert.Equal(ExitCodes.Ok, code);
        var text = await File.ReadAllTextAsync(Path.Combine(dir, "out_20260102.csv"));
        Assert.Equal("IP Address,Status\r\n10.0.0.2,Online\r\n", text);
        Assert.Equal("", err.ToString());
    }

    [Fact]
    public async Task Stdout_mode_and_range_autodetect()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.9.0.6");
        var (app, stdout, _, _) = Create(icmp);
        var code = await app.RunAsync(["/auto", "/range:v4", "/cols:ip", "/quiet"], CancellationToken.None);
        Assert.Equal(ExitCodes.Ok, code);
        Assert.Equal("IP Address\r\n10.9.0.6\r\n", stdout.ToString());
    }

    [Fact]
    public async Task Json_export()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        var (app, _, _, dir) = Create(icmp);
        var path = Path.Combine(dir, "r.json");
        Assert.Equal(ExitCodes.Ok, await app.RunAsync(["/auto:" + path, "/range:10.0.0.1", "/quiet"], CancellationToken.None));
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        Assert.Equal(1, doc.RootElement.GetProperty("devices").GetArrayLength());
    }

    [Theory]
    [InlineData(new[] { "/auto", "/range:10.0.0.0/8" }, ExitCodes.Targets)]           // needs /yes
    [InlineData(new[] { "/auto", "/range:2001:db8::/64" }, ExitCodes.Targets)]        // too large
    [InlineData(new[] { "/live:out.pdf", "/range:10.0.0.1" }, ExitCodes.Usage)]
    [InlineData(new[] { "/auto:out.pdf", "/range:10.0.0.1" }, ExitCodes.Usage)]
    [InlineData(new[] { "/wol:not-a-mac" }, ExitCodes.Usage)]
    [InlineData(new[] { "/range:10.0.0.1" }, ExitCodes.Usage)]                         // no /auto
    [InlineData(new[] { "/auto", "/range:10.0.0.1", "/cols:Nope" }, ExitCodes.Usage)]
    [InlineData(new[] { "/auto", "/file:does-not-exist.txt" }, ExitCodes.Targets)]
    [InlineData(new[] { "/auto" }, ExitCodes.Targets)]                                  // no saved ranges
    [InlineData(new[] { "/help" }, ExitCodes.Ok)]
    public async Task Exit_codes(string[] args, int expected)
    {
        var (app, _, _, _) = Create();
        Assert.Equal(expected, await app.RunAsync(args, CancellationToken.None));
    }

    [Fact]
    public async Task File_targets_with_rejected_lines_and_dedupe()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.2");
        icmp.Alive.Add("10.0.0.9");
        var (app, stdout, err, dir) = Create(icmp);
        var list = Path.Combine(dir, "t.txt");
        await File.WriteAllTextAsync(list, "10.0.0.2\n10.0.0.0/30\nbogus line!\n# comment\n10.0.0.9\n");
        var code = await app.RunAsync(["/auto", "/file:" + list, "/cols:ip"], CancellationToken.None);
        Assert.Equal(ExitCodes.Ok, code);
        Assert.Equal("IP Address\r\n10.0.0.2\r\n10.0.0.9\r\n", stdout.ToString());
        Assert.Contains(":3: ignored", err.ToString(), StringComparison.Ordinal);
        Assert.Contains("Scanning 3 addresses", err.ToString(), StringComparison.Ordinal); // .1, .2 (deduped), .9
    }

    [Fact]
    public async Task Ctrl_c_cancels_with_130_and_writes_nothing()
    {
        var (app, _, _, dir) = Create(new FakeIcmp { SilentDelay = TimeSpan.FromSeconds(30) });
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var path = Path.Combine(dir, "never.csv");
        var code = await app.RunAsync(["/auto:" + path, "/range:10.0.0.0/22", "/quiet"], cts.Token);
        Assert.Equal(ExitCodes.Cancelled, code);
        Assert.False(File.Exists(path));
    }
}

public class SettingsDefaultsTests
{
    [Fact]
    public async Task Partial_file_keeps_defaults_for_missing_sections()
    {
        var store = new SettingsStore(Directory.CreateTempSubdirectory("ipm-cfg-").FullName);
        await File.WriteAllTextAsync(store.FilePath, """{ "schemaVersion": 1, "scan": { "showTtl": true }, "ranges": [ { "target": "10.0.0.0/24" } ] }""");
        var s = store.Load().Settings;
        Assert.NotNull(s.View);
        Assert.NotNull(s.IgnoredAddresses);
        Assert.True(s.Scan.ShowTtl);
        Assert.Equal(256, s.Scan.MaxConcurrency);
        Assert.True(s.Ranges[0].Enabled);
    }
}
