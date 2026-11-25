using IPMaster.Core.Configuration;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure.Configuration;

namespace IPMaster.Tests;

/// <summary>Default result presentation (fresh profile / Reset to Default) and compatibility with saved settings.</summary>
public class PresentationDefaultsTests
{
    private static readonly DateTimeOffset T = new(2026, 11, 17, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Fresh_profile_shows_the_five_default_columns_in_order()
    {
        var ids = new AppSettings().DisplayColumns.Select(c => c.Id).ToList();
        Assert.Equal(["ip", "mac", "rtt", "hostName", "deviceType"], ids);
    }

    [Fact]
    public void Timestamp_columns_are_off_by_default_and_available_when_enabled()
    {
        var fresh = new AppSettings();
        Assert.False(fresh.Scan.ShowTimestamps);
        Assert.DoesNotContain(fresh.DisplayColumns, c => c.Id is "lastScanned" or "lastSeen");
        var on = fresh with { Scan = fresh.Scan with { ShowTimestamps = true } };
        Assert.Contains(on.DisplayColumns, c => c.Id == "lastScanned");
        Assert.Contains(on.DisplayColumns, c => c.Id == "lastSeen");
    }

    [Fact]
    public void Timestamps_are_still_recorded_when_their_columns_are_hidden()
    {
        // presentation default only: the scan still records LastScanned / LastSeen for history and exports
        var d = Samples.Device("10.0.0.2", "pc2");
        Assert.NotNull(d.LastSeen);
        Assert.Equal("Last Seen", ColumnCatalog.LastSeen.Header);
    }

    [Fact]
    public void Saved_preferences_survive_the_new_defaults()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-defaults-").FullName;
        try
        {
            // a v0.6.0 file: explicit values for the settings whose defaults changed, and a customised column layout
            File.WriteAllText(Path.Combine(dir, SettingsStore.FileName), """
                { "schemaVersion": 1,
                  "scan": { "showTimestamps": true, "resolveMac": false, "lookupVendor": true },
                  "view": { "columns": [ { "id": "ip", "visible": true, "width": 150 }, { "id": "vendor", "visible": true, "width": 120 },
                                         { "id": "rtt", "visible": true, "width": 90 }, { "id": "hostName", "visible": false, "width": 200 } ] } }
                """);
            var s = new SettingsStore(dir).Load().Settings;
            Assert.True(s.Scan.ShowTimestamps);
            Assert.False(s.Scan.ResolveMac);
            var ids = s.DisplayColumns.Select(c => c.Id).ToList();
            Assert.Equal(["ip", "vendor", "rtt"], ids.Take(3));
            Assert.DoesNotContain("hostName", ids); // explicitly hidden stays hidden
            Assert.Contains("lastSeen", ids);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Absent_settings_take_the_new_defaults()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-defaults-").FullName;
        try
        {
            File.WriteAllText(Path.Combine(dir, SettingsStore.FileName), """{ "schemaVersion": 1, "scan": { "pingTimeoutMs": 900 } }""");
            var s = new SettingsStore(dir).Load().Settings;
            Assert.Equal(900, s.Scan.PingTimeoutMs);
            Assert.False(s.Scan.ShowTimestamps);
            Assert.True(s.Scan.ResolveMac);
            Assert.Equal(["ip", "mac", "rtt", "hostName", "deviceType"], s.DisplayColumns.Select(c => c.Id));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---------------------------------------------------------------- Device Type (real observations only)

    private static DeviceResult Bare(string ip = "10.0.0.9") => Samples.Device(ip) with { Vendor = Observation<string>.NotRequested, Ttl = Observation<int>.NotRequested };

    [Fact]
    public void Device_type_is_blank_without_evidence()
    {
        Assert.Equal("", ColumnCatalog.DeviceType.Text(Bare(), ColumnFormat.Default));
        Assert.Equal(DeviceCategory.Unknown, DeviceTypes.Describe(Bare()).Category);
    }

    [Fact]
    public void Device_type_from_windows_version()
    {
        var d = Bare() with { OsVersion = Observation<string>.Ok("Windows 11 Pro 24H2", T) };
        var t = DeviceTypes.Describe(d);
        Assert.Equal(DeviceCategory.Computer, t.Category);
        Assert.Equal("Windows 11 Pro 24H2", t.Text);
        Assert.Equal(TypeEvidence.Observed, t.Evidence);
    }

    [Theory]
    [InlineData(64, "Linux/Unix?")]
    [InlineData(57, "Linux/Unix?")]   // 7 hops away
    [InlineData(128, "Windows?")]
    [InlineData(120, "Windows?")]
    [InlineData(255, "Network device?")]
    public void Ttl_only_gives_a_marked_guess_without_a_category(int ttl, string text)
    {
        // D-089: a TTL is a hint, never a classification: "?" in the text and export, no icon, the reason in the tooltip
        var t = DeviceTypes.Describe(Bare() with { Ttl = Observation<int>.Ok(ttl, T) });
        Assert.Equal(text, t.Text);
        Assert.Equal(DeviceCategory.Unknown, t.Category);
        Assert.Equal(TypeEvidence.Inferred, t.Evidence);
        Assert.Contains($"TTL {ttl}", t.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void Conflicting_observed_evidence_is_ambiguous()
    {
        var d = Bare() with
        {
            TcpPorts = Observation<IReadOnlyList<PortResult>>.Ok([new PortResult(PortProtocol.Tcp, 9100, PortState.Open)], T),
            Shares = Observation<IReadOnlyList<ShareInfo>>.Ok([new ShareInfo { Name = "data", Kind = ShareKind.Folder }], T),
            Ttl = Observation<int>.Ok(64, T),
        };
        var t = DeviceTypes.Describe(d);
        Assert.Equal(TypeEvidence.Ambiguous, t.Evidence);
        Assert.Equal(DeviceCategory.Unknown, t.Category);
        Assert.Equal("Printer or file server", t.Text);
        Assert.Contains("port 9100", t.Source, StringComparison.Ordinal);
        Assert.Contains("SMB", t.Source, StringComparison.Ordinal);
    }

    [Fact]
    public void Device_type_from_rtsp_stream_and_print_ports()
    {
        var cam = Bare() with { RtspStreams = Observation<IReadOnlyList<string>>.Ok(["rtsp://10.0.0.9/stream1"], T) };
        Assert.Equal(DeviceCategory.Camera, DeviceTypes.Describe(cam).Category);
        var printer = Bare() with { TcpPorts = Observation<IReadOnlyList<PortResult>>.Ok([new PortResult(PortProtocol.Tcp, 9100, PortState.Open)], T) };
        var p = DeviceTypes.Describe(printer);
        Assert.Equal(DeviceCategory.Printer, p.Category);
        Assert.Equal("Printer", p.Text);
        Assert.Equal((TypeEvidence.Observed, "Open TCP port 9100"), (p.Evidence, p.Source));
        Assert.Equal("Camera", DeviceTypes.Describe(cam).Text);
    }

    [Fact]
    public void Vendor_is_only_the_fallback_and_observed_evidence_wins_over_ttl()
    {
        var d = Bare() with { Vendor = Observation<string>.Ok("Brother Industries, Ltd.", T) };
        var t = DeviceTypes.Describe(d);
        Assert.Equal(DeviceCategory.Unknown, t.Category);
        Assert.Equal("Brother Industries, Ltd.", t.Text);
        var both = d with
        {
            Ttl = Observation<int>.Ok(255, T),
            TcpPorts = Observation<IReadOnlyList<PortResult>>.Ok([new PortResult(PortProtocol.Tcp, 631, PortState.Open)], T),
        };
        Assert.Equal("Printer", DeviceTypes.Describe(both).Text);
    }

    [Fact]
    public void Device_type_column_is_kept_for_existing_layouts()
    {
        // a saved layout from before the column existed: it is appended, not lost
        var s = new AppSettings { View = new ViewSettings { Columns = [new ColumnLayout { Id = "ip", Visible = true, Width = 150 }] } };
        Assert.Equal("deviceType", s.DisplayColumns.Select(c => c.Id).Last(id => id is "deviceType"));
    }
}

/// <summary>Nmap manager status: a bounded version check of the configured executable (D-072).</summary>
public class NmapDetectionTests
{
    [Fact]
    public async Task Configured_nmap_is_validated_with_a_version_check()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dir = Directory.CreateTempSubdirectory("ipm-fakenmap-").FullName;
        try
        {
            var good = Path.Combine(dir, "nmap.cmd");
            await File.WriteAllTextAsync(good, "@echo Nmap version 7.95 ( https://nmap.org )\r\n@echo Platform: x86_64-pc-windows-windows\r\n", TestContext.Current.CancellationToken);
            var ok = await IPMaster.Infrastructure.Queries.NmapQueryProvider.DetectAsync(good, TestContext.Current.CancellationToken);
            Assert.True(ok.Available);
            Assert.Contains("7.95", ok.Description, StringComparison.Ordinal);
            Assert.Contains(good, ok.Description, StringComparison.Ordinal);

            var notNmap = Path.Combine(dir, "other.cmd");
            await File.WriteAllTextAsync(notNmap, "@echo hello\r\n", TestContext.Current.CancellationToken);
            var bad = await IPMaster.Infrastructure.Queries.NmapQueryProvider.DetectAsync(notNmap, TestContext.Current.CancellationToken);
            Assert.False(bad.Available);
            Assert.Contains("did not report an Nmap version", bad.Description, StringComparison.Ordinal);

            var missing = await IPMaster.Infrastructure.Queries.NmapQueryProvider.DetectAsync(Path.Combine(dir, "nope.exe"), TestContext.Current.CancellationToken);
            Assert.False(missing.Available);
            Assert.Equal("Nmap was not found. Please install it.", missing.Description);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

/// <summary>Author metadata shown in About (D-072).</summary>
public class AuthorMetadataTests
{
    [Fact]
    public void Assemblies_name_the_author()
    {
        var desktop = typeof(IPMaster.Desktop.App).Assembly;
        Assert.Equal("Murat Bulat", System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyCompanyAttribute>(desktop)?.Company);
        Assert.Contains("Murat Bulat", System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyCopyrightAttribute>(desktop)?.Copyright, StringComparison.Ordinal);
        Assert.Equal("Author: Murat Bulat", IPMaster.Desktop.Views.MainWindow.AuthorLine);
    }
}
