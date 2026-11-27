using IPMaster.Core.Tools;
using IPMaster.Desktop.Views;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>WinGet Manager (D-106). Synthetic WinGet output and a fake service only: no test installs or updates anything.</summary>
public class WinGetParserTests
{
    // shaped like winget 1.29 redirected output: spinner frames before the header, padded columns, footer
    internal const string List = "\r   - \r   \\ \r" + """
        Name                          Id                                         Version         Available   Source
        -------------------------------------------------------------------------------------------------------
        7-Zip 24.09 (x64)             7zip.7zip                                  24.09           25.00       winget
        Contoso Tool                  Contoso.Tool                               1.2.0                       winget
        Fabrikam Agent                Fabrikam.Agent                             Unknown         3.1         winget
        Litware Launcher              Litware.Launcher                           < 3.14.7        3.15.2      winget
        Some MSIX App                 MSIX\Some.App_1.0.0.0_x64__8wekyb3d8bbwe   1.0.0.0
        Northwind Pinned              Northwind.Pinned                           2.0             2.1         winget
        Truncated Name                Truncated.Very.Long.Id…                    1.0             1.1         winget
        3 upgrades available.
        """;

    [Fact]
    public void List_rows_become_packages_with_statuses()
    {
        var pins = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Northwind.Pinned" };
        var p = WinGet.ParseList(List, pins).ToDictionary(x => x.Id);
        Assert.Equal(6, p.Count); // the truncated id is dropped: it cannot be addressed exactly
        Assert.Equal(("7-Zip 24.09 (x64)", "24.09", "25.00", "winget"), (p["7zip.7zip"].Name, p["7zip.7zip"].InstalledVersion, p["7zip.7zip"].AvailableVersion, p["7zip.7zip"].Source));
        Assert.Equal(WinGetStatus.UpdateAvailable, p["7zip.7zip"].Status);
        Assert.Equal(WinGetStatus.Current, p["Contoso.Tool"].Status);
        Assert.Equal(WinGetStatus.Unknown, p["Fabrikam.Agent"].Status); // unknown version is never "outdated"
        Assert.Equal(WinGetStatus.Unknown, p["Litware.Launcher"].Status); // a range is not a version
        Assert.Equal(WinGetStatus.NotSupported, p[@"MSIX\Some.App_1.0.0.0_x64__8wekyb3d8bbwe"].Status); // no source
        Assert.Equal(WinGetStatus.Pinned, p["Northwind.Pinned"].Status);
        Assert.Equal(["7zip.7zip"], p.Values.Where(WinGet.IsEligible).Select(x => x.Id));
    }

    [Fact]
    public void Localized_headers_and_wide_characters_keep_columns()
    {
        const string german = """
            Name             ID                 Version  Verfügbar Quelle
            ------------------------------------------------------------
            記事エディター   Contoso.Editor     2.0      2.5       winget
            Größe Tool       Contoso.Groesse    1.0                winget
            """;
        var p = WinGet.ParseList(german);
        Assert.Equal(2, p.Count);
        Assert.Equal(("記事エディター", "Contoso.Editor", "2.0", "2.5"), (p[0].Name, p[0].Id, p[0].InstalledVersion, p[0].AvailableVersion));
        Assert.Equal(WinGetStatus.Current, p[1].Status);
        Assert.Equal(2, WinGet.CellWidth('記'));
    }

    [Fact]
    public void Only_the_first_table_is_the_inventory_and_unreadable_output_gives_nothing()
    {
        const string upgrade = """
            Name   Id           Version Available Source
            --------------------------------------------
            Git    Git.Git      2.48    2.49      winget
            1 upgrades available.

            The following packages have an upgrade available, but require explicit targeting for upgrade:
            Name    Id              Version  Available Source
            -------------------------------------------------
            Discord Discord.Discord 1.0.9269 1.0.9270  winget
            """;
        Assert.Equal(2, WinGet.ParseTables(upgrade).Count);
        Assert.Equal(["Git.Git"], WinGet.ParseList(upgrade).Select(p => p.Id));
        Assert.Empty(WinGet.ParseList("No installed package found matching input criteria."));
        Assert.Empty(WinGet.ParseList(""));
        // a localized header with a space in one title would shift columns: rejected rather than guessed
        Assert.Empty(WinGet.ParseList("Nom   Id   Version installée Disponible Source\n-------------------------------------------\nA     B.C  1.0     2.0       winget\n"));
    }

    [Fact]
    public void Pins_are_read_by_id()
    {
        const string pins = """
            Name             Id               Version Source Pin type
            ---------------------------------------------------------
            Northwind Pinned Northwind.Pinned 2.0     winget Pinning
            """;
        Assert.Contains("northwind.pinned", WinGet.ParsePins(pins));
        Assert.Empty(WinGet.ParsePins("There are no pins configured."));
    }

    [Theory]
    [InlineData("1.10", "1.9", 1)]
    [InlineData("25.00", "24.09", 1)]
    [InlineData("2.48.1", "2.48", 1)]
    [InlineData("1.0.0-beta", "1.0.0", -1)]
    [InlineData("Unknown", "0.1", -1)]
    [InlineData("< 3.14", "1.0", -1)]
    [InlineData("1.2", "1.2.0", 0)]
    public void Versions_sort_by_value(string a, string b, int sign) => Assert.Equal(sign, Math.Sign(WinGet.CompareVersions(a, b)));

    [Fact]
    public void Filters_and_search_work_on_local_data()
    {
        var p = WinGet.ParseList(List);
        Assert.Equal(6, p.Count(x => WinGet.Matches(x, WinGet.Filter.All, "")));
        Assert.Equal(["7zip.7zip", "Northwind.Pinned"], p.Where(x => WinGet.Matches(x, WinGet.Filter.Updates, "")).Select(x => x.Id)); // without pins
        Assert.Equal(["Contoso.Tool"], p.Where(x => WinGet.Matches(x, WinGet.Filter.UpToDate, "")).Select(x => x.Id));
        Assert.Equal(["Contoso.Tool"], p.Where(x => WinGet.Matches(x, WinGet.Filter.All, "contoso.t")).Select(x => x.Id)); // by id
        Assert.Equal(["7zip.7zip"], p.Where(x => WinGet.Matches(x, WinGet.Filter.All, "7-zip")).Select(x => x.Id)); // by name
    }

    [Fact]
    public void Upgrade_arguments_are_exact_and_never_force()
    {
        var p = new WinGetPackage { Id = "7zip.7zip", Source = "winget", InstalledVersion = "24.09", AvailableVersion = "25.00" };
        var a = WinGet.UpgradeArguments(p, acceptAgreements: false);
        Assert.Equal(["upgrade", "--id", "7zip.7zip", "--exact", "--source", "winget", "--disable-interactivity"], a);
        var withConsent = WinGet.UpgradeArguments(p, acceptAgreements: true);
        Assert.Contains("--accept-package-agreements", withConsent);
        foreach (var bad in new[] { "--force", "--include-pinned", "--include-unknown", "--all", "--ignore-security-hash" }) Assert.DoesNotContain(bad, withConsent);
    }

    [Fact]
    public void Status_colours_are_semantic()
    {
        Assert.Equal("success", WinGet.StateClass(WinGetStatus.Current));
        Assert.Equal("success", WinGet.StateClass(WinGetStatus.Updated));
        Assert.Equal("warning", WinGet.StateClass(WinGetStatus.UpdateAvailable));
        Assert.Equal("error", WinGet.StateClass(WinGetStatus.Failed));
        Assert.Equal("info", WinGet.StateClass(WinGetStatus.Updating));
        Assert.Null(WinGet.StateClass(WinGetStatus.Pinned));
        Assert.Null(WinGet.StateClass(WinGetStatus.NotSupported));
    }

    [Fact]
    public void Results_are_verified_from_the_package_read_back()
    {
        var before = new WinGetPackage { Id = "Git.Git", Name = "Git", Source = "winget", InstalledVersion = "2.48", AvailableVersion = "2.49" };
        var updated = before with { InstalledVersion = "2.49", AvailableVersion = "" };
        Assert.Equal(WinGetStatus.Updated, WinGet.Verify(before, 0, updated).Status);
        Assert.Equal("2.49", WinGet.Verify(before, 0, updated).ToVersion);
        Assert.Equal(WinGetStatus.Failed, WinGet.Verify(before, 0, before).Status); // exit 0, but still offered: not a success
        Assert.Equal(WinGetStatus.Unverified, WinGet.Verify(before, 0, null).Status);
        Assert.Contains("could not be read back", WinGet.Verify(before, 0, null).Message, StringComparison.Ordinal);
        var same = WinGet.Verify(before, 0, before with { AvailableVersion = "" }); // exit 0, nothing offered, version unchanged
        Assert.Equal((WinGetStatus.Unverified, "Completed, but the installed version is still 2.48."), (same.Status, same.Message));
        Assert.Equal(WinGetStatus.Updated, WinGet.Verify(before, 0, before with { InstalledVersion = "2.50", AvailableVersion = "" }).Status); // newer than offered (gh 2.105 -> 2.106)
        Assert.Contains("Administrator", WinGet.ExitText(unchecked((int)0x80073D28)), StringComparison.Ordinal); // MSIX needs admin
        var failed = WinGet.Verify(before, unchecked((int)0x8A150011), before);
        Assert.Equal(WinGetStatus.Failed, failed.Status);
        Assert.Contains("hash", failed.Message, StringComparison.Ordinal);
        var restart = WinGet.Verify(before, unchecked((int)0x8A150109), updated);
        Assert.True(restart.RestartRequired);
        Assert.Equal(WinGetStatus.Updated, restart.Status);
        Assert.Contains("Administrator", WinGet.ExitText(unchecked((int)0x8A150019)), StringComparison.Ordinal);
        Assert.Contains("0x8A150041", WinGet.ExitText(unchecked((int)0x8A150041)), StringComparison.Ordinal);
    }

    [Fact]
    public void Search_tables_with_and_without_source_or_match()
    {
        // shapes of winget 1.29 output: all sources (Match + Source), one source (Match only), exact id (Source only)
        const string all = """
            Name                               Id                        Version       Match         Source
            -----------------------------------------------------------------------------------------------
            7-Zip                              7zip.7zip                 26.06         Moniker: 7zip winget
            NanaZip                            M2Team.NanaZip            7.0.1882.0    Tag: 7zip     winget
            Truncated                          Some.Very.Long.Id…        1.0           Tag: 7zip     winget
            """;
        var h = WinGet.ParseSearch(all);
        Assert.Equal(2, h.Count);
        Assert.Equal(new WinGetSearchHit("7-Zip", "7zip.7zip", "26.06", "Moniker: 7zip", "winget"), h[0]);
        Assert.True(WinGet.IsInstallable(h[0]));
        const string oneSource = """
            Name    Id             Version    Match
            ---------------------------------------------
            7-Zip   7zip.7zip      26.06      Moniker: 7zip
            NanaZip M2Team.NanaZip 7.0.1882.0 Tag: 7zip
            """;
        var o = WinGet.ParseSearch(oneSource);
        Assert.Equal(("Moniker: 7zip", ""), (o[0].Match, o[0].Source));
        Assert.False(WinGet.IsInstallable(o[0])); // no source: not installed by guess
        const string exact = """
            Name  Id        Version Source
            -------------------------------
            7-Zip 7zip.7zip 26.06   winget
            """;
        Assert.Equal(new WinGetSearchHit("7-Zip", "7zip.7zip", "26.06", "", "winget"), Assert.Single(WinGet.ParseSearch(exact)));
        Assert.Empty(WinGet.ParseSearch("No package found matching input criteria."));
    }

    [Fact]
    public void Read_back_table_without_a_source_column_is_not_a_package()
    {
        // 'winget list --id X --exact --source winget' omits Source: the cause of "Verification unavailable" (read back now runs without --source)
        Assert.Empty(WinGet.ParseList("Name Id      Version\n--------------------\nGit  Git.Git 2.56.1\n"));
        Assert.Equal("winget", Assert.Single(WinGet.ParseList("Name Id      Version Source\n----------------------------\nGit  Git.Git 2.56.1  winget\n")).Source);
    }

    [Fact]
    public void Install_arguments_are_exact_and_verified_by_listing()
    {
        var hit = new WinGetSearchHit("7-Zip", "7zip.7zip", "26.06", "", "winget");
        Assert.Equal(["install", "--id", "7zip.7zip", "--exact", "--source", "winget", "--disable-interactivity"], WinGet.InstallArguments(hit, false));
        Assert.Contains("--accept-source-agreements", WinGet.InstallArguments(hit, true));
        Assert.Equal(["search", "--query", "7zip", "--count", "100", "--disable-interactivity"], WinGet.SearchArguments(" 7zip "));
        var listed = new WinGetPackage { Id = "7zip.7zip", Source = "winget", InstalledVersion = "26.06" };
        Assert.Equal((WinGetStatus.Installed, "26.06"), (WinGet.VerifyInstall(hit, 0, listed).Status, WinGet.VerifyInstall(hit, 0, listed).ToVersion));
        Assert.Equal(WinGetStatus.Unverified, WinGet.VerifyInstall(hit, 0, null).Status);
        var failed = WinGet.VerifyInstall(hit, unchecked((int)0x8A150041), null);
        Assert.Equal(WinGetStatus.Failed, failed.Status);
        Assert.Contains("agreement", failed.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Service_refuses_packages_without_a_confirmed_update()
    {
        var current = new WinGetPackage { Id = "Contoso.Tool", Source = "winget", InstalledVersion = "1.0" };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new WinGetService().UpgradeAsync(current, false, _ => { }, TestContext.Current.CancellationToken));
        var pinned = current with { AvailableVersion = "2.0", IsPinned = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() => new WinGetService().UpgradeAsync(pinned, false, _ => { }, TestContext.Current.CancellationToken));
        var noSource = new WinGetSearchHit("A", "A.B", "1.0", "Tag: a", "");
        await Assert.ThrowsAsync<InvalidOperationException>(() => new WinGetService().InstallAsync(noSource, false, _ => { }, TestContext.Current.CancellationToken));
    }
}

/// <summary>Scripted WinGet: inventory from <see cref="WinGetParserTests.List"/>, upgrades by id with fixed exit codes.</summary>
internal sealed class FakeWinGet : IWinGetService
{
    public readonly List<string> Upgraded = [];
    public readonly Dictionary<string, int> ExitCodes = new(StringComparer.OrdinalIgnoreCase);
    public Action<string>? OnUpgrade;
    public bool Available = true;

    public bool IsSupported => true;

    /// <summary>Ids whose installer outlives the wait: the call returns null and the installer counts as still running.</summary>
    public readonly HashSet<string> TimesOut = new(StringComparer.OrdinalIgnoreCase);

    public bool InstallerRunning { get; set; }

    private int? TimedOut()
    {
        InstallerRunning = true;
        return null;
    }

    public IReadOnlyList<WinGetPackage> Packages { get; set; } = WinGet.ParseList(WinGetParserTests.List, new HashSet<string> { "Northwind.Pinned" });

    public Task<WinGetInfo> DetectAsync(CancellationToken ct) => Task.FromResult(Available ? new WinGetInfo(true, "v1.29.380", "") : new WinGetInfo(false, "", "winget.exe was not found."));

    public Task<WinGetInventory> ListAsync(CancellationToken ct) => Task.FromResult(new WinGetInventory(Packages, ""));

    public Task<int?> UpgradeAsync(WinGetPackage package, bool acceptAgreements, Action<string> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Upgraded.Add(package.Id);
        OnUpgrade?.Invoke(package.Id);
        progress("Starting package install...");
        if (TimesOut.Contains(package.Id)) return Task.FromResult(TimedOut());
        return Task.FromResult<int?>(ExitCodes.GetValueOrDefault(package.Id));
    }

    public readonly List<string> Installed = [];

    public IReadOnlyList<WinGetSearchHit> Hits { get; set; } =
        [new("7-Zip", "7zip.7zip", "26.06", "Moniker: 7zip", "winget"), new("Contoso Tool", "Contoso.Tool", "1.2.0", "", "winget"), new("NanaZip", "M2Team.NanaZip", "7.0", "Tag: 7zip", "winget")];

    public Task<WinGetSearchResult> SearchAsync(string query, CancellationToken ct) => Task.FromResult(new WinGetSearchResult(Hits, ""));

    public Task<int?> InstallAsync(WinGetSearchHit hit, bool acceptAgreements, Action<string> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        Installed.Add(hit.Id);
        progress("Starting package install...");
        if (TimesOut.Contains(hit.Id)) return Task.FromResult(TimedOut());
        return Task.FromResult<int?>(ExitCodes.GetValueOrDefault(hit.Id));
    }

    public Task<WinGetPackage?> ReadBackAsync(WinGetPackage package, CancellationToken ct)
    {
        var ok = ExitCodes.GetValueOrDefault(package.Id) == 0;
        var hit = Hits.FirstOrDefault(h => h.Id == package.Id);
        if (Installed.Contains(package.Id) && hit is not null) return Task.FromResult(ok ? package with { InstalledVersion = hit.Version } : null);
        return Task.FromResult<WinGetPackage?>(ok ? package with { InstalledVersion = package.AvailableVersion, AvailableVersion = "" } : package);
    }
}

[Collection("Headless UI")]
public class WinGetWindowTests
{
    private static async Task<WinGetManagerWindow> OpenAsync(FakeWinGet fake)
    {
        var w = new WinGetManagerWindow(fake);
        w.Show();
        for (var i = 0; i < 100 && w.AllRows.Count == 0 && fake.Available; i++)
        {
            UiDesignSystemTests.Dispatch();
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }

        UiDesignSystemTests.Dispatch();
        return w;
    }

    private static WinGetPackage Pkg(string id, string from = "1.0", string to = "2.0") =>
        new() { Id = id, Name = id + " with a long display name for the table", Source = "winget", InstalledVersion = from, AvailableVersion = to };

    [Fact]
    public Task Opening_lists_packages_and_updates_nothing() => HeadlessUi.RunAsync(async () =>
    {
        foreach (var variant in new[] { Avalonia.Styling.ThemeVariant.Light, Avalonia.Styling.ThemeVariant.Dark })
        {
            HeadlessUi.SetTheme(variant);
            var fake = new FakeWinGet();
            var w = await OpenAsync(fake);
            try
            {
                Assert.Equal(6, w.AllRows.Count);
                Assert.Empty(fake.Upgraded);
                HeadlessUi.Snapshot(w, $"WinGet Manager with packages - {variant}");
                w.Width = w.MinWidth;
                w.Height = w.MinHeight;
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(w, $"WinGet Manager with packages - {variant} - minimum size");
                UiDesignSystemTests.AssertNoActionCutOff(w, "WinGet Manager");
            }
            finally
            {
                w.Close();
            }
        }

        HeadlessUi.SetTheme(Avalonia.Styling.ThemeVariant.Default);
    });

    [Fact]
    public Task Missing_winget_shows_unavailable() => HeadlessUi.RunAsync(async () =>
    {
        var w = await OpenAsync(new FakeWinGet { Available = false });
        try
        {
            Assert.Empty(w.AllRows);
            Assert.Contains("WinGet is unavailable", Describe(w), StringComparison.Ordinal);
        }
        finally
        {
            w.Close();
        }
    });

    private static string Describe(Avalonia.Controls.Window w) =>
        string.Join("\n", Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(w).OfType<Avalonia.Controls.TextBlock>().Select(t => t.Text));

    [Fact]
    public Task Queue_runs_one_at_a_time_and_reports_partial_failure() => HeadlessUi.RunAsync(async () =>
    {
        var fake = new FakeWinGet { Packages = [Pkg("A.One"), Pkg("B.Two"), Pkg("C.Three")] };
        fake.ExitCodes["B.Two"] = unchecked((int)0x8A150011);
        var w = await OpenAsync(fake);
        try
        {
            await w.RunUpdatesAsync(w.AllRows.ToList(), accept: false);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["A.One", "B.Two", "C.Three"], fake.Upgraded);
            var states = w.AllRows.ToDictionary(r => r.Id, r => r.State);
            Assert.Equal(WinGetStatus.Updated, states["A.One"]);
            Assert.Equal(WinGetStatus.Failed, states["B.Two"]); // one failure does not mark the batch successful
            Assert.Equal(WinGetStatus.Updated, states["C.Three"]);
            Assert.Equal("2.0", w.AllRows.Single(r => r.Id == "A.One").Installed); // the version read back, not the old one
            Assert.Contains("1 failed", Describe(w), StringComparison.Ordinal);
            Assert.Contains("0x8A150011", w.LogText, StringComparison.Ordinal);
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public Task Cancel_stops_before_the_next_package() => HeadlessUi.RunAsync(async () =>
    {
        var fake = new FakeWinGet { Packages = [Pkg("A.One"), Pkg("B.Two"), Pkg("C.Three")] };
        var w = await OpenAsync(fake);
        fake.OnUpgrade = id =>
        {
            if (id == "A.One") w.CancelQueue(); // cancelled while the first installer runs
        };
        try
        {
            await w.RunUpdatesAsync(w.AllRows.ToList(), accept: false);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["A.One"], fake.Upgraded); // the running one finished, the queued ones never started
            Assert.Equal(WinGetStatus.Updated, w.AllRows.Single(r => r.Id == "A.One").State);
            Assert.Equal(WinGetStatus.UpdateAvailable, w.AllRows.Single(r => r.Id == "B.Two").State);
            Assert.Contains("not started (cancelled)", Describe(w), StringComparison.Ordinal);
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public Task Installer_still_running_after_the_wait_stops_the_queue_and_blocks_new_runs() => HeadlessUi.RunAsync(async () =>
    {
        var fake = new FakeWinGet { Packages = [Pkg("A.One"), Pkg("B.Two"), Pkg("C.Three")] };
        fake.TimesOut.Add("A.One");
        var w = await OpenAsync(fake);
        try
        {
            await w.RunUpdatesAsync(w.AllRows.ToList(), accept: false);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["A.One"], fake.Upgraded); // B and C would have run beside the unfinished installer
            Assert.Equal(WinGetStatus.Unverified, w.AllRows.Single(r => r.Id == "A.One").State);
            Assert.Contains("2 not started (an installer is still running)", Describe(w), StringComparison.Ordinal);
            await w.RunUpdatesAsync(w.AllRows.Where(r => r.Id != "A.One").ToList(), accept: false);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["A.One"], fake.Upgraded); // nothing new starts while it runs
            Assert.Contains(WinGet.StillRunning, Describe(w), StringComparison.Ordinal);
            fake.InstallerRunning = false; // it ended
            await w.RunUpdatesAsync(w.AllRows.Where(r => r.Id == "B.Two").ToList(), accept: false);
            Assert.Equal(["A.One", "B.Two"], fake.Upgraded);
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public Task Search_marks_installed_and_installs_only_new_packages() => HeadlessUi.RunAsync(async () =>
    {
        var fake = new FakeWinGet();
        fake.ExitCodes["M2Team.NanaZip"] = unchecked((int)0x80073D28);
        var log = new List<string>();
        var w = new WinGetInstallWindow(fake, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Contoso.Tool"] = "1.2.0" }, log.Add);
        w.Show();
        try
        {
            await w.SearchAsync();
            UiDesignSystemTests.Dispatch();
            Assert.Equal(3, w.Rows.Count);
            Assert.Equal(WinGetStatus.Installed, w.Rows.Single(r => r.Id == "Contoso.Tool").Shown);
            Assert.False(w.Rows.Single(r => r.Id == "Contoso.Tool").CanInstall); // already installed: not reinstalled
            await w.RunInstallsAsync(w.Rows.Where(r => r.CanInstall).ToList(), accept: false);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["7zip.7zip", "M2Team.NanaZip"], fake.Installed);
            Assert.Equal((WinGetStatus.Installed, "26.06"), (w.Rows.Single(r => r.Id == "7zip.7zip").State, w.Rows.Single(r => r.Id == "7zip.7zip").Installed));
            Assert.Equal(WinGetStatus.Failed, w.Rows.Single(r => r.Id == "M2Team.NanaZip").State);
            Assert.True(w.InstalledAny);
            Assert.Contains(log, l => l.Contains("0x80073D28", StringComparison.Ordinal));
            Assert.Contains("1 installed, 1 failed", Describe(w), StringComparison.Ordinal);
        }
        finally
        {
            w.Close();
        }
    });

    [Fact]
    public void Visible_filter_keeps_run_results_under_updates()
    {
        var row = new WinGetManagerWindow.Row(Pkg("A.One"));
        Assert.True(WinGetManagerWindow.Visible(row, WinGet.Filter.Updates, ""));
        Assert.True(WinGetManagerWindow.Visible(row with { Override = WinGetStatus.Updated }, WinGet.Filter.Updates, ""));
        Assert.True(WinGetManagerWindow.Visible(row with { Override = WinGetStatus.Updated }, WinGet.Filter.UpToDate, ""));
        Assert.False(WinGetManagerWindow.Visible(row, WinGet.Filter.UpToDate, ""));
        Assert.False(WinGetManagerWindow.Visible(row, WinGet.Filter.All, "zzz"));
    }
}
