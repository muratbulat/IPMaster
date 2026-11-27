using Avalonia.Controls;
using Avalonia.VisualTree;
using IPMaster.Core.Configuration;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using IPMaster.Desktop.Views;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Tests;

/// <summary>Built-in query examples (D-110, QRY-EX-01): catalog, insertion, persistence, test workflow and the dialog. Synthetic fakes only.</summary>
public class QueryExampleTests
{
    private static readonly QueryKind[] Required =
        [QueryKind.Wmi, QueryKind.Registry, QueryKind.Services, QueryKind.Performance, QueryKind.Files, QueryKind.Groups, QueryKind.PowerShell, QueryKind.Snmp, QueryKind.Ssh];

    public static TheoryData<string> Ids() => [.. QueryExamples.All.Select(e => e.Id)];

    private static QueryExample Get(string id) => QueryExamples.All.Single(e => e.Id == id);

    [Fact]
    public void Catalog_covers_every_required_family_with_unique_ids_and_names()
    {
        foreach (var k in Required) Assert.NotEmpty(QueryExamples.For(k));
        Assert.Equal(QueryExamples.All.Count, QueryExamples.All.Select(e => e.Id).Distinct(StringComparer.Ordinal).Count());
        foreach (var g in QueryExamples.All.GroupBy(e => e.Kind))
        {
            Assert.Equal(g.Count(), g.Select(e => e.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        }

        Assert.Equal(9, QueryExamples.For(QueryKind.Wmi).Count);
        Assert.Equal(6, QueryExamples.For(QueryKind.Registry).Count);
        Assert.Equal(12, QueryExamples.For(QueryKind.Services).Count);
        Assert.Equal(59, QueryExamples.All.Count);
        Assert.All(QueryExamples.All, e =>
        {
            Assert.False(string.IsNullOrWhiteSpace(e.Name));
            Assert.False(string.IsNullOrWhiteSpace(e.Category));
            Assert.False(string.IsNullOrWhiteSpace(e.Description));
            Assert.False(string.IsNullOrWhiteSpace(e.Platform));
            Assert.False(string.IsNullOrWhiteSpace(e.Requirements));
        });
    }

    [Theory]
    [MemberData(nameof(Ids))]
    public void Each_example_builds_a_disabled_item_of_its_kind_with_only_its_options_and_no_credential(string id)
    {
        var e = Get(id);
        var a = e.Create();
        var b = e.Create();
        Assert.Equal(e.Kind, a.Kind);
        Assert.Equal(e.Name, a.Name);
        Assert.False(a.Enabled);
        Assert.Null(a.CredentialId);
        Assert.NotEqual(Guid.Empty, a.Id);
        Assert.NotEqual(a.Id, b.Id);
        Assert.False(string.IsNullOrWhiteSpace(a.Summary));

        // exactly the options object QueryDefinition.New would create for this kind
        var template = QueryDefinition.New(e.Kind);
        object?[] Options(QueryDefinition q) => [q.Wmi, q.Registry, q.Files, q.Service, q.Group, q.Performance, q.PowerShell, q.Script, q.Snmp, q.Ssh, q.Http, q.Nmap, q.Python];
        Assert.Equal(Options(template).Select(o => o is null), Options(a).Select(o => o is null));
        Assert.Equal(template.TimeoutSeconds, a.TimeoutSeconds);
    }

    [Fact]
    public void Wmi_examples_parse_as_select_queries_in_cimv2_with_packet_privacy()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "System.Management parses WQL on Windows only.");
        foreach (var e in QueryExamples.For(QueryKind.Wmi))
        {
            var w = e.Create().Wmi!;
            Assert.Equal(@"root\cimv2", w.Namespace);
            Assert.True(w.PacketPrivacy);
#pragma warning disable CA1416 // guarded by SkipUnless above
            var parsed = new System.Management.SelectQuery(w.Query);
            Assert.StartsWith("Win32_", parsed.ClassName, StringComparison.Ordinal);
            Assert.NotEmpty(parsed.SelectedProperties);
#pragma warning restore CA1416
        }

        Assert.Equal("SELECT DeviceID, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3", Get("wmi.disk-free").Create().Wmi!.Query);
    }

    [Fact]
    public void Registry_examples_read_values_under_local_machine_with_plain_paths()
    {
        foreach (var e in QueryExamples.For(QueryKind.Registry))
        {
            var r = e.Create().Registry!;
            Assert.Equal(RegistryRoot.LocalMachine, r.Root);
            Assert.Equal(RegistryAction.ReadValue, r.Action);
            Assert.False(r.Key.StartsWith('\\') || r.Key.EndsWith('\\') || r.Key.Contains('*') || r.Key.Contains('['), r.Key);
            Assert.Matches("^(SOFTWARE|SYSTEM)\\\\", r.Key);
            Assert.NotEmpty(r.ValueName);
        }

        Assert.Contains("does not prove", Get("registry.deny-ts").Description, StringComparison.Ordinal);
        Assert.Contains("not runtime status", Get("registry.remote-registry-start").Description, StringComparison.Ordinal);
        Assert.Equal(["CurrentBuild", "DisplayVersion", "EnableLUA", "ProductName", "Start", "fDenyTSConnections"],
            QueryExamples.For(QueryKind.Registry).Select(e => e.Create().Registry!.ValueName).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Missing_registry_key_or_value_is_typed_no_data()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "Registry is Windows only.");
        var missingKey = RegistryQueryProvider.ReadLocal(new RegistryOptions { Key = @"SOFTWARE\IPMaster-Test-" + Guid.NewGuid().ToString("N"), ValueName = "X" });
        Assert.Equal(ObservationState.Empty, missingKey.State);
        var missingValue = RegistryQueryProvider.ReadLocal(new RegistryOptions { Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", ValueName = "IPMaster-" + Guid.NewGuid().ToString("N") });
        Assert.Equal(ObservationState.Empty, missingValue.State);
    }

    [Fact]
    public void Service_performance_file_group_and_remote_examples_use_the_real_options()
    {
        var services = QueryExamples.For(QueryKind.Services).Select(e => e.Create().Service!).ToList();
        Assert.Equal(["LanmanServer", "RemoteRegistry", "TermService", "W32Time", "WinRM", "wuauserv"], services.Select(s => s.ServiceName).Distinct().Order(StringComparer.Ordinal));
        Assert.All(services.GroupBy(s => s.ServiceName), g => Assert.Equal([ServiceProperty.Status, ServiceProperty.StartupType], g.Select(s => s.Property).Order()));

        var interval = new PerformanceOptions().SampleMilliseconds;
        foreach (var p in QueryExamples.For(QueryKind.Performance).Select(e => e.Create().Performance!))
        {
            _ = PerformanceQueryProvider.Parse(p.CounterPath); // throws on a malformed path
            Assert.Equal(interval, p.SampleMilliseconds);
        }

        Assert.Equal("*", PerformanceQueryProvider.Parse(Get("performance.network").Create().Performance!.CounterPath).Instance);
        Assert.All(QueryExamples.For(QueryKind.Performance), e => Assert.Contains("localized", e.Description, StringComparison.Ordinal));
        Assert.Contains("over the network", Get("files.sha256").Description, StringComparison.Ordinal);
        Assert.Equal(FileProperty.Exists, Get("files.exists").Create().Files!.Property);
        Assert.All(QueryExamples.For(QueryKind.Groups), e =>
        {
            Assert.Equal(GroupQueryType.LocalMembers, e.Create().Group!.Type);
            Assert.Contains("localized", e.Description, StringComparison.Ordinal);
        });
        Assert.All(QueryExamples.For(QueryKind.PowerShell), e => Assert.Contains("never enables", e.Requirements, StringComparison.Ordinal));

        foreach (var s in QueryExamples.For(QueryKind.Snmp).Select(e => e.Create().Snmp!))
        {
            Assert.Equal("", s.Communities);
            Assert.Equal(SnmpVersion.V3, s.Version);
            Assert.Equal(SnmpOperation.Get, s.Operation);
            Assert.StartsWith("1.3.6.1.2.1.1.", s.Oid, StringComparison.Ordinal);
        }

        Assert.All(QueryExamples.For(QueryKind.Ssh), e => Assert.Equal(HostKeyPolicy.Strict, e.Create().Ssh!.HostKeys));
        Assert.Equal("Linux only", Get("ssh.free").Platform);
        Assert.All(QueryExamples.For(QueryKind.Nmap), e =>
        {
            var n = e.Create().Nmap!;
            Assert.NotEqual(NmapIntensity.Thorough, n.Intensity);
            Assert.False(n.OsGuess);
            Assert.Equal("", n.ScriptArgs);
        });
        foreach (var e in QueryExamples.For(QueryKind.Python).Concat(QueryExamples.For(QueryKind.Script)))
        {
            Assert.Contains("not executed on the target", e.Description, StringComparison.Ordinal);
            Assert.DoesNotContain("remote execution", e.Description, StringComparison.OrdinalIgnoreCase);
        }

        Assert.All(QueryExamples.All.Where(e => e.Kind is QueryKind.Xml or QueryKind.Json && e.Category == "Templates"),
            e => Assert.Contains("configure first", e.Name, StringComparison.Ordinal));
    }

    [Fact]
    public void Extraction_expressions_work_on_synthetic_responses()
    {
        Assert.Equal(["1.15.0"], Extraction.JsonPath("""{"@odata.id":"/redfish/v1/","RedfishVersion":"1.15.0"}""", Get("json.redfish-version").Create().Http!.Expression));
        const string nmap = "<nmaprun><host><os><osmatch name=\"Linux 6.1\"/></os><ports><port><service product=\"OpenSSH\"/></port><port><service product=\"nginx\"/></port></ports></host></nmaprun>";
        Assert.Equal(["Linux 6.1"], Extraction.XPath(nmap, Get("nmap.os").Create().Nmap!.XPath));
        Assert.Equal(["OpenSSH", "nginx"], Extraction.XPath(nmap, Get("nmap.services").Create().Nmap!.XPath));
    }

    [Fact]
    public void Examples_contain_no_secrets()
    {
        foreach (var q in QueryExamples.All.Select(e => e.Create()))
        {
            Assert.Null(q.CredentialId);
            Assert.True(q.Snmp is null || (q.Snmp.Communities == "" && q.Snmp.PrivPassword == ""));
            Assert.True(q.Http is null || !q.Http.BasicAuthentication);
            Assert.DoesNotContain("public", QueryExample.Preview(q), StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Adding_keeps_existing_items_and_suffixes_a_clashing_name()
    {
        var e = Get("wmi.os-version");
        var mine = QueryTestKit.Q(QueryKind.Wmi, "Windows Version");
        var other = QueryTestKit.Q(QueryKind.Registry, "Windows Version (2)"); // other kind: no clash
        var (items, added) = QueryExamples.Add([mine, other], e);
        Assert.Equal(3, items.Count);
        Assert.Same(mine, items[0]);
        Assert.Same(other, items[1]);
        Assert.True(mine.Enabled);
        Assert.Equal("Windows Version (2)", added.Name);
        var (again, third) = QueryExamples.Add(items, e);
        Assert.Equal("Windows Version (3)", third.Name);
        Assert.Equal(4, again.Count);
        var (fresh, first) = QueryExamples.Add([], e);
        Assert.Equal("Windows Version", first.Name);
        Assert.Single(fresh);
    }

    [Fact]
    public async Task Added_examples_never_run_in_a_scan_until_enabled()
    {
        var provider = FakeQueryProvider.Const(QueryKind.Wmi, "x");
        var (items, added) = QueryExamples.Add([], Get("wmi.os-version"));
        Assert.Empty(new QuerySettings { Items = items }.Enabled);
        using var plan = QueryTestKit.Plan(items, providers: provider);
        var r = await plan.RunAsync(Samples.Device("10.0.0.9"), CancellationToken.None);
        Assert.Equal(0, provider.Calls);
        Assert.False(r.ContainsKey(added.ColumnId));
    }

    [Fact]
    public async Task Added_examples_survive_save_and_reload()
    {
        var store = new SettingsStore(Directory.CreateTempSubdirectory("ipm-ex-").FullName);
        var items = (IReadOnlyList<QueryDefinition>)[];
        foreach (var e in QueryExamples.All) items = QueryExamples.Add(items, e).Items;
        await store.SaveAsync(new AppSettings { Queries = new QuerySettings { Items = items } });
        var loaded = store.Load().Settings.Queries.Items;
        Assert.Equal(items.Count, loaded.Count);
        for (var i = 0; i < items.Count; i++)
        {
            Assert.Equal(items[i].Id, loaded[i].Id);
            Assert.Equal(items[i].Name, loaded[i].Name);
            Assert.False(loaded[i].Enabled);
            Assert.Null(loaded[i].CredentialId);
            Assert.Equal(QueryExample.Preview(items[i]), QueryExample.Preview(loaded[i]));
        }
    }

    public static TheoryData<string, ObservationState> Outcomes() => new()
    {
        { "ok", ObservationState.Success },
        { "empty", ObservationState.Empty },
        { "denied", ObservationState.AccessDenied },
        { "unreachable", ObservationState.NoResponse },
        { "unsupported", ObservationState.Unsupported },
        { "timeout", ObservationState.Timeout },
        { "missing-credential", ObservationState.Failed },
        { "locked", ObservationState.Failed },
    };

    [Theory]
    [MemberData(nameof(Outcomes))]
    public async Task Test_workflow_reports_typed_outcomes_for_an_example(string scenario, ObservationState expected)
    {
        var q = Get("registry.enable-lua").Create() with { Enabled = true, TimeoutSeconds = 1 }; // as QueryServices.TestAsync does
        if (scenario == "missing-credential" || scenario == "locked") q.CredentialId = Guid.NewGuid();
        var secrets = new FakeSecrets { CanReveal = scenario != "locked" };
        var provider = new FakeQueryProvider(QueryKind.Registry, async (_, ct) =>
        {
            if (scenario == "timeout") await Task.Delay(Timeout.Infinite, ct);
            if (scenario == "denied") throw new UnauthorizedAccessException("Access is denied.");
            return scenario switch
            {
                "empty" => Observation<string>.Of(ObservationState.Empty, DateTimeOffset.UtcNow, "Key not found."),
                "unreachable" => Observation<string>.Of(ObservationState.NoResponse, DateTimeOffset.UtcNow, "The network path was not found."),
                _ => Observation<string>.Ok("1", DateTimeOffset.UtcNow),
            };
        }, available: scenario != "unsupported");
        using var plan = QueryTestKit.Plan([q], secrets: secrets, providers: provider);
        var r = await plan.RunAsync(Samples.Device("10.0.0.7"), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(20));
        Assert.Equal(expected, r[q.ColumnId].State);
        if (scenario is "unsupported" or "missing-credential" or "locked") Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public void Preview_shows_the_configuration_of_each_family()
    {
        Assert.Contains(@"root\cimv2", QueryExample.Preview(Get("wmi.bios-serial").Create()), StringComparison.Ordinal);
        Assert.Contains("SELECT SerialNumber FROM Win32_BIOS", QueryExample.Preview(Get("wmi.bios-serial").Create()), StringComparison.Ordinal);
        var reg = QueryExample.Preview(Get("registry.deny-ts").Create());
        Assert.Contains("LocalMachine", reg, StringComparison.Ordinal);
        Assert.Contains(@"SYSTEM\CurrentControlSet\Control\Terminal Server", reg, StringComparison.Ordinal);
        Assert.Contains("fDenyTSConnections", reg, StringComparison.Ordinal);
        Assert.Contains("ReadValue", reg, StringComparison.Ordinal);
        var svc = QueryExample.Preview(Get("services.winrm.startuptype").Create());
        Assert.Contains("WinRM", svc, StringComparison.Ordinal);
        Assert.Contains("StartupType", svc, StringComparison.Ordinal);
        Assert.Equal("Get-Service -Name wuauserv | Select-Object Name, Status, StartType", QueryExample.Preview(Get("powershell.wuauserv").Create()));
        Assert.Contains("socket.gethostbyaddr", QueryExample.Preview(Get("python.reverse-dns").Create()), StringComparison.Ordinal);
    }

    [Fact]
    public Task Dialog_filters_previews_and_returns_the_choice_without_running_anything() => HeadlessUi.Run(() =>
    {
        var owner = new Window { Width = 900, Height = 600 };
        owner.Show();
        try
        {
            var dialog = new QueryExamplesWindow(QueryKind.Registry);
            var result = dialog.ShowDialog<QueryExample?>(owner);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(6, dialog.Visible.Count);
            Assert.NotNull(dialog.Selected); // first item preselected so Enter adds it

            dialog.SearchText = "terminal server";
            UiDesignSystemTests.Dispatch();
            var only = Assert.Single(dialog.Visible);
            Assert.Equal("registry.deny-ts", only.Id);
            Assert.Contains("fDenyTSConnections", dialog.PreviewText, StringComparison.Ordinal);
            Assert.Contains("Platform: Windows", dialog.PreviewText, StringComparison.Ordinal);
            Assert.Contains("Requirements:", dialog.PreviewText, StringComparison.Ordinal);

            dialog.SearchText = "no such example";
            UiDesignSystemTests.Dispatch();
            Assert.Empty(dialog.Visible);
            var add = dialog.GetVisualDescendants().OfType<Button>().Single(b => b.Content as string == "Add");
            Assert.False(add.IsEnabled);

            dialog.SearchText = "";
            UiDesignSystemTests.Dispatch();
            dialog.Select(QueryExamples.For(QueryKind.Registry)[3]);
            UiDesignSystemTests.Dispatch();
            Assert.False(result.IsCompleted); // selecting does nothing but preview
            add.RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            UiDesignSystemTests.Dispatch();
            Assert.True(result.IsCompleted);
            Assert.Equal(QueryExamples.For(QueryKind.Registry)[3], result.Result);
        }
        finally
        {
            owner.Close();
        }
    });

    [Fact]
    public Task Cancel_returns_nothing() => HeadlessUi.Run(() =>
    {
        var owner = new Window { Width = 900, Height = 600 };
        owner.Show();
        try
        {
            var dialog = new QueryExamplesWindow(QueryKind.Snmp);
            var result = dialog.ShowDialog<QueryExample?>(owner);
            UiDesignSystemTests.Dispatch();
            dialog.GetVisualDescendants().OfType<Button>().Single(b => b.Content as string == "Cancel").RaiseEvent(new Avalonia.Interactivity.RoutedEventArgs(Button.ClickEvent));
            UiDesignSystemTests.Dispatch();
            Assert.True(result.IsCompleted);
            Assert.Null(result.Result);
        }
        finally
        {
            owner.Close();
        }
    });

    [Fact]
    public Task Every_manager_offers_examples() => HeadlessUi.Run(() =>
    {
        foreach (var kind in Enum.GetValues<QueryKind>())
        {
            Assert.NotEmpty(QueryExamples.For(kind));
            var w = new QueryManagerWindow(HeadlessUi.Vm, kind);
            try
            {
                w.Show();
                UiDesignSystemTests.Dispatch();
                Assert.Contains(w.GetVisualDescendants().OfType<Button>(), b => b.Content as string == "Examples…");
            }
            finally
            {
                w.Close();
            }
        }
    });
}
