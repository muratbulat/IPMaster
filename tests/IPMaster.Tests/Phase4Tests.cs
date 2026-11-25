using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using IPMaster.Cli;
using IPMaster.Core.Configuration;
using IPMaster.Core.Queries;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Security;
using IPMaster.Infrastructure;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Security;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Tests;

internal sealed class FakeQueryProvider(QueryKind kind, Func<QueryCall, CancellationToken, Task<Observation<string>>> run, bool available = true) : IRemoteQueryProvider
{
    public int Calls;

    public QueryKind Kind => kind;

    public CapabilityStatus Capability => available ? CapabilityStatus.Yes("fake") : CapabilityStatus.No("fake runtime missing");

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref Calls);
        return run(call, cancellationToken);
    }

    public static FakeQueryProvider Const(QueryKind kind, string value) =>
        new(kind, (_, _) => Task.FromResult(Observation<string>.Ok(value, DateTimeOffset.UtcNow)));
}

internal sealed class FakeSecrets : ISecretSource
{
    public Dictionary<Guid, ResolvedCredential> Credentials { get; } = [];

    public bool CanReveal { get; set; } = true;

    public ResolvedCredential? Credential(Guid id) => Credentials.GetValueOrDefault(id);

    public string Reveal(string protectedText) => protectedText;
}

internal static class QueryTestKit
{
    public static QueryDefinition Q(QueryKind kind, string name, Action<QueryDefinition>? configure = null)
    {
        var q = QueryDefinition.New(kind, name);
        configure?.Invoke(q);
        return q;
    }

    public static QueryPlan Plan(IReadOnlyList<QueryDefinition> items, IReadOnlyList<VirtualColumnDefinition>? virtualColumns = null, ISecretSource? secrets = null,
        params IRemoteQueryProvider[] providers)
    {
        var qs = new QuerySettings { Items = items };
        var cols = ColumnSet.Build(new ScanSettings(), new FriendlyNameSettings(), virtualColumns ?? [], qs);
        return new QueryPlan(qs, virtualColumns ?? [], cols, providers, secrets ?? new FakeSecrets());
    }

    public static string Text(this IReadOnlyDictionary<string, Observation<string>> r, QueryDefinition q) => ObservationText.Render(r[q.ColumnId], v => v);
}

public class QueryTextTests
{
    [Fact]
    public void Alternatives_expand_in_order_and_literal_brackets_stay()
    {
        Assert.Equal([@"SOFTWARE\Microsoft\Windows\CurrentVersion", @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion"],
            PathPattern.Alternatives(@"SOFTWARE\[Microsoft|Policies\Microsoft]\Windows\CurrentVersion")); // manual example
        Assert.Equal(6, PathPattern.Alternatives(@"C:\[a|b|c]\[x|y]\f").Count);
        Assert.Equal(@"C:\[old]\x", Assert.Single(PathPattern.Alternatives(@"C:\[old]\x")));
        Assert.True(PathPattern.Match("chrome.EXE", "*.exe"));
        Assert.True(PathPattern.Match("CPU0", "CPU?"));
        Assert.False(PathPattern.Match("CPU10", "CPU?"));
    }

    [Fact]
    public void Resolver_expands_mid_path_wildcards_and_reports_denied_folders()
    {
        var tree = new Dictionary<string, string[]?>(StringComparer.OrdinalIgnoreCase)
        {
            [@"R\Users"] = ["alice", "bob", "Public"],
            [@"R\Users\alice"] = ["Desktop"],
            [@"R\Users\bob"] = ["Desktop"],
            [@"R\Users\bob\Desktop"] = null, // access denied
            [@"R\Users\Public"] = ["Desktop"],
            [@"R\Users\alice\Desktop"] = ["report.xlsx"],
            [@"R\Users\Public\Desktop"] = ["other.txt"],
        };
        var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { @"R\Users\alice\Desktop\report.xlsx", @"R\Users\Public\Desktop\other.txt" };
        bool Exists(string p) => tree.ContainsKey(p) || files.Contains(p);
        var r = PathResolver.Resolve("R", @"Users\*\Desktop\*.xlsx", p => tree.GetValueOrDefault(p) is { } c ? c : tree.ContainsKey(p) ? null : [], Exists);
        Assert.Equal(@"R\Users\alice\Desktop\report.xlsx", Assert.Single(r.Matches));
        Assert.Contains("bob", Assert.Single(r.Errors), StringComparison.Ordinal);
    }

    [Fact]
    public void Account_filter_strips_domains_and_excludes_wildcards()
    {
        var r = AccountFilter.Apply([@"CORP\alice", @"NT AUTHORITY\SYSTEM", @"PC1\Administrator", @"CORP\Domain Admins", @"OTHER\alice"], true,
            [@"NT AUTHORITY\*", "Domain *"]);
        Assert.Equal(["alice", "Administrator"], r); // duplicate short names collapse
    }

    [Fact]
    public void Ansi_sequences_are_stripped()
    {
        Assert.Equal("ok\nred done", AnsiText.Strip("\u001b[0mok\r\n\u001b[31mred\u001b[0m \u001b]0;title\u0007done\r\n"));
    }

    [Fact]
    public void Snmp_oid_variables_and_value_rendering()
    {
        var mac = System.Net.NetworkInformation.PhysicalAddress.Parse("00-11-22-33-44-FF");
        Assert.Equal("1.3.6.1.2.1.4.20.1.3.10.0.0.5", SnmpText.ExpandOid("1.3.6.1.2.1.4.20.1.3.%0", IPAddress.Parse("10.0.0.5"), null)); // manual example
        Assert.Equal("1.3.6.1.2.1.17.4.3.1.2.0.17.34.51.68.255", SnmpText.ExpandOid(".1.3.6.1.2.1.17.4.3.1.2.%1", IPAddress.Loopback, mac));
        Assert.Throws<InvalidOperationException>(() => SnmpText.ExpandOid("1.3.6.%1", IPAddress.Loopback, null));
        Assert.Throws<FormatException>(() => SnmpText.ExpandOid("sysDescr.0", IPAddress.Loopback, null));
        Assert.Equal("Printer ready", SnmpText.RenderOctets("Printer ready\0"u8, SnmpDisplay.Automatic));
        Assert.Equal("00 11 FF", SnmpText.RenderOctets(new byte[] { 0, 0x11, 0xFF }, SnmpDisplay.Automatic));
        Assert.Equal("41 42", SnmpText.RenderOctets("AB"u8, SnmpDisplay.Hex));
    }

    [Fact]
    public void Xpath_ignores_namespaces_and_rejects_dtds()
    {
        const string xml = "<RIBCL xmlns='urn:x'><HEALTH><STATUS VALUE='OK'/><FAN NAME='1' SPEED='30'/><FAN NAME='2' SPEED='35'/></HEALTH></RIBCL>";
        Assert.Equal(["OK"], Extraction.XPath(xml, "/RIBCL/HEALTH/STATUS/@VALUE"));
        Assert.Equal(["30", "35"], Extraction.XPath(xml, "//FAN/@SPEED"));
        Assert.Equal(["2"], Extraction.XPath(xml, "count(//FAN)"));
        Assert.Throws<System.Xml.XmlException>(() => Extraction.XPath("<!DOCTYPE a [<!ENTITY e SYSTEM 'file:///c:/x'>]><a>&e;</a>", "/a"));
        Assert.Equal(["5.4.1", "2"], Extraction.Regex("Version 5.4.1 build 2", @"(\d+(?:\.\d+)+)|build (\d+)").Take(1).Concat(Extraction.Regex("build 2", @"build (\d+)")));
    }

    [Fact]
    public void Jsonpath_subset()
    {
        const string json = """{"Name":"srv","Fans":[{"Name":"F1","Reading":3000,"Status":{"Health":"OK"}},{"Name":"F2","Reading":5200,"Status":{"Health":"Warning"}}],"Memory":{"TotalGiB":64}}""";
        Assert.Equal(["srv"], Extraction.JsonPath(json, "$.Name"));
        Assert.Equal(["F1", "F2"], Extraction.JsonPath(json, "$.Fans[*].Name"));
        Assert.Equal(["F2"], Extraction.JsonPath(json, "$.Fans[-1].Name"));
        Assert.Equal(["OK", "Warning"], Extraction.JsonPath(json, "$..Health"));
        Assert.Equal(["F2"], Extraction.JsonPath(json, "$.Fans[?(@.Reading > 4000)].Name"));
        Assert.Equal(["F1"], Extraction.JsonPath(json, "$.Fans[?(@.Status.Health == 'OK')].Name"));
        Assert.Equal(["64"], Extraction.JsonPath(json, "$['Memory']['TotalGiB']"));
        Assert.Equal(["3000", "5200"], Extraction.JsonPath(json, "$.Fans[0,1].Reading"));
        Assert.Throws<FormatException>(() => Extraction.JsonPath(json, "Name"));
        Assert.Throws<FormatException>(() => Extraction.JsonPath("{bad", "$.a"));
    }
}

public class QueryEngineTests
{
    [Fact]
    public void Static_cycles_through_remote_columns_and_virtual_columns_are_detected()
    {
        var a = QueryTestKit.Q(QueryKind.Script, "A", q => q.Script!.Script = "Output.Write Remote.WMI(\"B\")");
        var b = QueryTestKit.Q(QueryKind.Wmi, "B");
        var c = QueryTestKit.Q(QueryKind.Python, "C", q => q.Python!.Script = "Output.Write(Input.Column('Combined'))");
        var d = QueryTestKit.Q(QueryKind.Script, "D", q => q.Script!.Script = "Output.Write Input.Column(\"C\")");
        var e = QueryTestKit.Q(QueryKind.Script, "E", q => q.Script!.Script = "x = Input.Column(\"E\")");
        var f = QueryTestKit.Q(QueryKind.Script, "F", q => q.Script!.Script = "Output.Write Input.Column(\"A\")");
        var virt = new VirtualColumnDefinition { Name = "Combined", Source = "[D] / [Host Name]" };
        var g = QueryDependencies.Build([a, b, c, d, e, f], [virt]);
        Assert.Equal(0, g.Levels[b.Id]);
        Assert.Equal(1, g.Levels[a.Id]);
        Assert.Equal(2, g.Levels[f.Id]);
        Assert.Contains("cycle", g.Errors[c.Id], StringComparison.Ordinal); // C → Combined → D → C
        Assert.Contains("cycle", g.Errors[d.Id], StringComparison.Ordinal);
        Assert.Contains("cycle", g.Errors[e.Id], StringComparison.Ordinal); // self reference
        Assert.False(g.Errors.ContainsKey(a.Id));
        Assert.True(g.Order.ToList().IndexOf(b) < g.Order.ToList().IndexOf(a));
    }

    [Fact]
    public async Task Plan_runs_levels_nested_remote_calls_and_reports_typed_states()
    {
        var wmi = QueryTestKit.Q(QueryKind.Wmi, "OS");
        var slow = QueryTestKit.Q(QueryKind.Registry, "Slow", q => q.TimeoutSeconds = 1);
        var script = QueryTestKit.Q(QueryKind.Script, "Combo", q => q.Script!.Script = "Remote.WMI(\"OS\") Input.Column(\"Host Name\")");
        var noRuntime = QueryTestKit.Q(QueryKind.Python, "Py");
        var creds = QueryTestKit.Q(QueryKind.Ssh, "NeedsCred", q => q.CredentialId = Guid.NewGuid());
        var wmiProvider = FakeQueryProvider.Const(QueryKind.Wmi, "Windows 11");
        var scriptProvider = new FakeQueryProvider(QueryKind.Script, async (call, ct) =>
        {
            var os = await call.Context.RemoteAsync("WMI", "OS", ct);
            var missing = await call.Context.RemoteAsync("SNMP", "nothing", ct);
            return Observation<string>.Ok($"{os}|{call.Context.Column("Host Name")}|{missing}", DateTimeOffset.UtcNow);
        });
        var slowProvider = new FakeQueryProvider(QueryKind.Registry, async (_, ct) =>
        {
            await Task.Delay(TimeSpan.FromSeconds(30), ct);
            return Observation<string>.Ok("never", DateTimeOffset.UtcNow);
        });
        using var plan = QueryTestKit.Plan([wmi, slow, script, noRuntime, creds], null, null, wmiProvider, scriptProvider, slowProvider,
            new FakeQueryProvider(QueryKind.Python, (_, _) => throw new InvalidOperationException("not called"), available: false),
            FakeQueryProvider.Const(QueryKind.Ssh, "x"));
        var device = Samples.Device("10.0.0.5", "pc5");
        var r = await plan.RunAsync(device, CancellationToken.None);
        Assert.Equal("Windows 11", r.Text(wmi));
        Assert.Equal("Windows 11|pc5|[no SNMP item named 'nothing']", r.Text(script));
        Assert.Equal(1, wmiProvider.Calls); // the Remote call reused the memoised result (or vice versa)
        Assert.Equal(ObservationState.Timeout, r[slow.ColumnId].State);
        Assert.Equal(ObservationState.Unsupported, r[noRuntime.ColumnId].State);
        Assert.Contains("credential no longer exists", r[creds.ColumnId].Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Dynamic_remote_cycles_are_cut_without_deadlock()
    {
        var a = QueryTestKit.Q(QueryKind.Ssh, "A");
        var b = QueryTestKit.Q(QueryKind.Snmp, "B");
        // A and B call each other with names the static analysis cannot see (not scripts) → runtime detection.
        var pa = new FakeQueryProvider(QueryKind.Ssh, async (c, ct) => Observation<string>.Ok("A>" + await c.Context.RemoteAsync("SNMP", "B", ct), DateTimeOffset.UtcNow));
        var pb = new FakeQueryProvider(QueryKind.Snmp, async (c, ct) => Observation<string>.Ok("B>" + await c.Context.RemoteAsync("SSH", "A", ct), DateTimeOffset.UtcNow));
        using var plan = QueryTestKit.Plan([a, b], null, null, pa, pb);
        var r = await plan.RunAsync(Samples.Device("10.0.0.1"), CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Contains("[dependency cycle]", r.Text(a), StringComparison.Ordinal);
        Assert.Contains("[dependency cycle]", r.Text(b), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Single_column_rescan_runs_only_that_query_and_its_dependencies()
    {
        var dep = QueryTestKit.Q(QueryKind.Wmi, "Dep");
        var target = QueryTestKit.Q(QueryKind.Script, "Target", q => q.Script!.Script = "Output.Write Input.Column(\"Dep\")");
        var other = QueryTestKit.Q(QueryKind.Snmp, "Other");
        var pd = FakeQueryProvider.Const(QueryKind.Wmi, "dep");
        var po = FakeQueryProvider.Const(QueryKind.Snmp, "other");
        var pt = new FakeQueryProvider(QueryKind.Script, (c, _) => Task.FromResult(Observation<string>.Ok("t:" + c.Context.Column("Dep"), DateTimeOffset.UtcNow)));
        using var plan = QueryTestKit.Plan([dep, target, other], null, null, pd, po, pt);
        var r = await plan.RunAsync(Samples.Device("10.0.0.1"), CancellationToken.None, [target.Id]);
        Assert.Equal("t:dep", r.Text(target));
        Assert.Single(r);
        Assert.Equal(0, po.Calls);
    }

    [Fact]
    public async Task Scan_engine_runs_queries_for_online_devices_and_results_survive_xml()
    {
        var q = QueryTestKit.Q(QueryKind.Json, "Model");
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        using var plan = QueryTestKit.Plan([q], null, null, new FakeQueryProvider(QueryKind.Json, (c, _) => Task.FromResult(Observation<string>.Ok("model-" + c.Device.Key, DateTimeOffset.UtcNow))));
        var sink = new ListSink();
        using var s = new ScanEngine(icmp, new FakeArp(), new FakeDns()).Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.1-10.0.0.2"),
            Settings = new ScanSettings { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false, DeviceDeadlineSeconds = 0 },
            Queries = plan,
        }, sink);
        await s.Completion.WaitAsync(TimeSpan.FromSeconds(20));
        var d = sink.Get("10.0.0.1");
        Assert.True(d.IsComplete);
        Assert.Equal("model-10.0.0.1", d.Queries[q.ColumnId].Value);
        Assert.False(sink.Has("10.0.0.2"));

        var columns = ColumnSet.Build(new ScanSettings(), new FriendlyNameSettings(), [], new QuerySettings { Items = [q] });
        Assert.Equal("model-10.0.0.1", columns.Single(c => c.Header == "Model").Text(d));
        var doc = ResultsXml.ToDocument(columns, [d], new ScanMetadata { ExportedAt = Samples.T, StartedAt = Samples.T });
        using var ms = new MemoryStream();
        doc.Save(ms);
        ms.Position = 0;
        Assert.Equal("model-10.0.0.1", ResultsXml.Read(ms).Devices[0].Queries[q.ColumnId].Value);
    }
}

public class VaultTests
{
    [Fact]
    public void Secret_box_authenticates_and_rejects_wrong_keys()
    {
        var key = SecretBox.NewKey();
        var p = SecretBox.ProtectText(key, "pässwörd");
        Assert.StartsWith("v1:", p, StringComparison.Ordinal);
        Assert.NotEqual(p, SecretBox.ProtectText(key, "pässwörd")); // random nonce
        Assert.Equal("pässwörd", SecretBox.UnprotectText(key, p));
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.UnprotectText(SecretBox.NewKey(), p));
        var tampered = p[..^4] + (p[^4] == 'A' ? "B" : "A") + p[^3..];
        Assert.ThrowsAny<CryptographicException>(() => SecretBox.UnprotectText(key, tampered));
        Assert.Throws<ArgumentOutOfRangeException>(() => SecretBox.DeriveFromPassword("x", SecretBox.NewSalt(), 1000));
    }

    [Fact]
    public async Task Master_password_encrypts_the_settings_file_and_unlocks_it()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-vault-").FullName;
        var store = new SettingsStore(dir);
        var vault = store.Vault;
        var settings = vault.SetMasterPassword(new AppSettings(), "correct horse", 100_000);
        var cred = new StoredCredential { UserName = @"CORP\admin", Secret = vault.Protect("S3cret!pw"), Tag = "corp" };
        settings = settings with { Credentials = [cred], Ranges = [new RangeEntry { Target = "10.9.8.0/24" }] };
        await store.SaveAsync(settings);

        var raw = await File.ReadAllTextAsync(store.FilePath);
        Assert.Contains("ipmasterEncryptedConfig", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("10.9.8.0", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("admin", raw, StringComparison.Ordinal);
        Assert.DoesNotContain("S3cret", raw, StringComparison.Ordinal);

        var fresh = new SettingsStore(dir);
        Assert.Equal(SettingsLoadStatus.PasswordRequired, fresh.Load().Status);
        await Assert.ThrowsAsync<InvalidOperationException>(() => fresh.SaveAsync(new AppSettings())); // never overwritten while locked
        Assert.Equal(SettingsLoadStatus.WrongPassword, fresh.Unlock("wrong").Status);
        var ok = fresh.Unlock("correct horse");
        Assert.Equal(SettingsLoadStatus.Loaded, ok.Status);
        Assert.Equal("10.9.8.0/24", ok.Settings.Ranges[0].Target);
        Assert.True(fresh.Vault.CanReveal);
        Assert.Equal("S3cret!pw", fresh.Vault.Credential(cred.Id)!.Password);
        Assert.Equal("S3cret!pw", fresh.Vault.CredentialByTag("CORP")!.Password);
        Assert.Equal(@"CORP\admin (password hidden)", fresh.Vault.Credential(cred.Id)!.ToString());
    }

    [Fact]
    public void Os_protected_vault_and_encrypted_export()
    {
        if (!OperatingSystem.IsWindows()) return;
        var vault = new CredentialVault();
        var s = vault.EnsureKey(new AppSettings());
        Assert.Equal(VaultMode.OsProtected, s.Vault.Mode);
        var c = new StoredCredential { UserName = "root", Secret = vault.Protect("toor-pw"), Tag = "lab" };
        s = s with { Credentials = [c] };

        var other = new CredentialVault();
        other.Attach(s);
        Assert.True(other.CanReveal); // same Windows user
        Assert.Equal("toor-pw", other.Credential(c.Id)!.Password);

        var export = vault.Export([c], "export-pass");
        Assert.DoesNotContain("toor-pw", Encoding.UTF8.GetString(export), StringComparison.Ordinal);
        Assert.ThrowsAny<CryptographicException>(() => vault.Import(export, "nope"));
        var imported = Assert.Single(vault.Import(export, "export-pass"));
        Assert.Equal("toor-pw", vault.Reveal(imported.Secret));
        Assert.NotNull(CredentialVault.ValidateTags([c, imported]));
    }

    [Fact]
    public async Task Cli_unlocks_with_stdin_or_environment_and_fails_without_password()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-mpass-").FullName;
        var store = new SettingsStore(dir);
        var settings = store.Vault.SetMasterPassword(new AppSettings
        {
            Wol = new Core.Management.WolSettings { Targets = [], DefaultDestination = "127.0.0.1", Port = 9, DelayMs = 0 },
        }, "pw-123456", 100_000);
        await store.SaveAsync(settings);

        async Task<(int Code, string Err)> Run(string[] args, string? stdin = null)
        {
            var sp = new ServiceCollection().AddIPMaster(dir).BuildServiceProvider();
            var err = new StringWriter();
            var code = await new CliApp(sp, new StringWriter(), err, stdin: new StringReader(stdin ?? "")).RunAsync(args, CancellationToken.None);
            return (code, err.ToString());
        }

        var none = await Run(["/wakeall"]);
        Assert.Equal(ExitCodes.Settings, none.Code);
        Assert.Contains("master password", none.Err, StringComparison.Ordinal);
        Assert.Equal(ExitCodes.Settings, (await Run(["/mpass:-", "/wakeall"], "wrong")).Code);
        var viaStdin = await Run(["/mpass:-", "/wakeall"], "pw-123456");
        Assert.Equal(ExitCodes.Targets, viaStdin.Code); // unlocked; the WOL list is just empty
        Assert.DoesNotContain("pw-123456", viaStdin.Err, StringComparison.Ordinal);
        Assert.Equal(ExitCodes.Targets, (await Run(["/mpass:pw-123456", "/wakeall"])).Code);
    }
}

public class ScriptBridgeTests
{
    private static (QueryPlan Plan, QueryDefinition Script) ScriptPlan(ScriptLanguage language, string script, IRemoteQueryProvider provider)
    {
        var os = QueryTestKit.Q(QueryKind.Wmi, "OS");
        var q = QueryTestKit.Q(QueryKind.Script, "S", x =>
        {
            x.Script!.Language = language;
            x.Script.Script = script;
            x.TimeoutSeconds = 60;
        });
        if (provider.Kind == QueryKind.Python)
        {
            q = QueryTestKit.Q(QueryKind.Python, "S", x =>
            {
                x.Python!.Script = script;
                x.TimeoutSeconds = 60;
            });
        }

        return (QueryTestKit.Plan([os, q], null, null, FakeQueryProvider.Const(QueryKind.Wmi, "Windows ünïcode ✓"), provider), q);
    }

    [Fact]
    public async Task Vbscript_api_input_output_remote_and_internal_process()
    {
        var wsh = new WshScriptProvider();
        if (!WshScriptProvider.VbScriptAvailable) return;
        const string script = """
            Option Explicit
            Dim p, s
            Set p = Internal.CreateObject("Process")
            p.Execute "cmd.exe /c echo hello"
            Set s = Internal.CreateObject("SNMP")
            s.Query.AddOid "1.3.6.1.2.1.1.1.0"
            Output.Write Input.Current & "|" & Remote.WMI("OS") & "|" & Input.Column("Host Name") & "|" & p.Output(0) & "|" & p.ExitCode & "|" & s.Query.OidList
            """;
        var (plan, q) = ScriptPlan(ScriptLanguage.VBScript, script, wsh);
        using (plan)
        {
            var r = await plan.RunAsync(Samples.Device("10.1.2.3", "host-ä"), CancellationToken.None);
            Assert.True(r[q.ColumnId].State == ObservationState.Success, r[q.ColumnId].Detail);
            Assert.Equal("10.1.2.3|Windows ünïcode ✓|host-ä|hello|0|1.3.6.1.2.1.1.1.0", r.Text(q));
        }
    }

    [Fact]
    public async Task Vbscript_errors_point_at_user_lines()
    {
        if (!WshScriptProvider.VbScriptAvailable) return;
        var (plan, q) = ScriptPlan(ScriptLanguage.VBScript, "Output.Write \"a\"\r\nx = 1 / 0\r\n", new WshScriptProvider());
        using (plan)
        {
            var r = await plan.RunAsync(Samples.Device("10.1.2.3"), CancellationToken.None);
            // Output was written before the error: the value is kept; a script without output reports the error.
            Assert.Equal("a", r.Text(q));
        }

        var (plan2, q2) = ScriptPlan(ScriptLanguage.VBScript, "Dim y\r\ny = 1 / 0\r\n", new WshScriptProvider());
        using (plan2)
        {
            var r = await plan2.RunAsync(Samples.Device("10.1.2.3"), CancellationToken.None);
            Assert.Equal(ObservationState.Failed, r[q2.ColumnId].State);
            Assert.Contains("script(2,", r[q2.ColumnId].Detail, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Jscript_api()
    {
        var wsh = new WshScriptProvider();
        if (!wsh.Capability.Available) return;
        var (plan, q) = ScriptPlan(ScriptLanguage.JScript,
            "var d = Internal.CreateObject('DNS');\nOutput.Write(Input.Current + '|' + Remote.WMI('OS') + '|' + typeof d.GetName);", wsh);
        using (plan)
        {
            var r = await plan.RunAsync(Samples.Device("10.1.2.3"), CancellationToken.None);
            Assert.True(r[q.ColumnId].State == ObservationState.Success, r[q.ColumnId].Detail);
            Assert.Equal("10.1.2.3|Windows ünïcode ✓|function", r.Text(q));
        }
    }

    [Fact]
    public async Task Python_api_or_reported_unavailable()
    {
        var py = new PythonQueryProvider(() => "");
        var (plan, q) = ScriptPlan(ScriptLanguage.VBScript, "Output.Write(Input.Current + '|' + Remote.WMI('OS'))", py);
        using (plan)
        {
            var r = await plan.RunAsync(Samples.Device("10.1.2.3"), CancellationToken.None);
            if (!py.Capability.Available)
            {
                Assert.Equal(ObservationState.Unsupported, r[q.ColumnId].State);
                return;
            }

            Assert.Equal("10.1.2.3|Windows ünïcode ✓", r.Text(q));
        }
    }

    [Fact]
    public async Task Powershell_local_run()
    {
        if (PowerShellQueryProvider.Executable() is null) return;
        var r = await PowerShellQueryProvider.RunLocalAsync("'a' + 'b'; 40 + 2", CancellationToken.None);
        Assert.Equal("ab\n42", r.Value);
        var bad = await PowerShellQueryProvider.RunLocalAsync("throw 'boom'", CancellationToken.None);
        Assert.Equal(ObservationState.Failed, bad.State);
        Assert.Contains("boom", bad.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void Bridge_hex_round_trip() => Assert.Equal("a ✓\n€𝄞", ScriptBridge.Unhex(ScriptBridge.Hex("a ✓\n€𝄞")));
}

public class ExternalToolTests
{
    [Fact]
    public void Nmap_arguments_are_a_list_and_output_options_are_rejected()
    {
        var a = NmapQueryProvider.Arguments(new NmapOptions { ScanType = NmapScanType.OsDetection, OsLimit = true, OsGuess = true },
            new NmapSettings { Ports = "22,80", ExcludePorts = "9100", ExtraArguments = "-T4 --max-retries 1" }, IPAddress.Parse("10.0.0.7"));
        Assert.Equal(["-O", "--osscan-limit", "--osscan-guess", "-p", "22,80", "--exclude-ports=9100", "-T4", "--max-retries", "1", "-oX", "-", "--noninteractive", "10.0.0.7"], a);
        var v6 = NmapQueryProvider.Arguments(new NmapOptions { ScanType = NmapScanType.VersionDetection, Intensity = NmapIntensity.Thorough }, new NmapSettings(), IPAddress.Parse("fe80::1"));
        Assert.Contains("--version-all", v6);
        Assert.Contains("-6", v6);
        Assert.Throws<ArgumentException>(() => NmapQueryProvider.Arguments(new NmapOptions(), new NmapSettings { ExtraArguments = "-oN out.txt" }, IPAddress.Loopback));
        Assert.Throws<ArgumentException>(() => NmapQueryProvider.Arguments(new NmapOptions { ScanType = NmapScanType.Script, ScriptName = "x;rm -rf" }, new NmapSettings(), IPAddress.Loopback));
        const string xml = """
            <?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><os><osmatch name="Linux 5.4" accuracy="98"/><osmatch name="Linux 4.15" accuracy="90"/></os></host></nmaprun>
            """;
        Assert.Equal(["Linux 5.4"], Extraction.XPath(NmapQueryProvider.StripDoctype(xml), new NmapOptions().XPath));
    }

    [Fact]
    public void Known_hosts_plain_and_hashed_entries()
    {
        var blob = RandomNumberGenerator.GetBytes(51);
        var fp = KnownHostStore.Fingerprint(blob);
        var salt = RandomNumberGenerator.GetBytes(20);
#pragma warning disable CA5350
        var hashed = "|1|" + Convert.ToBase64String(salt) + "|" + Convert.ToBase64String(HMACSHA1.HashData(salt, Encoding.ASCII.GetBytes("[10.0.0.9]:2222")));
#pragma warning restore CA5350
        var file = Path.Combine(Directory.CreateTempSubdirectory("ipm-kh-").FullName, "known_hosts");
        File.WriteAllLines(file, [$"router,10.0.0.1 ssh-ed25519 {Convert.ToBase64String(blob)}", $"{hashed} ssh-rsa {Convert.ToBase64String(blob)}", "# comment"]);
        Assert.Equal(("ssh-ed25519", fp), Assert.Single(KnownHostStore.OpenSshKnownHosts("10.0.0.1", 22, file)));
        Assert.Equal("ssh-rsa", Assert.Single(KnownHostStore.OpenSshKnownHosts("10.0.0.9", 2222, file)).Algorithm);
        Assert.Empty(KnownHostStore.OpenSshKnownHosts("10.0.0.9", 22, file));

        var store = new KnownHostStore();
        KnownHostKey? added = null;
        store.Trusted += (_, k) => added = k;
        Assert.Equal(KnownHostStore.Verdict.Unknown, store.Check("192.0.2.1", 22, "ssh-ed25519", "AAA"));
        store.Trust(new KnownHostKey { Host = "192.0.2.1", Port = 22, Algorithm = "ssh-ed25519", Fingerprint = "AAA" });
        Assert.NotNull(added);
        Assert.Equal(KnownHostStore.Verdict.Trusted, store.Check("192.0.2.1", 22, "ssh-ed25519", "AAA"));
        Assert.Equal(KnownHostStore.Verdict.Changed, store.Check("192.0.2.1", 22, "ssh-ed25519", "BBB"));
    }

    [Fact]
    public async Task Http_xml_and_json_queries_against_a_loopback_server()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var requests = new List<string>();
        _ = Task.Run(async () =>
        {
            for (var i = 0; i < 4; i++)
            {
                using var client = await listener.AcceptTcpClientAsync();
                var stream = client.GetStream();
                var buf = new byte[8192];
                var n = await stream.ReadAsync(buf);
                var req = Encoding.ASCII.GetString(buf, 0, n);
                lock (requests) requests.Add(req);
                var (status, body, type) = req.Contains("GET /health", StringComparison.Ordinal)
                    ? ("200 OK", "<root><status>OK</status></root>", "text/xml")
                    : req.Contains("GET /secure", StringComparison.Ordinal) && !req.Contains("Authorization: Basic", StringComparison.Ordinal)
                        ? ("401 Unauthorized", "", "text/plain")
                        : ("200 OK", """{"items":[{"v":1},{"v":2}]}""", "application/json");
                var bytes = Encoding.UTF8.GetBytes(body);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: {type}\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"));
                await stream.WriteAsync(bytes);
            }
        });
        var device = Samples.Device("127.0.0.1");
        async Task<Observation<string>> Run(QueryKind kind, HttpOptions o, ResolvedCredential? cred = null)
        {
            var q = QueryTestKit.Q(kind, "h", x => x.Http = o);
            return await new HttpQueryProvider(kind).ExecuteAsync(new QueryCall(q, device, cred, new QuerySettings(), new FakeSecrets(), null!), CancellationToken.None);
        }

        Assert.Equal("OK", (await Run(QueryKind.Xml, new HttpOptions { Port = port, Path = "/health", Expression = "/root/status" })).Value);
        Assert.Equal("1\n2", (await Run(QueryKind.Json, new HttpOptions { Port = port, Path = "/data", Extraction = HttpExtraction.JsonPath, Expression = "$.items[*].v" })).Value);
        Assert.Equal(ObservationState.AccessDenied, (await Run(QueryKind.Json, new HttpOptions { Port = port, Path = "/secure" })).State);
        var authed = await Run(QueryKind.Json, new HttpOptions { Port = port, Path = "/secure", BasicAuthentication = true, Extraction = HttpExtraction.JsonPath, Expression = "$.items[0].v" },
            new ResolvedCredential("u", "p"));
        Assert.Equal("1", authed.Value);
        lock (requests) Assert.Contains(requests, r => r.Contains("Authorization: Basic dTpw", StringComparison.Ordinal));
    }

    [Fact]
    public void Blumenthal_key_extension_and_sha224_key_localisation()
    {
        var kul = Enumerable.Range(0, 20).Select(i => (byte)i).ToArray();
#pragma warning disable CA5350
        var expected = kul.Concat(SHA1.HashData(kul)).Take(32).ToArray();
#pragma warning restore CA5350
        Assert.Equal(expected, SnmpClient.BlumenthalExtend(kul, 32, SnmpAuth.Sha1));
        var key = new Sha224AuthenticationProvider(new OctetString("maplesyrup")).PasswordToKey("maplesyrup"u8.ToArray(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 });
        Assert.Equal(28, key.Length);
        Assert.Equal(16, new Sha224AuthenticationProvider(new OctetString("maplesyrup")).DigestLength);
        // AES-CFB on a non-block length round trips
        var k = RandomNumberGenerator.GetBytes(24);
        var iv = RandomNumberGenerator.GetBytes(16);
        var data = RandomNumberGenerator.GetBytes(37);
        Assert.Equal(data, BlumenthalAesPrivacyProvider.Cfb(false, k, iv, BlumenthalAesPrivacyProvider.Cfb(true, k, iv, data)));
    }
}

/// <summary>Minimal SNMPv2c agent on loopback (test fixture only).</summary>
internal sealed class FakeSnmpAgent : IDisposable
{
    private readonly UdpClient _udp = new(new IPEndPoint(IPAddress.Loopback, 0));
    private readonly CancellationTokenSource _cts = new();
    private readonly SortedDictionary<ObjectIdentifier, ISnmpData> _data;

    public FakeSnmpAgent(string community, Dictionary<string, ISnmpData> data)
    {
        _data = new SortedDictionary<ObjectIdentifier, ISnmpData>(data.ToDictionary(kv => new ObjectIdentifier(kv.Key), kv => kv.Value));
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                UdpReceiveResult r;
                try
                {
                    r = await _udp.ReceiveAsync(_cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return;
                }

                var m = MessageFactory.ParseMessages(r.Buffer, new UserRegistry())[0];
                if (m.Parameters.UserName.ToString() != community) continue; // wrong community: silence, like real agents
                var vars = m.Pdu().Variables;
                IList<Variable> resp = m.TypeCode() switch
                {
                    SnmpType.GetRequestPdu => vars.Select(v => new Variable(v.Id, _data.TryGetValue(v.Id, out var d) ? d : new NoSuchObject())).ToList(),
                    SnmpType.GetBulkRequestPdu => Next(vars[0].Id, 3),
                    _ => Next(vars[0].Id, 1),
                };
                var reply = new ResponseMessage(m.RequestId(), m.Version, m.Parameters.UserName, ErrorCode.NoError, 0, resp);
                await _udp.SendAsync(reply.ToBytes(), r.RemoteEndPoint);
            }
        });
    }

    public int Port => ((IPEndPoint)_udp.Client.LocalEndPoint!).Port;

    private List<Variable> Next(ObjectIdentifier after, int count)
    {
        var list = _data.Where(kv => kv.Key.CompareTo(after) > 0).Take(count).Select(kv => new Variable(kv.Key, kv.Value)).ToList();
        if (list.Count < count) list.Add(new Variable(list.Count > 0 ? list[^1].Id : after, new EndOfMibView()));
        return list;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _udp.Dispose();
        _cts.Dispose();
    }
}

public class SnmpQueryTests
{
    [Fact]
    public async Task Get_walk_community_list_and_display_modes()
    {
        using var agent = new FakeSnmpAgent("s3cret", new Dictionary<string, ISnmpData>
        {
            ["1.3.6.1.2.1.1.1.0"] = new OctetString("Lab switch v1"),
            ["1.3.6.1.2.1.1.5.0"] = new OctetString("sw-01"),
            ["1.3.6.1.2.1.2.2.1.2.1"] = new OctetString("eth0"),
            ["1.3.6.1.2.1.2.2.1.2.2"] = new OctetString("eth1"),
            ["1.3.6.1.2.1.2.2.1.6.1"] = new OctetString(new byte[] { 0, 0x11, 0x22, 0x33, 0x44, 0x55 }),
            ["1.3.6.1.2.1.4.20.1.3.127.0.0.1"] = new IP(IPAddress.Parse("255.0.0.0").GetAddressBytes()),
        });
        async Task<Observation<string>> Run(Action<SnmpOptions> configure)
        {
            var q = QueryTestKit.Q(QueryKind.Snmp, "s", x =>
            {
                x.Snmp!.Port = agent.Port;
                x.Snmp.Communities = "public, s3cret"; // the first is ignored by the agent; the second answers
                configure(x.Snmp);
                x.TimeoutSeconds = 15;
            });
            using var plan = QueryTestKit.Plan([q], null, null, new SnmpQueryProvider());
            var r = await plan.RunAsync(Samples.Device("127.0.0.1"), CancellationToken.None);
            return r[q.ColumnId];
        }

        Assert.Equal("Lab switch v1", (await Run(_ => { })).Value);
        Assert.Equal("255.0.0.0", (await Run(o => o.Oid = "1.3.6.1.2.1.4.20.1.3.%0")).Value); // manual netmask example
        Assert.Equal("00 11 22 33 44 55", (await Run(o => o.Oid = "1.3.6.1.2.1.2.2.1.6.1")).Value);
        Assert.Equal("sw-01", (await Run(o =>
        {
            o.Oid = "1.3.6.1.2.1.1.1.0";
            o.Operation = SnmpOperation.GetNext;
        })).Value);
        Assert.Equal("1.3.6.1.2.1.2.2.1.2.1: eth0\n1.3.6.1.2.1.2.2.1.2.2: eth1", (await Run(o =>
        {
            o.Oid = "1.3.6.1.2.1.2.2.1.2";
            o.Operation = SnmpOperation.Walk;
        })).Value);
        Assert.Equal(ObservationState.Empty, (await Run(o => o.Oid = "1.3.6.1.2.1.1.9.0")).State);
    }

    [Fact]
    public void V3_privacy_providers_cover_the_manual_algorithms()
    {
        foreach (var auth in Enum.GetValues<SnmpAuth>())
        {
            foreach (var priv in Enum.GetValues<SnmpPriv>())
            {
                var p = SnmpClient.Privacy(new SnmpTarget(new IPEndPoint(IPAddress.Loopback, 161), Core.Queries.SnmpVersion.V3, [], "u", SnmpSecurity.AuthPriv, auth, "authpass1", priv, "privpass1"));
                Assert.NotNull(p.AuthenticationProvider);
            }
        }

        Assert.Throws<IPMaster.Infrastructure.Queries.SnmpException>(() => SnmpClient.Authentication(SnmpAuth.Sha256, "short"));
    }
}

public class WindowsLocalQueryTests
{
    [Fact]
    public void Registry_files_services_wmi_and_performance_on_this_computer()
    {
        if (!OperatingSystem.IsWindows()) return;
        var reg = RegistryQueryProvider.ReadLocal(new RegistryOptions { Key = @"SOFTWARE\[NoSuchVendor|Microsoft]\Windows NT\CurrentVersion", ValueName = "CurrentBuild" });
        Assert.True(reg.State == ObservationState.Success, reg.Detail);
        Assert.True(int.Parse(reg.Value!, System.Globalization.CultureInfo.InvariantCulture) > 9000);
        var exists = RegistryQueryProvider.ReadLocal(new RegistryOptions { Key = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", Action = RegistryAction.KeyExists });
        Assert.Equal("Yes", exists.Value);
        var wild = RegistryQueryProvider.ReadLocal(new RegistryOptions { Key = @"HARDWARE\DESCRIPTION\System\CentralProcessor\*", ValueName = "ProcessorNameString", Action = RegistryAction.ReadWildcard });
        Assert.Contains(@"CentralProcessor\0: ", wild.Value, StringComparison.Ordinal); // manual example

        var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var version = FileQueryProvider.Query(new Core.Queries.FileOptions { Path = Path.Combine(win, @"System32\[nope|kernel32.dll]"), Property = FileProperty.FileVersion }, null, CancellationToken.None);
        Assert.Matches(@"^\d+\.\d+", version.Value);
        var many = FileQueryProvider.Query(new Core.Queries.FileOptions { Path = Path.Combine(win, @"System32\drivers\etc\*"), Property = FileProperty.Exists }, null, CancellationToken.None);
        Assert.Contains(@"etc\hosts: Yes", many.Value, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("No", FileQueryProvider.Query(new Core.Queries.FileOptions { Path = @"C:\no\such\file.txt", Property = FileProperty.Exists }, null, CancellationToken.None).Value);
        Assert.Throws<FormatException>(() => FileQueryProvider.MapToAdminShare(@"relative\path", "h"));
        Assert.Equal((@"\\10.0.0.1\D$", @"Data\x.txt"), FileQueryProvider.MapToAdminShare(@"d:\Data\x.txt", "10.0.0.1"));

        var crc = new Crc32();
        crc.Append("123456789"u8);
        Assert.Equal(0xCBF43926u, crc.Value); // standard check value

        Assert.Equal("Running", ServiceQueryProvider.Query(new ServiceOptions { ServiceName = "EventLog" }, ".").Value);
        Assert.Equal("Not installed", ServiceQueryProvider.Query(new ServiceOptions { ServiceName = "ipmaster-no-such-svc" }, ".").Value);
        Assert.Contains("svchost", ServiceQueryProvider.Query(new ServiceOptions { ServiceName = "EventLog", Property = ServiceProperty.ImagePath }, ".").Value,
            StringComparison.OrdinalIgnoreCase);

        var os = WmiQueryProvider.Query(new WmiOptions { Query = "SELECT Caption, OSArchitecture FROM Win32_OperatingSystem" }, ".", null, TimeSpan.FromSeconds(30));
        Assert.True(os.State == ObservationState.Success, os.Detail);
        Assert.Contains("Windows", os.Value, StringComparison.Ordinal);
        Assert.Contains("OSArchitecture: ", os.Value, StringComparison.Ordinal);
        var bad = WmiQueryProvider.Query(new WmiOptions { Query = "SELECT Nope FROM Win32_NoSuchClass" }, ".", null, TimeSpan.FromSeconds(30));
        Assert.Equal(ObservationState.Failed, bad.State);

        Assert.Equal(("Processor", "_Total", "% Processor Time"), PerformanceQueryProvider.Parse(@"\Processor(_Total)\% Processor Time"));
        Assert.Equal(("System", null, "System Up Time"), PerformanceQueryProvider.Parse(@"\System\System Up Time"));
        Assert.Throws<FormatException>(() => PerformanceQueryProvider.Parse(@"\\host\Processor(_Total)\% Processor Time"));
    }
}

public class PropertiesQueryRowsTests
{
    [Fact]
    public void Properties_list_query_results_with_names_and_one_row_per_line()
    {
        var q = QueryTestKit.Q(QueryKind.Wmi, "RAM");
        var d = Samples.Device("10.0.0.1") with
        {
            Queries = new Dictionary<string, Observation<string>>
            {
                [q.ColumnId] = Observation<string>.Ok("8589934592\n8589934592", Samples.T),
                ["q:deleted"] = Observation<string>.Of(ObservationState.Timeout, Samples.T, "No result within 15 s."),
            },
        };
        var rows = IPMaster.Desktop.Views.PropertiesWindow.Build(d, ColumnFormat.Default, [q]).Where(r => r.Category == "Remote queries").ToList();
        Assert.Equal(3, rows.Count);
        Assert.Equal("WMI: RAM", rows[0].Property);
        Assert.Equal("", rows[1].Property);
        Assert.Equal("[timeout]", rows[2].Value);
        Assert.Contains("No result", rows[2].State, StringComparison.Ordinal);
    }
}
