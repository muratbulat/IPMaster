using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using IPMaster.Core.Tools;
using IPMaster.Desktop.Views;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>KMS Activation Manager (D-104). Pure rules and fakes only: no test ever changes the licence of this computer.</summary>
public class KmsCatalogTests
{
    [Fact]
    public void Catalog_matches_the_reviewed_official_snapshot()
    {
        // counts of the Microsoft Learn pages reviewed 2026-11-26 (Windows: 82 keys, Office: 52 keys)
        Assert.Equal(82, KmsCatalog.All.Count(e => e.Family is KmsFamily.Windows or KmsFamily.WindowsServer));
        Assert.Equal(52, KmsCatalog.All.Count(e => e.Family is KmsFamily.Office or KmsFamily.Project or KmsFamily.Visio));
        Assert.Equal(KmsCatalog.All.Count, KmsCatalog.All.Select(e => e.Key).Distinct().Count()); // no duplicate keys
        Assert.All(KmsCatalog.All, e => Assert.Matches(new Regex("^[0-9A-Z]{5}(-[0-9A-Z]{5}){4}$"), e.Key));
        Assert.All(KmsCatalog.All, e => Assert.StartsWith("https://learn.microsoft.com/", e.Source, StringComparison.Ordinal));
        // match tokens never point at two keys
        var tokens = KmsCatalog.All.SelectMany(e => e.Match).ToList();
        Assert.Equal(tokens.Count, tokens.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Theory]
    [InlineData("Pro", "W269N-WFGWX-YVC9B-4J6C9-T83GX")]
    [InlineData("Enterprise", "NPPR9-FWDCX-D2C8J-H872K-2YT43")]
    public void Published_windows_examples_are_present(string edition, string key) =>
        Assert.Contains(KmsCatalog.All, e => e.Family == KmsFamily.Windows && e.Version == "Windows 11 / 10" && e.Edition == edition && e.Key == key);

    [Theory]
    [InlineData("Windows Server 2025", "Standard", "TVRH6-WHNXV-R9WG3-9XRFY-MY832")]
    [InlineData("Windows Server 2025", "Datacenter", "D764K-2NDRG-47T6Q-P8T8W-YP6DF")]
    [InlineData("Windows Server 2022", "Standard", "VDYBN-27WPP-V4HQT-9VMD4-VMK7H")]
    [InlineData("Windows Server 2022", "Datacenter", "WX4NM-KYWYW-QJJR4-XV3QB-6VM33")]
    public void Published_server_examples_are_present(string version, string edition, string key) =>
        Assert.Contains(KmsCatalog.All, e => e.Version == version && e.Edition == edition && e.Key == key);

    [Theory]
    [InlineData("Office LTSC Professional Plus 2024", "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB")]
    [InlineData("Office LTSC Standard 2024", "V28N4-JG22K-W66P8-VTMGK-H6HGR")]
    [InlineData("Office LTSC Professional Plus 2021", "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH")]
    [InlineData("Office LTSC Standard 2021", "KDX7X-BNVR8-TXXGX-4Q7Y8-78VT3")]
    [InlineData("Office Professional Plus 2019", "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP")]
    [InlineData("Office Professional Plus 2016", "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99")]
    public void Published_office_examples_are_present(string product, string key) => Assert.Contains(KmsCatalog.All, e => e.Edition == product && e.Key == key);

    [Theory]
    [InlineData("Professional", 26100, false, "Windows 10 Pro", "W269N-WFGWX-YVC9B-4J6C9-T83GX")]
    [InlineData("ProfessionalN", 19045, false, "Windows 10 Pro N", "MH37W-N47XK-V7XM9-C7227-GCQG9")]
    [InlineData("Enterprise", 22631, false, "Windows 10 Enterprise", "NPPR9-FWDCX-D2C8J-H872K-2YT43")]
    [InlineData("EnterpriseS", 19044, false, "Windows 10 Enterprise LTSC 2021", "M7XTQ-FN8P6-TTKYV-9D4CC-J462D")]
    [InlineData("EnterpriseS", 14393, false, "Windows 10 Enterprise 2016 LTSB", "DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ")]
    [InlineData("IoTEnterpriseS", 26100, false, "Windows 10 IoT Enterprise LTSC 2024", "KBN8V-HFGQ4-MGXVD-347P6-PDQGT")]
    [InlineData("ServerStandard", 20348, true, "Windows Server 2022 Standard", "VDYBN-27WPP-V4HQT-9VMD4-VMK7H")]
    [InlineData("ServerDatacenter", 26100, true, "Windows Server 2025 Datacenter", "D764K-2NDRG-47T6Q-P8T8W-YP6DF")]
    [InlineData("ServerStandard", 17763, true, "Windows Server 2019 Standard", "N69G4-B89J2-4G8F4-WWYCC-J464C")]
    public void Windows_matches_by_edition_and_build(string edition, int build, bool server, string name, string key) =>
        Assert.Equal(key, KmsCatalog.MatchWindows(edition, build, server, name)?.Key);

    [Theory]
    [InlineData("Core", 26100, false, "Windows 10 Home")] // Home has no GVLK
    [InlineData("CoreSingleLanguage", 22631, false, "Windows 10 Home Single Language")]
    [InlineData("EnterpriseS", 22631, false, "Windows 10 Enterprise LTSC")] // no LTSC on that build
    [InlineData("ServerStandardEval", 20348, true, "Windows Server 2022 Standard Evaluation")]
    [InlineData("ServerStandard", 17763, true, "Windows Server Standard")] // 2019 or version 1809: ambiguous
    [InlineData("ServerStandard", 26100, false, "Windows Server 2025 Standard")] // server key never for a client
    [InlineData("Professional", 20348, true, "Windows Server 2022")] // client key never for a server
    [InlineData("", 26100, false, "Windows 11 Pro")] // unknown edition
    public void Windows_without_an_exact_match_gets_no_key(string edition, int build, bool server, string name) =>
        Assert.Null(KmsCatalog.MatchWindows(edition, build, server, name));

    [Fact]
    public void Server_standard_never_gets_the_datacenter_key()
    {
        Assert.Equal("Standard", KmsCatalog.MatchWindows("ServerStandard", 26100, true, "Windows Server 2025 Standard")!.Edition);
        Assert.Equal("Datacenter", KmsCatalog.MatchWindows("ServerDatacenter", 26100, true, "Windows Server 2025 Datacenter")!.Edition);
    }

    [Theory]
    [InlineData("Office21ProPlus2021VL_KMS_Client_AE", "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH")]
    [InlineData("Office24ProPlus2024VL_MAK_AE", "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB")]
    [InlineData("Office24Standard2024VL_KMS_Client_AE", "V28N4-JG22K-W66P8-VTMGK-H6HGR")]
    [InlineData("Office19VisioPro2019VL_KMS_Client_AE", "9BGNQ-K37YR-RQHF2-38RQ3-7VCBB")]
    [InlineData("Office16ProjectStdVL_MAK", "GNFHQ-F6YQM-KQDGJ-327XX-KQBVC")]
    [InlineData("Office16SkypeforBusinessVL_KMS_Client", "869NQ-FJ69K-466HW-QYCP2-DDBV6")]
    [InlineData("Office16StandardVL_KMS_Client", "JNRGM-WHDWX-FJJG3-K47QV-DRTFM")]
    public void Office_matches_product_and_version(string family, string key) => Assert.Equal(key, KmsCatalog.MatchOffice(family)?.Key);

    [Theory]
    [InlineData("Office16ProPlus2021R_Retail")] // retail
    [InlineData("Office16O365ProPlusR_Subscription1")] // Microsoft 365 Apps
    [InlineData("Office21ProPlus2024VL_KMS_Client_AE")] // inconsistent version: no guess
    [InlineData("Office24PublisherVL2024_KMS_Client_AE")] // malformed
    [InlineData("Office24Publisher2024VL_KMS_Client_AE")] // no Publisher in LTSC 2024
    [InlineData("")]
    public void Office_without_an_exact_match_gets_no_key(string family) => Assert.Null(KmsCatalog.MatchOffice(family));

    [Fact]
    public void Office_2021_never_gets_the_2024_key_and_standard_never_pro_plus()
    {
        Assert.Equal("2021", KmsCatalog.MatchOffice("Office21ProPlus2021VL_KMS_Client_AE")!.Version);
        Assert.Equal("Office LTSC Standard 2021", KmsCatalog.MatchOffice("Office21Standard2021VL_MAK_AE")!.Edition);
    }
}

public class KmsDetectionTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 26, 12, 0, 0, TimeSpan.Zero);
    private static readonly WindowsInfo Win11Pro = new("Professional", "Windows 10 Pro", 26100, "24H2", "Client", "X64");

    private static LicenseRecord Os(string channel, uint status = 1, string family = "Professional", uint grace = 0) => new()
    {
        Id = Guid.NewGuid().ToString(), ApplicationId = Kms.WindowsApplicationId, LicenseFamily = family, ProductKeyChannel = channel, LicenseStatus = status, GraceMinutes = grace,
        PartialKey = "ABCDE", Name = "Windows(R), Professional edition",
    };

    private static LicenseRecord Office(string family, string channel, uint status = 1) => new()
    {
        Id = Guid.NewGuid().ToString(), ApplicationId = Kms.OfficeApplicationId, LicenseFamily = family, ProductKeyChannel = channel, LicenseStatus = status,
        Name = $"Office, {family} edition", PartialKey = "12345",
    };

    [Theory]
    [InlineData("Retail", LicenseChannel.Retail)]
    [InlineData("OEM:DM", LicenseChannel.Oem)]
    [InlineData("Volume:MAK", LicenseChannel.VolumeMak)]
    [InlineData("Volume:GVLK", LicenseChannel.VolumeKmsClient)]
    [InlineData("Volume:CSVLK", LicenseChannel.VolumeKmsHost)]
    public void Windows_channels(string channel, LicenseChannel expected)
    {
        var p = Assert.Single(KmsDetection.Build([Os(channel)], Win11Pro, null, "", null, Now));
        Assert.Equal(expected, p.Channel);
        Assert.Equal(ActivationState.Licensed, p.State);
        Assert.Equal("Windows 11 Pro", p.Name); // registry says Windows 10 on Windows 11 builds
        Assert.Equal("W269N-WFGWX-YVC9B-4J6C9-T83GX", p.Key?.Key);
    }

    [Fact]
    public void Kms_client_expiry_comes_from_the_reported_minutes_and_hosts_stay_separate()
    {
        var r = Os("Volume:GVLK", grace: 60 * 24 * 180) with { UsedHost = "kms1.corp.test", UsedPort = 1688 };
        var p = Assert.Single(KmsDetection.Build([r], Win11Pro, null, "kms.corp.test", 1688, Now));
        Assert.Equal(Now.AddDays(180), p.Expires);
        Assert.Equal("kms.corp.test", p.ConfiguredKmsHost); // configured (service default)
        Assert.Equal("kms1.corp.test", p.UsedKmsHost); // actually used
        Assert.Equal("Not applicable", Kms.ExpiresText(Assert.Single(KmsDetection.Build([Os("Retail")], Win11Pro, null, "", null, Now))));
    }

    [Fact]
    public void Missing_or_ambiguous_windows_licence_gives_no_product_id()
    {
        var none = Assert.Single(KmsDetection.Build([], Win11Pro, null, "", null, Now));
        Assert.Equal(LicenseChannel.Unknown, none.Channel);
        Assert.Equal(ActivationState.Unknown, none.State);
        Assert.Equal(KmsAction.None, Kms.Plan(none).Action);
        var two = Assert.Single(KmsDetection.Build([Os("Retail"), Os("Volume:MAK")], Win11Pro, null, "", null, Now));
        Assert.Equal("", two.ProductId);
        // add-on licences (e.g. ESU) are not the operating system licence
        var addon = Os("Volume:MAK", family: "ESU") with { IsAddon = true };
        Assert.Equal(LicenseChannel.Retail, Assert.Single(KmsDetection.Build([Os("Retail"), addon], Win11Pro, null, "", null, Now)).Channel);
    }

    [Fact]
    public void Edition_and_licence_family_disagreeing_gives_no_key()
    {
        var p = Assert.Single(KmsDetection.Build([Os("Retail", family: "Core")], Win11Pro, null, "", null, Now));
        Assert.Null(p.Key);
        Assert.Equal(KmsAction.None, Kms.Plan(p).Action);
    }

    [Fact]
    public void Server_is_detected_from_the_installation_type()
    {
        var info = new WindowsInfo("ServerDatacenter", "Windows Server 2025 Datacenter", 26100, "24H2", "Server Core", "X64");
        var p = Assert.Single(KmsDetection.Build([Os("Volume:GVLK", family: "ServerDatacenter")], info, null, "", null, Now));
        Assert.Equal(KmsFamily.WindowsServer, p.Family);
        Assert.Equal("Windows Server 2025 Datacenter", p.Name);
        Assert.Equal("D764K-2NDRG-47T6Q-P8T8W-YP6DF", p.Key?.Key);
    }

    [Fact]
    public void Several_office_products_stay_separate()
    {
        var records = new[]
        {
            Os("Retail"),
            Office("Office21ProPlus2021VL_KMS_Client_AE", "Volume:GVLK", 1),
            Office("Office21ProjectPro2021VL_MAK_AE", "Volume:MAK", 1),
            Office("Office21VisioStd2021VL_KMS_Client_AE", "Volume:GVLK", 0),
        };
        var list = KmsDetection.Build(records, Win11Pro, new ClickToRunInfo(["ProPlus2021Volume", "ProjectPro2021Volume", "VisioStd2021Volume"], "16.0.14332.20000"), "", null, Now);
        Assert.Equal(4, list.Count);
        var suite = list.Single(p => p.Family == KmsFamily.Office);
        Assert.Equal("Office LTSC Professional Plus 2021", suite.Name);
        Assert.Equal("2021", suite.Version);
        Assert.Equal(KmsAction.Activate, Kms.Plan(suite).Action);
        var project = list.Single(p => p.Family == KmsFamily.Project);
        Assert.Equal(LicenseChannel.VolumeMak, project.Channel);
        Assert.Equal("FTNWT-C6WBT-8HMGF-K9PRX-QV9H8", project.Key?.Key);
        Assert.Equal(KmsAction.InstallKey, Kms.Plan(project).Action);
        var visio = list.Single(p => p.Family == KmsFamily.Visio);
        Assert.Equal(ActivationState.Unlicensed, visio.State);
    }

    [Fact]
    public void Microsoft_365_apps_are_subscription_and_never_converted()
    {
        var list = KmsDetection.Build([Os("Retail")], Win11Pro, new ClickToRunInfo(["O365ProPlusRetail", "VisioProRetail"], "16.0.19127.20000"), "", null, Now);
        var m365 = Assert.Single(list, p => p.Channel == LicenseChannel.Subscription);
        Assert.Equal("Microsoft 365 Apps for enterprise", m365.Name);
        Assert.Equal(ActivationState.Unknown, m365.State);
        Assert.Equal(KmsAction.None, Kms.Plan(m365).Action);
        // a subscription licensing record is used instead of the Click-to-Run entry, and never offered a key
        var sub = KmsDetection.Build([Os("Retail"), Office("Office16O365ProPlusR_Subscription1", "Retail")], Win11Pro, new ClickToRunInfo(["O365ProPlusRetail"], "16.0"), "", null, Now);
        Assert.Equal(2, sub.Count);
        Assert.Equal(KmsAction.None, Kms.Plan(sub[1]).Action);
    }

    [Fact]
    public void Retail_office_cannot_be_converted()
    {
        var p = KmsDetection.Build([Os("Retail"), Office("Office21ProPlus2021R_Retail", "Retail")], Win11Pro, null, "", null, Now)[1];
        Assert.Null(p.Key);
        var plan = Kms.Plan(p);
        Assert.Equal(KmsAction.None, plan.Action);
        Assert.Contains("volume-licensed Office", plan.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void No_office_installation_gives_only_windows() => Assert.Single(KmsDetection.Build([Os("Retail")], Win11Pro, null, "", null, Now));
}

public class KmsRulesTests
{
    private static KmsProduct Pro(LicenseChannel c, ActivationState s = ActivationState.Licensed) => new()
    {
        Family = KmsFamily.Windows, Name = "Windows 11 Pro", Edition = "Professional", Channel = c, State = s, ProductId = Guid.NewGuid().ToString(),
        Key = KmsCatalog.MatchWindows("Professional", 26100, false, "Windows 10 Pro"), PartialKey = "T83GX",
    };

    [Fact]
    public void Plans_are_conservative()
    {
        Assert.Equal(KmsAction.Activate, Kms.Plan(Pro(LicenseChannel.VolumeKmsClient)).Action);
        var retail = Kms.Plan(Pro(LicenseChannel.Retail));
        Assert.Equal(KmsAction.InstallKey, retail.Action);
        Assert.True(retail.NeedsEntitlement && retail.ReplacesKey);
        Assert.True(Kms.Plan(Pro(LicenseChannel.VolumeMak)).NeedsEntitlement);
        Assert.Equal(KmsAction.None, Kms.Plan(Pro(LicenseChannel.VolumeKmsHost)).Action);
        Assert.Equal(KmsAction.None, Kms.Plan(Pro(LicenseChannel.Unknown)).Action);
        Assert.Equal("No matching KMS key.", Kms.Plan(Pro(LicenseChannel.Retail) with { Key = null }).Reason);
    }

    [Fact]
    public void Steps_follow_the_plan()
    {
        var p = Pro(LicenseChannel.Retail);
        var steps = Kms.Steps(p, Kms.Plan(p), "kms.corp.test", 1688, activate: true);
        Assert.Equal([KmsStepKind.InstallKey, KmsStepKind.SetHost, KmsStepKind.Activate], steps.Select(s => s.Kind));
        Assert.Equal("W269N-WFGWX-YVC9B-4J6C9-T83GX", steps[0].Key);
        Assert.Equal([KmsStepKind.InstallKey], Kms.Steps(p, Kms.Plan(p), "", 1688, activate: false).Select(s => s.Kind));
        Assert.Empty(Kms.Steps(p with { Key = null }, Kms.Plan(p with { Key = null }), "kms", 1688, true));
    }

    [Theory]
    [InlineData("kms.corp.example.com", 1688, null)]
    [InlineData("192.0.2.10", 1688, null)]
    [InlineData("kms01", 65535, null)]
    [InlineData("2001:db8::1", 1688, "IPv6")]
    [InlineData("kms corp", 1688, "not a valid")]
    [InlineData("kms.corp.test", 0, "Port")]
    [InlineData("kms.corp.test", 70000, "Port")]
    [InlineData("", 1688, "enter a host")]
    public void Server_validation(string host, int port, string? error)
    {
        var e = Kms.ValidateServer(host, port, false);
        if (error is null) Assert.Null(e);
        else Assert.Contains(error, e, StringComparison.Ordinal);
    }

    [Fact]
    public void Requests_accept_only_catalog_keys_valid_hosts_and_guids()
    {
        var id = Guid.NewGuid().ToString();
        KmsRequest R(params KmsStep[] s) => new() { ApplicationId = Kms.WindowsApplicationId, Steps = s };
        Assert.Null(Kms.ValidateRequest(R(new KmsStep { Kind = KmsStepKind.InstallKey, ProductId = id, Key = "W269N-WFGWX-YVC9B-4J6C9-T83GX" })));
        Assert.NotNull(Kms.ValidateRequest(R(new KmsStep { Kind = KmsStepKind.InstallKey, ProductId = id, Key = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE" })));
        Assert.NotNull(Kms.ValidateRequest(R(new KmsStep { Kind = KmsStepKind.SetHost, ProductId = id, Host = "a b", Port = 1688 })));
        Assert.NotNull(Kms.ValidateRequest(R(new KmsStep { Kind = KmsStepKind.Activate, ProductId = "x' OR 1=1" })));
        Assert.NotNull(Kms.ValidateRequest(R()));
        Assert.NotNull(Kms.ValidateRequest(new KmsRequest { ApplicationId = "other", Steps = [new KmsStep { Kind = KmsStepKind.Activate, ProductId = id }] }));
    }

    [Fact]
    public void Success_is_reported_only_from_the_licence_read_afterwards()
    {
        var ok = new KmsApplyResult { Steps = [new() { Kind = KmsStepKind.Activate, Succeeded = true, Code = 0 }] };
        Assert.Equal(KmsOutcome.Activated, Kms.Verify(ok, Pro(LicenseChannel.VolumeKmsClient), true));
        Assert.Equal(KmsOutcome.NotVerified, Kms.Verify(ok, Pro(LicenseChannel.VolumeKmsClient, ActivationState.Grace), true)); // exit code fine, licence not
        Assert.Equal(KmsOutcome.NotVerified, Kms.Verify(ok, Pro(LicenseChannel.Retail), true));
        Assert.Equal(KmsOutcome.NotVerified, Kms.Verify(ok, null, true));
        Assert.Equal(KmsOutcome.KeyInstalled, Kms.Verify(ok, Pro(LicenseChannel.VolumeKmsClient, ActivationState.Grace), false));
        var failed = new KmsApplyResult { Steps = [new() { Kind = KmsStepKind.Activate, Succeeded = false, Code = 0xC004F074 }] };
        Assert.Equal(KmsOutcome.Failed, Kms.Verify(failed, Pro(LicenseChannel.VolumeKmsClient), true));
        Assert.Equal(KmsOutcome.NotRun, Kms.Verify(new KmsApplyResult { Error = "Administrator access declined. Nothing was changed." }, Pro(LicenseChannel.Retail), true));
        Assert.Contains("contacted", Kms.ErrorText(0xC004F074), StringComparison.Ordinal);
        Assert.Equal("0xC004F038", Kms.Code(0xC004F038));
    }

    [Fact]
    public void Reports_show_only_the_partial_key()
    {
        var p = Pro(LicenseChannel.VolumeKmsClient);
        var attempt = new Kms.ReportAttempt("Activate", KmsOutcome.Failed, [new() { Kind = KmsStepKind.Activate, Code = 0xC004F074, Message = Kms.ErrorText(0xC004F074) }]);
        foreach (var text in new[] { Kms.Report("PC01", DateTimeOffset.Now, p, attempt), Kms.ReportJson("PC01", DateTimeOffset.Now, p, attempt) })
        {
            Assert.DoesNotContain("W269N-WFGWX", text, StringComparison.Ordinal);
            Assert.Contains("T83GX", text, StringComparison.Ordinal);
            Assert.Contains("0xC004F074", text, StringComparison.Ordinal);
            Assert.Contains("PC01", text, StringComparison.Ordinal);
        }

        using var doc = System.Text.Json.JsonDocument.Parse(Kms.ReportJson("PC01", DateTimeOffset.Now, p, null));
        Assert.Equal("Volume KMS", doc.RootElement.GetProperty("channel").GetString());
    }

    [Fact]
    public void Srv_answers_are_parsed_and_ordered()
    {
        var hosts = Kms.ParseSrv(["10 50 1688 kms2.corp.test.", "0 100 1688 kms1.corp.test.", "bad", "0 0 0 zero.corp.test."], "corp.test");
        Assert.Equal(["kms1.corp.test", "kms2.corp.test"], hosts.Select(h => h.Host));
        Assert.Equal(1688, hosts[0].Port);
    }

    [Fact]
    public void Profiles_upsert_rename_and_delete()
    {
        IReadOnlyList<KmsProfile> list = [new() { Name = "Production KMS", Server = "kms.corp.test" }];
        list = Kms.Upsert(list, new KmsProfile { Name = "production kms", Server = "kms2.corp.test", Port = 1700 }); // same name, any case: replaced
        Assert.Equal("kms2.corp.test", Assert.Single(list).Server);
        list = Kms.Upsert(list, new KmsProfile { Name = "Lab", Server = "192.0.2.5" });
        Assert.Null(Kms.Rename(list, "Lab", "PRODUCTION KMS", out var error));
        Assert.Contains("already exists", error, StringComparison.Ordinal);
        list = Kms.Rename(list, "Lab", "Lab KMS", out error)!;
        Assert.Null(error);
        Assert.Contains(list, p => p.Name == "Lab KMS");
        Assert.Single(Kms.Delete(list, "Lab KMS"));
    }

    [Fact]
    public async Task Profiles_persist_in_the_settings_file()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-kms-").FullName;
        try
        {
            var store = new IPMaster.Infrastructure.Configuration.SettingsStore(dir);
            var profile = new KmsProfile { Name = "Production KMS", Server = "kms.corp.test", Port = 1688, Description = "HQ" };
            await store.SaveAsync(new IPMaster.Core.Configuration.AppSettings { Tools = new ToolSettings { KmsProfiles = [profile] } });
            Assert.Equal(profile, Assert.Single(store.Load().Settings.Tools.KmsProfiles));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task Tcp_test_reports_connection_and_refusal_without_claiming_kms()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var ok = await KmsNetwork.TestAsync("127.0.0.1", port, TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        Assert.True(ok.Connected);
        Assert.Contains("does not prove", ok.Text, StringComparison.Ordinal);
        listener.Stop();
        var refused = await KmsNetwork.TestAsync("127.0.0.1", port, TimeSpan.FromSeconds(3), TestContext.Current.CancellationToken);
        Assert.False(refused.Connected);
        Assert.Contains("Connection failed", refused.Text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_requests_never_reach_the_licensing_service()
    {
        var r = await new WindowsKmsService().ApplyAsync(new KmsRequest { ApplicationId = Kms.WindowsApplicationId, Steps = [new KmsStep { Kind = KmsStepKind.InstallKey, ProductId = Guid.NewGuid().ToString(), Key = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE" }] },
            TestContext.Current.CancellationToken);
        Assert.Empty(r.Steps);
        Assert.NotEmpty(r.Error);
    }

    [Fact]
    public void Helper_refuses_unexpected_files() => Assert.Equal(2, KmsHelper.Run(Path.Combine(Path.GetTempPath(), "not-a-request.json")));
}

[Collection("Headless UI")]
public class KmsWindowTests
{
    /// <summary>Synthetic products (tests only): long names, several Office products, nothing touches the real licence.</summary>
    private sealed class FakeKms : IKmsService
    {
        public int Applied;

        public bool IsSupported => true;

        public Task<KmsDetectionResult> DetectAsync(CancellationToken ct) => Task.FromResult(new KmsDetectionResult(
            KmsDetection.Build(
            [
                new LicenseRecord { Id = Guid.NewGuid().ToString(), ApplicationId = Kms.WindowsApplicationId, LicenseFamily = "Professional", ProductKeyChannel = "Retail", LicenseStatus = 1, PartialKey = "ABCDE" },
                new LicenseRecord { Id = Guid.NewGuid().ToString(), ApplicationId = Kms.OfficeApplicationId, LicenseFamily = "Office24ProPlus2024VL_KMS_Client_AE", ProductKeyChannel = "Volume:GVLK", LicenseStatus = 2, GraceMinutes = 3000 },
                new LicenseRecord { Id = Guid.NewGuid().ToString(), ApplicationId = Kms.OfficeApplicationId, LicenseFamily = "Office24ProjectPro2024VL_MAK_AE", ProductKeyChannel = "Volume:MAK", LicenseStatus = 1 },
                new LicenseRecord { Id = Guid.NewGuid().ToString(), ApplicationId = Kms.OfficeApplicationId, LicenseFamily = "Office24VisioPro2024VL_KMS_Client_AE", ProductKeyChannel = "Volume:GVLK", LicenseStatus = 0 },
            ],
            new WindowsInfo("Professional", "Windows 10 Pro for a very long product name that must not push the other columns away", 26100, "24H2", "Client", "X64"),
            new ClickToRunInfo(["O365ProPlusRetail"], "16.0.19127.20000"), "", null, DateTimeOffset.Now), ""));

        public Task<KmsApplyResult> ApplyAsync(KmsRequest request, CancellationToken ct)
        {
            Applied++;
            return Task.FromResult(new KmsApplyResult());
        }
    }

    [Fact]
    public Task Opening_detects_read_only_and_renders_in_both_themes() => HeadlessUi.RunAsync(async () =>
    {
        foreach (var variant in new[] { Avalonia.Styling.ThemeVariant.Light, Avalonia.Styling.ThemeVariant.Dark })
        {
            HeadlessUi.SetTheme(variant);
            var fake = new FakeKms();
            var w = new KmsManagerWindow(HeadlessUi.Vm, fake);
            try
            {
                w.Show();
                for (var i = 0; i < 100 && w.Rows.Count == 0; i++)
                {
                    UiDesignSystemTests.Dispatch();
                    await Task.Delay(20, TestContext.Current.CancellationToken);
                }

                UiDesignSystemTests.Dispatch();
                Assert.Equal(5, w.Rows.Count); // Windows, Office, Project, Visio, Microsoft 365 Apps
                Assert.Equal(0, fake.Applied); // opening never changes anything
                HeadlessUi.Snapshot(w, $"KMS with products - {variant}");
                w.Width = w.MinWidth;
                w.Height = w.MinHeight;
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(w, $"KMS with products - {variant} - minimum size");
                UiDesignSystemTests.AssertNoActionCutOff(w, "KMS Activation Manager");
            }
            finally
            {
                w.Close();
            }
        }

        HeadlessUi.SetTheme(Avalonia.Styling.ThemeVariant.Default);
    });
}
