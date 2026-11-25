using IPMaster.Core.Tools;
using IPMaster.Desktop.Views;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Group Policy Viewer (D-107). Synthetic RSoP XML only; nothing changes policy (no gpupdate, no registry writes).</summary>
public class GroupPolicyParserTests
{
    // shaped like gpresult /x output: Rsop namespace, typed extension data in its own namespace
    internal const string Computer = """
        <?xml version="1.0" encoding="utf-16"?>
        <Rsop xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
          <ReadTime>2026-11-26T08:00:00.0000000Z</ReadTime>
          <DataType>LoggedOnUser</DataType>
          <ComputerResults>
            <Name>CONTOSO\PC01$</Name>
            <Domain>contoso.test</Domain>
            <Site>HQ</Site>
            <SlowLink>false</SlowLink>
            <ExtensionStatus><Name>Group Policy Infrastructure</Name><Identifier>{00000000-0000-0000-0000-000000000000}</Identifier>
              <BeginTime>2026-11-26T06:10:00</BeginTime><EndTime>2026-11-26T06:10:05</EndTime><Error>0</Error></ExtensionStatus>
            <GPO><Name>Default Domain Policy</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier><Domain xmlns="http://www.microsoft.com/GroupPolicy/Types">contoso.test</Domain></Path>
              <VersionDirectory>12</VersionDirectory><VersionSysvol>12</VersionSysvol><Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied>
              <Link><SOMPath>contoso.test</SOMPath><AppliedOrder>2</AppliedOrder><Enabled>true</Enabled></Link><ExtensionName>Registry</ExtensionName><ExtensionName>Security</ExtensionName></GPO>
            <GPO><Name>Security Baseline</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{AAAA0000-0000-0000-0000-000000000001}</Identifier></Path>
              <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied>
              <Link><SOMPath>contoso.test/Workstations</SOMPath><AppliedOrder>1</AppliedOrder><Enabled>true</Enabled></Link><ExtensionName>Registry</ExtensionName></GPO>
            <GPO><Name>Legacy Printer Policy for the very long organizational unit name of the old printing department</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{AAAA0000-0000-0000-0000-000000000002}</Identifier></Path>
              <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>true</AccessDenied>
              <Link><SOMPath>contoso.test/Printers</SOMPath><AppliedOrder>0</AppliedOrder><Enabled>true</Enabled></Link></GPO>
            <GPO><Name>Laptops Only</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{AAAA0000-0000-0000-0000-000000000003}</Identifier></Path>
              <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>false</FilterAllowed><FilterName>Is Laptop</FilterName><AccessDenied>false</AccessDenied>
              <Link><SOMPath>contoso.test</SOMPath><AppliedOrder>0</AppliedOrder><Enabled>true</Enabled></Link></GPO>
            <GPO><Name>Local Group Policy</Name><Path><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">LocalGPO</Identifier></Path>
              <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied>
              <Link><SOMPath>Local</SOMPath><AppliedOrder>0</AppliedOrder><Enabled>true</Enabled></Link></GPO>
            <ExtensionData><Extension xmlns:q1="http://www.microsoft.com/GroupPolicy/Settings/Registry" xsi:type="q1:RegistrySettings" xmlns="http://www.microsoft.com/GroupPolicy/Settings">
                <q1:Policy><GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{AAAA0000-0000-0000-0000-000000000001}</Identifier></GPO>
                  <Precedence xmlns="http://www.microsoft.com/GroupPolicy/Settings">1</Precedence><q1:Name>Turn off Autoplay</q1:Name><q1:State>Enabled</q1:State><q1:Category>Windows Components/AutoPlay Policies</q1:Category></q1:Policy>
                <q1:Policy><GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier></GPO>
                  <Precedence xmlns="http://www.microsoft.com/GroupPolicy/Settings">2</Precedence><q1:Name>Turn off Autoplay</q1:Name><q1:State>Disabled</q1:State><q1:Category>Windows Components/AutoPlay Policies</q1:Category></q1:Policy>
                <q1:RegistrySetting><GPO xmlns="http://www.microsoft.com/GroupPolicy/Settings"><Identifier xmlns="http://www.microsoft.com/GroupPolicy/Types">{31B2F340-016D-11D2-945F-00C04FB984F9}</Identifier></GPO>
                  <Precedence xmlns="http://www.microsoft.com/GroupPolicy/Settings">1</Precedence><q1:KeyPath>Software\Policies\Contoso</q1:KeyPath><q1:Value><q1:Name>Mode</q1:Name></q1:Value></q1:RegistrySetting>
              </Extension><Name>Registry</Name></ExtensionData>
          </ComputerResults>
        </Rsop>
        """;

    internal const string User = """
        <?xml version="1.0" encoding="utf-16"?>
        <Rsop xmlns="http://www.microsoft.com/GroupPolicy/Rsop">
          <ReadTime>2026-11-26T08:00:01Z</ReadTime>
          <UserResults>
            <Name>CONTOSO\alice</Name><Domain>contoso.test</Domain>
            <GPO><Name>Desktop Restrictions</Name><Path><Identifier>{BBBB0000-0000-0000-0000-000000000001}</Identifier></Path>
              <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied>
              <Link><SOMPath>contoso.test/Users</SOMPath><AppliedOrder>1</AppliedOrder><Enabled>true</Enabled></Link><ExtensionName>Registry</ExtensionName></GPO>
            <GPO><Name>Old Link</Name><Path><Identifier>{BBBB0000-0000-0000-0000-000000000002}</Identifier></Path>
              <Enabled>true</Enabled><IsValid>true</IsValid><FilterAllowed>true</FilterAllowed><AccessDenied>false</AccessDenied>
              <Link><SOMPath>contoso.test/Users</SOMPath><AppliedOrder>0</AppliedOrder><Enabled>false</Enabled></Link><ExtensionName>Registry</ExtensionName></GPO>
            <GPO><Name>Partial Entry</Name><Enabled>true</Enabled></GPO>
          </UserResults>
        </Rsop>
        """;

    [Fact]
    public void Applied_and_filtered_gpos_are_told_apart_with_the_reported_reason()
    {
        var (time, scopes, gpos, _) = GroupPolicy.Parse(Computer);
        Assert.Equal(new DateTimeOffset(2026, 11, 26, 8, 0, 0, TimeSpan.Zero), time);
        var by = gpos.ToDictionary(g => g.Name[..Math.Min(g.Name.Length, 21)]);
        Assert.Equal(GpoState.Applied, by["Default Domain Policy"].State);
        Assert.Equal("{31B2F340-016D-11D2-945F-00C04FB984F9}", by["Default Domain Policy"].Id);
        Assert.Equal("contoso.test", by["Default Domain Policy"].Domain);
        Assert.Equal(["Registry", "Security"], by["Default Domain Policy"].Extensions);
        Assert.Equal(GpoState.Applied, by["Security Baseline"].State);
        Assert.Equal("Denied (Security)", by["Legacy Printer Policy"].Reason);
        Assert.Equal("Denied (WMI Filter): Is Laptop", by["Laptops Only"].Reason);
        Assert.Equal("Not Applied (Empty)", by["Local Group Policy"].Reason);
        Assert.All(gpos, g => Assert.Equal(GpoScope.Computer, g.Scope));
        var s = Assert.Single(scopes);
        Assert.Equal("CONTOSO\\PC01$", s.Account);
        Assert.Equal(new DateTimeOffset(2026, 11, 26, 6, 10, 5, TimeSpan.Zero), s.LastProcessing); // processing time, not the report time
        Assert.Equal(0, s.ProcessingError);
    }

    [Fact]
    public void Only_winning_settings_are_listed_with_their_gpo()
    {
        var (_, _, _, settings) = GroupPolicy.Parse(Computer);
        Assert.Equal(2, settings.Count); // the precedence-2 Autoplay setting lost
        var autoplay = settings.Single(x => x.Name == "Turn off Autoplay");
        Assert.Equal(("Enabled", "Security Baseline", "Windows Components/AutoPlay Policies"), (autoplay.Value, autoplay.WinningGpo, autoplay.Category));
        var reg = settings.Single(x => x.Name.StartsWith("Software", StringComparison.Ordinal));
        Assert.Equal("Default Domain Policy", reg.WinningGpo);
        Assert.Equal("Registry", reg.Category);
    }

    [Fact]
    public void User_scope_disabled_links_and_missing_metadata()
    {
        var (_, scopes, gpos, settings) = GroupPolicy.Parse(User);
        Assert.Equal(GpoScope.User, Assert.Single(scopes).Scope);
        Assert.Null(scopes[0].LastProcessing); // not reported → Unavailable, never the report time
        Assert.Equal("Unavailable", GroupPolicy.Time(scopes[0].LastProcessing));
        Assert.Equal(GpoState.Applied, gpos.Single(g => g.Name == "Desktop Restrictions").State);
        Assert.Equal("Disabled (Link)", gpos.Single(g => g.Name == "Old Link").Reason);
        var partial = gpos.Single(g => g.Name == "Partial Entry");
        Assert.Equal(GpoState.Unknown, partial.State); // never "Applied" without the report saying so
        Assert.Equal("", partial.Id);
        Assert.Empty(settings);
    }

    [Fact]
    public void Mixed_scopes_combine_and_filter()
    {
        var r = GroupPolicy.Combine(DateTimeOffset.Now, GroupPolicy.Parse(Computer), GroupPolicy.Parse(User));
        Assert.Equal(2, r.Scopes.Count);
        Assert.Equal(8, r.Gpos.Count);
        Assert.Equal(5, r.Gpos.Count(g => GroupPolicy.Matches(g, GpoScope.Computer, "")));
        Assert.Equal(3, r.Gpos.Count(g => GroupPolicy.Matches(g, GpoScope.User, "")));
        Assert.Equal(["Desktop Restrictions"], r.Gpos.Where(g => GroupPolicy.Matches(g, null, "desktop")).Select(g => g.Name));
        Assert.Single(r.Settings, s => GroupPolicy.Matches(s, "autoplay"));
        var text = GroupPolicy.Summary(r);
        Assert.Contains("Applied   Default Domain Policy", text, StringComparison.Ordinal);
        Assert.Contains("Denied (Security)", text, StringComparison.Ordinal);
        Assert.Contains("Applied: 3", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Empty_results_are_not_an_error()
    {
        var (_, scopes, gpos, _) = GroupPolicy.Parse("<Rsop xmlns=\"http://www.microsoft.com/GroupPolicy/Rsop\"><UserResults><Name>PC01\\bob</Name></UserResults></Rsop>");
        Assert.Single(scopes);
        Assert.Empty(gpos);
    }

    [Theory]
    [InlineData("<Rsop><ComputerResults>")] // truncated
    [InlineData("not xml at all")]
    [InlineData("<Other/>")]
    [InlineData("")]
    public void Malformed_reports_fail_clearly(string xml) => Assert.Throws<GpoReportException>(() => GroupPolicy.Parse(xml));

    [Fact]
    public void External_entities_are_never_resolved()
    {
        const string xxe = "<?xml version=\"1.0\"?><!DOCTYPE Rsop [<!ENTITY x SYSTEM \"file:///c:/windows/win.ini\">]><Rsop><UserResults><Name>&x;</Name></UserResults></Rsop>";
        Assert.Throws<GpoReportException>(() => GroupPolicy.Parse(xxe));
    }

    [Fact]
    public void Status_colours_are_semantic()
    {
        Assert.Equal("success", GroupPolicy.StateClass(GpoState.Applied));
        Assert.Equal("warning", GroupPolicy.StateClass(GpoState.Filtered));
        Assert.Null(GroupPolicy.StateClass(GpoState.Unknown));
    }

    [Fact]
    public async Task Real_collection_is_read_only_and_leaves_no_temporary_reports()
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal("Windows only.", (await new WindowsGroupPolicyService().CollectAsync(TestContext.Current.CancellationToken)).Error);
            return;
        }

        static string[] Temp() => Directory.GetDirectories(Path.GetTempPath(), "ipmaster-gpo-*");
        var before = Temp();
        var r = await new WindowsGroupPolicyService().CollectAsync(TestContext.Current.CancellationToken);
        Assert.True(r.Report is not null || r.Error.Length > 0); // either data or a stated failure, never an empty "success"
        Assert.Equal(before, Temp());
    }

    [Fact]
    public async Task Cancellation_stops_collection()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new WindowsGroupPolicyService().CollectAsync(cts.Token));
        Assert.DoesNotContain(Directory.GetDirectories(Path.GetTempPath(), "ipmaster-gpo-*"), d => Directory.GetLastWriteTimeUtc(d) > DateTime.UtcNow.AddMinutes(-1));
    }
}

internal sealed class FakeGroupPolicy(GpoResult result) : IGroupPolicyService
{
    public int Exports;

    public bool IsSupported => true;

    public Task<GpoResult> CollectAsync(CancellationToken ct) => Task.FromResult(result);

    public Task<string?> ExportNativeAsync(bool html, string path, CancellationToken ct)
    {
        Exports++;
        return Task.FromResult<string?>(null);
    }
}

[Collection("Headless UI")]
public class GroupPolicyWindowTests
{
    private static async Task<GroupPolicyViewerWindow> OpenAsync(GpoResult r)
    {
        var w = new GroupPolicyViewerWindow(new FakeGroupPolicy(r));
        w.Show();
        for (var i = 0; i < 100 && w.Report is null && r.Report is not null; i++)
        {
            UiDesignSystemTests.Dispatch();
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }

        for (var i = 0; i < 5; i++)
        {
            UiDesignSystemTests.Dispatch();
            await Task.Delay(20, TestContext.Current.CancellationToken);
        }

        return w;
    }

    private static string Text(Avalonia.Controls.Window w) =>
        string.Join("\n", Avalonia.VisualTree.VisualExtensions.GetVisualDescendants(w).OfType<Avalonia.Controls.TextBlock>().Select(t => t.Text));

    [Fact]
    public Task Report_renders_in_both_themes() => HeadlessUi.RunAsync(async () =>
    {
        var report = GroupPolicy.Combine(DateTimeOffset.Now, GroupPolicy.Parse(GroupPolicyParserTests.Computer), GroupPolicy.Parse(GroupPolicyParserTests.User));
        foreach (var variant in new[] { Avalonia.Styling.ThemeVariant.Light, Avalonia.Styling.ThemeVariant.Dark })
        {
            HeadlessUi.SetTheme(variant);
            var w = await OpenAsync(new GpoResult(report, ""));
            try
            {
                Assert.Equal(8, w.Rows.Count);
                Assert.Contains("Refresh completed.", Text(w), StringComparison.Ordinal);
                HeadlessUi.Snapshot(w, $"Group Policy Viewer with GPOs - {variant}");
                w.Width = w.MinWidth;
                w.Height = w.MinHeight;
                UiDesignSystemTests.Dispatch();
                HeadlessUi.Snapshot(w, $"Group Policy Viewer with GPOs - {variant} - minimum size");
                UiDesignSystemTests.AssertNoActionCutOff(w, "Group Policy Viewer");
            }
            finally
            {
                w.Close();
            }
        }

        HeadlessUi.SetTheme(Avalonia.Styling.ThemeVariant.Default);
    });

    [Fact]
    public Task Partial_and_failed_reports_are_never_shown_as_empty_success() => HeadlessUi.RunAsync(async () =>
    {
        var user = GroupPolicy.Parse(GroupPolicyParserTests.User);
        var partial = GroupPolicy.Combine(DateTimeOffset.Now, (null, [new GpoScopeInfo { Scope = GpoScope.Computer, Available = false, Message = "Access denied." }], [], []), user);
        var w = await OpenAsync(new GpoResult(partial, ""));
        try
        {
            Assert.Contains("Partial data. Computer: Access denied.", Text(w), StringComparison.Ordinal);
            Assert.Equal(3, w.Rows.Count);
        }
        finally
        {
            w.Close();
        }

        w = await OpenAsync(new GpoResult(null, "Computer: Report failed. User: Report failed."));
        try
        {
            Assert.Empty(w.Rows);
            Assert.Contains("Report failed", Text(w), StringComparison.Ordinal);
            Assert.DoesNotContain("No GPOs reported.", Text(w), StringComparison.Ordinal);
        }
        finally
        {
            w.Close();
        }
    });
}
