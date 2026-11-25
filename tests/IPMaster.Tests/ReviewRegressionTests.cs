using System.Numerics;
using IPMaster.Infrastructure.Tools;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Tests;

/// <summary>Regression tests for defects found in the 2026-11-17 project review.</summary>
public class ReviewRegressionTests
{
    // R-01: switching family must keep a prefix the user typed, not overwrite it with the family default.
    [Theory]
    [InlineData(0, "2001:db8::1/48", 1, "2001:db8::/48")]
    [InlineData(1, "10.0.0.1/16", 0, "10.0.0.0/16")]
    public void Switching_family_keeps_typed_prefix(int from, string text, int to, string expected)
    {
        using var vm = new IpCalculatorViewModel { FamilyIndex = from, AddressText = text };
        Assert.Null(vm.Result); // wrong family reported first
        vm.FamilyIndex = to;
        Assert.Equal(text, vm.AddressText);
        Assert.Equal(expected, vm.Result!.Block.ToString());
    }

    // R-02: re-clicking the example that is already in the box after a family switch must recalculate cleanly.
    [Fact]
    public void Same_example_after_family_switch_recalculates()
    {
        using var vm = new IpCalculatorViewModel();
        vm.UseExample("192.168.10.25/24");
        vm.FamilyIndex = 1;
        vm.UseExample("192.168.10.25/24");
        Assert.True(vm.IsV4);
        Assert.Equal(24, vm.Prefix);
        Assert.Equal("255.255.255.0", vm.MaskText);
        Assert.Equal("", vm.Validation);
        Assert.Equal("192.168.10.0/24", vm.Result!.Block.ToString());
    }

    // R-03 / R-06: bracketed forms with a port, or around IPv4, are not addresses.
    [Theory]
    [InlineData("[::1]:80")]
    [InlineData("[::1]:99999")]
    [InlineData("[1.2.3.4]")]
    [InlineData("[::1")]
    public void Bracket_and_port_forms_are_rejected(string text)
    {
        Assert.False(IpCalculator.TryParseAddress(text, out _, out var error));
        Assert.NotEmpty(error);
    }

    [Fact]
    public void Bracketed_ipv6_without_port_is_still_accepted()
    {
        Assert.True(IpCalculator.TryParseAddress("[2001:db8::1]", out var a, out var error), error);
        Assert.Equal("2001:db8::1", a.ToString());
    }

    // R-04: approximations never show a mantissa of 10.
    [Theory]
    [InlineData("1000000000000000", "≈ 1 × 10^15")]
    [InlineData("99990000000000", "≈ 1 × 10^14")]
    [InlineData("1000000000000", "≈ 1 × 10^12")]
    public void Readable_count_normalises_mantissa(string n, string expected)
        => Assert.Equal(expected, IpText.Readable(BigInteger.Parse(n, System.Globalization.CultureInfo.InvariantCulture)));

    // R-05: a zone ID containing '-' must not be read as a range separator.
    [Fact]
    public void Zone_with_dash_is_not_a_range()
    {
        Assert.True(IpCalculator.TryCompare("fe80::1%eth-0", "fe80::/64", out var r, out var error), error);
        Assert.Equal(SubnetRelation.BContainsA, r.Relation);
    }

    // R-07: "address /prefix" with a space is understood.
    [Fact]
    public void Space_before_prefix_is_accepted()
    {
        Assert.True(IpCalculator.TryParseInput("10.0.0.1 /24", IpFamily.IPv4, out _, out var p, out var error), error);
        Assert.Equal(24, p);
    }

    // R-10: the CSV comment line is a single cell so spreadsheets do not split it.
    [Fact]
    public async Task Csv_comment_line_is_one_cell()
    {
        Assert.True(IpCalculator.TryParseNetwork("0.0.0.0/0", null, out var parent, out _, out _));
        var w = new StringWriter();
        await new SubnetSplit(parent, 30).WriteCsvAsync(w, 0, 2, "test", TestContext.Current.CancellationToken);
        var rows = FriendlyNameMap.ParseCsv(w.ToString());
        Assert.Single(rows[0]);
        Assert.StartsWith("# IPMaster subnet export", rows[0][0], StringComparison.Ordinal);
        Assert.Equal("Index", rows[1][0]);
    }

    // R-11: clearing the prefix box restores the prefix in use instead of leaving it blank.
    [Fact]
    public void Cleared_prefix_box_shows_prefix_in_use()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "10.0.0.1/24" };
        vm.PrefixNumber = null;
        Assert.Equal(24m, vm.PrefixNumber);
    }

    // R-14: entries present in the current IANA special-purpose registries.
    [Theory]
    [InlineData("2001:1::3", "DNS-SD Service Registration Protocol Anycast", true)]
    [InlineData("192.88.99.2", "6a44-relay anycast address", false)]
    [InlineData("100:0:0:1::5", "Dummy IPv6 Prefix", false)]
    public void Registry_includes_current_iana_entries(string address, string name, bool global)
    {
        Assert.True(IpCalculator.TryParseAddress(address, out var a, out _));
        var c = IpSpecialRanges.Classify(a.Value, a.IsV6);
        Assert.Equal(name, c.Name);
        Assert.Equal(global, c.GloballyReachable);
    }

    // R-15: an export path the OS rejects reports a failure instead of crashing the window.
    [Fact]
    public async Task Export_to_invalid_path_reports_failure()
    {
        using var vm = new IpCalculatorViewModel { AddressText = "10.0.0.1/24" };
        await vm.ExportSummaryAsync("bad\0name.txt", json: false);
        Assert.StartsWith("Export failed", vm.Status, StringComparison.Ordinal);
    }
}

/// <summary>SMTP Client Tester regressions from the 2026-11-17 review (S-xx).</summary>
public class SmtpReviewRegressionTests
{
    private static readonly SmtpMessageTemplate Msg = new()
    {
        From = "Lab Sender <sender@lab.test>", To = "a@lab.test", Subject = "review", Body = "body",
    };

    private static SmtpProfile Conn(SmtpFixture f) => new()
    {
        Name = "fixture", Server = "127.0.0.1", Port = f.Port, Security = SmtpConnectionSecurity.None,
        ConnectTimeoutSeconds = 5, OperationTimeoutSeconds = 10, ValidateCertificate = false,
    };

    private static async Task<SmtpTestReport> RunAsync(SmtpTestRequest request)
        => await new SmtpClientTester().RunAsync(request, _ => { }, TestContext.Current.CancellationToken);

    // S-01: a duplicated envelope recipient (de-duplicated inside MailKit) must not defeat "abort before DATA".
    [Fact]
    public async Task Duplicate_envelope_recipient_still_aborts_before_data()
    {
        await using var f = new SmtpFixture();
        f.RejectRecipients.Add("bad@lab.test");
        var r = await RunAsync(new SmtpTestRequest
        {
            Operation = SmtpOperation.Send, Connection = Conn(f),
            Message = Msg with { EnvelopeRecipients = "a@lab.test; bad@lab.test; A@lab.test" },
        });
        Assert.False(f.DataSeen);
        Assert.False(r.DataSent);
        Assert.Equal(StageOutcome.Failed, r.Stages.Single(s => s.Stage == SmtpStage.Submission).Outcome);
    }

    // S-05: the window log stays bounded across many runs; the oldest lines go first and the cut is marked.
    [Fact]
    public void Window_log_is_bounded()
    {
        var log = new System.Text.StringBuilder();
        for (var i = 0; i < 5000; i++) SmtpText.AppendBounded(log, $"line {i:D5} " + new string('x', 90), 100_000);
        Assert.True(log.Length <= 100_000);
        var text = log.ToString();
        Assert.StartsWith(SmtpText.LogTrimmedMarker, text, StringComparison.Ordinal);
        Assert.Contains("line 04999", text, StringComparison.Ordinal);
        Assert.DoesNotContain("line 00000", text, StringComparison.Ordinal);
    }

    // S-06: "552 5.2.2" is a full mailbox (quota), not a message-size limit.
    [Fact]
    public void Mailbox_full_is_not_explained_as_size_limit()
    {
        var text = SmtpText.ExplainReply(SmtpStage.Recipients, 552, "5.2.2 Mailbox full");
        Assert.NotNull(text);
        Assert.Contains("mailbox is full", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("size limit", text, StringComparison.OrdinalIgnoreCase);
    }

    // S-07: the request record's generated ToString() must never print the password.
    [Fact]
    public void Request_tostring_hides_password()
    {
        var r = new SmtpTestRequest { Operation = SmtpOperation.Connection, Connection = new SmtpProfile { Name = "x" }, Password = "Sup3r-S3cret!" };
        Assert.DoesNotContain("Sup3r-S3cret!", r.ToString(), StringComparison.Ordinal);
    }

    // S-02: an unexpected exception type (here from DNS for an over-long name) is a failed stage, not an app crash.
    [Fact]
    public async Task Unexpected_exception_becomes_failed_stage()
    {
        var host = string.Join(".", Enumerable.Repeat("abcdefghij", 26)) + ".test"; // 290 characters, valid labels
        var r = await RunAsync(new SmtpTestRequest
        {
            Operation = SmtpOperation.Connection,
            Connection = new SmtpProfile { Name = "x", Server = host, Port = 25, Security = SmtpConnectionSecurity.None, ConnectTimeoutSeconds = 2, OperationTimeoutSeconds = 2 },
            Message = Msg,
        });
        Assert.Contains(r.Stages, s => s.Outcome == StageOutcome.Failed);
    }
}

/// <summary>Settings and scan-engine regressions from the 2026-11-17 review (C-xx).</summary>
public class CoreReviewRegressionTests
{
    // C-07: text reported by a device (host name, share name, banners) can never add batch lines or commands.
    [Fact]
    public void Batch_file_neutralises_device_supplied_text()
    {
        var evil = Samples.Device("10.0.0.3", "pc3\r\ndel /q C:\\x & calc %PATH% ^ | > o.txt \"q");
        var bat = IPMaster.Core.Management.BatchFile.Generate("echo [Host Name]", [evil], IPMaster.Core.Results.ColumnCatalog.All, IPMaster.Core.Results.ColumnFormat.Default);
        var lines = bat.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        Assert.Equal(3, lines.Length); // @echo off, rem, one echo line
        var line = lines[2];
        Assert.StartsWith("echo pc3", line, StringComparison.Ordinal);
        Assert.DoesNotContain("&", line, StringComparison.Ordinal);
        Assert.DoesNotContain("|", line, StringComparison.Ordinal);
        Assert.DoesNotContain(">", line, StringComparison.Ordinal);
        Assert.DoesNotContain("\"", line, StringComparison.Ordinal);
        Assert.Contains("%%PATH%%", line, StringComparison.Ordinal);
    }

    // C-07: launch commands (applications, background-event launches) get device text without quotes, operators or line breaks.
    [Fact]
    public void Application_launch_neutralises_device_supplied_host_name()
    {
        var cmd = IPMaster.Core.Management.CommandTemplate.Expand("app.exe \"%1\"", "10.0.0.3", "pc\" & calc \"x\r\n", "", new Dictionary<string, string>(), []);
        Assert.Equal("app.exe \"pc_ _ calc _x  \"", cmd);
    }

    [Fact]
    public void Background_launch_neutralises_device_supplied_text()
    {
        var device = Samples.Device("10.0.0.3", "pc3\" & calc");
        var e = new IPMaster.Core.Monitoring.BackgroundEvent(IPMaster.Core.Monitoring.BackgroundEventType.Join, DateTimeOffset.UnixEpoch, device.Key, null, "joined", device);
        var cmd = IPMaster.Core.Monitoring.OfflineClearer.Expand("notify.exe \"[Host Name]\"", e, IPMaster.Core.Results.ColumnCatalog.All, IPMaster.Core.Results.ColumnFormat.Default);
        Assert.Equal("notify.exe \"pc3_ _ calc\"", cmd);
    }

    // C-08: an SSH host presenting a key of a different algorithm than the one trusted is "Changed", not "Unknown".
    [Fact]
    public void Known_host_with_other_algorithm_is_changed()
    {
        var store = new IPMaster.Infrastructure.Queries.KnownHostStore();
        store.Load([new IPMaster.Core.Queries.KnownHostKey { Host = "198.51.100.77", Port = 2222, Algorithm = "ssh-ed25519", Fingerprint = "AAAA" }]);
        Assert.Equal(IPMaster.Infrastructure.Queries.KnownHostStore.Verdict.Changed, store.Check("198.51.100.77", 2222, "ssh-rsa", "BBBB"));
        Assert.Equal(IPMaster.Infrastructure.Queries.KnownHostStore.Verdict.Unknown, store.Check("198.51.100.78", 2222, "ssh-rsa", "BBBB"));
    }

    // C-09: an iteration count read from a file is bounded, so a crafted file cannot hang the unlock or import.
    [Fact]
    public void Credential_import_rejects_absurd_iteration_count()
    {
        var vault = new IPMaster.Infrastructure.Security.CredentialVault();
        var crafted = System.Text.Encoding.UTF8.GetBytes(
            "{\"format\":\"ipmaster-credentials\",\"iterations\":2000000000,\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\",\"data\":\"AAAA\"}");
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.Throws<FormatException>(() => vault.Import(crafted, "x"));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(5), $"took {sw.Elapsed}");
    }

    // C-03: a probe that failed locally (exception, saturated ARP queue) is not evidence that the device is offline.
    [Fact]
    public async Task Local_probe_failure_is_not_offline()
    {
        var icmp = new FakeIcmp { Override = _ => new IPMaster.Core.Scanning.ProbeReply(IPMaster.Core.Scanning.ObservationState.Failed, Detail: "PingException: no resources") };
        var engine = new IPMaster.Core.Scanning.ScanEngine(icmp, new FakeArp(), new FakeDns());
        var sink = new ListSink();
        using var session = engine.Start(new IPMaster.Core.Scanning.ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.5"),
            Settings = new IPMaster.Core.Scanning.ScanSettings { MaxConcurrency = 4, PingTimeoutMs = 50, PingAttempts = 2, DisplayInactiveDevices = true, DeviceDeadlineSeconds = 0 },
        }, sink);
        await session.Completion.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        var d = sink.Get("10.0.0.5");
        Assert.NotEqual(IPMaster.Core.Scanning.DeviceStatus.Offline, d.Status);
        Assert.Equal(IPMaster.Core.Scanning.DeviceStatus.Unsupported, d.Status);
    }

    [Fact]
    public void Rounds_without_an_answer_either_way_do_not_count_as_misses()
    {
        var detector = new IPMaster.Core.Monitoring.ChangeDetector(leaveAfterMisses: 2);
        var online = Samples.Device("10.0.0.5", "pc5");
        var at = DateTimeOffset.UnixEpoch;
        detector.ApplyRound([online], _ => true, complete: true, at);
        var failed = online with { Status = IPMaster.Core.Scanning.DeviceStatus.Unsupported };
        for (var i = 0; i < 4; i++)
        {
            var events = detector.ApplyRound([failed], _ => true, complete: true, at);
            Assert.DoesNotContain(events, e => e.Type == IPMaster.Core.Monitoring.BackgroundEventType.Leave);
        }

        var offline = online with { Status = IPMaster.Core.Scanning.DeviceStatus.Offline };
        detector.ApplyRound([offline], _ => true, complete: true, at);
        Assert.Contains(detector.ApplyRound([offline], _ => true, complete: true, at), e => e.Type == IPMaster.Core.Monitoring.BackgroundEventType.Leave);
    }

    // C-04: a background round reports the plan it really scanned (New mode excludes known devices), so history does
    // not record "offline" for addresses that were deliberately not scanned.
    [Fact]
    public async Task Background_round_carries_the_scanned_plan()
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        var engine = new IPMaster.Core.Scanning.ScanEngine(icmp, new FakeArp(), new FakeDns());
        var settings = new IPMaster.Core.Scanning.ScanSettings { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false, DeviceDeadlineSeconds = 0 };
        var excluded = new HashSet<IPMaster.Core.Targets.AddressKey> { IPMaster.Core.Targets.AddressKey.From(System.Net.IPAddress.Parse("10.0.0.2")) };
        var plan = TestPlans.Plan(new IPMaster.Core.Targets.PlanOptions { Exclude = excluded }, "10.0.0.1-10.0.0.4");
        using var scanner = new IPMaster.Core.Monitoring.BackgroundScanner(engine, (_, _, _) => Task.FromResult<IPMaster.Core.Scanning.ScanRequest?>(new IPMaster.Core.Scanning.ScanRequest { Plan = plan, Settings = settings }))
        {
            Settings = new IPMaster.Core.Monitoring.BackgroundSettings { RoundDelayMinutes = 0 },
        };
        var first = new TaskCompletionSource<IPMaster.Core.Monitoring.BackgroundRound>();
        scanner.RoundCompleted += (_, r) => first.TrySetResult(r);
        scanner.Start();
        var round = await first.Task.WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        await scanner.StopAsync();
        Assert.NotNull(round.Plan);
        Assert.False(round.Plan!.Contains(excluded.Single()));
        Assert.True(round.Plan.Contains(IPMaster.Core.Targets.AddressKey.From(System.Net.IPAddress.Parse("10.0.0.3"))));
    }

    // C-05: in continuous operation an unanswered round keeps what is known about the device (Clear Offline decides
    // later what to drop), and the LEAVE event names the device as it was last seen.
    [Fact]
    public void Background_merge_keeps_known_fields_for_unanswered_rounds()
    {
        var online = Samples.Device("10.0.0.5", "pc5");
        var offline = Samples.Device("10.0.0.5", "pc5") with
        {
            Status = IPMaster.Core.Scanning.DeviceStatus.Offline,
            HostName = IPMaster.Core.Scanning.Observation<IPMaster.Core.Scanning.HostNameInfo>.Of(IPMaster.Core.Scanning.ObservationState.NotRequested, DateTimeOffset.UnixEpoch),
            LastScanned = DateTimeOffset.UnixEpoch.AddHours(1),
        };
        var merged = IPMaster.Core.Scanning.DeviceResult.MergeBackground(online, offline);
        Assert.Equal(IPMaster.Core.Scanning.DeviceStatus.Offline, merged.Status);
        Assert.Equal("pc5", merged.HostName.Value!.Name);
        Assert.Equal(offline.LastScanned, merged.LastScanned);
        Assert.Equal(IPMaster.Core.Scanning.DeviceStatus.Online, IPMaster.Core.Scanning.DeviceResult.MergeBackground(offline, online).Status);
    }

    [Fact]
    public void Leave_event_names_the_device_as_last_seen()
    {
        var detector = new IPMaster.Core.Monitoring.ChangeDetector(leaveAfterMisses: 1);
        var online = Samples.Device("10.0.0.5", "pc5");
        detector.ApplyRound([online], _ => true, complete: true, DateTimeOffset.UnixEpoch);
        var bare = online with
        {
            Status = IPMaster.Core.Scanning.DeviceStatus.Offline,
            HostName = IPMaster.Core.Scanning.Observation<IPMaster.Core.Scanning.HostNameInfo>.Of(IPMaster.Core.Scanning.ObservationState.NotRequested, DateTimeOffset.UnixEpoch),
        };
        var leave = Assert.Single(detector.ApplyRound([bare], _ => true, complete: true, DateTimeOffset.UnixEpoch), e => e.Type == IPMaster.Core.Monitoring.BackgroundEventType.Leave);
        Assert.Contains("pc5", leave.Message, StringComparison.Ordinal);
        Assert.Equal("pc5", leave.Device!.HostName.Value!.Name);
    }

    // C-02: rows published while their enrichment item was waiting for space in the full queue must not stay Pending after Stop.
    [Fact]
    public async Task Stop_with_full_enrichment_queue_leaves_no_pending_rows()
    {
        var icmp = new FakeIcmp { Override = _ => new IPMaster.Core.Scanning.ProbeReply(IPMaster.Core.Scanning.ObservationState.Success, TimeSpan.Zero, 64) };
        var dns = new FakeDns { Delay = TimeSpan.FromSeconds(60) };
        var engine = new IPMaster.Core.Scanning.ScanEngine(icmp, new FakeArp(), dns);
        var sink = new ListSink();
        using var session = engine.Start(new IPMaster.Core.Scanning.ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.0/18"),
            Settings = new IPMaster.Core.Scanning.ScanSettings { MaxConcurrency = 64, PingTimeoutMs = 50, PingAttempts = 1, DnsTimeoutMs = 60_000, DnsConcurrency = 1, DeviceDeadlineSeconds = 0 },
        }, sink);
        var until = DateTime.UtcNow.AddSeconds(30);
        while (sink.Count < 4096 + 64 && DateTime.UtcNow < until) await Task.Delay(20, TestContext.Current.CancellationToken);
        await Task.Delay(200, TestContext.Current.CancellationToken); // liveness workers are now blocked writing to the full queue
        session.Stop();
        await session.Completion.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        var pending = sink.Latest.Values.Count(d => !d.IsComplete);
        Assert.Equal(0, pending);
    }

    // C-01: a window without the master key must not overwrite a configuration another window has encrypted.
    [Fact]
    public async Task Shared_save_never_replaces_encrypted_configuration_with_plaintext()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-review-mpass-").FullName;
        try
        {
            var a = new IPMaster.Infrastructure.Configuration.SettingsStore(dir);
            var b = new IPMaster.Infrastructure.Configuration.SettingsStore(dir);
            var sa = a.Load().Settings;
            await a.SaveAsync(sa);
            sa = a.Load().Settings;
            var sb = b.Load().Settings;
            await b.SaveSharedAsync(b.Vault.SetMasterPassword(sb, "pw-123456", 100_000));
            var path = Path.Combine(dir, IPMaster.Infrastructure.Configuration.SettingsStore.FileName);
            var encrypted = await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken);

            await Assert.ThrowsAsync<InvalidOperationException>(() => a.SaveSharedAsync(sa with { AutoLoadSaveRecent = true }, TestContext.Current.CancellationToken));
            Assert.Equal(encrypted, await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken));
            Assert.Equal(IPMaster.Infrastructure.Configuration.SettingsLoadStatus.PasswordRequired, new IPMaster.Infrastructure.Configuration.SettingsStore(dir).Load().Status);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
