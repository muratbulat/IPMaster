using System.Net;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;

namespace IPMaster.Tests;

/// <summary>Regression tests for the "Remaining" items of the project review, fixed on 2026-11-17.</summary>
public class RemainingReviewTests
{
    // C-06: background rounds wait in a bounded queue: while one is processed (e.g. slow notifications) at most one more
    // waits; older waiting rounds are dropped and reported, never queued without limit.
    // C-05b: the results grid keeps what it knows when a background round finds the device offline, whatever merge mode
    // the last interactive scan used.
    [Fact]
    public void Grid_background_update_keeps_known_fields()
    {
        var view = new IPMaster.Desktop.ViewModels.ResultsView { Columns = [IPMaster.Core.Results.ColumnCatalog.IpAddress, IPMaster.Core.Results.ColumnCatalog.HostName] };
        var online = Samples.Device("10.0.0.5", "pc5") with { Revision = 1 };
        view.Upsert(online, mergeRescan: false);
        var offline = online with
        {
            Status = DeviceStatus.Offline,
            Revision = 2,
            HostName = Observation<HostNameInfo>.Of(ObservationState.NotRequested, DateTimeOffset.UnixEpoch),
        };
        view.Upsert(offline, mergeRescan: false, background: true);
        var row = view.Find(online.Key)!.Result;
        Assert.Equal(DeviceStatus.Offline, row.Status);
        Assert.Equal("pc5", row.HostName.Value!.Name);
    }

    [Fact]
    public async Task Round_processor_is_bounded_and_reports_dropped_rounds()
    {
        var release = new TaskCompletionSource();
        var processed = new List<int>();
        var dropped = new List<int>();
        var queue = new RoundProcessor<int>(async (item, ct) =>
        {
            if (item == 1) await release.Task.WaitAsync(ct);
            lock (processed) processed.Add(item);
        }, d => { lock (dropped) dropped.Add(d); });

        queue.Post(1);
        await Task.Delay(100, TestContext.Current.CancellationToken); // 1 is now being processed and blocks
        for (var i = 2; i <= 10; i++) queue.Post(i);
        Assert.Equal([2, 3, 4, 5, 6, 7, 8, 9], dropped);
        release.SetResult();
        await queue.StopAsync(cancelRunning: false);
        Assert.Equal([1, 10], processed);
    }

    [Fact]
    public async Task Round_processor_reports_a_handler_fault_and_keeps_processing()
    {
        var processed = new List<int>();
        var faults = new List<(int, string)>();
        var queue = new RoundProcessor<int>((item, _) =>
        {
            if (item == 1) throw new InvalidOperationException("disk full");
            lock (processed) processed.Add(item);
            return Task.CompletedTask;
        }, _ => { }, capacity: 4, failed: (i, ex) => { lock (faults) faults.Add((i, ex.Message)); });
        queue.Post(1);
        queue.Post(2);
        await queue.StopAsync(cancelRunning: false).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Equal([(1, "disk full")], faults); // D-086: reported at once, not only at the next Stop
        Assert.Equal([2], processed);
    }

    [Fact]
    public async Task Essential_round_queue_keeps_every_waiting_round()
    {
        var release = new TaskCompletionSource();
        var processed = new List<int>();
        var dropped = new List<int>();
        var queue = new RoundProcessor<int>(async (item, ct) =>
        {
            if (item == 1) await release.Task.WaitAsync(ct);
            lock (processed) processed.Add(item);
        }, d => { lock (dropped) dropped.Add(d); }, capacity: 16);
        queue.Post(1);
        await Task.Delay(100, TestContext.Current.CancellationToken);
        for (var i = 2; i <= 10; i++) queue.Post(i);
        release.SetResult();
        await queue.StopAsync(cancelRunning: false).WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        Assert.Empty(dropped);
        Assert.Equal(Enumerable.Range(1, 10), processed);
    }

    [Fact]
    public async Task Round_processor_stop_cancels_the_running_handler()
    {
        var started = new TaskCompletionSource();
        var queue = new RoundProcessor<int>(async (_, ct) =>
        {
            started.SetResult();
            await Task.Delay(Timeout.Infinite, ct);
        }, _ => { });
        queue.Post(1);
        await started.Task.WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        await queue.StopAsync().WaitAsync(TimeSpan.FromSeconds(10), TestContext.Current.CancellationToken);
        queue.Post(2); // after stop: ignored, no exception
    }
}

/// <summary>C-10: local socket errors during port scans are not "filtered" ports of the device.</summary>
public class PortScanLocalFailureTests
{
    private sealed class FailingTcp(params int[] open) : ITcpPortProbe
    {
        public Task<PortResult> ProbeAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken cancellationToken)
            => Task.FromResult(open.Contains(port)
                ? new PortResult(PortProtocol.Tcp, port, PortState.Open)
                : new PortResult(PortProtocol.Tcp, port, PortState.Failed, Detail: "NoBufferSpaceAvailable"));
    }

    private static async Task<DeviceResult> ScanAsync(ITcpPortProbe tcp)
    {
        var icmp = new FakeIcmp();
        icmp.Alive.Add("10.0.0.1");
        var engine = new ScanEngine(new ScanProbes(icmp, new FakeArp(), new FakeDns()) { Tcp = tcp });
        var sink = new ListSink();
        using var session = engine.Start(new ScanRequest
        {
            Plan = TestPlans.Plan("10.0.0.1"),
            Settings = new ScanSettings { PingTimeoutMs = 50, PingAttempts = 1, ResolveHostNames = false, DeviceDeadlineSeconds = 0, ScanTcpPorts = true, TcpPorts = "20-25, 80" },
        }, sink);
        await session.Completion.WaitAsync(TimeSpan.FromSeconds(30), TestContext.Current.CancellationToken);
        return sink.Get("10.0.0.1");
    }

    [Fact]
    public async Task All_ports_failing_locally_is_a_failed_observation()
    {
        var d = await ScanAsync(new FailingTcp());
        Assert.Equal(ObservationState.Failed, d.TcpPorts.State);
        Assert.Contains("NoBufferSpaceAvailable", d.TcpPorts.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Partial_local_failures_are_counted_separately()
    {
        var d = await ScanAsync(new FailingTcp(22));
        Assert.Equal(ObservationState.Success, d.TcpPorts.State);
        Assert.Contains("6 could not be probed", d.TcpPorts.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("filtered", d.TcpPorts.Detail!.Replace("0 filtered", "", StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(System.Net.Sockets.SocketError.NoBufferSpaceAvailable, PortState.Failed)]
    [InlineData(System.Net.Sockets.SocketError.AddressAlreadyInUse, PortState.Failed)]
    [InlineData(System.Net.Sockets.SocketError.AccessDenied, PortState.Failed)]
    [InlineData(System.Net.Sockets.SocketError.HostUnreachable, PortState.Filtered)]
    [InlineData(System.Net.Sockets.SocketError.NetworkUnreachable, PortState.Filtered)]
    [InlineData(System.Net.Sockets.SocketError.TimedOut, PortState.Filtered)]
    [InlineData(System.Net.Sockets.SocketError.ConnectionRefused, PortState.Closed)]
    public void Socket_errors_are_classified(System.Net.Sockets.SocketError error, PortState expected)
        => Assert.Equal(expected, IPMaster.Infrastructure.Probes.TcpPortProbe.Classify(error));
}

/// <summary>C-11 / C-16: external tools are bounded in time and output.</summary>
public class ExternalToolBoundsTests
{
    private static readonly string Ps = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

    // C-11: a neighbour-table tool that hangs yields "no output" after its time limit; it does not throw out of the device.
    [Fact]
    public async Task Hanging_neighbour_tool_returns_empty_without_throwing()
    {
        if (!OperatingSystem.IsWindows()) return;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var text = await IPMaster.Infrastructure.Network.NeighborTable.RunToolAsync(Ps, ["-NoProfile", "-Command", "Start-Sleep 30"], TestContext.Current.CancellationToken);
        Assert.Equal("", text);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15), $"took {sw.Elapsed}");
    }

    // C-16: one endless line without a newline is cut at the output bound instead of being buffered without limit.
    [Fact]
    public async Task Single_huge_line_is_truncated_at_the_bound()
    {
        if (!OperatingSystem.IsWindows()) return;
        var r = await IPMaster.Infrastructure.Queries.ProcessRunner.RunAsync(Ps,
                ["-NoProfile", "-Command", "1..3200 | ForEach-Object { [Console]::Out.Write('x' * 65536) }; Start-Sleep 600"],
                TestContext.Current.CancellationToken, maxOutput: 1024 * 1024)
            .WaitAsync(TimeSpan.FromSeconds(60), TestContext.Current.CancellationToken);
        Assert.True(r.Truncated);
        Assert.True(r.Output.Length <= 1024 * 1024);
    }
}

/// <summary>C-12: Python detection is cached process-wide, including "not found", so it is not repeated per window or device.</summary>
public class PythonDetectionCacheTests
{
    [Fact]
    public async Task Failed_detection_is_cached_across_provider_instances()
    {
        if (!OperatingSystem.IsWindows()) return;
        var dir = Directory.CreateTempSubdirectory("ipm-fakepy-").FullName;
        try
        {
            var fake = Path.Combine(dir, "python.cmd");
            await File.WriteAllTextAsync(fake, "@ping -n 4 127.0.0.1 >nul\r\n", TestContext.Current.CancellationToken);
            var first = new IPMaster.Infrastructure.Queries.PythonQueryProvider(() => fake);
            Assert.Null((await first.DetectAsync(TestContext.Current.CancellationToken)).Version);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var second = new IPMaster.Infrastructure.Queries.PythonQueryProvider(() => fake);
            Assert.Null((await second.DetectAsync(TestContext.Current.CancellationToken)).Version);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(1), $"second detection took {sw.Elapsed}");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}

/// <summary>C-13: the history database carries a schema version; a newer one is not modified.</summary>
public class HistorySchemaVersionTests
{
    private static long UserVersion(string path)
    {
        using var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={path};Pooling=False");
        c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "PRAGMA user_version;";
        return (long)cmd.ExecuteScalar()!;
    }

    [Fact]
    public void Version_1_database_is_migrated_and_keeps_its_history()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-hist-").FullName;
        try
        {
            var net = new IPMaster.Core.Monitoring.NetworkIdentity("gateway-mac:AA", "Lab") { Gateway = "gateway:10.0.0.254" };
            var dev = Samples.Device("10.0.0.1") with
            {
                Status = DeviceStatus.Online,
                Mac = Observation<System.Net.NetworkInformation.PhysicalAddress>.Ok(System.Net.NetworkInformation.PhysicalAddress.Parse("00-00-00-00-00-01"), DateTimeOffset.UtcNow),
            };
            new IPMaster.Infrastructure.Monitoring.HistoryStore(dir).RecordSession(net, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, true, [dev], _ => true);
            using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path.Combine(dir, "ipmaster.history.db")};Pooling=False"))
            {
                c.Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "DROP TABLE network_gateways; PRAGMA user_version = 1;"; // what IPMaster 0.6.x wrote
                cmd.ExecuteNonQuery();
            }

            var store = new IPMaster.Infrastructure.Monitoring.HistoryStore(dir);
            Assert.Single(store.Devices(net));
            Assert.Equal(2, UserVersion(store.Path));
            store.RecordSession(net, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, true, [dev], _ => true); // the new table is there
            Assert.Equal(2, store.Devices(net).Single().Value.Eligible);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void New_database_is_stamped_and_newer_schema_is_refused()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-hist-").FullName;
        try
        {
            var store = new IPMaster.Infrastructure.Monitoring.HistoryStore(dir);
            store.Cleanup(30, DateTimeOffset.UtcNow);
            Assert.Equal(IPMaster.Infrastructure.Monitoring.HistoryStore.SchemaVersion, UserVersion(store.Path));

            using (var c = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={store.Path};Pooling=False"))
            {
                c.Open();
                using var cmd = c.CreateCommand();
                cmd.CommandText = "PRAGMA user_version = 99;";
                cmd.ExecuteNonQuery();
            }

            var newer = new IPMaster.Infrastructure.Monitoring.HistoryStore(dir);
            var ex = Assert.Throws<InvalidOperationException>(() => newer.Cleanup(30, DateTimeOffset.UtcNow));
            Assert.Contains("newer", ex.Message, StringComparison.Ordinal);
            Assert.Equal(99, UserVersion(store.Path));
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            Directory.Delete(dir, recursive: true);
        }
    }
}

/// <summary>C-14: SNMP probe and router-MIB communities are stored like other secrets (vault-protected), revealed only for scanning.</summary>
public class ScanSecretsTests
{
    [Fact]
    public void Communities_are_protected_for_storage_and_revealed_for_scans()
    {
        var vault = new IPMaster.Infrastructure.Security.CredentialVault();
        vault.SetMasterPassword(new IPMaster.Core.Configuration.AppSettings(), "pw-123456", 100_000);
        var plain = new ScanSettings { SnmpProbeCommunity = "s3cret-probe", RouterMibCommunity = "s3cret-router" };

        var stored = IPMaster.Infrastructure.Security.ScanSecrets.Protect(plain, vault);
        Assert.DoesNotContain("s3cret", stored.SnmpProbeCommunity, StringComparison.Ordinal);
        Assert.DoesNotContain("s3cret", stored.RouterMibCommunity, StringComparison.Ordinal);
        Assert.Equal(stored, IPMaster.Infrastructure.Security.ScanSecrets.Protect(stored, vault)); // idempotent

        var forScan = IPMaster.Infrastructure.Security.ScanSecrets.Reveal(stored, vault);
        Assert.Equal("s3cret-probe", forScan.SnmpProbeCommunity);
        Assert.Equal("s3cret-router", forScan.RouterMibCommunity);
        Assert.Equal("public", IPMaster.Infrastructure.Security.ScanSecrets.Reveal(new ScanSettings(), vault).SnmpProbeCommunity); // legacy plaintext
    }

    [Fact]
    public void Without_a_vault_key_communities_stay_usable()
    {
        var vault = new IPMaster.Infrastructure.Security.CredentialVault();
        var plain = new ScanSettings { SnmpProbeCommunity = "x" };
        Assert.Equal("x", IPMaster.Infrastructure.Security.ScanSecrets.Protect(plain, vault).SnmpProbeCommunity);
    }
}

/// <summary>C-18: Nmap "additional parameters" are checked against an allow-list (block-lists miss -datadir, prefixes, extra targets).</summary>
public class NmapArgumentAllowListTests
{
    private static IReadOnlyList<string> Args(string extra) => IPMaster.Infrastructure.Queries.NmapQueryProvider.Arguments(
        new IPMaster.Core.Queries.NmapOptions { ScanType = IPMaster.Core.Queries.NmapScanType.OsDetection },
        new IPMaster.Core.Queries.NmapSettings { ExtraArguments = extra }, IPAddress.Parse("10.0.0.7"));

    [Theory]
    [InlineData("-T4 --max-retries 1")]
    [InlineData("-sS -Pn --top-ports 100 --host-timeout 30s")]
    [InlineData("--min-rate=200 -n --reason --open")]
    public void Allowed_performance_and_discovery_options(string extra)
    {
        var args = Args(extra);
        Assert.Equal("10.0.0.7", args[^1]);
    }

    [Theory]
    [InlineData("-datadir /tmp/x")]
    [InlineData("-oN out.txt")]
    [InlineData("--stylesheet=evil.xsl")]
    [InlineData("--script-args-file /etc/shadow")]
    [InlineData("--resu x")]
    [InlineData("10.0.0.0/8")]
    [InlineData("-T4 10.0.0.0/8")]
    [InlineData("--privileged")]
    public void Everything_else_is_rejected(string extra)
        => Assert.Throws<ArgumentException>(() => Args(extra));
}

/// <summary>C-19: host-name targets are resolved concurrently (bounded), not one after another.</summary>
public class HostTargetResolutionTests
{
    [Fact]
    public async Task Host_names_resolve_concurrently_and_keep_order_and_errors()
    {
        var specs = Enumerable.Range(1, 20).Select(i =>
        {
            Assert.True(TargetParser.TryParse($"host{i:D2}.lab.test", out var s, out _));
            return s;
        }).ToList();
        var active = 0;
        var peak = 0;
        async Task<IPAddress?> Resolve(string name, CancellationToken ct)
        {
            var now = Interlocked.Increment(ref active);
            int p;
            while (now > (p = Volatile.Read(ref peak)) && Interlocked.CompareExchange(ref peak, now, p) != p) { }
            await Task.Delay(200, ct);
            Interlocked.Decrement(ref active);
            return name == "host07.lab.test" ? null : IPAddress.Parse("10.0.0." + int.Parse(name.AsSpan(4, 2), System.Globalization.CultureInfo.InvariantCulture));
        }

        var sw = System.Diagnostics.Stopwatch.StartNew();
        var r = await TargetPlanBuilder.BuildAsync(specs, new PlanOptions { Confirmed = true }, Resolve, TestContext.Current.CancellationToken);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2), $"took {sw.Elapsed}");
        Assert.InRange(peak, 2, 16);
        Assert.Contains("Host name 'host07.lab.test' could not be resolved.", r.Errors);
        Assert.Equal(19UL, r.Plan.CountExact(TestContext.Current.CancellationToken));
    }
}

/// <summary>S-09 / S-10: SMTP tester polish and the missing fixture scenarios.</summary>
public class SmtpRemainingTests
{
    private static readonly IPMaster.Core.Tools.SmtpMessageTemplate Msg = new() { From = "Lab <sender@lab.test>", To = "a@lab.test", Subject = "x", Body = "y" };

    private static IPMaster.Core.Tools.SmtpProfile Conn(SmtpFixture f, IPMaster.Core.Tools.SmtpConnectionSecurity sec = IPMaster.Core.Tools.SmtpConnectionSecurity.None,
        IPMaster.Core.Tools.SmtpAuthMode auth = IPMaster.Core.Tools.SmtpAuthMode.None, string mechanism = "Auto") => new()
        {
            Name = "f", Server = "127.0.0.1", Port = f.Port, Security = sec, ConnectTimeoutSeconds = 5, OperationTimeoutSeconds = 10,
            ValidateCertificate = false, AuthMode = auth, UserName = f.User, Mechanism = mechanism, AllowPlaintextAuth = true,
        };

    private static async Task<(IPMaster.Core.Tools.SmtpTestReport Report, List<IPMaster.Core.Tools.SmtpLogEntry> Log)> RunAsync(IPMaster.Infrastructure.Tools.SmtpTestRequest r, CancellationToken ct)
    {
        var log = new List<IPMaster.Core.Tools.SmtpLogEntry>();
        var report = await new IPMaster.Infrastructure.Tools.SmtpClientTester().RunAsync(r, e => { lock (log) log.Add(e); }, ct);
        return (report, log);
    }

    private static IPMaster.Core.Tools.StageResult Stage(IPMaster.Core.Tools.SmtpTestReport r, IPMaster.Core.Tools.SmtpStage s) => r.Stages.Single(x => x.Stage == s);

    [Fact]
    public async Task Refused_starttls_is_a_tls_failure_not_a_greeting_failure()
    {
        await using var f = new SmtpFixture(SmtpFixture.Kind.StartTls) { RefuseStartTls = true };
        var (r, _) = await RunAsync(new() { Operation = IPMaster.Core.Tools.SmtpOperation.Connection, Connection = Conn(f, IPMaster.Core.Tools.SmtpConnectionSecurity.StartTlsRequired) }, TestContext.Current.CancellationToken);
        Assert.Equal(IPMaster.Core.Tools.StageOutcome.Success, Stage(r, IPMaster.Core.Tools.SmtpStage.Greeting).Outcome);
        var tls = Stage(r, IPMaster.Core.Tools.SmtpStage.Tls);
        Assert.Equal(IPMaster.Core.Tools.StageOutcome.Failed, tls.Outcome);
        Assert.Contains("STARTTLS", tls.Explanation, StringComparison.Ordinal);
        Assert.DoesNotContain(f.Commands, c => c.StartsWith("MAIL", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Server_closing_with_421_is_reported_not_thrown()
    {
        await using var f = new SmtpFixture { Reply421OnMail = true };
        var (r, _) = await RunAsync(new() { Operation = IPMaster.Core.Tools.SmtpOperation.Recipients, Connection = Conn(f), Message = Msg }, TestContext.Current.CancellationToken);
        var rcpt = Stage(r, IPMaster.Core.Tools.SmtpStage.Recipients);
        Assert.Equal(IPMaster.Core.Tools.StageOutcome.Failed, rcpt.Outcome);
        Assert.False(f.DataSeen);
    }

    [Fact]
    public async Task Cancel_during_authentication_is_a_clean_cancellation()
    {
        await using var f = new SmtpFixture { StallAuth = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.CancelAfter(TimeSpan.FromMilliseconds(800));
        var (r, _) = await RunAsync(new()
        {
            Operation = IPMaster.Core.Tools.SmtpOperation.Connection, Connection = Conn(f, auth: IPMaster.Core.Tools.SmtpAuthMode.UsernamePassword, mechanism: "PLAIN"),
            Password = f.Password,
        }, cts.Token);
        Assert.Equal(IPMaster.Core.Tools.StageOutcome.Cancelled, Stage(r, IPMaster.Core.Tools.SmtpStage.Authentication).Outcome);
    }

    [Fact]
    public async Task Cram_md5_exchange_never_logs_the_response()
    {
        await using var f = new SmtpFixture { OfferCramMd5 = true };
        var (r, log) = await RunAsync(new()
        {
            Operation = IPMaster.Core.Tools.SmtpOperation.Connection, Connection = Conn(f, auth: IPMaster.Core.Tools.SmtpAuthMode.UsernamePassword, mechanism: "CRAM-MD5"),
            Password = f.Password,
        }, TestContext.Current.CancellationToken);
        Assert.Equal(IPMaster.Core.Tools.StageOutcome.Success, Stage(r, IPMaster.Core.Tools.SmtpStage.Authentication).Outcome);
        var response = f.Commands.Last(c => !c.Contains(' ', StringComparison.Ordinal) && c.Length > 20); // the base64 CRAM response line
        var text = string.Join("\n", log.Select(e => e.Text));
        Assert.DoesNotContain(response, text, StringComparison.Ordinal);
        Assert.DoesNotContain(f.Password, text, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Failed_rset_keeps_the_sender_rejection_explanation()
    {
        await using var f = new SmtpFixture { RejectSender = true, CloseAfterSenderReject = true };
        var (r, _) = await RunAsync(new() { Operation = IPMaster.Core.Tools.SmtpOperation.Recipients, Connection = Conn(f), Message = Msg }, TestContext.Current.CancellationToken);
        var rcpt = Stage(r, IPMaster.Core.Tools.SmtpStage.Recipients);
        Assert.Equal(IPMaster.Core.Tools.StageOutcome.Failed, rcpt.Outcome);
        Assert.Contains("553", rcpt.Summary + " " + rcpt.ServerResponse, StringComparison.Ordinal);
    }

    [Fact]
    public void Logger_decodes_utf8_split_across_buffers_and_flags_binary()
    {
        var log = new List<IPMaster.Core.Tools.SmtpLogEntry>();
        var l = new IPMaster.Infrastructure.Tools.SmtpSessionLogger(log.Add);
        var bytes = System.Text.Encoding.UTF8.GetBytes("250 Grüße\r\n");
        var cut = Array.IndexOf(bytes, (byte)0xC3) + 1; // inside "ü"
        l.LogServer(bytes, 0, cut);
        l.LogServer(bytes, cut, bytes.Length - cut);
        Assert.Contains(log, e => e.Text.Contains("Grüße", StringComparison.Ordinal));
        Assert.False(l.ReceivedBinary);
        l.LogServer([0x16, 0x03, 0x01, 0x00, 0x2a, 0x02], 0, 6);
        Assert.True(l.ReceivedBinary);
    }

    [Fact]
    public void Revocation_problems_get_their_own_hint()
    {
        var hint = IPMaster.Infrastructure.Tools.SmtpClientTester.ChainHint(["RevocationStatusUnknown: The revocation function was unable to check revocation for the certificate."]);
        Assert.Contains("revocation", hint, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("offline", hint, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Envelope_recipients_override_bcc_with_a_visible_note()
    {
        var notes = IPMaster.Infrastructure.Tools.SmtpMessages.EnvelopeNotes(Msg with { Bcc = "audit@lab.test", EnvelopeRecipients = "a@lab.test" });
        Assert.Contains(notes, n => n.Contains("Bcc", StringComparison.Ordinal));
        Assert.Empty(IPMaster.Infrastructure.Tools.SmtpMessages.EnvelopeNotes(Msg with { Bcc = "audit@lab.test" }));
    }
}

/// <summary>R-16: prefix lengths follow the same no-leading-zero rule as IPv4 octets.</summary>
public class PrefixLeadingZeroTests
{
    [Theory]
    [InlineData("10.0.0.1/024")]
    [InlineData("2001:db8::1/064")]
    public void Leading_zero_prefix_is_rejected_with_hint(string text)
    {
        Assert.False(IPMaster.Core.Tools.IpCalculator.TryParseInput(text, null, out _, out _, out var error));
        Assert.Contains("leading zero", error, StringComparison.Ordinal);
    }

    [Fact]
    public void Zero_prefix_is_still_valid()
    {
        Assert.True(IPMaster.Core.Tools.IpCalculator.TryParseInput("10.0.0.1/0", null, out _, out var p, out var error), error);
        Assert.Equal(0, p);
    }
}
