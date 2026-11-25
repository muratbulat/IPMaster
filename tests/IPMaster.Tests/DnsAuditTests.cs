using System.Net;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>Bulk DNS Audit (D-094): rules on synthetic lookups, and the runner against loopback DNS fixtures only.</summary>
public class DnsAuditTests
{
    private static DnsLookup L(string server, string name, string type, string status, params string[] values) => new(server, name, type, status, values);

    [Fact]
    public void Forward_confirmed_name_is_ok()
    {
        var e = new DnsAuditEntry("web.lab.test", false,
        [
            L("s1", "web.lab.test", "A", "NOERROR", "192.0.2.10"), L("s1", "web.lab.test", "AAAA", "NOERROR (no data)"),
            L("s1", "192.0.2.10", "PTR", "NOERROR", "web.lab.test"), L("s1", "web.lab.test", "A", "NOERROR", "192.0.2.10"),
        ]);
        var f = DnsAudit.Analyze(e);
        Assert.Contains(f, x => x.Level == AuditLevel.Ok && x.Text.Contains("forward-confirmed", StringComparison.Ordinal));
        Assert.DoesNotContain(f, x => x.Level >= AuditLevel.Warning);
    }

    [Fact]
    public void Missing_and_unconfirmed_ptr_are_warnings_but_shared_names_are_information()
    {
        var missing = DnsAudit.Analyze(new DnsAuditEntry("a.lab.test", false,
            [L("s1", "a.lab.test", "A", "NOERROR", "192.0.2.20"), L("s1", "192.0.2.20", "PTR", "NXDOMAIN")]));
        Assert.Contains(missing, x => x.Level == AuditLevel.Warning && x.Text.StartsWith("No PTR record for 192.0.2.20", StringComparison.Ordinal));

        var shared = DnsAudit.Analyze(new DnsAuditEntry("www.lab.test", false,
        [
            L("s1", "www.lab.test", "A", "NOERROR", "192.0.2.30"), L("s1", "192.0.2.30", "PTR", "NOERROR", "host30.lab.test"),
            L("s1", "host30.lab.test", "A", "NOERROR", "192.0.2.30"),
        ]));
        Assert.Contains(shared, x => x.Level == AuditLevel.Info && x.Text.Contains("normal when several names share", StringComparison.Ordinal));
        Assert.DoesNotContain(shared, x => x.Level >= AuditLevel.Warning); // www → host30 → back: fine

        var wrong = DnsAudit.Analyze(new DnsAuditEntry("192.0.2.40", true,
            [L("s1", "192.0.2.40", "PTR", "NOERROR", "old.lab.test"), L("s1", "old.lab.test", "A", "NOERROR", "192.0.2.99")]));
        Assert.Contains(wrong, x => x.Level == AuditLevel.Warning && x.Text.Contains("not forward-confirmed; it resolves to 192.0.2.99", StringComparison.Ordinal));
    }

    [Fact]
    public void Disagreeing_servers_errors_and_nxdomain_are_classified()
    {
        var split = DnsAudit.Analyze(new DnsAuditEntry("app.lab.test", false,
            [L("s1", "app.lab.test", "A", "NOERROR", "192.0.2.1"), L("s2", "app.lab.test", "A", "NOERROR", "192.0.2.2"), L("s3", "app.lab.test", "A", "TIMEOUT")]));
        Assert.Contains(split, x => x.Level == AuditLevel.Warning && x.Text.StartsWith("Servers disagree", StringComparison.Ordinal) && x.Text.Contains("may be intended", StringComparison.Ordinal));
        Assert.Contains(split, x => x.Level == AuditLevel.Error && x.Text == "s3: TIMEOUT for A app.lab.test.");
        Assert.Contains(split, x => x.Level == AuditLevel.Info && x.Text.Contains("2 addresses", StringComparison.Ordinal));

        var gone = DnsAudit.Analyze(new DnsAuditEntry("gone.lab.test", false, [L("s1", "gone.lab.test", "A", "NXDOMAIN"), L("s1", "gone.lab.test", "AAAA", "NXDOMAIN")]));
        Assert.Equal(AuditLevel.Error, Assert.Single(gone).Level);
    }

    [Fact]
    public void Input_parsing_skips_comments_and_duplicates()
    {
        Assert.Equal(["a.test", "192.0.2.1", "b.test"], DnsAudit.ParseInput("a.test.\n# comment\n192.0.2.1, b.test;a.test"));
    }

    [Fact]
    public async Task Runner_queries_each_server_follows_ptr_and_forward_confirms()
    {
        const ushort A = 1, Ptr = 12;
        DnsFixture Server(string address) => new((id, n, t, _) => (n, t) switch
        {
            ("web.lab.test", A) => DnsFixture.Reply(id, n, t, 0, false, (A, 60, IPAddress.Parse(address).GetAddressBytes())),
            (_, Ptr) when n == DnsWire.PtrName(IPAddress.Parse(address)).TrimEnd('.') => DnsFixture.Reply(id, n, t, 0, false, (Ptr, 60, DnsFixture.Name("web.lab.test."))),
            _ => DnsFixture.Reply(id, n, t, 3, false),
        });
        await using var s1 = Server("192.0.2.10");
        await using var s2 = Server("192.0.2.11"); // split DNS: another address
        var ct = TestContext.Current.CancellationToken;
        var entries = await DnsAuditRunner.RunAsync(["web.lab.test", "192.0.2.10"], [s1.EndPoint, s2.EndPoint],
            new DnsQueryOptions { Timeout = TimeSpan.FromSeconds(2), Retries = 0, Transport = DnsTransport.Udp }, null, ct);
        var web = DnsAudit.Analyze(entries[0]);
        Assert.Contains(web, x => x.Text.StartsWith("Servers disagree", StringComparison.Ordinal));
        Assert.True(web.Count(x => x.Level == AuditLevel.Ok) == 2, // both addresses forward-confirmed on their own server
            string.Join(" | ", entries[0].Lookups.Select(l => $"{l.Server} {l.Type} {l.Name} {l.Status} [{string.Join(",", l.Values)}]")) + " || " + string.Join(" | ", web.Select(x => x.Text)));
        var ip = DnsAudit.Analyze(entries[1]);
        Assert.Contains(ip, x => x.Level == AuditLevel.Ok); // s1: PTR web.lab.test → 192.0.2.10
        Assert.Contains(ip, x => x.Level == AuditLevel.Warning && x.Text.StartsWith("Servers disagree on the PTR of 192.0.2.10", StringComparison.Ordinal)); // s2 has none
    }

    [Fact]
    public async Task Runner_limits_are_enforced()
    {
        var many = Enumerable.Range(0, DnsAuditRunner.MaxEntries + 1).Select(i => $"h{i}.test").ToList();
        await Assert.ThrowsAsync<ArgumentException>(() => DnsAuditRunner.RunAsync(many, [new IPEndPoint(IPAddress.Loopback, 53)], new DnsQueryOptions(), null, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentException>(() => DnsAuditRunner.RunAsync(["a.test"], [], new DnsQueryOptions(), null, CancellationToken.None));
    }
}
