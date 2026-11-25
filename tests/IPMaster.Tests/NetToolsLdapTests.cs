using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Formats.Asn1;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Tests;

/// <summary>
/// Scripted LDAPv3 server on 127.0.0.1 (BER via System.Formats.Asn1). Supports simple bind, search with the paged-results
/// control, unbind; anything else is answered unwillingToPerform. Records what arrives so tests can inspect the wire. Test-only.
/// </summary>
internal sealed class LdapFixture : IAsyncDisposable
{
    private const string PagedOid = "1.2.840.113556.1.4.319";
    private static readonly Asn1Tag Ctx0 = new(TagClass.ContextSpecific, 0, true);

    public sealed record SearchSeen(string Base, int Scope, string Filter, IReadOnlyList<string> Attributes, int? PageSize, string Cookie);

    private readonly TcpListener _l = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    public LdapFixture()
    {
        _l.Start();
        _loop = Task.Run(AcceptLoopAsync);
    }

    public int Port => ((IPEndPoint)_l.LocalEndpoint).Port;

    public Dictionary<string, string> Users { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<(string Dn, Dictionary<string, string[]> Attributes)> Entries { get; } = [];

    public bool Silent { get; init; }

    public ConcurrentQueue<string> Binds { get; } = new();

    public ConcurrentQueue<SearchSeen> Searches { get; } = new();

    public ConcurrentQueue<string> Other { get; } = new();

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient c;
            try
            {
                c = await _l.AcceptTcpClientAsync(_cts.Token);
            }
            catch (Exception ex) when (ex is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _ = Task.Run(() => ServeAsync(c));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var s = client.GetStream();
                while (!_cts.IsCancellationRequested)
                {
                    var message = await ReadElementAsync(s, _cts.Token);
                    if (message is null) return;
                    if (Silent) continue;
                    var reply = Handle(message, out var close);
                    if (reply is not null) await s.WriteAsync(reply, _cts.Token);
                    if (close) return;
                }
            }
            catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException or AsnContentException)
            {
            }
        }
    }

    private byte[]? Handle(byte[] message, out bool close)
    {
        close = false;
        var seq = new AsnReader(message, AsnEncodingRules.BER).ReadSequence();
        var id = (int)seq.ReadInteger();
        var tag = seq.PeekTag();
        if (tag.TagClass == TagClass.Application && tag.TagValue == 2)
        {
            close = true; // unbind
            return null;
        }

        if (tag.TagClass == TagClass.Application && tag.TagValue == 0)
        {
            var bind = seq.ReadSequence(new Asn1Tag(TagClass.Application, 0));
            bind.ReadInteger();
            var name = Encoding.UTF8.GetString(bind.ReadOctetString());
            if (bind.PeekTag().TagValue != 0)
            {
                Binds.Enqueue(name + " (SASL)");
                return Result(id, 1, 7, "SASL is not supported by the fixture");
            }

            var password = Encoding.UTF8.GetString(bind.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0)));
            Binds.Enqueue(name);
            var ok = (name.Length == 0 && password.Length == 0) || (Users.TryGetValue(name, out var expected) && expected == password);
            return Result(id, 1, ok ? 0 : 49, ok ? "" : "80090308: invalid credentials");
        }

        if (tag.TagClass == TagClass.Application && tag.TagValue == 3)
        {
            var search = seq.ReadSequence(new Asn1Tag(TagClass.Application, 3));
            var baseDn = Encoding.UTF8.GetString(search.ReadOctetString());
            var scope = (int)search.ReadEnumeratedBytes().Span[^1];
            search.ReadEnumeratedBytes();
            search.ReadInteger();
            search.ReadInteger();
            search.ReadBoolean();
            var filter = Filter(search.ReadEncodedValue());
            var attrs = new List<string>();
            var al = search.ReadSequence();
            while (al.HasData) attrs.Add(Encoding.UTF8.GetString(al.ReadOctetString()));
            int? pageSize = null;
            var cookie = "";
            if (seq.HasData && seq.PeekTag() == Ctx0)
            {
                var controls = seq.ReadSequence(Ctx0);
                while (controls.HasData)
                {
                    var control = controls.ReadSequence();
                    var oid = Encoding.UTF8.GetString(control.ReadOctetString());
                    if (control.HasData && control.PeekTag() == Asn1Tag.Boolean) control.ReadBoolean();
                    if (oid == PagedOid && control.HasData)
                    {
                        var v = new AsnReader(control.ReadOctetString(), AsnEncodingRules.BER).ReadSequence();
                        pageSize = (int)v.ReadInteger();
                        cookie = Encoding.UTF8.GetString(v.ReadOctetString());
                    }
                }
            }

            Searches.Enqueue(new SearchSeen(baseDn, scope, filter, attrs, pageSize, cookie));
            using var output = new MemoryStream();
            if (baseDn.Length == 0 && scope == 0)
            {
                output.Write(Entry(id, "", new() { ["namingContexts"] = ["DC=lab,DC=test"], ["supportedLDAPVersion"] = ["3"], ["vendorName"] = ["IPMaster test fixture"] }));
                output.Write(Done(id, 0, null));
                return output.ToArray();
            }

            var matching = Entries.Where(e => e.Dn.EndsWith(baseDn, StringComparison.OrdinalIgnoreCase)).ToList();
            var start = cookie.Length > 0 ? int.Parse(cookie, CultureInfo.InvariantCulture) : 0;
            var count = pageSize ?? matching.Count;
            foreach (var (dn, a) in matching.Skip(start).Take(count)) output.Write(Entry(id, dn, a));
            var next = start + count;
            output.Write(Done(id, 0, pageSize is null ? null : next < matching.Count ? next.ToString(CultureInfo.InvariantCulture) : ""));
            return output.ToArray();
        }

        if (tag.TagClass == TagClass.Application && tag.TagValue == 16) return null; // abandon
        Other.Enqueue(tag.ToString());
        var op = tag.TagClass == TagClass.Application && tag.TagValue == 23 ? 24 : 5; // extended → extended response
        return Result(id, op, 53, "unwilling to perform");
    }

    /// <summary>Renders a BER filter back to RFC 4515 text, escaping assertion values (so "a*b" as a value shows as a\2ab).</summary>
    private static string Filter(ReadOnlyMemory<byte> encoded)
    {
        var r = new AsnReader(encoded, AsnEncodingRules.BER);
        var tag = r.PeekTag();
        string V(byte[] b) => Core.Targets.ActiveDirectoryFilters.Escape(Encoding.UTF8.GetString(b));
        switch (tag.TagValue)
        {
            case 0 or 1:
            {
                var set = r.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, tag.TagValue, true));
                var parts = new List<string>();
                while (set.HasData) parts.Add(Filter(set.ReadEncodedValue()));
                return "(" + (tag.TagValue == 0 ? "&" : "|") + string.Concat(parts) + ")";
            }

            case 2:
            {
                var not = r.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true));
                return "(!" + Filter(not.ReadEncodedValue()) + ")";
            }

            case 3 or 5 or 6 or 8:
            {
                var ava = r.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, tag.TagValue, true));
                var attr = Encoding.UTF8.GetString(ava.ReadOctetString());
                var op = tag.TagValue switch { 5 => ">=", 6 => "<=", 8 => "~=", _ => "=" };
                return $"({attr}{op}{V(ava.ReadOctetString())})";
            }

            case 4:
            {
                var sub = r.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 4, true));
                var attr = Encoding.UTF8.GetString(sub.ReadOctetString());
                var parts = sub.ReadSequence();
                var sb = new StringBuilder();
                var first = true;
                while (parts.HasData)
                {
                    var t = parts.PeekTag().TagValue;
                    var value = V(parts.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, t)));
                    if (t != 0 && first) sb.Append('*');
                    sb.Append(value);
                    if (t != 2) sb.Append('*');
                    first = false;
                }

                return $"({attr}={sb})";
            }

            case 7:
                return "(" + Encoding.UTF8.GetString(r.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 7))) + "=*)";
            default:
                return "(?" + tag + ")";
        }
    }

    private static byte[] Result(int id, int op, int code, string message)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(id);
            using (w.PushSequence(new Asn1Tag(TagClass.Application, op, true)))
            {
                w.WriteEnumeratedValue((ResultCode)code);
                w.WriteOctetString([]);
                w.WriteOctetString(Encoding.UTF8.GetBytes(message));
            }
        }

        return w.Encode();
    }

    private static byte[] Entry(int id, string dn, Dictionary<string, string[]> attributes)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(id);
            using (w.PushSequence(new Asn1Tag(TagClass.Application, 4, true)))
            {
                w.WriteOctetString(Encoding.UTF8.GetBytes(dn));
                using (w.PushSequence())
                {
                    foreach (var (name, values) in attributes)
                    {
                        using (w.PushSequence())
                        {
                            w.WriteOctetString(Encoding.UTF8.GetBytes(name));
                            using (w.PushSetOf())
                            {
                                foreach (var v in values) w.WriteOctetString(name.Equals("objectGUID", StringComparison.OrdinalIgnoreCase) ? Guid.Parse(v).ToByteArray() : Encoding.UTF8.GetBytes(v));
                            }
                        }
                    }
                }
            }
        }

        return w.Encode();
    }

    private static byte[] Done(int id, int code, string? cookie)
    {
        var w = new AsnWriter(AsnEncodingRules.BER);
        using (w.PushSequence())
        {
            w.WriteInteger(id);
            using (w.PushSequence(new Asn1Tag(TagClass.Application, 5, true)))
            {
                w.WriteEnumeratedValue((ResultCode)code);
                w.WriteOctetString([]);
                w.WriteOctetString([]);
            }

            if (cookie is not null)
            {
                using (w.PushSequence(Ctx0))
                using (w.PushSequence())
                {
                    w.WriteOctetString(Encoding.UTF8.GetBytes(PagedOid));
                    var v = new AsnWriter(AsnEncodingRules.BER);
                    using (v.PushSequence())
                    {
                        v.WriteInteger(0);
                        v.WriteOctetString(Encoding.UTF8.GetBytes(cookie));
                    }

                    w.WriteOctetString(v.Encode());
                }
            }
        }

        return w.Encode();
    }

    /// <summary>Reads one BER element (definite length) from the stream; null at end of stream.</summary>
    private static async Task<byte[]?> ReadElementAsync(Stream s, CancellationToken ct)
    {
        var head = new byte[2];
        if (await s.ReadAtLeastAsync(head, 2, throwOnEndOfStream: false, ct) < 2) return null;
        var lengthBytes = new List<byte>();
        long length = head[1];
        if ((head[1] & 0x80) != 0)
        {
            var n = head[1] & 0x7F;
            var lb = new byte[n];
            await s.ReadExactlyAsync(lb, ct);
            lengthBytes.AddRange(lb);
            length = 0;
            foreach (var b in lb) length = (length << 8) | b;
        }

        if (length > 1 << 20) throw new IOException("Element too large.");
        var body = new byte[length];
        await s.ReadExactlyAsync(body, ct);
        return [.. head, .. lengthBytes, .. body];
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync();
        _l.Stop();
        await _loop;
    }
}

public class NetToolsLdapTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static LdapFixture Directory(int people)
    {
        var f = new LdapFixture();
        f.Users["CN=reader,DC=lab,DC=test"] = "R3ad-only!";
        for (var i = 0; i < people; i++)
        {
            f.Entries.Add(($"CN=user{i:D2},OU=People,DC=lab,DC=test", new()
            {
                ["cn"] = [$"user{i:D2}"], ["objectGUID"] = ["0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"], ["userPassword"] = ["should-never-show"],
            }));
        }

        return f;
    }

    private static LdapProfile Profile(LdapFixture f, LdapBindKind bind = LdapBindKind.Anonymous, string password = "R3ad-only!", bool allowPlain = false) => new()
    {
        Server = "127.0.0.1", Port = f.Port, Bind = bind, User = bind == LdapBindKind.Simple ? "CN=reader,DC=lab,DC=test" : "", Password = password,
        AllowPlaintextPassword = allowPlain, Timeout = TimeSpan.FromSeconds(5),
    };

    [Fact]
    public async Task Plaintext_simple_bind_is_blocked_before_anything_is_sent()
    {
        await using var f = Directory(1);
        var r = await LdapTester.BindTestAsync(Profile(f, LdapBindKind.Simple), Ct);
        Assert.Equal(LdapOutcome.PlaintextPasswordBlocked, r.Outcome);
        Assert.Empty(f.Binds);
        Assert.Empty(f.Searches);
    }

    [Fact]
    public async Task Simple_bind_with_override_succeeds_and_wrong_password_is_authentication_failure()
    {
        await using var f = Directory(1);
        var ok = await LdapTester.BindTestAsync(Profile(f, LdapBindKind.Simple, allowPlain: true), Ct);
        Assert.Equal(LdapOutcome.Success, ok.Outcome);
        Assert.Contains("CN=reader,DC=lab,DC=test", f.Binds);

        var bad = await LdapTester.BindTestAsync(Profile(f, LdapBindKind.Simple, password: "wrong", allowPlain: true), Ct);
        Assert.Equal(LdapOutcome.AuthenticationFailed, bad.Outcome);
        Assert.DoesNotContain("wrong", LdapTester.Report(bad), StringComparison.Ordinal);
        Assert.DoesNotContain("R3ad-only!", LdapTester.Report(ok), StringComparison.Ordinal);
    }

    [Fact]
    public async Task RootDse_is_read_anonymously()
    {
        await using var f = Directory(0);
        var r = await LdapTester.RootDseAsync(Profile(f), Ct);
        Assert.Equal(LdapOutcome.Success, r.Outcome);
        var dse = Assert.Single(r.Entries);
        Assert.Equal("", dse.Dn);
        Assert.Contains(dse.Attributes, a => a.Name == "namingContexts" && a.Values.Single() == "DC=lab,DC=test");
        var seen = Assert.Single(f.Searches);
        Assert.Equal(0, seen.Scope);
        Assert.Equal("(objectClass=*)", seen.Filter);
    }

    [Fact]
    public async Task Paged_search_follows_cookies_until_done()
    {
        await using var f = Directory(7);
        var r = await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { BaseDn = "OU=People,DC=lab,DC=test", Filter = "(cn=*)", PageSize = 3 }, Ct);
        Assert.Equal(LdapOutcome.Success, r.Outcome);
        Assert.Equal(7, r.Entries.Count);
        Assert.Equal(3, r.Pages);
        Assert.False(r.Truncated);
        var seen = f.Searches.ToList();
        Assert.Equal(["", "3", "6"], seen.Select(s => s.Cookie));
        Assert.All(seen, s => Assert.Equal(3, s.PageSize));
        Assert.Equal("user06", r.Entries[^1].Attributes.Single(a => a.Name == "cn").Values.Single());
    }

    [Fact]
    public async Task Max_entries_bounds_the_search_and_reports_truncation()
    {
        await using var f = Directory(10);
        var r = await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { BaseDn = "DC=lab,DC=test", PageSize = 4, MaxEntries = 5 }, Ct);
        Assert.Equal(5, r.Entries.Count);
        Assert.True(r.Truncated);
        Assert.Equal(2, f.Searches.Count); // stopped after the page that reached the limit
    }

    [Fact]
    public async Task Empty_result_is_success_with_no_entries_not_an_error()
    {
        await using var f = Directory(2);
        var r = await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { BaseDn = "OU=Nobody,DC=lab,DC=test" }, Ct);
        Assert.Equal(LdapOutcome.NoEntries, r.Outcome);
        Assert.Empty(r.Entries);
    }

    [Fact]
    public async Task Escaped_values_reach_the_server_as_literal_equality_not_wildcards()
    {
        await using var f = Directory(1);
        var value = @"a*b(c)\d";
        var filter = $"(&(objectClass=user)(cn={Core.Targets.ActiveDirectoryFilters.Escape(value)}))";
        Assert.Equal(@"(&(objectClass=user)(cn=a\2ab\28c\29\5cd))", filter);
        await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { BaseDn = "DC=lab,DC=test", Filter = filter }, Ct);
        // the fixture re-renders the BER filter: an equality match (tag 3) whose value is the literal string
        Assert.Equal(filter, f.Searches.Single().Filter);

        await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { BaseDn = "DC=lab,DC=test", Filter = "(cn=a*b)" }, Ct);
        Assert.Equal("(cn=a*b)", f.Searches.Last().Filter); // unescaped "*": sent as a substring filter (initial "a", final "b")
    }

    [Fact]
    public async Task Invalid_filter_and_limits_are_rejected_without_network()
    {
        await using var f = Directory(1);
        Assert.Equal(LdapOutcome.InvalidInput, (await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { Filter = "(cn=x" }, Ct)).Outcome);
        Assert.Equal(LdapOutcome.InvalidInput, (await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { PageSize = 0 }, Ct)).Outcome);
        Assert.Equal(LdapOutcome.InvalidInput, (await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { MaxEntries = LdapTester.MaxEntriesLimit + 1 }, Ct)).Outcome);
        Assert.Empty(f.Searches);
    }

    [Fact]
    public async Task Secret_attributes_are_redacted_and_binary_guids_formatted()
    {
        await using var f = Directory(1);
        var r = await LdapTester.SearchAsync(Profile(f), new LdapSearchSpec { BaseDn = "DC=lab,DC=test" }, Ct);
        var e = Assert.Single(r.Entries);
        Assert.Equal("[redacted: secret attribute]", e.Attributes.Single(a => a.Name == "userPassword").Values.Single());
        Assert.Equal("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", e.Attributes.Single(a => a.Name == "objectGUID").Values.Single());
        Assert.DoesNotContain("should-never-show", LdapTester.Report(r), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Silent_server_times_out_and_cancel_returns_promptly()
    {
        await using var f = new LdapFixture { Silent = true };
        var p = Profile(f) with { Timeout = TimeSpan.FromSeconds(1) };
        var t = await LdapTester.RootDseAsync(p, Ct);
        Assert.Equal(LdapOutcome.Timeout, t.Outcome);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Ct);
        cts.CancelAfter(200);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var c = await LdapTester.RootDseAsync(p with { Timeout = TimeSpan.FromSeconds(10) }, cts.Token);
        Assert.Equal(LdapOutcome.Cancelled, c.Outcome);
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(3));
    }

    [Fact]
    public void Value_formatting()
    {
        byte[] sid = [1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xF4, 1, 0, 0];
        Assert.Equal("S-1-5-21-1-2-3-500", LdapValues.Format("objectSid", sid));
        Assert.Null(LdapValues.Sid([1, 5, 0]));
        Assert.Equal("0x0001FF (3 bytes)", LdapValues.Format("thumbnailPhoto", [0, 1, 255]));
        Assert.StartsWith("0x", LdapValues.Format("description", [0, 1, 2]), StringComparison.Ordinal); // control characters → hex
        Assert.Equal("2026-11-17 08:30:00 UTC", LdapValues.Time("20261117083000.0Z"));
        Assert.Equal("[redacted: secret attribute]", LdapValues.Format("ms-Mcs-AdmPwd", "x"u8.ToArray()));
        Assert.Equal("DEADBEEF", LdapTester.NormalizeThumbprint("de:ad be-ef"));
    }
}
