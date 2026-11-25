using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IPMaster.Core.Targets;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

public enum LdapSecurity
{
    None,
    StartTls,
    Ldaps,
}

public enum LdapBindKind
{
    Anonymous,
    Simple,
    Integrated,
}

public enum LdapOutcome
{
    Success,
    NoEntries,
    AuthenticationFailed,
    PlaintextPasswordBlocked,
    InvalidInput,
    Timeout,
    ServerUnavailable,
    TlsFailed,
    ServerError,
    Unsupported,
    Cancelled,
}

public sealed record LdapProfile
{
    public required string Server { get; init; }

    /// <summary>0 = 389 (None/STARTTLS) or 636 (LDAPS).</summary>
    public int Port { get; init; }

    public LdapSecurity Security { get; init; }

    public LdapBindKind Bind { get; init; }

    public string User { get; init; } = "";

    /// <summary>Session-only; never written to results or reports.</summary>
    public string Password { get; init; } = "";

    /// <summary>Explicit user override: allow a simple bind (password) over an unencrypted connection.</summary>
    public bool AllowPlaintextPassword { get; init; }

    /// <summary>Explicit, profile-specific exception: accept exactly this server certificate (SHA-256 hex) even if it fails validation.</summary>
    public string PinnedSha256 { get; init; } = "";

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);

    public int EffectivePort => Port > 0 ? Port : Security == LdapSecurity.Ldaps ? 636 : 389;
}

public sealed record LdapSearchSpec
{
    public string BaseDn { get; init; } = "";

    public SearchScope Scope { get; init; } = SearchScope.Subtree;

    public string Filter { get; init; } = "(objectClass=*)";

    public IReadOnlyList<string> Attributes { get; init; } = [];

    public int PageSize { get; init; } = 200;

    public int MaxEntries { get; init; } = 1000;
}

public sealed record LdapAttributeValues(string Name, IReadOnlyList<string> Values);

public sealed record LdapEntryView(string Dn, IReadOnlyList<LdapAttributeValues> Attributes);

public sealed record LdapResult(
    LdapOutcome Outcome,
    string Detail,
    IReadOnlyList<LdapEntryView> Entries,
    int Pages,
    bool Truncated,
    string Connection,
    TimeSpan Duration);

/// <summary>
/// LDAP / Active Directory Tester (D-077): read-only (bind, RootDSE, paged search; no add/modify/delete/rename),
/// referrals off, server certificates validated (chain + name) unless the profile pins one exact certificate,
/// and a password is never sent in plain text unless the profile explicitly allows it.
/// </summary>
public static class LdapTester
{
    public const int MaxEntriesLimit = 100_000;

    public static Task<LdapResult> BindTestAsync(LdapProfile p, CancellationToken ct) => RunAsync(p, (_, _, _) => (LdapOutcome.Success, "Bind succeeded.", [], 0, false), ct);

    public static Task<LdapResult> RootDseAsync(LdapProfile p, CancellationToken ct) => RunAsync(p, (c, timeout, _) =>
    {
        var r = (SearchResponse)c.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base, "*", "+"), timeout);
        var entries = r.Entries.Cast<SearchResultEntry>().Select(View).ToList();
        return entries.Count == 0 ? (LdapOutcome.NoEntries, "The server returned no RootDSE.", entries, 1, false) : (LdapOutcome.Success, "", entries, 1, false);
    }, ct);

    public static Task<LdapResult> SearchAsync(LdapProfile p, LdapSearchSpec s, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(s);
        if (ActiveDirectoryFilters.Validate(s.Filter) is { } problem) return Task.FromResult(Fail(LdapOutcome.InvalidInput, problem, p));
        if (s.PageSize is < 1 or > 5000) return Task.FromResult(Fail(LdapOutcome.InvalidInput, "Page size must be 1–5000.", p));
        if (s.MaxEntries is < 1 or > MaxEntriesLimit) return Task.FromResult(Fail(LdapOutcome.InvalidInput, $"Maximum entries must be 1–{MaxEntriesLimit:N0}.", p));
        return RunAsync(p, (c, timeout, token) =>
        {
            var entries = new List<LdapEntryView>();
            var paging = new PageResultRequestControl(Math.Min(s.PageSize, s.MaxEntries)) { IsCritical = false };
            var request = new SearchRequest(s.BaseDn.Trim(), s.Filter.Trim(), s.Scope, s.Attributes.Where(a => a.Trim().Length > 0).Select(a => a.Trim()).ToArray());
            request.Controls.Add(paging);
            for (var page = 1; ; page++)
            {
                token.ThrowIfCancellationRequested();
                var response = (SearchResponse)c.SendRequest(request, timeout);
                foreach (SearchResultEntry e in response.Entries)
                {
                    entries.Add(View(e));
                    if (entries.Count >= s.MaxEntries) return (LdapOutcome.Success, $"Stopped at the {s.MaxEntries:N0}-entry limit; more entries exist.", entries, page, true);
                }

                var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
                if (cookie is null || cookie.Length == 0)
                {
                    return entries.Count == 0
                        ? (LdapOutcome.NoEntries, "The search succeeded and matched no entries.", entries, page, false)
                        : (LdapOutcome.Success, "", entries, page, false);
                }

                paging.Cookie = cookie;
            }
        }, ct);
    }

    private delegate (LdapOutcome Outcome, string Detail, List<LdapEntryView> Entries, int Pages, bool Truncated) Operation(LdapConnection c, TimeSpan timeout,
        CancellationToken ct);

    private static LdapResult Fail(LdapOutcome o, string detail, LdapProfile p, TimeSpan duration = default) => new(o, detail, [], 0, false, Describe(p), duration);

    public static string Describe(LdapProfile p)
    {
        ArgumentNullException.ThrowIfNull(p);
        var security = p.Security switch { LdapSecurity.Ldaps => "LDAPS", LdapSecurity.StartTls => "STARTTLS", _ => "unencrypted" };
        var bind = p.Bind switch { LdapBindKind.Simple => "simple bind as " + p.User, LdapBindKind.Integrated => "integrated (" + (p.User.Length > 0 ? p.User : "current account") + ")", _ => "anonymous" };
        return string.Create(CultureInfo.InvariantCulture, $"{p.Server}:{p.EffectivePort}, {security}, {bind}");
    }

    private static async Task<LdapResult> RunAsync(LdapProfile p, Operation op, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(p);
        if (string.IsNullOrWhiteSpace(p.Server)) return Fail(LdapOutcome.InvalidInput, "Enter a server.", p);
        if (p.Bind == LdapBindKind.Simple && p.User.Trim().Length == 0) return Fail(LdapOutcome.InvalidInput, "A simple bind needs a user (DN or user@domain).", p);
        if (p.Bind == LdapBindKind.Simple && p.Security == LdapSecurity.None && !p.AllowPlaintextPassword)
        {
            return Fail(LdapOutcome.PlaintextPasswordBlocked,
                "Not sent: a simple bind over an unencrypted connection exposes the password. Use STARTTLS or LDAPS, or explicitly allow it for this profile.", p);
        }

        var sw = Stopwatch.StartNew();
        string? tlsProblem = null;
        var work = Task.Run(() =>
        {
            using var c = Open(p, problem => tlsProblem = problem);
            if (p.Security == LdapSecurity.StartTls) c.SessionOptions.StartTransportLayerSecurity(null);
            if (p.Bind != LdapBindKind.Anonymous) c.Bind();
            return op(c, p.Timeout, ct);
        }, CancellationToken.None);
        try
        {
            // Wall-clock bound: on Linux, libldap does not apply the request timeout to a server that accepts the
            // connection and then stays silent, so the call could block for ever. A paged search sends several requests.
            var limit = p.Timeout * 4 + TimeSpan.FromSeconds(2);
            var (outcome, detail, entries, pages, truncated) = await work.WaitAsync(limit, ct).ConfigureAwait(false);
            return new LdapResult(outcome, detail, entries, pages, truncated, Describe(p), sw.Elapsed);
        }
        catch (TimeoutException) when (!work.IsCompleted)
        {
            _ = work.ContinueWith(t => t.Exception, TaskScheduler.Default); // observed; it ends when the connection closes
            return Fail(LdapOutcome.Timeout, $"No answer within {p.Timeout.TotalSeconds:0} s. Check the server and port.", p, sw.Elapsed);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            _ = work.ContinueWith(t => t.Exception, TaskScheduler.Default); // observed; it ends within the request timeout
            return Fail(LdapOutcome.Cancelled, "Cancelled.", p, sw.Elapsed);
        }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException or TlsOperationException or PlatformNotSupportedException or DirectoryException
                                       or InvalidOperationException)
        {
            var (o, d) = Map(ex, tlsProblem, p);
            return Fail(o, d, p, sw.Elapsed);
        }
    }

    private static (LdapOutcome, string) Map(Exception ex, string? tlsProblem, LdapProfile p)
    {
        if (tlsProblem is not null) return (LdapOutcome.TlsFailed, "The server certificate was rejected: " + tlsProblem);
        switch (ex)
        {
            case PlatformNotSupportedException:
                return (LdapOutcome.Unsupported, "Not supported on this platform: " + ex.Message);
            case TlsOperationException:
                return (LdapOutcome.TlsFailed, "STARTTLS failed: " + ex.Message);
            case DirectoryOperationException d:
                var code = d.Response?.ResultCode;
                if (code is ResultCode.InappropriateAuthentication or ResultCode.StrongAuthRequired or ResultCode.ConfidentialityRequired)
                {
                    return (LdapOutcome.AuthenticationFailed, $"{code}: {d.Response?.ErrorMessage}".Trim());
                }

                return (LdapOutcome.ServerError, $"{code}: {(d.Response?.ErrorMessage is { Length: > 0 } m ? m : d.Message)}");
            case LdapException l:
                return l.ErrorCode switch
                {
                    49 => (LdapOutcome.AuthenticationFailed, "Invalid credentials (49)" + (l.ServerErrorMessage is { Length: > 0 } s ? ": " + s : ".")),
                    48 or 7 or 8 or 13 => (LdapOutcome.AuthenticationFailed, $"{l.Message} ({l.ErrorCode})"),
                    85 => (LdapOutcome.Timeout, $"No answer within {p.Timeout.TotalSeconds:0} s."),
                    81 or 91 or 52 => (LdapOutcome.ServerUnavailable, $"{l.Message} ({l.ErrorCode})" + (p.Security != LdapSecurity.None ? " — this can also be a TLS failure." : "")),
                    _ => (LdapOutcome.ServerError, $"{l.Message} ({l.ErrorCode})"),
                };
            default:
                return (LdapOutcome.ServerError, ex.Message);
        }
    }

    private static LdapConnection Open(LdapProfile p, Action<string> tlsProblem)
    {
        var host = p.Server.Trim();
        var c = new LdapConnection(new LdapDirectoryIdentifier(host, p.EffectivePort, false, false))
        {
            AuthType = p.Bind switch { LdapBindKind.Simple => AuthType.Basic, LdapBindKind.Integrated => AuthType.Negotiate, _ => AuthType.Anonymous },
            Timeout = p.Timeout,
        };
        try
        {
            if (p.Bind == LdapBindKind.Simple)
            {
                c.Credential = new NetworkCredential(p.User.Trim(), p.Password);
            }
            else if (p.Bind == LdapBindKind.Integrated && p.User.Trim().Length > 0)
            {
                var (domain, user) = p.User.Contains('\\', StringComparison.Ordinal) ? (p.User[..p.User.IndexOf('\\', StringComparison.Ordinal)], p.User[(p.User.IndexOf('\\', StringComparison.Ordinal) + 1)..]) : ("", p.User);
                c.Credential = new NetworkCredential(user.Trim(), p.Password, domain.Trim());
            }

            c.SessionOptions.ProtocolVersion = 3;
            c.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (p.Bind == LdapBindKind.Integrated && p.Security == LdapSecurity.None && OperatingSystem.IsWindows())
            {
                c.SessionOptions.Signing = true;
                c.SessionOptions.Sealing = true;
            }

            if (p.Security == LdapSecurity.Ldaps) c.SessionOptions.SecureSocketLayer = true;
            if (p.Security != LdapSecurity.None && OperatingSystem.IsWindows())
            {
                c.SessionOptions.VerifyServerCertificate = (_, cert) =>
                {
                    using var x = new X509Certificate2(cert);
                    var problem = CertificateProblem(x, host);
                    if (problem is null) return true;
                    if (p.PinnedSha256.Length > 0 && NormalizeThumbprint(p.PinnedSha256) == x.GetCertHashString(HashAlgorithmName.SHA256)) return true; // explicit profile exception
                    tlsProblem(problem + " (SHA-256 " + x.GetCertHashString(HashAlgorithmName.SHA256) + ")");
                    return false;
                };
            }

            return c;
        }
        catch
        {
            c.Dispose();
            throw;
        }
    }

    public static string NormalizeThumbprint(string s) => new((s ?? "").Where(Uri.IsHexDigit).Select(char.ToUpperInvariant).ToArray());

    /// <summary>Chain (current trust store) and host-name validation; null when valid. Revocation is not checked here (TLS Inspector does).</summary>
    public static string? CertificateProblem(X509Certificate2 cert, string host)
    {
        ArgumentNullException.ThrowIfNull(cert);
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
        var problems = new List<string>();
        if (!chain.Build(cert)) problems.Add(string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()).Distinct()));
        var ip = IPAddress.TryParse(host, out _);
        if (!cert.MatchesHostname(host, allowWildcards: !ip, allowCommonName: false)) problems.Add($"the certificate is not valid for '{host}'");
        return problems.Count == 0 ? null : string.Join("; ", problems);
    }

    private static LdapEntryView View(SearchResultEntry e)
    {
        var attrs = new List<LdapAttributeValues>();
        foreach (DirectoryAttribute a in e.Attributes.Values)
        {
            var name = a.Name;
            var values = LdapValues.IsSecret(name)
                ? ["[redacted: secret attribute]"]
                : a.GetValues(typeof(byte[])).Cast<byte[]>().Take(1000).Select(v => LdapValues.Format(name, v)).Select(v => TimeAttribute(name) ? LdapValues.Time(v) : v).ToList();
            attrs.Add(new LdapAttributeValues(name, values));
        }

        return new LdapEntryView(e.DistinguishedName, attrs.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList());
    }

    private static bool TimeAttribute(string name) => name is "whenCreated" or "whenChanged" or "currentTime" or "createTimestamp" or "modifyTimestamp";

    public static string Report(LdapResult r, bool includeEntries = true)
    {
        ArgumentNullException.ThrowIfNull(r);
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        sb.AppendLine(c, $"LDAP {r.Connection} — {r.Duration.TotalMilliseconds:0} ms");
        sb.AppendLine(c, $"Outcome: {r.Outcome}{(r.Detail.Length > 0 ? " — " + r.Detail : "")}");
        if (r.Pages > 0) sb.AppendLine(c, $"Entries: {r.Entries.Count:N0} in {r.Pages} page(s){(r.Truncated ? " (truncated)" : "")}");
        if (!includeEntries) return sb.ToString();
        foreach (var e in r.Entries)
        {
            sb.AppendLine();
            sb.AppendLine("dn: " + (e.Dn.Length == 0 ? "(RootDSE)" : e.Dn));
            foreach (var a in e.Attributes)
            {
                foreach (var v in a.Values) sb.AppendLine(c, $"{a.Name}: {v}");
            }
        }

        return sb.ToString();
    }
}
