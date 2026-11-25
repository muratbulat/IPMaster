using System.DirectoryServices.Protocols;
using System.Net;
using IPMaster.Core.Security;
using IPMaster.Core.Targets;

namespace IPMaster.Infrastructure.Targets;

/// <summary>
/// Active Directory computer import over LDAP (TGT-13, D-058): Negotiate (Kerberos/NTLM) with signing and sealing, the
/// current account or a stored credential, paged results, bounded count.
/// </summary>
public static class ActiveDirectoryImport
{
    public const int MaxResults = 20_000;

    private static LdapConnection Connect(string server, ResolvedCredential? credential, TimeSpan timeout)
    {
        var id = new LdapDirectoryIdentifier(string.IsNullOrWhiteSpace(server) ? null : server.Trim(), 389, false, false);
        var c = credential is null
            ? new LdapConnection(id) { AuthType = AuthType.Negotiate }
            : new LdapConnection(id, MakeCredential(credential), AuthType.Negotiate);
        c.SessionOptions.ProtocolVersion = 3;
        c.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        if (OperatingSystem.IsWindows())
        {
            c.SessionOptions.Signing = true;
            c.SessionOptions.Sealing = true;
        }

        c.Timeout = timeout;
        c.Bind();
        return c;
    }

    private static NetworkCredential MakeCredential(ResolvedCredential c)
    {
        var (domain, user) = c.Split();
        return new NetworkCredential(user, c.Password, domain);
    }

    /// <summary>defaultNamingContext from RootDSE (the default base).</summary>
    public static Task<string> DefaultBaseAsync(string server, ResolvedCredential? credential, CancellationToken ct) => Task.Run(() =>
    {
        using var c = Connect(server, credential, TimeSpan.FromSeconds(15));
        var r = (SearchResponse)c.SendRequest(new SearchRequest("", "(objectClass=*)", SearchScope.Base, "defaultNamingContext"));
        return r.Entries.Count > 0 && r.Entries[0].Attributes["defaultNamingContext"] is { Count: > 0 } a ? a[0]?.ToString() ?? "" : "";
    }, ct);

    public static Task<IReadOnlyList<AdComputer>> SearchAsync(string server, string baseDn, string filter, ResolvedCredential? credential, CancellationToken ct,
        int max = MaxResults) => Task.Run<IReadOnlyList<AdComputer>>(() =>
    {
        if (ActiveDirectoryFilters.Validate(filter) is { } err) throw new ArgumentException(err, nameof(filter));
        using var c = Connect(server, credential, TimeSpan.FromSeconds(30));
        var list = new List<AdComputer>();
        var paging = new PageResultRequestControl(500);
        var request = new SearchRequest(baseDn, filter, SearchScope.Subtree, "name", "dNSHostName", "operatingSystem");
        request.Controls.Add(paging);
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var response = (SearchResponse)c.SendRequest(request);
            foreach (SearchResultEntry e in response.Entries)
            {
                list.Add(new AdComputer(Attr(e, "name"), Attr(e, "dNSHostName"), Attr(e, "operatingSystem")));
                if (list.Count >= max) return list;
            }

            var cookie = response.Controls.OfType<PageResultResponseControl>().FirstOrDefault()?.Cookie;
            if (cookie is null || cookie.Length == 0) return list;
            paging.Cookie = cookie;
        }
    }, ct);

    private static string Attr(SearchResultEntry e, string name) => e.Attributes[name] is { Count: > 0 } a ? a[0]?.ToString() ?? "" : "";
}
