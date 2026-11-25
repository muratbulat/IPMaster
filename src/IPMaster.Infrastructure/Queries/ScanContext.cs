using System.Net;
using System.Net.Sockets;
using IPMaster.Core.Configuration;
using IPMaster.Core.Network;
using IPMaster.Core.Security;

namespace IPMaster.Infrastructure.Queries;

/// <summary>Per-scan values derived from settings at start: routers for the Router MIB method and resolved credentials (WKS-07).</summary>
public sealed record ScanContext(IReadOnlyList<IPAddress> Routers, ResolvedCredential? WorkstationCredential, ResolvedCredential? SharesCredential,
    IReadOnlyList<string> Warnings)
{
    public static ScanContext Resolve(AppSettings settings, ISecretSource secrets, INetworkAdapterProvider adapters)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(secrets);
        ArgumentNullException.ThrowIfNull(adapters);
        var warnings = new List<string>();
        var s = settings.Scan;
        var routers = new List<IPAddress>();
        if (s.ResolveMac && s.MacMethods.Contains(Core.Scanning.MacMethod.RouterMib))
        {
            routers.AddRange(adapters.GetAdapters().SelectMany(a => a.Gateways).Where(g => g.AddressFamily == AddressFamily.InterNetwork && !g.Equals(IPAddress.Any)));
            foreach (var part in s.RouterMibRouters.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
            {
                if (IPAddress.TryParse(part, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork) routers.Add(ip);
                else warnings.Add($"Router MIB: '{part}' is not an IPv4 address.");
            }
        }

        ResolvedCredential? Resolve(Guid? id, string what)
        {
            if (id is not { } g) return null;
            if (!secrets.CanReveal)
            {
                warnings.Add($"{what}: credentials are locked; the current account is used.");
                return null;
            }

            var c = secrets.Credential(g);
            if (c is null) warnings.Add($"{what}: the selected credential no longer exists; the current account is used.");
            return c;
        }

        return new ScanContext(routers.Distinct().ToList(), Resolve(s.WorkstationCredentialId, "Workstation"), Resolve(s.SharesCredentialId, "Shares"), warnings);
    }
}
