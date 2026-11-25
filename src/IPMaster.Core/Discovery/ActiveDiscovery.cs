using System.Net;
using IPMaster.Core.Targets;

namespace IPMaster.Core.Discovery;

/// <summary>
/// Candidate addresses for active discovery (D-090): only what the user entered, IPv4 only, at most
/// <see cref="MaxAddresses"/>. Never the whole address space: an unknown static address can only be found where the
/// user says to look.
/// </summary>
public static class CandidateList
{
    public const int MaxAddresses = 4096;

    /// <summary>Parses comma- or line-separated addresses, ranges and CIDR blocks; the network and broadcast address of a
    /// block of /30 or larger are skipped. Returns null with an error when nothing usable or too much is given.</summary>
    public static IReadOnlyList<IPAddress>? Parse(string text, out string error)
    {
        ArgumentNullException.ThrowIfNull(text);
        error = "";
        var result = new List<IPAddress>();
        var seen = new HashSet<uint>();
        foreach (var part in text.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!TargetParser.TryParse(part, out var spec, out var why))
            {
                error = $"'{part}': {why}";
                return null;
            }

            if (spec.Kind is not (TargetKind.SingleAddress or TargetKind.Range or TargetKind.Cidr) || spec.Start.IsV6)
            {
                error = $"'{part}': enter IPv4 addresses, ranges or CIDR blocks (no host names, no IPv6).";
                return null;
            }

            var first = (uint)spec.Start.Value;
            var last = (uint)spec.End.Value;
            if (spec.Kind == TargetKind.Cidr && spec.PrefixLength is <= 30)
            {
                first++;
                last--;
            }

            if ((ulong)last - first + 1 + (ulong)seen.Count > MaxAddresses)
            {
                error = $"More than {MaxAddresses:N0} candidate addresses: narrow the ranges.";
                return null;
            }

            for (var a = (ulong)first; a <= last; a++)
            {
                if (seen.Add((uint)a)) result.Add(AddressKey.FromIPv4((uint)a).ToIPAddress());
            }
        }

        if (result.Count == 0) error = "Enter at least one candidate address, range or CIDR block.";
        return result.Count == 0 ? null : result;
    }
}

/// <summary>Factory-default management addresses, used when the controller's DHCP client is off. Candidates, not facts.</summary>
public static class ManagementDefaults
{
    public static IReadOnlyList<(string Product, string Candidates)> All { get; } =
    [
        ("Dell iDRAC", "192.168.0.120"),
        ("Lenovo XClarity Controller / IMM", "192.168.70.125"),
        ("Huawei iBMC", "192.168.2.100"),
        ("HPE iLO", "DHCP by default (use the DHCP server or passive mode)"),
    ];
}
