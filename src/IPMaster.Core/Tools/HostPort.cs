using System.Globalization;
using System.Text.RegularExpressions;

namespace IPMaster.Core.Tools;

/// <summary>"host:port" / "[v6]:port" splitting for tool inputs.</summary>
public static partial class HostPort
{
    [GeneratedRegex(@"^\[(?<h>[^\]]+)\]:(?<p>\d{1,5})$|^(?<h>[^:\[\]]+):(?<p>\d{1,5})$", RegexOptions.None, 1000)]
    private static partial Regex Pattern();

    /// <summary>(host, port) when an explicit valid port is given; null for a bare host or bare IPv6 address (use the default port).</summary>
    public static (string Host, int Port)? Split(string s)
    {
        var m = Pattern().Match((s ?? "").Trim());
        return m.Success && int.TryParse(m.Groups["p"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) && port is > 0 and <= 65535
            ? (m.Groups["h"].Value, port)
            : null;
    }
}
