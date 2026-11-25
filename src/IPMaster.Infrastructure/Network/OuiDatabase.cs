using System.Globalization;
using System.Net.NetworkInformation;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Network;

/// <summary>
/// Offline vendor lookup from IEEE registry CSV files (MA-L <c>oui.csv</c>, MA-M <c>mam.csv</c>, MA-S <c>oui36.csv</c>).
/// The registry is not bundled (D-033): it is downloaded only when the user asks (<see cref="DownloadAsync"/>)
/// or copied into the settings folder manually. Longest prefix wins (36 → 28 → 24 bits).
/// </summary>
public sealed class OuiDatabase : IVendorLookup
{
    public static readonly string[] FileNames = ["oui.csv", "mam.csv", "oui36.csv"];
    public static readonly Uri[] SourceUrls =
    [
        new("https://standards-oui.ieee.org/oui/oui.csv"),
        new("https://standards-oui.ieee.org/oui28/mam.csv"),
        new("https://standards-oui.ieee.org/oui36/oui36.csv"),
    ];

    private const long MaxFileBytes = 32L * 1024 * 1024;
    private readonly string[] _directories;
    private readonly object _lock = new();
    private Dictionary<string, string>? _map;
    private CapabilityStatus? _capability;

    public OuiDatabase(params string[] directories) => _directories = directories.Where(d => !string.IsNullOrEmpty(d)).Distinct().ToArray();

    public string PrimaryDirectory => _directories.FirstOrDefault() ?? AppContext.BaseDirectory;

    public CapabilityStatus Capability
    {
        get
        {
            Ensure();
            return _capability!;
        }
    }

    public int Count
    {
        get
        {
            Ensure();
            return _map!.Count;
        }
    }

    public string? Lookup(PhysicalAddress mac)
    {
        ArgumentNullException.ThrowIfNull(mac);
        Ensure();
        var hex = Convert.ToHexString(mac.GetAddressBytes());
        if (hex.Length < 6) return null;
        foreach (var len in new[] { 9, 7, 6 })
        {
            if (hex.Length >= len && _map!.TryGetValue(hex[..len], out var v)) return v;
        }

        return null;
    }

    /// <summary>Forgets the loaded data so the next lookup re-reads the files (after a download).</summary>
    public void Reload()
    {
        lock (_lock)
        {
            _map = null;
            _capability = null;
        }
    }

    private void Ensure()
    {
        if (_map is not null) return;
        lock (_lock)
        {
            if (_map is not null) return;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var files = new List<string>();
            foreach (var dir in _directories)
            {
                foreach (var name in FileNames)
                {
                    var path = Path.Combine(dir, name);
                    if (!File.Exists(path) || files.Any(f => Path.GetFileName(f) == name)) continue;
                    var info = new FileInfo(path);
                    if (info.Length > MaxFileBytes) continue;
                    using var reader = new StreamReader(path);
                    Parse(reader, map);
                    files.Add(path);
                }
            }

            _capability = map.Count > 0
                ? CapabilityStatus.Yes(string.Create(CultureInfo.InvariantCulture, $"IEEE registry: {map.Count:N0} prefixes from {string.Join(", ", files.Select(Path.GetFileName))} ({File.GetLastWriteTime(files[0]):yyyy-MM-dd})."))
                : CapabilityStatus.No($"No IEEE OUI registry installed. Use Options → Additional → Download OUI database, or copy oui.csv into {PrimaryDirectory}.");
            _map = map;
        }
    }

    /// <summary>Parses IEEE CSV ("Registry,Assignment,Organization Name,Organization Address") or "PREFIX&lt;tab&gt;Vendor" lines.</summary>
    internal static void Parse(TextReader reader, Dictionary<string, string> map)
    {
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("Registry,", StringComparison.OrdinalIgnoreCase)) continue;
            string prefix, vendor;
            if (line.StartsWith("MA-", StringComparison.OrdinalIgnoreCase) || line.StartsWith("IAB", StringComparison.OrdinalIgnoreCase))
            {
                var f = SplitCsv(line);
                if (f.Count < 3) continue;
                prefix = f[1];
                vendor = f[2];
            }
            else
            {
                var tab = line.IndexOf('\t', StringComparison.Ordinal);
                if (tab < 0) continue;
                prefix = new string(line[..tab].Where(Uri.IsHexDigit).ToArray());
                vendor = line[(tab + 1)..];
            }

            prefix = prefix.Trim().ToUpperInvariant();
            if (prefix.Length is 6 or 7 or 9 && prefix.All(Uri.IsHexDigit)) map[prefix] = vendor.Trim();
        }
    }

    private static List<string> SplitCsv(string line)
    {
        var fields = new List<string>();
        var sb = new System.Text.StringBuilder();
        var quoted = false;
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (c == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"')
                {
                    sb.Append('"');
                    i++;
                }
                else
                {
                    quoted = !quoted;
                }
            }
            else if (c == ',' && !quoted)
            {
                fields.Add(sb.ToString());
                sb.Clear();
            }
            else
            {
                sb.Append(c);
            }
        }

        fields.Add(sb.ToString());
        return fields;
    }

    /// <summary>Downloads the IEEE registry files into <see cref="PrimaryDirectory"/>. Explicit user action only.</summary>
    public async Task<string> DownloadAsync(HttpClient http, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        var done = new List<string>();
        for (var i = 0; i < SourceUrls.Length; i++)
        {
            using var response = await http.GetAsync(SourceUrls[i], HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaxFileBytes) throw new InvalidOperationException("Registry file is unexpectedly large.");
            await using var body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var ms = new MemoryStream();
            var buffer = new byte[81920];
            int n;
            while ((n = await body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (ms.Length + n > MaxFileBytes) throw new InvalidOperationException("Registry file is unexpectedly large.");
                ms.Write(buffer, 0, n);
            }

            var bytes = ms.ToArray();
            var probe = new Dictionary<string, string>();
            using (var reader = new StreamReader(new MemoryStream(bytes))) Parse(reader, probe);
            if (probe.Count == 0) throw new InvalidOperationException($"{SourceUrls[i]} did not contain registry data.");
            await AtomicFile.WriteAsync(Path.Combine(PrimaryDirectory, FileNames[i]), s => s.WriteAsync(bytes, cancellationToken).AsTask(), cancellationToken).ConfigureAwait(false);
            done.Add($"{FileNames[i]} ({probe.Count:N0})");
        }

        Reload();
        return "Downloaded " + string.Join(", ", done);
    }
}
