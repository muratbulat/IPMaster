using System.Globalization;

namespace IPMaster.Core.Tools;

public enum WinGetStatus
{
    Unknown,
    Current,
    UpdateAvailable,
    Updating,
    Updated,
    Failed,
    NotSupported,
    Pinned,
    Installed,

    /// <summary>The command ended without an error, but reading the package back did not confirm the change.</summary>
    Unverified,
}

/// <summary>One package as <c>winget list</c> reports it. <see cref="Id"/> and <see cref="Source"/> address it exactly.</summary>
public sealed record WinGetPackage
{
    public string Name { get; init; } = "";

    public string Id { get; init; } = "";

    public string InstalledVersion { get; init; } = "";

    /// <summary>Empty = no upgrade reported (not "up to date" unless a source and an installed version are known).</summary>
    public string AvailableVersion { get; init; } = "";

    /// <summary>Empty = not from a WinGet source (ARP/MSIX entry WinGet cannot upgrade).</summary>
    public string Source { get; init; } = "";

    public bool IsPinned { get; init; }

    public WinGetStatus Status => WinGet.StatusOf(this);
}

/// <summary>A parsed WinGet table (<c>winget list</c>, <c>winget pin list</c>): rows of cells by column position.</summary>
public sealed record WinGetTable(IReadOnlyList<string> Headers, IReadOnlyList<IReadOnlyList<string>> Rows);

/// <summary>One row of <c>winget search</c>. An empty <see cref="Source"/> means the source column was absent: not installable exactly.</summary>
public sealed record WinGetSearchHit(string Name, string Id, string Version, string Match, string Source);

public sealed record WinGetUpdateResult(string Id, string Name, string FromVersion, string? ToVersion, WinGetStatus Status, int ExitCode, string Message, bool RestartRequired);

/// <summary>
/// WinGet Manager rules (D-106): parsing of WinGet's console tables, statuses, version order, filters and messages.
/// WinGet has no stable JSON output for <c>list</c>; tables are parsed by column position (measured in display cells, so
/// wide characters and localized headers work) and any row that does not fit is dropped rather than guessed.
/// </summary>
public static class WinGet
{
    public const string MicrosoftLink = "https://learn.microsoft.com/windows/package-manager/winget/";

    public static string StatusText(WinGetStatus s) => s switch
    {
        WinGetStatus.Current => "Current",
        WinGetStatus.UpdateAvailable => "Update Available",
        WinGetStatus.Updating => "Updating",
        WinGetStatus.Updated => "Updated",
        WinGetStatus.Failed => "Failed",
        WinGetStatus.NotSupported => "Not Supported",
        WinGetStatus.Pinned => "Pinned",
        WinGetStatus.Installed => "Installed",
        WinGetStatus.Unverified => "Not Verified",
        _ => "Unknown",
    };

    /// <summary>Semantic state class: success, warning, error, info, or null (neutral).</summary>
    public static string? StateClass(WinGetStatus s) => s switch
    {
        WinGetStatus.Current or WinGetStatus.Updated or WinGetStatus.Installed => "success",
        WinGetStatus.UpdateAvailable or WinGetStatus.Unverified => "warning",
        WinGetStatus.Failed => "error",
        WinGetStatus.Updating => "info",
        _ => null,
    };

    public static bool IsUnknownVersion(string v) => v.Length == 0 || v.Equals("Unknown", StringComparison.OrdinalIgnoreCase) || v.StartsWith('<') || v.StartsWith('>');

    /// <summary>From the reported metadata only: an unknown version or a missing source is never "Current".</summary>
    public static WinGetStatus StatusOf(WinGetPackage p)
    {
        if (p.Source.Length == 0) return WinGetStatus.NotSupported;
        if (p.IsPinned) return WinGetStatus.Pinned;
        if (IsUnknownVersion(p.InstalledVersion)) return WinGetStatus.Unknown;
        return p.AvailableVersion.Length > 0 ? WinGetStatus.UpdateAvailable : WinGetStatus.Current;
    }

    /// <summary>Only packages with a confirmed upgrade, a source and a known version; never pinned ones.</summary>
    public static bool IsEligible(WinGetPackage p) => StatusOf(p) == WinGetStatus.UpdateAvailable && p.Id.Length > 0 && !p.Id.Contains(' ', StringComparison.Ordinal);

    // ---------------- table parsing ----------------

    /// <summary>
    /// Every table in the output. A table starts at a header line directly above a line of dashes; columns start where the
    /// header words start. Spinner/progress text before the header is ignored (only the part after the last CR counts).
    /// </summary>
    public static IReadOnlyList<WinGetTable> ParseTables(string output)
    {
        var lines = (output ?? "").Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n').Select(l => l.Contains('\r', StringComparison.Ordinal) ? l[(l.LastIndexOf('\r') + 1)..] : l).ToList();
        var tables = new List<WinGetTable>();
        for (var i = 1; i < lines.Count; i++)
        {
            if (!IsSeparator(lines[i]) || lines[i - 1].Trim().Length == 0) continue;
            var header = lines[i - 1];
            var starts = HeaderStarts(header);
            if (starts.Count < 2) continue;
            var headers = starts.Select((s, k) => Cut(header, s, k + 1 < starts.Count ? starts[k + 1] : int.MaxValue).Trim()).ToList();
            var rows = new List<IReadOnlyList<string>>();
            var j = i + 1;
            for (; j < lines.Count; j++)
            {
                var line = lines[j].TrimEnd();
                if (line.Length == 0) break; // a blank line ends the table (footers and a second table follow)
                if (j + 1 < lines.Count && IsSeparator(lines[j + 1])) break; // next table's header
                if (Width(line) < starts[1]) break; // a sentence, not a row
                var cells = starts.Select((s, k) => Cut(line, s, k + 1 < starts.Count ? starts[k + 1] : int.MaxValue).Trim()).ToList();
                rows.Add(cells);
            }

            tables.Add(new WinGetTable(headers, rows));
            i = j;
        }

        return tables;
    }

    /// <summary>
    /// Packages from <c>winget list</c>: columns Name, Id, Version, [Available], Source by position (header words may be
    /// localized). Rows whose Id is empty, holds spaces or is truncated ("…") are dropped: they cannot be addressed exactly.
    /// </summary>
    public static IReadOnlyList<WinGetPackage> ParseList(string output, IReadOnlySet<string>? pinnedIds = null)
    {
        var table = ParseTables(output).FirstOrDefault(t => t.Headers.Count is 4 or 5);
        if (table is null) return [];
        var hasAvailable = table.Headers.Count == 5;
        var list = new List<WinGetPackage>();
        foreach (var r in table.Rows)
        {
            var id = r[1];
            if (id.Length == 0 || id.Contains(' ', StringComparison.Ordinal) || id.Contains('…', StringComparison.Ordinal)) continue;
            list.Add(new WinGetPackage
            {
                Name = r[0], Id = id, InstalledVersion = r[2], AvailableVersion = hasAvailable ? r[3] : "", Source = r[^1],
                IsPinned = pinnedIds?.Contains(id) == true,
            });
        }

        return list;
    }

    /// <summary>Ids from <c>winget pin list</c> (Name, Id, Version, Source, Pin type, …).</summary>
    public static IReadOnlySet<string> ParsePins(string output)
    {
        var table = ParseTables(output).FirstOrDefault(t => t.Headers.Count >= 4);
        return table is null ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : table.Rows.Select(r => r[1]).Where(id => id.Length > 0 && !id.Contains(' ', StringComparison.Ordinal)).ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Hits from <c>winget search</c>: Name, Id, Version, [Match], Source. Match cells look like "Tag: x" (always a colon,
    /// source names never have one), which tells a 4-column table without Source from one without Match.
    /// </summary>
    public static IReadOnlyList<WinGetSearchHit> ParseSearch(string output)
    {
        var table = ParseTables(output).FirstOrDefault(t => t.Headers.Count is 3 or 4 or 5);
        if (table is null) return [];
        var lastIsMatch = table.Headers.Count == 4 && table.Rows.Any(r => r[3].Contains(':', StringComparison.Ordinal));
        var hasSource = table.Headers.Count == 5 || (table.Headers.Count == 4 && !lastIsMatch);
        var hasMatch = table.Headers.Count == 5 || lastIsMatch;
        return table.Rows
            .Where(r => r[1].Length > 0 && !r[1].Contains(' ', StringComparison.Ordinal) && !r[1].Contains('…', StringComparison.Ordinal))
            .Select(r => new WinGetSearchHit(r[0], r[1], r[2], hasMatch ? r[3] : "", hasSource ? r[^1] : ""))
            .ToList();
    }

    private static bool IsSeparator(string line)
    {
        var t = line.Trim();
        return t.Length >= 10 && t.All(c => c == '-');
    }

    /// <summary>Display-cell positions where header words start. A localized header with a space in one title gives an extra column, so the table is rejected (fail safe).</summary>
    private static List<int> HeaderStarts(string header)
    {
        var starts = new List<int>();
        var cell = 0;
        var prevSpace = true;
        foreach (var ch in header.TrimEnd())
        {
            var space = ch == ' ';
            if (!space && prevSpace) starts.Add(cell);
            prevSpace = space;
            cell += CellWidth(ch);
        }

        return starts;
    }

    /// <summary>Text between two display-cell positions.</summary>
    private static string Cut(string line, int from, int to)
    {
        var sb = new System.Text.StringBuilder();
        var cell = 0;
        foreach (var ch in line)
        {
            if (cell >= to) break;
            if (cell >= from) sb.Append(ch);
            cell += CellWidth(ch);
        }

        return sb.ToString();
    }

    public static int Width(string s) => s.Sum(CellWidth);

    /// <summary>East Asian wide and fullwidth characters take two console cells (as WinGet pads them).</summary>
    public static int CellWidth(char c) => c switch
    {
        >= 'ᄀ' and <= 'ᅟ' => 2,
        >= '⺀' and <= '꓏' when c != '〿' => 2,
        >= '가' and <= '힣' => 2,
        >= '豈' and <= '﫿' => 2,
        >= '︰' and <= '﹏' => 2,
        >= '＀' and <= '｠' => 2,
        >= '￠' and <= '￦' => 2,
        _ => 1,
    };

    // ---------------- versions, filters ----------------

    /// <summary>Version order: numeric parts numerically, text parts ordinal; unknown and range versions ("&lt; 2.0") first.</summary>
    public static int CompareVersions(string? a, string? b)
    {
        a ??= "";
        b ??= "";
        var ua = IsUnknownVersion(a);
        var ub = IsUnknownVersion(b);
        if (ua || ub) return ua && ub ? string.Compare(a, b, StringComparison.OrdinalIgnoreCase) : ua ? -1 : 1;
        var pa = a.Split('.', '-', '+', '_', ' ');
        var pb = b.Split('.', '-', '+', '_', ' ');
        for (var i = 0; i < Math.Max(pa.Length, pb.Length); i++)
        {
            var x = i < pa.Length ? pa[i] : "0";
            var y = i < pb.Length ? pb[i] : "0";
            var nx = long.TryParse(x, NumberStyles.None, CultureInfo.InvariantCulture, out var vx);
            var ny = long.TryParse(y, NumberStyles.None, CultureInfo.InvariantCulture, out var vy);
            var c = nx && ny ? vx.CompareTo(vy) : nx ? 1 : ny ? -1 : string.Compare(x, y, StringComparison.OrdinalIgnoreCase);
            if (c != 0) return c;
        }

        return 0;
    }

    public enum Filter
    {
        All,
        Updates,
        UpToDate,
    }

    public static bool Matches(WinGetPackage p, Filter filter, string search)
    {
        var ok = filter switch
        {
            Filter.Updates => p.Status == WinGetStatus.UpdateAvailable,
            Filter.UpToDate => p.Status is WinGetStatus.Current or WinGetStatus.Updated,
            _ => true,
        };
        search = search.Trim();
        return ok && (search.Length == 0 || p.Name.Contains(search, StringComparison.CurrentCultureIgnoreCase) || p.Id.Contains(search, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The exact upgrade command for one package: id, --exact and its source, no agreement or pin overrides unless asked.</summary>
    public static IReadOnlyList<string> UpgradeArguments(WinGetPackage p, bool acceptAgreements)
    {
        var a = new List<string> { "upgrade", "--id", p.Id, "--exact", "--source", p.Source, "--disable-interactivity" };
        if (acceptAgreements) a.AddRange(["--accept-package-agreements", "--accept-source-agreements"]);
        return a;
    }

    public const int SearchLimit = 100;

    public static IReadOnlyList<string> SearchArguments(string query) => ["search", "--query", query.Trim(), "--count", SearchLimit.ToString(CultureInfo.InvariantCulture), "--disable-interactivity"];

    /// <summary>The exact install command: id, --exact and its source; agreements only when the user accepted them.</summary>
    public static IReadOnlyList<string> InstallArguments(WinGetSearchHit h, bool acceptAgreements)
    {
        var a = new List<string> { "install", "--id", h.Id, "--exact", "--source", h.Source, "--disable-interactivity" };
        if (acceptAgreements) a.AddRange(["--accept-package-agreements", "--accept-source-agreements"]);
        return a;
    }

    public static bool IsInstallable(WinGetSearchHit h) => h.Source.Length > 0 && h.Id.Length > 0 && !h.Id.Contains(' ', StringComparison.Ordinal);

    // ---------------- results ----------------

    /// <summary>Short text of documented WinGet exit codes (winget-cli returnCodes.md); other codes show as hex.</summary>
    public static string ExitText(int code) => unchecked((uint)code) switch
    {
        0 => "Completed.",
        0x8A150014 or 0x8A150017 => "Package not found.",
        0x8A150016 => "Several packages match. Not updated.",
        0x8A15002B or 0x8A15004F => "No applicable update.",
        0x8A150041 => "Package agreement not accepted.",
        0x8A150046 => "Source agreement not accepted.",
        0x8A150011 => "Installer hash does not match. Not installed.",
        0x8A15003A or 0x8A15010F => "Blocked by policy.",
        0x8A150109 or 0x8A15010B => "Restart required.",
        0x8A15010A => "Restart the computer, then try again.",
        0x8A150019 or 0x80073D28 => "Administrator access required.",
        0x8A15010C => "Update cancelled.",
        0x8A150045 or 0x8A15004B or 0x8A150015 => "Source unavailable.",
        0x8A15006D => "Service unavailable. Try again later.",
        0x8A150107 or 0x8A150008 or 0x8A15002E or 0x8A150086 => "Connection failed.",
        0x8A150068 => "Package is pinned.",
        0x8A150102 => "Another installation is in progress.",
        _ => "Update failed.",
    } + (code != 0 ? $" ({Hex(code)})" : "");

    public static string Hex(int code) => "0x" + unchecked((uint)code).ToString("X8", CultureInfo.InvariantCulture);

    public static bool IsRestartCode(int code) => unchecked((uint)code) is 0x8A150109 or 0x8A15010B;

    /// <summary>
    /// The result from the exit code and the package read back afterwards. A zero exit code is "Updated" only when the
    /// installed version changed and no upgrade is offered any more; otherwise "Not Verified" with the reason.
    /// </summary>
    public static WinGetUpdateResult Verify(WinGetPackage before, int exitCode, WinGetPackage? after)
    {
        var restart = IsRestartCode(exitCode);
        WinGetUpdateResult R(WinGetStatus s, string m) => new(before.Id, before.Name, before.InstalledVersion, after?.InstalledVersion, s, exitCode, m, restart);
        if (exitCode != 0 && !restart) return R(WinGetStatus.Failed, ExitText(exitCode)) with { RestartRequired = false };
        var tail = restart ? " Restart required." : "";
        if (after is null) return R(WinGetStatus.Unverified, "Completed, but the package could not be read back." + tail);
        if (IsUnknownVersion(after.InstalledVersion)) return R(WinGetStatus.Unverified, $"Completed, but WinGet reports the installed version as \"{after.InstalledVersion}\"." + tail);
        if (after.InstalledVersion != before.InstalledVersion && after.AvailableVersion.Length == 0) return R(WinGetStatus.Updated, "Updated." + tail);
        if (after.InstalledVersion == before.InstalledVersion && after.AvailableVersion.Length > 0 && !restart) return R(WinGetStatus.Failed, "Completed, but the update is still offered.");
        if (after.AvailableVersion.Length > 0) return R(WinGetStatus.Unverified, $"Now {after.InstalledVersion}; {after.AvailableVersion} is still offered." + tail);
        return R(WinGetStatus.Unverified, $"Completed, but the installed version is still {after.InstalledVersion}." + tail);
    }

    /// <summary>An install is "Installed" only when WinGet lists the package afterwards.</summary>
    public static WinGetUpdateResult VerifyInstall(WinGetSearchHit h, int exitCode, WinGetPackage? after)
    {
        var restart = IsRestartCode(exitCode);
        if (exitCode != 0 && !restart) return new(h.Id, h.Name, "", null, WinGetStatus.Failed, exitCode, ExitText(exitCode).Replace("Update", "Install", StringComparison.Ordinal), false);
        var tail = restart ? " Restart required." : "";
        return after is null
            ? new(h.Id, h.Name, "", null, WinGetStatus.Unverified, exitCode, "Completed, but the package is not listed as installed." + tail, restart)
            : new(h.Id, h.Name, "", after.InstalledVersion, WinGetStatus.Installed, exitCode, $"Installed {after.InstalledVersion}." + tail, restart);
    }
}
