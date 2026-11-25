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
        _ => "Unknown",
    };

    /// <summary>Semantic state class: success, warning, error, info, or null (neutral).</summary>
    public static string? StateClass(WinGetStatus s) => s switch
    {
        WinGetStatus.Current or WinGetStatus.Updated => "success",
        WinGetStatus.UpdateAvailable => "warning",
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
        0x8A150019 => "Administrator access required.",
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
    /// installed version changed and no upgrade is offered any more; otherwise "Completed. Verification unavailable."
    /// </summary>
    public static WinGetUpdateResult Verify(WinGetPackage before, int exitCode, WinGetPackage? after)
    {
        var restart = IsRestartCode(exitCode);
        if (exitCode != 0 && !restart) return new(before.Id, before.Name, before.InstalledVersion, after?.InstalledVersion, WinGetStatus.Failed, exitCode, ExitText(exitCode), false);
        if (after is not null && !IsUnknownVersion(after.InstalledVersion) && after.InstalledVersion != before.InstalledVersion && after.AvailableVersion.Length == 0)
        {
            return new(before.Id, before.Name, before.InstalledVersion, after.InstalledVersion, WinGetStatus.Updated, exitCode, restart ? "Updated. Restart required." : "Updated.", restart);
        }

        if (after is not null && after.InstalledVersion == before.InstalledVersion && after.AvailableVersion.Length > 0 && !restart)
        {
            return new(before.Id, before.Name, before.InstalledVersion, after.InstalledVersion, WinGetStatus.Failed, exitCode, "Completed, but the update is still offered.", false);
        }

        return new(before.Id, before.Name, before.InstalledVersion, after?.InstalledVersion, WinGetStatus.Unknown, exitCode, restart ? "Restart required. Verification unavailable." : "Completed. Verification unavailable.", restart);
    }
}
