using IPMaster.Core.Targets;

namespace IPMaster.Cli;

public enum AutoDetectKind
{
    None,
    All,
    V4,
    V6,
}

public sealed class CommandLineOptions
{
    public bool Auto { get; set; }

    public string? AutoPath { get; set; }

    /// <summary>/live[:file]: background scanning until Ctrl+C; the file is rewritten after every complete round (CLI-11).</summary>
    public bool Live { get; set; }

    public string? LivePath { get; set; }

    public List<TargetSpec> Ranges { get; } = [];

    public AutoDetectKind AutoDetect { get; set; }

    public string? FilePath { get; set; }

    public List<string>? Columns { get; set; }

    public bool Hide { get; set; }

    public bool Yes { get; set; }

    public bool Quiet { get; set; }

    public bool Help { get; set; }

    public bool Version { get; set; }

    public string? LoadPath { get; set; }

    public string? ConfigPath { get; set; }

    public bool Append { get; set; }

    public bool Merge { get; set; }

    public bool SplitMultiValues { get; set; }

    public string? ShareTypes { get; set; }

    public List<string> WolMacs { get; } = [];

    public string? WolFile { get; set; }

    public bool WakeAll { get; set; }

    public bool IsWol => WolMacs.Count > 0 || WolFile is not null || WakeAll;

    /// <summary>Recognised manual switches that this build does not implement yet (never silently ignored).</summary>
    public List<string> NotImplemented { get; } = [];

    /// <summary>Master password from <c>/mpass</c>; <c>-</c> reads it from stdin. Never echoed (D-008).</summary>
    public string? MasterPassword { get; set; }

    public List<string> Errors { get; } = [];

    /// <summary>Redacted echo of the command line for logs (D-008: secrets never printed).</summary>
    public List<string> Redacted { get; } = [];
}

/// <summary>
/// Parses the manual's slash switches (<c>/auto:file</c>, <c>/range:a-b,c-d#N</c>, ...). <c>-switch</c> and
/// <c>--switch=value</c> forms are accepted as well. Values are taken after the first ':' (or '='), so Windows
/// paths such as <c>/auto:c:\out.csv</c> work.
/// </summary>
public static class CommandLineParser
{
    private static readonly Dictionary<string, string> FutureSwitches = new(StringComparer.OrdinalIgnoreCase)
    {
    };

    public static CommandLineOptions Parse(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        var o = new CommandLineOptions();
        foreach (var arg in args)
        {
            if (!TrySplit(arg, out var name, out var value))
            {
                o.Errors.Add($"Unexpected argument '{arg}'. Switches start with '/'.");
                o.Redacted.Add(arg);
                continue;
            }

            o.Redacted.Add(name.Equals("mpass", StringComparison.OrdinalIgnoreCase) ? "/mpass:***" : arg);
            switch (name.ToLowerInvariant())
            {
                case "auto":
                    o.Auto = true;
                    o.AutoPath = string.IsNullOrWhiteSpace(value) ? null : value.Trim().Trim('"');
                    break;
                case "range":
                    ParseRange(value, o);
                    break;
                case "file":
                    if (string.IsNullOrWhiteSpace(value)) o.Errors.Add("/file requires a file name.");
                    else o.FilePath = value.Trim().Trim('"');
                    break;
                case "cols":
                    if (string.IsNullOrWhiteSpace(value)) o.Errors.Add("/cols requires column names separated by ';'.");
                    else o.Columns = value.Trim('"').Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
                    break;
                case "load":
                    if (string.IsNullOrWhiteSpace(value)) o.Errors.Add("/load requires an XML results file.");
                    else o.LoadPath = value.Trim().Trim('"');
                    break;
                case "config":
                    if (string.IsNullOrWhiteSpace(value)) o.Errors.Add("/config requires an XML configuration file.");
                    else o.ConfigPath = value.Trim().Trim('"');
                    break;
                case "append":
                    o.Append = true;
                    break;
                case "merge":
                    o.Merge = true;
                    break;
                case "splitmv":
                    o.SplitMultiValues = true;
                    break;
                case "sharetype":
                    var letters = (value ?? "").Trim().Trim('"').ToUpperInvariant();
                    if (letters.Length == 0 || letters.Any(ch => !"CRWAP".Contains(ch, StringComparison.Ordinal))) o.Errors.Add("/sharetype takes letters C, R, W, A, P (e.g. /sharetype:CW).");
                    else o.ShareTypes = letters;
                    break;
                case "wol":
                    if (string.IsNullOrWhiteSpace(value)) o.Errors.Add("/wol requires a MAC address, e.g. /wol:AABBCCDDEEFF.");
                    else o.WolMacs.Add(value.Trim().Trim('"'));
                    break;
                case "wolfile":
                    if (string.IsNullOrWhiteSpace(value)) o.Errors.Add("/wolfile requires a file name.");
                    else o.WolFile = value.Trim().Trim('"');
                    break;
                case "wakeall":
                    o.WakeAll = true;
                    break;
                case "live":
                    o.Live = true;
                    o.LivePath = string.IsNullOrWhiteSpace(value) ? null : value.Trim().Trim('"');
                    break;
                case "mpass":
                    o.MasterPassword = value;
                    break;
                case "hide":
                    o.Hide = true;
                    break;
                case "yes":
                    o.Yes = true;
                    break;
                case "quiet":
                    o.Quiet = true;
                    break;
                case "?":
                case "h":
                case "help":
                    o.Help = true;
                    break;
                case "version":
                    o.Version = true;
                    break;
                default:
                    if (FutureSwitches.TryGetValue(name, out var phase)) o.NotImplemented.Add($"/{name.ToLowerInvariant()} ({phase})");
                    else o.Errors.Add($"Unknown switch '/{name}'.");
                    break;
            }
        }

        return o;
    }

    private static bool TrySplit(string arg, out string name, out string? value)
    {
        name = "";
        value = null;
        string body;
        if (arg.StartsWith("--", StringComparison.Ordinal)) body = arg[2..];
        else if (arg.Length > 1 && (arg[0] == '/' || arg[0] == '-')) body = arg[1..];
        else return false;

        var sep = body.IndexOfAny([':', '=']);
        if (sep < 0)
        {
            name = body;
            return name.Length > 0;
        }

        name = body[..sep];
        value = body[(sep + 1)..];
        return name.Length > 0;
    }

    private static void ParseRange(string? value, CommandLineOptions o)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            o.Errors.Add("/range requires a range, e.g. /range:192.168.0.1-192.168.0.254 or /range:v4.");
            return;
        }

        var v = value.Trim().Trim('"');
        switch (v.ToLowerInvariant())
        {
            case "all":
                o.AutoDetect = AutoDetectKind.All;
                return;
            case "v4":
                o.AutoDetect = o.AutoDetect == AutoDetectKind.V6 ? AutoDetectKind.All : AutoDetectKind.V4;
                return;
            case "v6":
                o.AutoDetect = o.AutoDetect == AutoDetectKind.V4 ? AutoDetectKind.All : AutoDetectKind.V6;
                return;
        }

        foreach (var part in v.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var octet = part.EndsWith("#N", StringComparison.OrdinalIgnoreCase);
            var text = octet ? part[..^2] : part;
            if (TargetParser.TryParse(text, octet, out var spec, out var error)) o.Ranges.Add(spec);
            else o.Errors.Add($"/range: {error}");
        }
    }

    public const string Usage = """
        IPMaster command line

        Usage: IPMaster [--cli] /auto[:file] [/range:...] [/file:list.txt] [/load:results.xml] [/config:config.xml]
                        [/cols:"Col1;Col2"] [/append | /merge] [/splitmv] [/sharetype:CRWAP] [/yes] [/quiet]

          /auto[:file]     Scan with saved settings and export. Format from the extension:
                           .csv .txt .htm .html .xml .json .db (SQLite: DEVICE and SHARE tables).
                           Date/time tokens: %yyyy% %yy% %mm% %mmm% %dd% %ddd% %hh% %nn% %ss% ...
                           Without a file name, results are written to stdout as tab-separated text.
          /range:a-b,c/24  Comma-separated ranges (IPv4/IPv6, CIDR, host names). Append #N for octet mode.
          /range:all|v4|v6 Auto-detect ranges from local adapters.
          /file:list.txt   Targets from a text file (one address/range/CIDR/host name per line).
          /load:file.xml   Load saved XML results; with /auto the listed devices are rescanned and re-exported.
          /config:file.xml Use this XML configuration instead of the saved settings (not persisted).
          /cols:"A;B"      Export only these columns (header names or ids).
          /append          Text/CSV only: append rows to an existing file.
          /merge           Text/CSV only: merge with an existing file; lines sorted, duplicates removed.
          /splitmv         Text/CSV only: one row per value of multi-value cells.
          /sharetype:CW    Export only shares of these types: C common, R restricted, W writable,
                           A administrative, P printer.
          /wol:AABBCCDDEEFF  Send a Wake-on-LAN packet (WOL manager default destination and port) and exit.
          /wolfile:macs.txt Wake every MAC listed in the file (one per line) and exit.
          /wakeall         Wake every device in the WOL manager and exit.
          /live[:file]     Background scanning (Browsing tab mode and delay) until Ctrl+C; the file
                           is rewritten after every complete round. Events go to stderr.
          /mpass:-         Read the master password of an encrypted configuration from stdin (first line).
                           /mpass:secret also works but exposes the password to other local users; the
                           IPMASTER_MPASS environment variable is used when /mpass is absent.
          /hide            Accepted for compatibility; the CLI never shows a window.
          /yes             Confirm scans larger than the confirmation threshold.
          /quiet           No progress output on stderr.
          /help, /version

        Exit codes: 0 ok, 1 usage, 2 invalid/empty/oversized targets, 3 settings error,
                    4 output error, 5 switch not implemented in this build, 6 scan failed,
                    130 cancelled (Ctrl+C).
        """;
}
