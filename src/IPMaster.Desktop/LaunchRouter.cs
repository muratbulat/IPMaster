namespace IPMaster.Desktop;

public enum LaunchMode
{
    Gui,
    Cli,
    Help,
    Error,
}

public sealed record LaunchDecision(LaunchMode Mode, string[] Args, string Message = "");

/// <summary>
/// Decides GUI or CLI for the single IPMaster executable (D-103), deterministically and without guessing:
/// <list type="bullet">
/// <item>no arguments → GUI;</item>
/// <item><c>--gui [args]</c> → GUI; <c>--cli [args]</c> → CLI (the rest goes to the existing command line);</item>
/// <item>first argument <c>--new-window</c> or <c>--range</c> (the GUI's own options) → GUI with all arguments;</item>
/// <item>first argument a slash switch (<c>/help</c>, <c>/range:…</c>, <c>/?</c>) → CLI (compatible with the former
/// <c>ipmaster</c> executable); <c>--version</c> → CLI <c>/version</c>;</item>
/// <item><c>--help</c>, <c>-h</c>, <c>-?</c> → the launcher's help;</item>
/// <item>anything else → an error message and a non-zero exit code, never an accidental GUI start.</item>
/// </list>
/// </summary>
public static class LaunchRouter
{
    public const string Usage = """
        IPMaster — one executable for the desktop app and the command line.

          IPMaster                       start the desktop app
          IPMaster --gui [--new-window] [--range <targets>]
          IPMaster --cli <switches>      command line, e.g. --cli /help, --cli /range:192.168.1.0/24 /file:out.csv
          IPMaster /<switch> ...         command line (switches as before: /help, /version, /range:..., /auto, /live)
          IPMaster --version             print the version
          IPMaster --help                this text
        """;

    private static readonly HashSet<string> GuiOptions = new(StringComparer.Ordinal) { "--new-window", "--range" };

    public static LaunchDecision Decide(IReadOnlyList<string> args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Count == 0) return new(LaunchMode.Gui, []);
        var first = args[0];
        var rest = args.Skip(1).ToArray();
        switch (first)
        {
            case "--gui":
                return new(LaunchMode.Gui, rest);
            case "--cli":
                return new(LaunchMode.Cli, rest.Length == 0 ? ["/help"] : rest);
            case "--help" or "-h" or "-?":
                return new(LaunchMode.Help, [], Usage);
            case "--version":
                return new(LaunchMode.Cli, ["/version"]);
        }

        if (GuiOptions.Contains(first)) return new(LaunchMode.Gui, [.. args]);
        if (first.Length > 1 && first[0] == '/' && (char.IsLetter(first[1]) || first[1] == '?')) return new(LaunchMode.Cli, [.. args]);
        return new(LaunchMode.Error, [], $"Unknown argument '{first}'. Start IPMaster without arguments for the desktop app, or see 'IPMaster --help'.");
    }
}
