using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Avalonia;

namespace IPMaster.Desktop;

/// <summary>
/// Entry point of the single IPMaster executable (D-103). <see cref="LaunchRouter"/> picks the mode; CLI mode runs
/// <see cref="Cli.CliHost"/> and never initialises Avalonia; GUI mode starts the desktop lifetime.
/// </summary>
internal static partial class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // elevated KMS helper (D-104): started by IPMaster itself with "runas"; never shows a window
        if (args is [Infrastructure.Tools.KmsHelper.Switch, var request]) return Infrastructure.Tools.KmsHelper.Run(request);
        var decision = LaunchRouter.Decide(args);
        switch (decision.Mode)
        {
            case LaunchMode.Cli:
                return Cli.CliHost.RunAsync(decision.Args).GetAwaiter().GetResult();
            case LaunchMode.Help:
                Console.Out.WriteLine(decision.Message);
                return 0;
            case LaunchMode.Error:
                Console.Error.WriteLine(decision.Message);
                return Cli.ExitCodes.Usage;
            default:
                ReleaseOwnConsole();
                return RunGui(decision.Args);
        }
    }

    /// <summary>Separate method: the Avalonia assemblies load only when the GUI really starts.</summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int RunGui(string[] args) => BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UsePlatformDetect().LogToTrace();

    /// <summary>
    /// Windows before 11 24H2 ignores the manifest's detached console policy and opens a console for a console-subsystem
    /// program started from Explorer. If that console belongs to IPMaster alone (no shell shares it), release it so the
    /// window closes; a console shared with a shell is left alone (D-103).
    /// </summary>
    private static void ReleaseOwnConsole()
    {
        if (!OperatingSystem.IsWindows() || GetConsoleWindow() == IntPtr.Zero) return;
        var ids = new uint[2];
        if (GetConsoleProcessList(ids, (uint)ids.Length) == 1) FreeConsole();
    }

    [LibraryImport("kernel32.dll")]
    private static partial IntPtr GetConsoleWindow();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetConsoleProcessList([Out] uint[] processList, uint processCount);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool FreeConsole();
}
