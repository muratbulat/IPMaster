using System.Diagnostics;
using IPMaster.Desktop;

namespace IPMaster.Tests;

/// <summary>Mode routing of the single executable (D-103): pure decisions, no process.</summary>
public class LaunchRouterTests
{
    [Fact]
    public void No_arguments_and_gui_options_start_the_gui()
    {
        Assert.Equal(LaunchMode.Gui, LaunchRouter.Decide([]).Mode);
        var newWindow = LaunchRouter.Decide(["--new-window", "--range", "10.0.0.0/24"]);
        Assert.Equal(LaunchMode.Gui, newWindow.Mode);
        Assert.Equal(["--new-window", "--range", "10.0.0.0/24"], newWindow.Args); // passed through unchanged
        Assert.Equal(LaunchMode.Gui, LaunchRouter.Decide(["--range", "10.0.0.1"]).Mode);
        var gui = LaunchRouter.Decide(["--gui", "--new-window"]);
        Assert.Equal(LaunchMode.Gui, gui.Mode);
        Assert.Equal(["--new-window"], gui.Args);
    }

    [Fact]
    public void Cli_explicitly_or_by_slash_switches()
    {
        Assert.Equal(["/range:192.168.1.1-192.168.1.254", "/file:r.csv"], LaunchRouter.Decide(["--cli", "/range:192.168.1.1-192.168.1.254", "/file:r.csv"]).Args);
        Assert.Equal(["/help"], LaunchRouter.Decide(["--cli"]).Args);
        Assert.Equal(LaunchMode.Cli, LaunchRouter.Decide(["/help"]).Mode);
        Assert.Equal(["/help"], LaunchRouter.Decide(["/help"]).Args);
        Assert.Equal(LaunchMode.Cli, LaunchRouter.Decide(["/?"]).Mode);
        Assert.Equal(["/version"], LaunchRouter.Decide(["--version"]).Args);
        Assert.Equal(LaunchMode.Help, LaunchRouter.Decide(["--help"]).Mode);
    }

    [Theory]
    [InlineData("--bogus")]
    [InlineData("scan")]
    [InlineData("-x")]
    [InlineData("/")]
    public void Anything_else_is_an_error_not_a_gui_start(string arg)
    {
        var d = LaunchRouter.Decide([arg]);
        Assert.Equal(LaunchMode.Error, d.Mode);
        Assert.Contains(arg, d.Message, StringComparison.Ordinal);
    }
}

/// <summary>
/// The built executable as a process (D-103): stdout, stderr, stdin and exit codes, as scripts and CI use it. Never
/// starts the GUI (no test passes no arguments or a GUI option).
/// </summary>
public class UnifiedExecutableTests
{
    private static readonly TimeSpan Cap = TimeSpan.FromSeconds(60);

    private static string Exe()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "IPMaster.slnx"))) dir = dir.Parent;
        var config = AppContext.BaseDirectory.Contains($"{Path.DirectorySeparatorChar}Release{Path.DirectorySeparatorChar}", StringComparison.Ordinal) ? "Release" : "Debug";
        var path = Path.Combine(dir!.FullName, "src", "IPMaster.Desktop", "bin", config, "net10.0", OperatingSystem.IsWindows() ? "IPMaster.exe" : "IPMaster");
        Assert.True(File.Exists(path), "build the solution first: " + path);
        return path;
    }

    private static async Task<(int Code, string Out, string Err)> Run(string[] args, string? stdin = null, string? configDir = null)
    {
        var psi = new ProcessStartInfo(Exe()) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        psi.Environment["IPMASTER_CONFIG_DIR"] = configDir ?? Path.Combine(Path.GetTempPath(), "ipmaster-exe-" + Guid.NewGuid().ToString("N"));
        using var p = Process.Start(psi)!;
        if (stdin is not null) await p.StandardInput.WriteAsync(stdin);
        p.StandardInput.Close();
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync().WaitAsync(Cap);
        return (p.ExitCode, await stdout, await stderr);
    }

    [Theory]
    [InlineData("--cli", "/version")]
    [InlineData("/version", null)]
    [InlineData("--version", null)]
    public async Task Version_goes_to_stdout_with_exit_code_zero(string a, string? b)
    {
        var (code, stdout, stderr) = await Run(b is null ? [a] : [a, b]);
        Assert.Equal(0, code);
        Assert.Matches(@"^IPMaster \d+\.\d+\.\d+", stdout);
        Assert.Equal("", stderr);
    }

    [Fact]
    public async Task Help_is_redirectable_and_complete()
    {
        var (code, stdout, _) = await Run(["--cli", "/help"]);
        Assert.Equal(0, code);
        Assert.Contains("/range", stdout, StringComparison.Ordinal);
        var launcher = await Run(["--help"]);
        Assert.Equal(0, launcher.Code);
        Assert.Contains("--cli <switches>", launcher.Out, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Errors_go_to_stderr_with_a_non_zero_exit_code()
    {
        var unknown = await Run(["--bogus"]);
        Assert.Equal(1, unknown.Code);
        Assert.Equal("", unknown.Out);
        Assert.Contains("Unknown argument '--bogus'", unknown.Err, StringComparison.Ordinal);
        var badSwitch = await Run(["--cli", "/nosuchswitch"]);
        Assert.NotEqual(0, badSwitch.Code);
        Assert.NotEqual("", badSwitch.Err);
    }

    [Fact]
    public async Task Stdin_supplies_the_master_password_of_a_protected_configuration()
    {
        var dir = Path.Combine(Path.GetTempPath(), "ipmaster-exe-mpass-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new IPMaster.Infrastructure.Configuration.SettingsStore(dir);
            store.Load();
            await store.SaveAsync(store.Vault.SetMasterPassword(new IPMaster.Core.Configuration.AppSettings(), "correct horse", iterations: 100_000), TestContext.Current.CancellationToken);
            var output = Path.Combine(dir, "out.csv");
            var ok = await Run(["--cli", "/range:127.0.0.1", "/auto:" + output, "/mpass:-"], "correct horse\n", dir);
            Assert.True(ok.Code == 0, ok.Err);
            Assert.True(File.Exists(output));
            var wrong = await Run(["--cli", "/range:127.0.0.1", "/auto:" + output, "/mpass:-"], "wrong\n", dir);
            Assert.Equal(IPMaster.Cli.ExitCodes.Settings, wrong.Code);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Cli_mode_never_loads_avalonia()
    {
        Assert.SkipUnless(OperatingSystem.IsWindows(), "module inspection uses Windows process modules");
        var dir = Path.Combine(Path.GetTempPath(), "ipmaster-exe-live-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        var psi = new ProcessStartInfo(Exe()) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in new[] { "--cli", "/live", "/range:127.0.0.1", "/file:" + Path.Combine(dir, "live.csv") }) psi.ArgumentList.Add(a);
        psi.Environment["IPMASTER_CONFIG_DIR"] = dir;
        using var p = Process.Start(psi)!;
        try
        {
            await Task.Delay(3000, TestContext.Current.CancellationToken); // CLI running (a /live session)
            Assert.False(p.HasExited, "the /live session should still run");
            p.Refresh();
            var modules = p.Modules.Cast<ProcessModule>().Select(m => m.ModuleName).ToList();
            Assert.Contains(modules, m => m.Equals("IPMaster.Cli.dll", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(modules, m => m.StartsWith("Avalonia", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            p.Kill(entireProcessTree: true);
            await p.WaitForExitAsync().WaitAsync(Cap);
            Directory.Delete(dir, recursive: true);
        }
    }
}
