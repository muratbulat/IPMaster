using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Infrastructure.Tools;

public sealed record WinGetInfo(bool Available, string Version, string Message);

public sealed record WinGetInventory(IReadOnlyList<WinGetPackage> Packages, string Error);

/// <summary>Tools → WinGet Manager (D-106). Listing is read-only; <see cref="UpgradeAsync"/> is the only changing call.</summary>
public interface IWinGetService
{
    bool IsSupported { get; }

    Task<WinGetInfo> DetectAsync(CancellationToken ct);

    Task<WinGetInventory> ListAsync(CancellationToken ct);

    /// <summary>
    /// Upgrades one package by exact id and source. <paramref name="ct"/> only prevents the start: a running installer is
    /// never killed. Returns the exit code, or null when waiting stopped after <see cref="WinGetService.UpgradeTimeout"/>.
    /// </summary>
    Task<int?> UpgradeAsync(WinGetPackage package, bool acceptAgreements, Action<string> progress, CancellationToken ct);

    /// <summary>The package as WinGet reports it now (exact id and source), or null.</summary>
    Task<WinGetPackage?> ReadBackAsync(WinGetPackage package, CancellationToken ct);
}

/// <summary>The WinGet command line (winget.exe from PATH / App Installer alias), argument lists only, bounded output.</summary>
public sealed class WinGetService : IWinGetService
{
    public static readonly TimeSpan ListTimeout = TimeSpan.FromMinutes(3);
    public static readonly TimeSpan UpgradeTimeout = TimeSpan.FromMinutes(60);
    private const string Exe = "winget.exe";

    public bool IsSupported => OperatingSystem.IsWindows();

    public async Task<WinGetInfo> DetectAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return new(false, "", "Windows only.");
        try
        {
            var r = await RunAsync(["--version"], TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
            var v = r.Output.Trim();
            return r.ExitCode == 0 && v.StartsWith('v') ? new(true, v, "") : new(false, "", $"WinGet is unavailable. 'winget --version' failed ({WinGet.Hex(r.ExitCode)}).");
        }
        catch (InvalidOperationException)
        {
            return new(false, "", "WinGet is unavailable. Install or update App Installer from Microsoft.");
        }
    }

    public async Task<WinGetInventory> ListAsync(CancellationToken ct)
    {
        try
        {
            var pins = await RunAsync(["pin", "list", "--disable-interactivity"], ListTimeout, ct).ConfigureAwait(false);
            var list = await RunAsync(["list", "--disable-interactivity"], ListTimeout, ct).ConfigureAwait(false);
            if (list.ExitCode != 0) return new([], WinGet.ExitText(list.ExitCode) + " " + LastLine(list.Output));
            var packages = WinGet.ParseList(list.Output, pins.ExitCode == 0 ? WinGet.ParsePins(pins.Output) : null);
            if (packages.Count == 0 && list.Output.Trim().Length > 0 && WinGet.ParseTables(list.Output).Count == 0) return new([], "The WinGet output could not be read.");
            return new(packages, pins.ExitCode == 0 ? "" : "Pins could not be read; pinned packages may show as Update Available.");
        }
        catch (InvalidOperationException ex)
        {
            return new([], "WinGet is unavailable. " + ex.Message);
        }
        catch (TimeoutException)
        {
            return new([], "WinGet did not answer in time.");
        }
    }

    public async Task<WinGetPackage?> ReadBackAsync(WinGetPackage package, CancellationToken ct)
    {
        try
        {
            var r = await RunAsync(["list", "--id", package.Id, "--exact", "--source", package.Source, "--disable-interactivity"], ListTimeout, ct).ConfigureAwait(false);
            return r.ExitCode == 0 ? WinGet.ParseList(r.Output).FirstOrDefault(p => string.Equals(p.Id, package.Id, StringComparison.OrdinalIgnoreCase)) : null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException)
        {
            return null;
        }
    }

    public async Task<int?> UpgradeAsync(WinGetPackage package, bool acceptAgreements, Action<string> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!WinGet.IsEligible(package)) throw new InvalidOperationException("The package has no confirmed update.");
        var psi = Start(WinGet.UpgradeArguments(package, acceptAgreements));
        using var p = new Process { StartInfo = psi };
        try
        {
            p.Start();
        }
        catch (Win32Exception ex)
        {
            throw new InvalidOperationException("WinGet is unavailable: " + ex.Message, ex);
        }

        p.StandardInput.Close();
        var err = p.StandardError.ReadToEndAsync(CancellationToken.None);
        var buffer = new char[2048];
        var line = new StringBuilder();
        using var timeout = new CancellationTokenSource(UpgradeTimeout);
        try
        {
            int n;
            while ((n = await p.StandardOutput.ReadAsync(buffer, timeout.Token).ConfigureAwait(false)) > 0)
            {
                for (var i = 0; i < n; i++)
                {
                    var c = buffer[i];
                    if (c is '\r' or '\n')
                    {
                        var text = line.ToString().Trim();
                        if (text.Length > 1 && text.Any(char.IsLetter)) progress(text.Length > 200 ? text[..200] : text); // skip spinner frames
                        line.Clear();
                    }
                    else if (line.Length < 4096)
                    {
                        line.Append(c);
                    }
                }
            }

            await p.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
            await err.ConfigureAwait(false);
            return p.ExitCode;
        }
        catch (OperationCanceledException)
        {
            return null; // still running: the installer is left alone
        }
    }

    private static ProcessStartInfo Start(IEnumerable<string> args)
    {
        var psi = new ProcessStartInfo(Exe)
        {
            UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        return psi;
    }

    private static async Task<ProcessResult> RunAsync(IReadOnlyList<string> args, TimeSpan timeout, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        try
        {
            // listing only: cancelling or a timeout ends winget (nothing is installed by these commands)
            return await ProcessRunner.RunAsync(Exe, args, cts.Token, maxOutput: 8 * 1024 * 1024).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException();
        }
    }

    private static string LastLine(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault(l => l.Any(char.IsLetter)) ?? "";
}
