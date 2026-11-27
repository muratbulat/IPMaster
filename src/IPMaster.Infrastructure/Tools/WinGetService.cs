using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Infrastructure.Tools;

public sealed record WinGetInfo(bool Available, string Version, string Message);

public sealed record WinGetInventory(IReadOnlyList<WinGetPackage> Packages, string Error);

public sealed record WinGetSearchResult(IReadOnlyList<WinGetSearchHit> Hits, string Error);

/// <summary>Tools → WinGet Manager (D-106, D-109). Listing and search are read-only; <see cref="UpgradeAsync"/> and <see cref="InstallAsync"/> change the system.</summary>
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

    /// <summary>Installs one search hit by exact id and source; same rules as <see cref="UpgradeAsync"/>.</summary>
    Task<int?> InstallAsync(WinGetSearchHit hit, bool acceptAgreements, Action<string> progress, CancellationToken ct);

    /// <summary>
    /// An installer started here outlived <see cref="WinGetService.UpgradeTimeout"/> and is still running. It is never
    /// killed; no new install or update starts until it ends (overlapping installers fail or confuse the result).
    /// </summary>
    bool InstallerRunning { get; }

    /// <summary>Catalog search (<c>winget search</c>), at most <see cref="WinGet.SearchLimit"/> hits.</summary>
    Task<WinGetSearchResult> SearchAsync(string query, CancellationToken ct);

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
            // no --source: with it WinGet drops the Source column and the table no longer parses; the source is matched below
            var r = await RunAsync(["list", "--id", package.Id, "--exact", "--disable-interactivity"], ListTimeout, ct).ConfigureAwait(false);
            return r.ExitCode == 0
                ? WinGet.ParseList(r.Output).FirstOrDefault(p => string.Equals(p.Id, package.Id, StringComparison.OrdinalIgnoreCase) && string.Equals(p.Source, package.Source, StringComparison.OrdinalIgnoreCase))
                : null;
        }
        catch (Exception ex) when (ex is InvalidOperationException or TimeoutException)
        {
            return null;
        }
    }

    public async Task<WinGetSearchResult> SearchAsync(string query, CancellationToken ct)
    {
        if (query.Trim().Length == 0) return new([], "Enter a name, id, moniker or tag.");
        try
        {
            var r = await RunAsync(WinGet.SearchArguments(query), ListTimeout, ct).ConfigureAwait(false);
            if (unchecked((uint)r.ExitCode) == 0x8A150014) return new([], "No package found.");
            if (r.ExitCode != 0) return new([], WinGet.ExitText(r.ExitCode).Replace("Update failed", "Search failed", StringComparison.Ordinal) + " " + LastLine(r.Output));
            var hits = WinGet.ParseSearch(r.Output);
            return hits.Count == 0 && r.Output.Trim().Length > 0 ? new([], "The WinGet output could not be read.") : new(hits, "");
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

    public Task<int?> UpgradeAsync(WinGetPackage package, bool acceptAgreements, Action<string> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!WinGet.IsEligible(package)) throw new InvalidOperationException("The package has no confirmed update.");
        return RunInstallerAsync(WinGet.UpgradeArguments(package, acceptAgreements), progress);
    }

    public Task<int?> InstallAsync(WinGetSearchHit hit, bool acceptAgreements, Action<string> progress, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!WinGet.IsInstallable(hit)) throw new InvalidOperationException("The package has no source to install from.");
        return RunInstallerAsync(WinGet.InstallArguments(hit, acceptAgreements), progress);
    }

    private volatile Process? _unfinished;

    public bool InstallerRunning
    {
        get
        {
            var p = _unfinished;
            if (p is null) return false;
            if (!p.HasExited) return true;
            _unfinished = null;
            p.Dispose();
            return false;
        }
    }

    /// <summary>Runs an installing command to the end (never killed); null when waiting stopped after <see cref="UpgradeTimeout"/>.</summary>
    private async Task<int?> RunInstallerAsync(IReadOnlyList<string> args, Action<string> progress)
    {
        if (InstallerRunning) throw new InvalidOperationException(WinGet.StillRunning);
        var psi = Start(args);
        var p = new Process { StartInfo = psi };
        var left = false;
        try
        {
            p.Start();
        }
        catch (Win32Exception ex)
        {
            p.Dispose();
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
            // still running: the installer is left alone, and remembered so nothing new starts beside it
            _unfinished = p;
            left = true;
            return null;
        }
        finally
        {
            if (!left) p.Dispose();
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
