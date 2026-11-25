using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Infrastructure.Tools;

/// <summary>Tools → iPerf Network Performance (D-108). No engine is bundled or downloaded; installed ones are detected.</summary>
public interface IIperfService
{
    /// <summary>Engines found: the configured executable first, then iperf3 / iperf / iperf2 on PATH (each probed with -v).</summary>
    Task<IReadOnlyList<IperfEngine>> DetectAsync(string configuredPath, CancellationToken ct);

    /// <summary>The engine at <paramref name="path"/>, or null when it does not answer as iperf2/iperf3.</summary>
    Task<IperfEngine?> ProbeAsync(string path, CancellationToken ct);

    /// <summary>Starts the engine with an argument list. Output arrives in chunks on a background thread.</summary>
    IIperfProcess Start(IperfEngine engine, IReadOnlyList<string> arguments, Action<string> stdout, Action<string> stderr);
}

/// <summary>One engine process started and owned by IPMaster.</summary>
public interface IIperfProcess : IDisposable
{
    /// <summary>Completes with the exit code when the process and its output streams have ended.</summary>
    Task<int> Completion { get; }

    /// <summary>Ends this process (and its children) only; never other iperf processes.</summary>
    void Stop();
}

public sealed class IperfService : IIperfService
{
    private static readonly string[] Names = OperatingSystem.IsWindows() ? ["iperf3.exe", "iperf.exe", "iperf2.exe"] : ["iperf3", "iperf", "iperf2"];

    public async Task<IReadOnlyList<IperfEngine>> DetectAsync(string configuredPath, CancellationToken ct)
    {
        var paths = new List<string>();
        if (configuredPath.Trim().Length > 0) paths.Add(configuredPath.Trim());
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            foreach (var n in Names)
            {
                string full;
                try
                {
                    full = Path.Combine(dir.Trim('"'), n);
                }
                catch (ArgumentException)
                {
                    continue;
                }

                if (File.Exists(full) && !paths.Contains(full, StringComparer.OrdinalIgnoreCase)) paths.Add(full);
            }
        }

        var list = new List<IperfEngine>();
        foreach (var p in paths.Take(8))
        {
            if (await ProbeAsync(p, ct).ConfigureAwait(false) is { } e && !list.Any(x => x.Kind == e.Kind && x.Version == e.Version)) list.Add(e);
        }

        return list;
    }

    public async Task<IperfEngine?> ProbeAsync(string path, CancellationToken ct)
    {
        if (!File.Exists(path)) return null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var r = await ProcessRunner.RunAsync(path, ["-v"], cts.Token, maxOutput: 64 * 1024).ConfigureAwait(false);
            return Iperf.ParseVersion(path, r.Output + "\n" + r.Error); // iperf2 writes its version to stderr
        }
        catch (Exception ex) when (ex is InvalidOperationException or OperationCanceledException or IOException)
        {
            ct.ThrowIfCancellationRequested();
            return null;
        }
    }

    public IIperfProcess Start(IperfEngine engine, IReadOnlyList<string> arguments, Action<string> stdout, Action<string> stderr) => new EngineProcess(engine.Path, arguments, stdout, stderr);

    private sealed class EngineProcess : IIperfProcess
    {
        private readonly Process _p;

        public EngineProcess(string path, IReadOnlyList<string> args, Action<string> stdout, Action<string> stderr)
        {
            var psi = new ProcessStartInfo(path)
            {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8, WorkingDirectory = Path.GetTempPath(),
            };
            foreach (var a in args) psi.ArgumentList.Add(a);
            _p = new Process { StartInfo = psi };
            try
            {
                _p.Start();
            }
            catch (Win32Exception ex)
            {
                _p.Dispose();
                throw new InvalidOperationException($"{Path.GetFileName(path)} could not start: {ex.Message}", ex);
            }

            _p.StandardInput.Close();
            Completion = RunAsync(stdout, stderr);
        }

        public Task<int> Completion { get; }

        // both streams are read concurrently until EOF, so a full pipe never blocks the engine
        private async Task<int> RunAsync(Action<string> stdout, Action<string> stderr)
        {
            static async Task Pump(StreamReader r, Action<string> sink)
            {
                var buf = new char[16 * 1024];
                int n;
                while ((n = await r.ReadAsync(buf.AsMemory()).ConfigureAwait(false)) > 0) sink(new string(buf, 0, n));
            }

            await Task.WhenAll(Pump(_p.StandardOutput, stdout), Pump(_p.StandardError, stderr)).ConfigureAwait(false);
            await _p.WaitForExitAsync().ConfigureAwait(false);
            return _p.ExitCode;
        }

        public void Stop()
        {
            try
            {
                if (!_p.HasExited) _p.Kill(entireProcessTree: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
            {
                // already exited
            }
        }

        public void Dispose()
        {
            Stop();
            _p.Dispose();
        }
    }
}
