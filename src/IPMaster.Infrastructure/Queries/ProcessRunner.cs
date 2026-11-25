using System.Diagnostics;
using System.Text;

namespace IPMaster.Infrastructure.Queries;

public sealed record ProcessResult(int ExitCode, string Output, string Error, bool Truncated);

/// <summary>
/// Out-of-process execution for external tools and scripts (NMP-02): argument lists only (no shell
/// string), bounded stdout/stderr, cancellation kills the whole process tree. Running a script in another process
/// isolates crashes and hangs; it is not a security sandbox.
/// </summary>
public static class ProcessRunner
{
    public const int DefaultMaxOutput = 1024 * 1024;

    /// <summary>Lines starting with this marker are bridge requests from a script, not output.</summary>
    public const string BridgeMarker = "@@IPM@@ ";

    /// <param name="bridge">Called for each bridge request line (without the marker); a non-null return value is written to stdin as one line.</param>
    public static async Task<ProcessResult> RunAsync(string fileName, IEnumerable<string> arguments, CancellationToken cancellationToken,
        string? stdin = null, IReadOnlyDictionary<string, string>? environment = null, Func<string, Task<string?>>? bridge = null,
        int maxOutput = DefaultMaxOutput, string? workingDirectory = null, Encoding? outputEncoding = null)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var psi = new ProcessStartInfo(fileName)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Path.GetTempPath(),
            StandardOutputEncoding = outputEncoding ?? Encoding.UTF8,
            StandardErrorEncoding = outputEncoding ?? Encoding.UTF8,
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        if (environment is not null)
        {
            foreach (var (k, v) in environment) psi.Environment[k] = v;
        }

        using var p = new Process { StartInfo = psi };
        try
        {
            p.Start();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            throw new InvalidOperationException($"Could not start {Path.GetFileName(fileName)}: {ex.Message}", ex);
        }

        var output = new StringBuilder();
        var error = new StringBuilder();
        var truncated = false;
        await using var reg = cancellationToken.Register(() => Kill(p));
        if (stdin is not null)
        {
            await p.StandardInput.WriteLineAsync(stdin.AsMemory(), cancellationToken).ConfigureAwait(false);
            await p.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        if (bridge is null) p.StandardInput.Close();

        var errTask = Task.Run(async () =>
        {
            var buf = new char[4096];
            int n;
            while ((n = await p.StandardError.ReadAsync(buf, cancellationToken).ConfigureAwait(false)) > 0)
            {
                lock (error)
                {
                    if (error.Length < maxOutput) error.Append(buf, 0, Math.Min(n, maxOutput - error.Length));
                }
            }
        }, CancellationToken.None);

        try
        {
            // Chunked reading with a bounded line buffer: ReadLineAsync would buffer an endless line without limit (review C-16).
            async Task<bool> HandleLineAsync(string line)
            {
                if (bridge is not null && line.StartsWith(BridgeMarker, StringComparison.Ordinal))
                {
                    var reply = await bridge(line[BridgeMarker.Length..]).ConfigureAwait(false);
                    if (reply is not null)
                    {
                        await p.StandardInput.WriteLineAsync(reply.AsMemory(), cancellationToken).ConfigureAwait(false);
                        await p.StandardInput.FlushAsync(cancellationToken).ConfigureAwait(false);
                    }

                    return true;
                }

                if (output.Length + line.Length + 1 > maxOutput) return false;
                output.Append(line).Append('\n');
                return true;
            }

            var pending = new StringBuilder();
            var chunk = new char[8192];
            int read;
            while (!truncated && (read = await p.StandardOutput.ReadAsync(chunk.AsMemory(), cancellationToken).ConfigureAwait(false)) > 0)
            {
                for (var i = 0; i < read && !truncated; i++)
                {
                    var ch = chunk[i];
                    if (ch == '\n')
                    {
                        var line = pending.ToString().TrimEnd('\r');
                        pending.Clear();
                        truncated = !await HandleLineAsync(line).ConfigureAwait(false);
                    }
                    else
                    {
                        pending.Append(ch);
                        truncated = output.Length + pending.Length + 1 > maxOutput;
                    }
                }
            }

            if (!truncated && pending.Length > 0) truncated = !await HandleLineAsync(pending.ToString().TrimEnd('\r')).ConfigureAwait(false);
            if (truncated)
            {
                Kill(p);
                // keep what fits of the unfinished line (the bound applies to the whole output)
                var room = Math.Max(0, maxOutput - output.Length);
                output.Append(pending.ToString(0, Math.Min(room, pending.Length)));
                await p.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
                return new ProcessResult(-1, output.ToString().TrimEnd('\n'), "", true);
            }

            await p.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            await errTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            Kill(p);
            throw;
        }
        catch (IOException) when (truncated)
        {
            // pipe closed after the kill
        }

        string err;
        lock (error) err = error.ToString();
        return new ProcessResult(truncated ? -1 : p.ExitCode, output.ToString().TrimEnd('\n'), err.Trim(), truncated);
    }

    private static void Kill(Process p)
    {
        try
        {
            if (!p.HasExited) p.Kill(entireProcessTree: true);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // already gone
        }
    }

    /// <summary>Finds an executable on PATH (Windows: also tries .exe).</summary>
    public static string? FindOnPath(string name)
    {
        var dirs = (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);
        var names = OperatingSystem.IsWindows() && !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? new[] { name + ".exe", name } : [name];
        foreach (var d in dirs)
        {
            foreach (var n in names)
            {
                try
                {
                    var full = Path.Combine(d.Trim('"'), n);
                    if (File.Exists(full)) return full;
                }
                catch (ArgumentException)
                {
                    // invalid PATH entry
                }
            }
        }

        return null;
    }

    /// <summary>Splits a command-line fragment into arguments (double quotes group; no shell expansion).</summary>
    public static IReadOnlyList<string> SplitArguments(string text)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        var quoted = false;
        var any = false;
        foreach (var c in text ?? "")
        {
            if (c == '"')
            {
                quoted = !quoted;
                any = true;
            }
            else if (char.IsWhiteSpace(c) && !quoted)
            {
                if (any) list.Add(sb.ToString());
                sb.Clear();
                any = false;
            }
            else
            {
                sb.Append(c);
                any = true;
            }
        }

        if (any) list.Add(sb.ToString());
        return list;
    }
}

/// <summary>
/// Host side of the script bridge (VBS-01..03, PY-01). Scripts write <c>@@IPM@@ op hex1 hex2</c> lines; arguments and
/// replies are UTF-16 code units in hex (4 digits each) so any text survives console code pages. Replies: <c>ok hex</c> or
/// <c>err hex</c>. <c>out</c> requests carry Output.Write text and get no reply.
/// </summary>
public sealed class ScriptBridge(Core.Queries.IQueryContext context, Func<string, string, CancellationToken, Task<string>>? extra, CancellationToken cancellationToken)
{
    private readonly StringBuilder _output = new();

    public string Output => _output.ToString().TrimEnd('\n');

    public bool WroteOutput { get; private set; }

    public static string Hex(string s)
    {
        var sb = new StringBuilder(s.Length * 4);
        foreach (var c in s) sb.Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    public static string Unhex(string hex)
    {
        if (hex.Length % 4 != 0) throw new FormatException("Bridge argument has an invalid length.");
        var chars = new char[hex.Length / 4];
        for (var i = 0; i < chars.Length; i++) chars[i] = (char)Convert.ToUInt16(hex.Substring(i * 4, 4), 16);
        return new string(chars);
    }

    /// <summary>Handles one request; returns the reply line, or null for <c>out</c> (no reply expected).</summary>
    public async Task<string?> HandleAsync(string request)
    {
        var parts = request.Split(' ');
        var op = parts[0];
        string Arg(int i) => parts.Length > i ? Unhex(parts[i]) : "";
        try
        {
            switch (op)
            {
                case "out":
                    if (_output.Length < ProcessRunner.DefaultMaxOutput) _output.Append(Arg(1)).Append('\n');
                    WroteOutput = true;
                    return null;
                case "column":
                    return "ok " + Hex(context.Column(Arg(1)));
                case "remote":
                    return "ok " + Hex(await context.RemoteAsync(Arg(1), Arg(2), cancellationToken).ConfigureAwait(false));
                default:
                    if (extra is null) return "err " + Hex($"Unknown request '{op}'.");
                    return "ok " + Hex(await extra(op, string.Join('\u0001', parts.Skip(1).Select(Unhex)), cancellationToken).ConfigureAwait(false));
            }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return "err " + Hex(ex.Message);
        }
    }
}
