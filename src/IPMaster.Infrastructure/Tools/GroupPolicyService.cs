using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;

namespace IPMaster.Infrastructure.Tools;

public sealed record GpoResult(GpoReport? Report, string Error);

/// <summary>Tools → Group Policy Viewer (D-107). Read-only: only <c>gpresult</c> reporting switches are used.</summary>
public interface IGroupPolicyService
{
    bool IsSupported { get; }

    Task<GpoResult> CollectAsync(CancellationToken ct);

    /// <summary>Writes gpresult's own report (HTML or XML, both scopes) to <paramref name="path"/>; null = success, else the error.</summary>
    Task<string?> ExportNativeAsync(bool html, string path, CancellationToken ct);
}

/// <summary>
/// Local RSoP through <c>gpresult.exe /scope computer|user /x</c> (argument lists, 2-minute timeout, cancellable). Reports
/// are written to a new folder under the user's temp folder (per-user ACL) and deleted afterwards.
/// </summary>
public sealed class WindowsGroupPolicyService : IGroupPolicyService
{
    public static readonly TimeSpan Timeout = TimeSpan.FromMinutes(2);

    public bool IsSupported => OperatingSystem.IsWindows();

    private static string Exe => Path.Combine(Environment.SystemDirectory, "gpresult.exe");

    public async Task<GpoResult> CollectAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return new(null, "Windows only.");
        if (!File.Exists(Exe)) return new(null, "RSoP unavailable: gpresult.exe was not found.");
        var dir = Directory.CreateTempSubdirectory("ipmaster-gpo-");
        try
        {
            var parts = new List<(DateTimeOffset?, IReadOnlyList<GpoScopeInfo>, IReadOnlyList<GpoEntry>, IReadOnlyList<GpoSetting>)>();
            var errors = new List<string>();
            foreach (var scope in new[] { GpoScope.Computer, GpoScope.User })
            {
                var file = Path.Combine(dir.FullName, scope + ".xml");
                var (xml, error) = await RunAsync(["/scope", scope.ToString().ToLowerInvariant(), "/x", file, "/f"], file, ct).ConfigureAwait(false);
                if (xml is null)
                {
                    parts.Add((null, [new GpoScopeInfo { Scope = scope, Available = false, Message = error }], [], []));
                    errors.Add($"{scope}: {error}");
                    continue;
                }

                try
                {
                    parts.Add(GroupPolicy.Parse(xml));
                }
                catch (GpoReportException ex)
                {
                    parts.Add((null, [new GpoScopeInfo { Scope = scope, Available = false, Message = ex.Message }], [], []));
                    errors.Add($"{scope}: {ex.Message}");
                }
            }

            var report = GroupPolicy.Combine(DateTimeOffset.Now, [.. parts]);
            return new(report, errors.Count == 2 ? string.Join(" ", errors) : "");
        }
        finally
        {
            Delete(dir);
        }
    }

    public async Task<string?> ExportNativeAsync(bool html, string path, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return "Windows only.";
        var dir = Directory.CreateTempSubdirectory("ipmaster-gpo-");
        try
        {
            var file = Path.Combine(dir.FullName, html ? "report.html" : "report.xml");
            var (content, error) = await RunAsync([html ? "/h" : "/x", file, "/f"], file, ct).ConfigureAwait(false);
            if (content is null) return error;
            File.Copy(file, path, overwrite: true); // explicit user export only
            return null;
        }
        finally
        {
            Delete(dir);
        }
    }

    /// <summary>Runs gpresult; returns the written file's text, or null and a short error (with gpresult's own message).</summary>
    private static async Task<(string? Text, string Error)> RunAsync(IReadOnlyList<string> args, string file, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Timeout);
        ProcessResult r;
        try
        {
            r = await ProcessRunner.RunAsync(Exe, args, cts.Token, outputEncoding: System.Text.Encoding.Default).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return (null, "Report failed: gpresult did not finish in time.");
        }
        catch (InvalidOperationException ex)
        {
            return (null, "RSoP unavailable: " + ex.Message);
        }

        var message = (r.Error.Trim().Length > 0 ? r.Error : r.Output).Trim();
        if (r.ExitCode != 0 || !File.Exists(file))
        {
            var denied = message.Contains("denied", StringComparison.OrdinalIgnoreCase) || r.ExitCode == 5;
            return (null, (denied ? "Access denied." : "Report failed.") + (message.Length > 0 ? " " + Short(message) : $" (exit {r.ExitCode})"));
        }

        return (await File.ReadAllTextAsync(file, ct).ConfigureAwait(false), "");
    }

    private static string Short(string s) => s.Length > 300 ? s[..300] + "…" : s.Replace("\r\n", " ", StringComparison.Ordinal);

    private static void Delete(DirectoryInfo dir)
    {
        try
        {
            dir.Delete(true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
