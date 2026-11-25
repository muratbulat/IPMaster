using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Sockets;
using System.Reflection;
using IPMaster.Core.Configuration;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Export;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Cli;

public static class ExitCodes
{
    public const int Ok = 0;
    public const int Usage = 1;
    public const int Targets = 2;
    public const int Settings = 3;
    public const int Output = 4;
    public const int NotImplemented = 5;
    public const int ScanFailed = 6;
    public const int Cancelled = 130;
}

/// <summary>Headless entry point. Uses the same application services as the desktop app; never touches a display.</summary>
public sealed class CliApp
{
    private readonly IServiceProvider _services;
    private readonly TextWriter _out;
    private readonly TextWriter _err;
    private readonly Func<DateTime> _now;
    private readonly TextReader _in;

    public CliApp(IServiceProvider services, TextWriter stdout, TextWriter stderr, Func<DateTime>? now = null, TextReader? stdin = null)
    {
        _in = stdin ?? Console.In;
        _services = services;
        _out = stdout;
        _err = stderr;
        _now = now ?? (() => DateTime.Now);
    }

    public async Task<int> RunAsync(IReadOnlyList<string> args, CancellationToken cancellationToken)
    {
        var o = CommandLineParser.Parse(args);
        if (o.Help)
        {
            await _out.WriteLineAsync(CommandLineParser.Usage);
            return ExitCodes.Ok;
        }

        if (o.Version)
        {
            await _out.WriteLineAsync("IPMaster " + (Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "?"));
            return ExitCodes.Ok;
        }

        if (o.Errors.Count > 0)
        {
            foreach (var e in o.Errors) await _err.WriteLineAsync("error: " + e);
            await _err.WriteLineAsync("Run 'IPMaster --cli /help' for usage.");
            return ExitCodes.Usage;
        }

        if (o.NotImplemented.Count > 0)
        {
            await _err.WriteLineAsync("error: not implemented in this build: " + string.Join(", ", o.NotImplemented));
            return ExitCodes.NotImplemented;
        }

        if (o.IsWol) return await WakeAsync(o, cancellationToken);
        if (o.Live) return await LiveAsync(o, cancellationToken);

        if (!o.Auto)
        {
            await _err.WriteLineAsync("error: nothing to do. Use /auto[:file] to run a scan (see /help).");
            return ExitCodes.Usage;
        }

        if (o.Append && o.Merge)
        {
            await _err.WriteLineAsync("error: /append and /merge cannot be combined.");
            return ExitCodes.Usage;
        }

        string? outputPath = null;
        if (o.AutoPath is not null)
        {
            outputPath = FileNameTokens.Expand(o.AutoPath, _now());
            if (!ResultExport.IsSupported(outputPath))
            {
                await _err.WriteLineAsync($"error: unknown output extension '{Path.GetExtension(outputPath)}'. Supported: {string.Join(", ", ResultExport.Extensions)}.");
                return ExitCodes.Usage;
            }
        }

        if ((o.Append || o.Merge || o.SplitMultiValues) && outputPath is not null && !ResultExport.IsTextFormat(outputPath))
        {
            await _err.WriteLineAsync("error: /append, /merge and /splitmv apply to .txt and .csv output only.");
            return ExitCodes.Usage;
        }

        // settings
        var store = _services.GetRequiredService<SettingsStore>();
        AppSettings settings;
        if (o.ConfigPath is not null)
        {
            try
            {
                var loaded = ConfigXml.Load(o.ConfigPath, store);
                if (loaded.Status == SettingsLoadStatus.NewerSchemaReadOnly)
                {
                    await _err.WriteLineAsync("error: " + loaded.Message);
                    return ExitCodes.Settings;
                }

                settings = loaded.Settings;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or System.Xml.XmlException or System.Text.Json.JsonException)
            {
                await _err.WriteLineAsync($"error: cannot load configuration '{o.ConfigPath}': {ex.Message}");
                return ExitCodes.Settings;
            }
        }
        else
        {
            var (loadedSettings, exit) = await LoadSettingsAsync(o);
            if (loadedSettings is null) return exit;
            settings = loadedSettings;
        }

        var format = settings.Format with { ShareTypeFilter = o.ShareTypes };

        // columns
        IReadOnlyList<ResultColumn> columns = settings.DisplayColumns;
        if (o.Columns is not null)
        {
            var (cols, unknown) = ColumnCatalog.Select(o.Columns, settings.AvailableColumns.Concat(ColumnCatalog.All).DistinctBy(c => c.Id).ToList());
            if (unknown.Count > 0)
            {
                await _err.WriteLineAsync($"error: unknown column(s): {string.Join(", ", unknown)}. Available: {string.Join("; ", ColumnCatalog.All.Select(c => c.Header))}.");
                return ExitCodes.Usage;
            }

            columns = cols;
        }

        // loaded results (rescanned with /auto)
        ResultDocument? loadedDoc = null;
        if (o.LoadPath is not null)
        {
            try
            {
                loadedDoc = await ResultsXml.LoadAsync(o.LoadPath, cancellationToken);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or FormatException or System.Xml.XmlException)
            {
                await _err.WriteLineAsync($"error: cannot load results '{o.LoadPath}': {ex.Message}");
                return ExitCodes.Targets;
            }

            if (!o.Quiet) await _err.WriteLineAsync($"Loaded {loadedDoc.Devices.Count:N0} devices from {o.LoadPath}.");
        }

        // targets
        var specs = new List<TargetSpec>(o.Ranges);
        var adapters = _services.GetRequiredService<INetworkAdapterProvider>();
        if (o.AutoDetect != AutoDetectKind.None)
        {
            var skipped = new List<string>();
            var detected = LocalNetworks.AutoDetect(adapters.GetAdapters(),
                o.AutoDetect is AutoDetectKind.All or AutoDetectKind.V4,
                o.AutoDetect is AutoDetectKind.All or AutoDetectKind.V6, skipped);
            foreach (var s in skipped) await _err.WriteLineAsync("warning: " + s);
            specs.AddRange(detected);
            if (!o.Quiet)
            {
                await _err.WriteLineAsync("Detected: " + (detected.Count == 0 ? "(none)" : string.Join(", ", detected.Select(d => d.Original))));
            }
        }

        if (o.FilePath is not null)
        {
            var file = await ReadTargetFileAsync(o.FilePath, cancellationToken);
            if (file is null) return ExitCodes.Targets;
            specs.AddRange(file);
        }

        if (loadedDoc is not null)
        {
            specs.AddRange(loadedDoc.Devices.Select(d => new TargetSpec { Kind = TargetKind.SingleAddress, Start = d.Key, End = d.Key, Original = d.Key.ToString() }));
        }

        if (o.Ranges.Count == 0 && o.AutoDetect == AutoDetectKind.None && o.FilePath is null && loadedDoc is null)
        {
            var (saved, errors) = AppSettings.ParseRanges(settings.Ranges);
            foreach (var e in errors) await _err.WriteLineAsync("warning: saved range skipped: " + e);
            specs.AddRange(saved);
        }

        var planner = _services.GetRequiredService<ScanPlanner>();
        var built = await planner.PlanAsync(specs, settings, o.Yes, cancellationToken: cancellationToken);
        foreach (var w in built.Warnings) await _err.WriteLineAsync("warning: " + w);
        foreach (var e in built.Errors) await _err.WriteLineAsync((built.Status == PlanStatus.Ready || built.Status == PlanStatus.NeedsConfirmation ? "warning: " : "error: ") + e);
        switch (built.Status)
        {
            case PlanStatus.Empty:
            case PlanStatus.TooLarge:
                return ExitCodes.Targets;
            case PlanStatus.NeedsConfirmation:
                await _err.WriteLineAsync($"error: {built.RawCount:N0} addresses exceed the confirmation threshold ({settings.ConfirmationThreshold:N0}). Add /yes to proceed.");
                return ExitCodes.Targets;
        }

        using var queryPlan = _services.GetRequiredService<Infrastructure.Queries.QueryServices>().Plan(settings);
        var scanContext = Infrastructure.Queries.ScanContext.Resolve(settings, _services.GetRequiredService<Infrastructure.Security.CredentialVault>(),
            _services.GetRequiredService<Core.Network.INetworkAdapterProvider>());
        foreach (var warning in scanContext.Warnings) await _err.WriteLineAsync("warning: " + warning);
        if (queryPlan is not null && !o.Quiet)
        {
            await _err.WriteLineAsync($"Remote queries: {queryPlan.All.Count}" + (queryPlan.Graph.Errors.Count > 0 ? $" ({queryPlan.Graph.Errors.Count} cannot run: {string.Join("; ", queryPlan.Graph.Errors.Values.Distinct())})" : ""));
        }

        var exact = built.Plan.RawCount <= 4_000_000 ? built.Plan.CountExact(cancellationToken) : (ulong?)null;
        var sink = new CollectingSink();
        var engine = _services.GetRequiredService<ScanEngine>();
        var startedAt = DateTimeOffset.Now;
        var known = loadedDoc?.Devices.Select(d => d.Key).ToHashSet();
        using var session = engine.Start(new ScanRequest
        {
            Plan = built.Plan,
            Settings = Infrastructure.Security.ScanSecrets.Reveal(settings.Scan, _services.GetRequiredService<Infrastructure.Security.CredentialVault>()),
            LocalSubnets = planner.LocalSubnets(),
            IPv6ScopeIds = LinkLocalScopes(adapters),
            KnownAddresses = known,
            ExactCount = exact,
            Queries = queryPlan,
            Routers = scanContext.Routers,
            WorkstationCredential = scanContext.WorkstationCredential,
            SharesCredential = scanContext.SharesCredential,
        }, sink, cancellationToken);

        if (!o.Quiet) await _err.WriteLineAsync($"Scanning {(exact ?? built.Plan.RawCount):N0} addresses with {settings.Scan.MaxConcurrency} workers...");
        var summary = await WaitWithProgressAsync(session, o.Quiet);
        if (summary.State == ScanState.Cancelled)
        {
            await _err.WriteLineAsync($"Cancelled after {summary.Processed:N0} addresses; nothing exported.");
            return ExitCodes.Cancelled;
        }

        if (summary.State == ScanState.Faulted)
        {
            await _err.WriteLineAsync("error: scan failed: " + summary.Error);
            return ExitCodes.ScanFailed;
        }

        if (settings.History.Enabled)
        {
            var ops = _services.GetRequiredService<Infrastructure.Monitoring.ContinuousOperations>();
            await ops.RecordHistoryAsync(settings, sink.Snapshot(), startedAt, DateTimeOffset.Now, summary.State == ScanState.Completed, built.Plan);
            if (!o.Quiet) await _err.WriteLineAsync($"History recorded for {ops.HistoryView.Network?.Name}.");
        }

        var devices = sink.Snapshot();
        if (loadedDoc is not null)
        {
            var merged = loadedDoc.Devices.ToDictionary(d => d.Key);
            foreach (var d in devices) merged[d.Key] = merged.TryGetValue(d.Key, out var old) ? DeviceResult.MergeRescan(old, d) : d;
            devices = merged.Values.OrderBy(d => d.Key).ToList();
        }

        if (settings.Scan.DetectDuplicateMacs)
        {
            var dup = DuplicateMacs.Find(devices);
            format = format with { DuplicateMacs = dup };
            if (dup.Count > 0 && !o.Quiet) await _err.WriteLineAsync($"warning: {dup.Count} MAC address(es) answer for more than one IP address.");
        }

        if (!o.Quiet)
        {
            await _err.WriteLineAsync(string.Create(CultureInfo.InvariantCulture,
                $"Done: {summary.Processed:N0} scanned, {summary.Online:N0} online, {summary.Elapsed.TotalSeconds:0.0} s."));
        }

        if (outputPath is null)
        {
            foreach (var row in new[] { columns.Select(c => c.Header).ToArray() }.Concat(TableRows.Build(columns, devices, format, o.SplitMultiValues)))
            {
                CsvExporter.WriteRow(_out, row, '\t', protectFormulas: false);
            }

            await _out.FlushAsync(CancellationToken.None);
            return ExitCodes.Ok;
        }

        try
        {
            await ResultExport.ExportAsync(new ExportRequest
            {
                Path = outputPath,
                Columns = columns,
                Devices = devices,
                Format = format,
                Csv = settings.Csv with
                {
                    ExistingFile = o.Append ? ExistingFileMode.Append : o.Merge ? ExistingFileMode.Merge : ExistingFileMode.Overwrite,
                    SplitMultiValues = o.SplitMultiValues,
                },
                Metadata = new ScanMetadata
                {
                    StartedAt = startedAt,
                    Elapsed = summary.Elapsed,
                    Targets = specs.Select(s => s.Original).Distinct().Take(10_000).ToList(),
                },
            }, CancellationToken.None);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException
                                       or Microsoft.Data.Sqlite.SqliteException)
        {
            await _err.WriteLineAsync($"error: could not write '{outputPath}': {ex.Message}");
            return ExitCodes.Output;
        }

        if (!o.Quiet) await _err.WriteLineAsync("Saved " + Path.GetFullPath(outputPath));
        return ExitCodes.Ok;
    }

    /// <summary>/live (CLI-11): background rounds with per-round export until cancelled; exit 0 on Ctrl+C.</summary>
    private async Task<int> LiveAsync(CommandLineOptions o, CancellationToken ct)
    {
        if (o.LivePath is not null && !ResultExport.Extensions.Contains(Path.GetExtension(o.LivePath).ToLowerInvariant()))
        {
            await _err.WriteLineAsync("error: /live output must be .csv, .txt, .htm, .html, .xml, .json or .db.");
            return ExitCodes.Usage;
        }

        var (loaded, exit) = await LoadSettingsAsync(o);
        if (loaded is null) return exit;
        var settings = o.Ranges.Count > 0
            ? loaded with { Ranges = o.Ranges.Select(r => new RangeEntry { Target = r.Original, OctetMode = r.OctetMode }).ToList() }
            : loaded;
        if (settings.Ranges.Count == 0)
        {
            await _err.WriteLineAsync("error: no ranges. Use /range or save ranges in the GUI.");
            return ExitCodes.Targets;
        }

        var ops = _services.GetRequiredService<Infrastructure.Monitoring.ContinuousOperations>();
        ops.OutputOverride = o.LivePath;
        var printed = 0;
        void Flush()
        {
            var items = ops.Log.Items;
            lock (_err)
            {
                for (; printed < items.Count; printed++) _err.WriteLine($"{items[printed].At.ToLocalTime():yyyy-MM-dd HH:mm:ss} {items[printed].Text}");
            }
        }

        if (!o.Quiet) ops.Log.Changed += (_, _) => Flush();
        ops.Start(() => settings, null, null);
        try
        {
            await Task.Delay(Timeout.Infinite, ct);
        }
        catch (OperationCanceledException)
        {
            // Ctrl+C ends /live normally
        }

        await ops.StopAsync();
        if (!o.Quiet) Flush();
        return ExitCodes.Ok;
    }

    /// <summary>Loads the saved settings, unlocking an encrypted file with /mpass, stdin (/mpass:-) or IPMASTER_MPASS (SEC-02, D-008).</summary>
    private async Task<(AppSettings? Settings, int Exit)> LoadSettingsAsync(CommandLineOptions o)
    {
        var store = _services.GetRequiredService<SettingsStore>();
        var load = store.Load();
        if (load.Status == SettingsLoadStatus.PasswordRequired)
        {
            var password = o.MasterPassword == "-" ? await _in.ReadLineAsync() : o.MasterPassword ?? Environment.GetEnvironmentVariable("IPMASTER_MPASS");
            if (string.IsNullOrEmpty(password))
            {
                await _err.WriteLineAsync("error: the configuration is protected by a master password. Use /mpass:- (stdin) or set IPMASTER_MPASS.");
                return (null, ExitCodes.Settings);
            }

            load = store.Unlock(password);
            if (load.Status == SettingsLoadStatus.WrongPassword)
            {
                await _err.WriteLineAsync("error: " + load.Message);
                return (null, ExitCodes.Settings);
            }
        }

        if (load.Message is not null) await _err.WriteLineAsync("warning: " + load.Message);
        return (load.Settings, ExitCodes.Ok);
    }

    private async Task<int> WakeAsync(CommandLineOptions o, CancellationToken ct)
    {
        var (all, exit) = await LoadSettingsAsync(o);
        if (all is null) return exit;
        var settings = all.Wol;
        var targets = new List<Core.Management.WolTarget>();
        foreach (var m in o.WolMacs)
        {
            if (Formats.ParseMac(m) is not { } mac)
            {
                await _err.WriteLineAsync($"error: '{m}' is not a MAC address.");
                return ExitCodes.Usage;
            }

            targets.Add(new Core.Management.WolTarget { Mac = Formats.Mac(mac), Destination = Core.Management.WakeOnLan.CombineDestination(settings.DefaultDestination, null) });
        }

        if (o.WolFile is not null)
        {
            string text;
            try
            {
                if (new FileInfo(o.WolFile).Length > 4 * 1024 * 1024) throw new IOException("file is larger than 4 MB");
                text = await File.ReadAllTextAsync(o.WolFile, ct);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                await _err.WriteLineAsync($"error: cannot read '{o.WolFile}': {ex.Message}");
                return ExitCodes.Targets;
            }

            var (macs, rejected) = Core.Management.WakeOnLan.ParseMacList(text);
            foreach (var r in rejected) await _err.WriteLineAsync($"warning: {o.WolFile}:{r.LineNumber}: ignored ({r.Reason})");
            targets.AddRange(macs.Select(mac => new Core.Management.WolTarget { Mac = Formats.Mac(mac), Destination = Core.Management.WakeOnLan.CombineDestination(settings.DefaultDestination, null) }));
        }

        if (o.WakeAll) targets.AddRange(settings.Targets);
        if (targets.Count == 0)
        {
            await _err.WriteLineAsync("error: no Wake-on-LAN targets.");
            return ExitCodes.Targets;
        }

        var sender = _services.GetRequiredService<Infrastructure.Management.WakeOnLanSender>();
        var results = await sender.WakeAllAsync(targets, settings, ct);
        foreach (var r in results) await (r.Success ? _out : _err).WriteLineAsync((r.Success ? "" : "error: ") + $"{r.Target}: {r.Message}");
        return results.All(r => r.Success) ? ExitCodes.Ok : ExitCodes.Output;
    }

    internal static IReadOnlyList<long> LinkLocalScopes(INetworkAdapterProvider adapters) =>
        adapters.GetAdapters().SelectMany(a => a.Addresses)
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetworkV6 && a.Address.IsIPv6LinkLocal && a.Address.ScopeId != 0)
            .Select(a => a.Address.ScopeId).Distinct().ToList();

    private async Task<List<TargetSpec>?> ReadTargetFileAsync(string path, CancellationToken ct)
    {
        const long maxBytes = 16 * 1024 * 1024;
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
            {
                await _err.WriteLineAsync($"error: target file '{path}' not found.");
                return null;
            }

            if (info.Length > maxBytes)
            {
                await _err.WriteLineAsync($"error: target file is larger than {maxBytes / (1024 * 1024)} MB.");
                return null;
            }

            var parsed = TargetParser.ParseList(await File.ReadAllTextAsync(path, ct));
            foreach (var r in parsed.Rejected.Take(20)) await _err.WriteLineAsync($"warning: {path}:{r.LineNumber}: ignored ({r.Reason})");
            if (parsed.Rejected.Count > 20) await _err.WriteLineAsync($"warning: {parsed.Rejected.Count - 20} more lines ignored.");
            return parsed.Targets.ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            await _err.WriteLineAsync($"error: cannot read '{path}': {ex.Message}");
            return null;
        }
    }

    private async Task<ScanSummary> WaitWithProgressAsync(ScanSession session, bool quiet)
    {
        var interactive = !Console.IsErrorRedirected && ReferenceEquals(_err, Console.Error);
        while (true)
        {
            var done = await Task.WhenAny(session.Completion, Task.Delay(TimeSpan.FromSeconds(1)));
            if (done == session.Completion)
            {
                if (interactive && !quiet) await _err.WriteLineAsync();
                return await session.Completion;
            }

            if (quiet) continue;
            var p = session.Progress;
            var pct = p.Total == 0 ? 100 : 100.0 * p.Processed / p.Total;
            var line = string.Create(CultureInfo.InvariantCulture,
                $"{pct,5:0.0}%  {p.Processed:N0}/{p.Total:N0}  online {p.Online:N0}  workers {p.ActiveWorkers}  enrich {p.PendingEnrichment}  {p.State}");
            if (interactive) await _err.WriteAsync("\r" + line.PadRight(78));
            else await _err.WriteLineAsync(line);
        }
    }

    private sealed class CollectingSink : IScanResultSink
    {
        private readonly ConcurrentDictionary<AddressKey, DeviceResult> _results = new();

        public void OnDevice(DeviceResult result) =>
            _results.AddOrUpdate(result.Key, result, (_, old) => result.Revision >= old.Revision ? result : old);

        public List<DeviceResult> Snapshot() => _results.Values.OrderBy(r => r.Key).ToList();
    }
}
