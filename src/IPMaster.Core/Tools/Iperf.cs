using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace IPMaster.Core.Tools;

public enum IperfEngineKind
{
    Iperf3,
    Iperf2,
}

public enum IperfProtocol
{
    Tcp,
    Udp,
}

public enum IperfDirection
{
    /// <summary>This computer sends (client → server).</summary>
    Upload,

    /// <summary>The server sends (iperf3 -R, iperf2 -R).</summary>
    Download,

    /// <summary>Both at the same time (iperf3 --bidir): two separate series, never summed into one link rate.</summary>
    Bidirectional,
}

public enum IperfState
{
    Ready,
    Preparing,
    Connecting,
    Running,
    Stopping,
    Completed,
    Stopped,
    Failed,
}

/// <summary>A detected iPerf executable and what it supports (by version and platform, never assumed).</summary>
public sealed record IperfEngine(IperfEngineKind Kind, string Path, Version Version, string VersionText)
{
    public string Name => Kind == IperfEngineKind.Iperf3 ? "iperf3" : "iperf2";

    /// <summary>iperf3 3.17+: one JSON event per line, so intervals arrive live.</summary>
    public bool JsonStream => Kind == IperfEngineKind.Iperf3 && Version >= new Version(3, 17);

    /// <summary>iperf3 3.7+ --bidir. Not offered for iperf2 (its full-duplex mode reports differently).</summary>
    public bool Bidirectional => Kind == IperfEngineKind.Iperf3 && Version >= new Version(3, 7);

    /// <summary>-R: every iperf3; iperf2 from 2.1.</summary>
    public bool Reverse => Kind == IperfEngineKind.Iperf3 || Version >= new Version(2, 1);

    /// <summary>iperf3 3.16+ runs each stream in its own thread (needed for 100G multi-stream tests).</summary>
    public bool MultiThreaded => Kind == IperfEngineKind.Iperf3 ? Version >= new Version(3, 16) : true;

    /// <summary>Live intervals: iperf3 JSON stream or iperf2 CSV; older iperf3 gives intervals only at the end (-J).</summary>
    public bool LiveIntervals => JsonStream || Kind == IperfEngineKind.Iperf2;

    /// <summary>-C and -Z have an effect only on Linux iperf3 builds.</summary>
    public bool CongestionControl => Kind == IperfEngineKind.Iperf3 && OperatingSystem.IsLinux();

    public bool ZeroCopy => Kind == IperfEngineKind.Iperf3 && OperatingSystem.IsLinux();

    public int DefaultPort => Kind == IperfEngineKind.Iperf3 ? 5201 : 5001;

    public string Label => $"{Name} {VersionText}" + (Kind == IperfEngineKind.Iperf3 && OperatingSystem.IsWindows() ? " (not supported by ESnet on Windows)" : "");
}

public sealed record IperfOptions
{
    public string Server { get; init; } = "";

    public int Port { get; init; } = 5201;

    public IperfProtocol Protocol { get; init; }

    public IperfDirection Direction { get; init; }

    public int Seconds { get; init; } = 10;

    public int Streams { get; init; } = 4;

    /// <summary>UDP target bit rate per stream (iperf applies -b to each stream).</summary>
    public long UdpBitsPerStream { get; init; } = 100_000_000;

    /// <summary>Socket buffer / TCP window in bytes; null = OS default.</summary>
    public long? WindowBytes { get; init; }

    /// <summary>Seconds left out at the start (iperf3 -O); 0 = none.</summary>
    public int OmitSeconds { get; init; }

    public int IntervalSeconds { get; init; } = 1;

    /// <summary>Local source address (-B); empty = the OS chooses.</summary>
    public string BindAddress { get; init; } = "";

    public string Congestion { get; init; } = "";

    public bool ZeroCopy { get; init; }
}

/// <summary>One reporting interval of one direction (sum over all streams). Bytes are 64-bit; rates are bit/s.</summary>
public sealed record IperfInterval(bool Upload, double Start, double End, long Bytes, double BitsPerSecond, long? Retransmits, double? JitterMs, long? LostPackets, long? Packets, bool Omitted);

/// <summary>Final numbers of one direction: sender and receiver measured separately.</summary>
public sealed record IperfDirectionResult(bool Upload, double? SenderBitsPerSecond, double? ReceiverBitsPerSecond, long? SenderBytes, long? ReceiverBytes, long? Retransmits,
    double? JitterMs, long? LostPackets, long? Packets, double? LostPercent, double Seconds);

public sealed record IperfConnection(string LocalHost, int LocalPort, string RemoteHost, int RemotePort);

/// <summary>Everything one test reported. Missing values stay null; nothing is derived from a wrong unit.</summary>
public sealed class IperfRun
{
    public List<IperfInterval> Intervals { get; } = [];

    public List<IperfDirectionResult> Results { get; } = [];

    public List<IperfConnection> Connections { get; } = [];

    public string Version { get; set; } = "";

    public string Protocol { get; set; } = "";

    public int? Streams { get; set; }

    public double? Duration { get; set; }

    public double? CpuLocal { get; set; }

    public double? CpuRemote { get; set; }

    public string Error { get; set; } = "";

    public bool Started { get; set; }

    public bool Ended { get; set; }

    /// <summary>test_start.reverse: true = the server sends. Decides the direction of "sum" (end-report sender flags differ between TCP and UDP).</summary>
    public bool? Reverse { get; set; }

    public IReadOnlyList<IperfInterval> Series(bool upload) => Intervals.Where(i => i.Upload == upload && !i.Omitted).ToList();

    public double? Peak(bool upload) => Series(upload).Select(i => i.BitsPerSecond).DefaultIfEmpty().Max() is var m && Series(upload).Count > 0 ? m : null;

    public IperfDirectionResult? Result(bool upload) => Results.FirstOrDefault(r => r.Upload == upload);

    /// <summary>Average of one direction: the receiver's final rate; without a final report, the mean of the received intervals.</summary>
    public double? Average(bool upload)
    {
        if (Result(upload) is { } r) return r.ReceiverBitsPerSecond ?? r.SenderBitsPerSecond;
        var s = Series(upload);
        var seconds = s.Sum(i => i.End - i.Start);
        return seconds > 0 ? s.Sum(i => (double)i.Bytes) * 8 / seconds : null;
    }

    public long? Transferred(bool upload) => Result(upload) is { } r ? r.ReceiverBytes ?? r.SenderBytes : Series(upload) is { Count: > 0 } s ? s.Sum(i => i.Bytes) : null;

    public bool HasDirection(bool upload) => Intervals.Any(i => i.Upload == upload) || Results.Any(r => r.Upload == upload);
}

/// <summary>Rules of the iPerf tool (D-108): engine versions, arguments, parsing of iperf3 JSON and iperf2 CSV, units, exports.</summary>
public static partial class Iperf
{
    private static readonly bool[] BothDirections = [true, false];
    public static readonly int[] StreamChoices = [1, 2, 4, 8, 16, 32, 64];
    public const int MaxStreams = 128;

    /// <summary>Presets suggest streams and duration only; they never cap TCP (no -b).</summary>
    public static readonly IReadOnlyList<(string Name, int Streams, int Seconds)> Presets =
        [("Standard", 4, 10), ("10G", 8, 10), ("25G", 8, 15), ("40G", 16, 20), ("100G", 32, 30)];

    [GeneratedRegex(@"\biperf\s+(?:version\s+)?(\d+)\.(\d+)(?:\.(\d+))?", RegexOptions.IgnoreCase, 1000)]
    private static partial Regex VersionPattern();

    /// <summary>"iperf 3.20 (cJSON …)" or "iperf version 2.2.1 (4 Nov 2024) pthreads" → engine; null when unknown.</summary>
    public static IperfEngine? ParseVersion(string path, string output)
    {
        var m = VersionPattern().Match(output ?? "");
        if (!m.Success) return null;
        var major = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        var minor = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
        var build = m.Groups[3].Success ? int.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture) : 0;
        var kind = major switch
        {
            3 => IperfEngineKind.Iperf3,
            2 => IperfEngineKind.Iperf2,
            _ => (IperfEngineKind?)null,
        };
        return kind is null ? null : new IperfEngine(kind.Value, path, new Version(major, minor, build), m.Groups[3].Success ? $"{major}.{minor}.{build}" : $"{major}.{minor}");
    }

    // ---------------- validation and arguments ----------------
    public static IReadOnlyList<string> Validate(IperfEngine engine, IperfOptions o, bool server)
    {
        var e = new List<string>();
        if (!server)
        {
            var host = o.Server.Trim().Trim('[', ']');
            if (host.Length == 0) e.Add("Server: enter a host name or an IP address.");
            else if (host.StartsWith('-') || Uri.CheckHostName(host) == UriHostNameType.Unknown) e.Add($"Server: '{host}' is not a valid host name or IP address.");
            if (o.Seconds is < 1 or > 86_400) e.Add("Duration: 1 to 86400 seconds.");
            if (o.Streams is < 1 or > MaxStreams) e.Add($"Streams: 1 to {MaxStreams}.");
            if (o.Direction == IperfDirection.Bidirectional && !engine.Bidirectional) e.Add($"Bidirectional: needs iperf3 3.7 or later ({engine.Name} {engine.VersionText}).");
            if (o.Direction == IperfDirection.Download && !engine.Reverse) e.Add($"Download: needs iperf2 2.1 or later ({engine.VersionText}).");
            if (o.Protocol == IperfProtocol.Udp && o.UdpBitsPerStream is < 1_000 or > 1_000_000_000_000) e.Add("UDP rate: enter a target rate from 1 Kbps to 1 Tbps per stream.");
            if (o.OmitSeconds is < 0 or > 600 || (o.OmitSeconds > 0 && engine.Kind != IperfEngineKind.Iperf3)) e.Add("Omit: 0 to 600 seconds, iperf3 only.");
            if (o.Congestion.Length > 0 && (!engine.CongestionControl || !CongestionPattern().IsMatch(o.Congestion))) e.Add("Congestion control: not supported here, or not a valid name.");
            if (o.ZeroCopy && !engine.ZeroCopy) e.Add("Zero-copy: not supported here.");
        }

        if (o.Port is < 1 or > 65535) e.Add("Port: 1 to 65535.");
        if (o.IntervalSeconds is < 1 or > 60) e.Add("Interval: 1 to 60 seconds.");
        if (o.WindowBytes is < 4096 or > 2L * 1024 * 1024 * 1024) e.Add("Window: 4 KB to 2 GB.");
        if (o.BindAddress.Length > 0 && !System.Net.IPAddress.TryParse(o.BindAddress, out _)) e.Add("Bind address: enter an IP address of this computer.");
        return e;
    }

    [GeneratedRegex("^[A-Za-z0-9_-]{1,32}$", RegexOptions.None, 1000)]
    private static partial Regex CongestionPattern();

    /// <summary>Client arguments for the engine; only options that engine supports (validated first).</summary>
    public static IReadOnlyList<string> ClientArguments(IperfEngine engine, IperfOptions o)
    {
        var host = o.Server.Trim().Trim('[', ']');
        var inv = CultureInfo.InvariantCulture;
        var a = new List<string> { "-c", host, "-p", o.Port.ToString(inv), "-t", o.Seconds.ToString(inv), "-P", o.Streams.ToString(inv), "-i", o.IntervalSeconds.ToString(inv) };
        if (host.Contains(':', StringComparison.Ordinal) && engine.Kind == IperfEngineKind.Iperf2) a.Add("-V");
        if (o.Protocol == IperfProtocol.Udp) a.AddRange(["-u", "-b", o.UdpBitsPerStream.ToString(inv)]);
        if (o.Direction == IperfDirection.Download) a.Add("-R");
        if (o.Direction == IperfDirection.Bidirectional) a.Add("--bidir");
        if (o.WindowBytes is { } w) a.AddRange(["-w", w.ToString(inv)]);
        if (o.BindAddress.Length > 0) a.AddRange(["-B", o.BindAddress]);
        if (engine.Kind == IperfEngineKind.Iperf3)
        {
            if (o.OmitSeconds > 0) a.AddRange(["-O", o.OmitSeconds.ToString(inv)]);
            if (o.Congestion.Length > 0) a.AddRange(["-C", o.Congestion]);
            if (o.ZeroCopy) a.Add("-Z");
            a.Add(engine.JsonStream ? "--json-stream" : "-J");
        }
        else
        {
            a.AddRange(["-y", "C"]); // CSV: fixed fields, no locale
        }

        return a;
    }

    /// <summary>Server arguments. iperf2 needs -u for a UDP server.</summary>
    public static IReadOnlyList<string> ServerArguments(IperfEngine engine, int port, string bind, bool udp)
    {
        var a = new List<string> { "-s", "-p", port.ToString(CultureInfo.InvariantCulture) };
        if (bind.Length > 0) a.AddRange(["-B", bind]);
        if (engine.Kind == IperfEngineKind.Iperf3) a.Add("-J"); // one JSON report per test
        else
        {
            if (udp) a.Add("-u");
            a.AddRange(["-i", "1", "-y", "C"]);
        }

        return a;
    }

    // ---------------- iperf3 JSON ----------------

    /// <summary>
    /// Splits text into complete top-level JSON objects (iperf3 -J pretty output, server reports, or --json-stream lines).
    /// Returns the objects and the unfinished rest, which the caller keeps for the next chunk.
    /// </summary>
    public static (IReadOnlyList<string> Objects, string Remainder) SplitJson(string text)
    {
        var list = new List<string>();
        int depth = 0, start = -1;
        var inString = false;
        var escape = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (inString)
            {
                if (escape) escape = false;
                else if (c == '\\') escape = true;
                else if (c == '"') inString = false;
                continue;
            }

            if (c == '"' && depth > 0) inString = true;
            else if (c == '{')
            {
                if (depth == 0) start = i;
                depth++;
            }
            else if (c == '}' && depth > 0 && --depth == 0)
            {
                list.Add(text[start..(i + 1)]);
                start = -1;
            }
        }

        return (list, start >= 0 ? text[start..] : "");
    }

    /// <summary>
    /// Applies one iperf3 JSON object to the run: a --json-stream event ({"event":…,"data":…}) or a complete -J report.
    /// Returns false when the text is not valid JSON (kept out of the results).
    /// </summary>
    public static bool ApplyJson(IperfRun run, string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            if (root.TryGetProperty("event", out var ev) && ev.ValueKind == JsonValueKind.String)
            {
                var data = root.TryGetProperty("data", out var d) ? d : default;
                switch (ev.GetString())
                {
                    case "start": Start(run, data); break;
                    case "interval": Interval(run, data); break;
                    case "end": End(run, data); break;
                    case "error": run.Error = data.ValueKind == JsonValueKind.String ? data.GetString() ?? "" : "iperf3 reported an error."; break;
                }

                return true;
            }

            if (root.TryGetProperty("start", out var s)) Start(run, s);
            if (root.TryGetProperty("intervals", out var ivs) && ivs.ValueKind == JsonValueKind.Array)
            {
                foreach (var iv in ivs.EnumerateArray()) Interval(run, iv);
            }

            if (root.TryGetProperty("end", out var e)) End(run, e);
            if (Str(root, "error") is { Length: > 0 } err) run.Error = err;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static void Start(IperfRun run, JsonElement s)
    {
        if (s.ValueKind != JsonValueKind.Object) return;
        run.Started = true;
        run.Version = Str(s, "version") ?? run.Version;
        if (s.TryGetProperty("connected", out var c) && c.ValueKind == JsonValueKind.Array)
        {
            foreach (var x in c.EnumerateArray())
            {
                var conn = new IperfConnection(Str(x, "local_host") ?? "", (int)(Long(x, "local_port") ?? 0), Str(x, "remote_host") ?? "", (int)(Long(x, "remote_port") ?? 0));
                if (!run.Connections.Contains(conn)) run.Connections.Add(conn);
            }
        }

        if (s.TryGetProperty("test_start", out var t) && t.ValueKind == JsonValueKind.Object)
        {
            run.Protocol = Str(t, "protocol") ?? run.Protocol;
            run.Streams = (int?)Long(t, "num_streams") ?? run.Streams;
            run.Duration = Num(t, "duration") ?? run.Duration;
            if (Bool(t, "reverse") is { } rev) run.Reverse = rev;
        }
    }

    /// <summary>"sum" and (bidirectional) "sum_bidir_reverse"; the direction comes from the report's own "sender" flag.</summary>
    private static void Interval(IperfRun run, JsonElement iv)
    {
        if (iv.ValueKind != JsonValueKind.Object) return;
        foreach (var name in new[] { "sum", "sum_bidir_reverse" })
        {
            if (!iv.TryGetProperty(name, out var s) || s.ValueKind != JsonValueKind.Object) continue;
            var sender = name == "sum_bidir_reverse" ? false : run.Reverse is { } rev ? !rev : Bool(s, "sender") ?? true;
            run.Intervals.Add(new IperfInterval(sender, Num(s, "start") ?? 0, Num(s, "end") ?? 0, Long(s, "bytes") ?? 0, Num(s, "bits_per_second") ?? 0,
                Long(s, "retransmits"), Num(s, "jitter_ms"), Long(s, "lost_packets"), Long(s, "packets"), Bool(s, "omitted") == true));
        }
    }

    private static void End(IperfRun run, JsonElement e)
    {
        run.Ended = true;
        if (e.ValueKind != JsonValueKind.Object) return;
        void Dir(string suffix)
        {
            JsonElement? Get(string n) => e.TryGetProperty(n + suffix, out var v) && v.ValueKind == JsonValueKind.Object ? v : null;
            var sent = Get("sum_sent");
            var recv = Get("sum_received");
            var udp = Get("sum"); // UDP: receiver jitter/loss (older versions have only this)
            if (sent is null && recv is null && udp is null) return;
            var any = (sent ?? recv ?? udp)!.Value;
            // direction from test_start (UDP end sums mark sum_sent as sender even when the server sent)
            var upload = suffix.Length > 0 ? false : run.Reverse is { } rev ? !rev : Bool(any, "sender") ?? true;
            var lossSource = recv is { } r && Num(r, "jitter_ms") is not null ? r : udp;
            run.Results.RemoveAll(x => x.Upload == upload);
            run.Results.Add(new IperfDirectionResult(upload,
                sent is { } a ? Num(a, "bits_per_second") : null, recv is { } b ? Num(b, "bits_per_second") : udp is { } u0 && recv is null ? Num(u0, "bits_per_second") : null,
                sent is { } a2 ? Long(a2, "bytes") : null, recv is { } b2 ? Long(b2, "bytes") : null,
                sent is { } a3 ? Long(a3, "retransmits") : null,
                lossSource is { } l ? Num(l, "jitter_ms") : null, lossSource is { } l2 ? Long(l2, "lost_packets") : null, lossSource is { } l3 ? Long(l3, "packets") : null,
                lossSource is { } l4 ? Num(l4, "lost_percent") : null, Num(recv ?? sent ?? any, "seconds") ?? 0));
        }

        Dir("");
        Dir("_bidir_reverse");
        if (e.TryGetProperty("cpu_utilization_percent", out var cpu) && cpu.ValueKind == JsonValueKind.Object)
        {
            run.CpuLocal = Num(cpu, "host_total");
            run.CpuRemote = Num(cpu, "remote_total");
        }
    }

    private static string? Str(JsonElement e, string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static double? Num(JsonElement e, string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) && double.IsFinite(d) ? d : null;

    /// <summary>64-bit counters; values written as floating point (some versions) are rounded, never truncated to 32 bits.</summary>
    private static long? Long(JsonElement e, string n)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(n, out var v) || v.ValueKind != JsonValueKind.Number) return null;
        if (v.TryGetInt64(out var l)) return l;
        return v.TryGetDouble(out var d) && double.IsFinite(d) && Math.Abs(d) < 9.2e18 ? (long)Math.Round(d) : null;
    }

    private static bool? Bool(JsonElement e, string n) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(n, out var v) ? v.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number when v.TryGetInt32(out var i) => i != 0,
        _ => null,
    } : null;

    // ---------------- iperf2 CSV (-y C) ----------------

    /// <summary>
    /// iperf2 CSV: time,src,srcport,dst,dstport,id,start-end,bytes,bps[,jitter,lost,total,pct,ooo]. A line of id -1 is the sum
    /// of parallel streams; with one stream the stream line is the sum. The report over the whole test (span &gt; 1.5
    /// intervals, starting at 0) is the final result. "-nan" and negative counts mean "not reported".
    /// </summary>
    public static bool ApplyIperf2Csv(IperfRun run, string line, int streams, double interval, bool upload)
    {
        var f = line.Trim().Split(',');
        if (f.Length is not (9 or 14) || !long.TryParse(f[5], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var id)) return false;
        var span = f[6].Split('-');
        if (span.Length != 2 || !double.TryParse(span[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var start)
            || !double.TryParse(span[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var end)) return false;
        if (!long.TryParse(f[7], NumberStyles.None, CultureInfo.InvariantCulture, out var bytes) || !double.TryParse(f[8], NumberStyles.Float, CultureInfo.InvariantCulture, out var bps)) return false;
        run.Started = true;
        var conn = new IperfConnection(f[1], int.TryParse(f[2], CultureInfo.InvariantCulture, out var lp) ? lp : 0, f[3], int.TryParse(f[4], CultureInfo.InvariantCulture, out var rp) ? rp : 0);
        if (id != -1 && !run.Connections.Contains(conn)) run.Connections.Add(conn);
        if (streams > 1 && id != -1) return true; // per-stream line: the sum line follows
        double? jitter = null;
        long? lost = null, total = null;
        double? pct = null;
        if (f.Length == 14 && !upload) // the sending side writes 0.000 jitter: only the receiver measures jitter and loss
        {
            jitter = double.TryParse(f[9], NumberStyles.Float, CultureInfo.InvariantCulture, out var j) && double.IsFinite(j) && j >= 0 ? j : null;
            lost = long.TryParse(f[10], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var lo) && lo >= 0 ? lo : null;
            total = long.TryParse(f[11], NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var to) && to >= 0 ? to : null;
            pct = total is > 0 && double.TryParse(f[12], NumberStyles.Float, CultureInfo.InvariantCulture, out var p) && double.IsFinite(p) && p >= 0 ? p : null;
            if (total is null) lost = null;
        }

        if (start == 0 && end - start > interval * 1.5)
        {
            run.Ended = true;
            run.Results.RemoveAll(r => r.Upload == upload);
            // one side's measurement only (iperf2 CSV does not label sender/receiver); shown as the receiver rate when this side received
            run.Results.Add(new IperfDirectionResult(upload, upload ? bps : null, upload ? null : bps, upload ? bytes : null, upload ? null : bytes, null, jitter, lost, total, pct, end - start));
        }
        else
        {
            run.Intervals.Add(new IperfInterval(upload, start, end, bytes, bps, null, jitter, lost, total, false));
        }

        return true;
    }

    // ---------------- units ----------------

    /// <summary>bit/s with an automatic unit (SI, 1000-based): 87.6 Gbps.</summary>
    public static string Rate(double? bitsPerSecond)
    {
        if (bitsPerSecond is not { } v || !double.IsFinite(v)) return "N/A";
        string[] units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps"];
        var i = 0;
        while (Math.Abs(v) >= 1000 && i < units.Length - 1)
        {
            v /= 1000;
            i++;
        }

        return v.ToString(Math.Abs(v) >= 100 ? "0" : Math.Abs(v) >= 10 ? "0.0" : "0.00", CultureInfo.InvariantCulture) + " " + units[i];
    }

    /// <summary>Bytes with an SI unit (GB = 10^9 B, as iperf's bit rates).</summary>
    public static string Bytes(long? bytes)
    {
        if (bytes is not { } b) return "N/A";
        double v = b;
        string[] units = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];
        var i = 0;
        while (Math.Abs(v) >= 1000 && i < units.Length - 1)
        {
            v /= 1000;
            i++;
        }

        return v.ToString(i == 0 ? "0" : Math.Abs(v) >= 100 ? "0" : Math.Abs(v) >= 10 ? "0.0" : "0.00", CultureInfo.InvariantCulture) + " " + units[i];
    }

    /// <summary>"100M", "2.5G", "500 Mbps" → bit/s; null when not a positive rate.</summary>
    public static long? ParseRate(string text)
    {
        var m = Regex.Match((text ?? "").Trim(), @"^(\d+(?:\.\d+)?)\s*([kKmMgGtT]?)(?:bps|bit/s|b)?$", RegexOptions.None, TimeSpan.FromSeconds(1));
        if (!m.Success || !double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var v)) return null;
        v *= m.Groups[2].Value.ToUpperInvariant() switch
        {
            "K" => 1e3,
            "M" => 1e6,
            "G" => 1e9,
            "T" => 1e12,
            _ => 1,
        };
        return v is >= 1 and < 9.2e18 ? (long)Math.Round(v) : null;
    }

    /// <summary>High-rate tests may fill a production link: TCP with many streams, or UDP of 1 Gbps or more in total.</summary>
    public static bool NeedsRateWarning(IperfOptions o) =>
        o.Protocol == IperfProtocol.Udp ? (double)o.UdpBitsPerStream * o.Streams >= 1e9 : o.Streams >= 8;

    // ---------------- reports ----------------
    public sealed record ReportInfo(DateTimeOffset At, IperfEngine Engine, IperfOptions Options, IperfState Outcome, string Detail);

    private static string Dir(bool upload) => upload ? "Upload" : "Download";

    public static string Summary(ReportInfo info, IperfRun run)
    {
        var sb = new StringBuilder();
        void L(string k, string v) => sb.Append(CultureInfo.InvariantCulture, $"{k,-16}{v}").AppendLine();
        var o = info.Options;
        sb.AppendLine("iPerf Test").AppendLine(new string('-', 44));
        L("Time:", info.At.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
        L("Engine:", $"{info.Engine.Name} {info.Engine.VersionText}{(run.Version.Length > 0 ? $" ({run.Version})" : "")}");
        L("Server:", $"{o.Server}:{o.Port}");
        foreach (var c in run.Connections.Take(1)) L("Local:", $"{c.LocalHost}:{c.LocalPort} → {c.RemoteHost}:{c.RemotePort}");
        L("Protocol:", o.Protocol.ToString().ToUpperInvariant());
        L("Direction:", o.Direction.ToString());
        L("Duration:", $"{o.Seconds} s" + (run.Duration is { } d && Math.Abs(d - o.Seconds) > 0.5 ? $" (reported {d:0.#} s)" : ""));
        L("Streams:", o.Streams.ToString(CultureInfo.InvariantCulture));
        if (o.Protocol == IperfProtocol.Udp) L("UDP target:", $"{Rate(o.UdpBitsPerStream)} per stream");
        foreach (var up in BothDirections.Where(run.HasDirection))
        {
            var r = run.Result(up);
            sb.AppendLine().AppendLine(Dir(up));
            L("  Average:", Rate(run.Average(up)));
            L("  Peak:", Rate(run.Peak(up)) + " (interval)");
            L("  Sender:", Rate(r?.SenderBitsPerSecond));
            L("  Receiver:", Rate(r?.ReceiverBitsPerSecond));
            L("  Transferred:", Bytes(run.Transferred(up)));
            if (o.Protocol == IperfProtocol.Tcp) L("  Retransmits:", r?.Retransmits?.ToString(CultureInfo.InvariantCulture) ?? "N/A");
            else
            {
                L("  Jitter:", r?.JitterMs is { } j ? $"{j:0.###} ms" : "N/A");
                L("  Loss:", r?.LostPackets is { } lp && r.Packets is { } pk ? $"{lp}/{pk} ({r.LostPercent ?? (pk > 0 ? 100.0 * lp / pk : 0):0.###} %)" : "N/A");
            }
        }

        if (run.CpuLocal is { } cl) L("CPU:", $"local {cl:0.#} %, remote {(run.CpuRemote is { } cr ? $"{cr:0.#} %" : "N/A")}");
        sb.AppendLine();
        L("Outcome:", info.Outcome + (info.Detail.Length > 0 ? " — " + info.Detail : ""));
        return sb.ToString();
    }

    /// <summary>Intervals as CSV with full values (bytes, bit/s), invariant culture.</summary>
    public static string IntervalsCsv(IperfRun run)
    {
        var sb = new StringBuilder("direction,start_s,end_s,bytes,bits_per_second,retransmits,jitter_ms,lost_packets,packets,omitted\n");
        foreach (var i in run.Intervals)
        {
            sb.Append(CultureInfo.InvariantCulture, $"{Dir(i.Upload)},{i.Start:0.######},{i.End:0.######},{i.Bytes},{i.BitsPerSecond:0.###},{i.Retransmits},{i.JitterMs},{i.LostPackets},{i.Packets},{(i.Omitted ? 1 : 0)}\n");
        }

        return sb.ToString();
    }

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>Complete values plus the engine's own report lines (raw), never shortened UI text.</summary>
    public static string Json(ReportInfo info, IperfRun run, IReadOnlyList<string> raw) => JsonSerializer.Serialize(new
    {
        time = info.At.ToString("o", CultureInfo.InvariantCulture),
        engine = new { name = info.Engine.Name, version = info.Engine.VersionText, reported = run.Version },
        options = new { server = info.Options.Server, port = info.Options.Port, protocol = info.Options.Protocol.ToString(), direction = info.Options.Direction.ToString(), seconds = info.Options.Seconds, streams = info.Options.Streams, udpBitsPerStream = info.Options.Protocol == IperfProtocol.Udp ? info.Options.UdpBitsPerStream : (long?)null },
        outcome = info.Outcome.ToString(),
        detail = info.Detail,
        connections = run.Connections,
        results = BothDirections.Where(run.HasDirection).Select(up => new
        {
            direction = Dir(up), averageBitsPerSecond = run.Average(up), peakBitsPerSecond = run.Peak(up), transferredBytes = run.Transferred(up), final = run.Result(up),
        }),
        cpu = new { local = run.CpuLocal, remote = run.CpuRemote },
        intervals = run.Intervals,
        engineReport = raw,
    }, Indented);
}
