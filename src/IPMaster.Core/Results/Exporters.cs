using System.Globalization;
using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using IPMaster.Core.Scanning;

namespace IPMaster.Core.Results;

public enum CsvEncoding
{
    Utf8,
    Utf8Bom,
    Utf16LittleEndian,
}

/// <summary>How text exports combine with an existing file (CLI /append, /merge).</summary>
public enum ExistingFileMode
{
    Overwrite,
    Append,

    /// <summary>Existing and new lines are sorted and duplicates removed.</summary>
    Merge,
}

public sealed record CsvOptions
{
    /// <summary>Single delimiter character. Null = regional list separator (manual: "System default").</summary>
    public char? Delimiter { get; init; } = ',';

    public CsvEncoding Encoding { get; init; } = CsvEncoding.Utf8Bom;

    public bool IncludeHeader { get; init; } = true;

    /// <summary>Prefix cells that a spreadsheet would treat as a formula with an apostrophe (CWE-1236).</summary>
    public bool ProtectFormulas { get; init; } = true;

    public ExistingFileMode ExistingFile { get; init; } = ExistingFileMode.Overwrite;

    /// <summary>Split multi-value cells into separate rows (CLI /splitmv).</summary>
    public bool SplitMultiValues { get; init; }

    public char ResolveDelimiter()
    {
        if (Delimiter is { } d) return d;
        var sep = CultureInfo.CurrentCulture.TextInfo.ListSeparator;
        return string.IsNullOrEmpty(sep) ? ',' : sep[0];
    }
}

public sealed record ScanMetadata
{
    public DateTimeOffset ExportedAt { get; init; } = DateTimeOffset.Now;

    public DateTimeOffset? StartedAt { get; init; }

    public TimeSpan? Elapsed { get; init; }

    public string State { get; init; } = "completed";

    public IReadOnlyList<string> Targets { get; init; } = [];
}

/// <summary>Builds rows of display text, optionally split into one row per multi-value item.</summary>
public static class TableRows
{
    public static IEnumerable<string[]> Build(IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ColumnFormat format, bool splitMultiValues)
    {
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(format);
        foreach (var d in devices)
        {
            var cells = columns.Select(c => c.Text(d, format)).ToArray();
            if (!splitMultiValues || format.Separator.Length == 0)
            {
                yield return cells;
                continue;
            }

            // Row i takes the i-th value of every multi-value cell; single values repeat (D-031).
            var parts = cells.Select(c => c.Split(format.Separator)).ToArray();
            var n = parts.Max(p => p.Length);
            for (var i = 0; i < n; i++) yield return parts.Select(p => p.Length == 1 ? p[0] : i < p.Length ? p[i] : "").ToArray();
        }
    }
}

public static class CsvExporter
{
    public static Encoding ToEncoding(CsvEncoding e) => e switch
    {
        CsvEncoding.Utf8 => new UTF8Encoding(false),
        CsvEncoding.Utf16LittleEndian => new UnicodeEncoding(false, true),
        _ => new UTF8Encoding(true),
    };

    public static void Write(TextWriter writer, IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, CsvOptions options,
        ColumnFormat? format = null)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(options);
        var d = options.ResolveDelimiter();
        if (options.IncludeHeader) WriteRow(writer, columns.Select(c => c.Header), d, options.ProtectFormulas);
        foreach (var row in TableRows.Build(columns, devices, format ?? ColumnFormat.Default, options.SplitMultiValues))
        {
            WriteRow(writer, row, d, options.ProtectFormulas);
        }
    }

    public static void WriteRow(TextWriter writer, IEnumerable<string> cells, char delimiter, bool protectFormulas)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(cells);
        var first = true;
        foreach (var raw in cells)
        {
            if (!first) writer.Write(delimiter);
            first = false;
            writer.Write(Escape(raw ?? "", delimiter, protectFormulas));
        }

        writer.Write("\r\n");
    }

    public static string Escape(string value, char delimiter, bool protectFormulas)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (protectFormulas && value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r'
            && !double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out _))
        {
            value = "'" + value;
        }

        var needsQuotes = value.Contains(delimiter, StringComparison.Ordinal) || value.Contains('"', StringComparison.Ordinal)
                          || value.Contains('\n', StringComparison.Ordinal) || value.Contains('\r', StringComparison.Ordinal)
                          || (value.Length > 0 && (value[0] == ' ' || value[^1] == ' '));
        return needsQuotes ? "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"" : value;
    }

    public static Task ExportAsync(string path, IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, CsvOptions options,
        ColumnFormat? format = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var enc = ToEncoding(options.Encoding);
        using var sw = new StringWriter(CultureInfo.InvariantCulture);
        Write(sw, columns, devices, options with { IncludeHeader = true }, format);
        return TextFiles.WriteLinesAsync(path, sw.ToString(), options.ExistingFile, hasHeader: true, enc, cancellationToken);
    }
}

/// <summary>Plain-text table export (manual .txt): aligned columns, header and rule.</summary>
public static class TextExporter
{
    public static string Render(IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ColumnFormat format, bool splitMultiValues)
    {
        ArgumentNullException.ThrowIfNull(columns);
        var rows = TableRows.Build(columns, devices, format, splitMultiValues)
            .Select(r => r.Select(c => c.Replace('\r', ' ').Replace('\n', ' ')).ToArray()).ToList();
        var widths = columns.Select((c, i) => Math.Min(80, Math.Max(c.Header.Length, rows.Count == 0 ? 0 : rows.Max(r => r[i].Length)))).ToArray();
        var sb = new StringBuilder();
        void Line(IReadOnlyList<string> cells)
        {
            for (var i = 0; i < cells.Count; i++)
            {
                var cell = cells[i].Length > widths[i] ? cells[i][..(widths[i] - 1)] + "…" : cells[i];
                sb.Append(i == cells.Count - 1 ? cell : cell.PadRight(widths[i] + 2));
            }

            sb.Append("\r\n");
        }

        Line(columns.Select(c => c.Header).ToList());
        Line(widths.Select(w => new string('-', w)).ToList());
        foreach (var r in rows) Line(r);
        return sb.ToString();
    }

    public static Task ExportAsync(string path, IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ColumnFormat format,
        bool splitMultiValues, ExistingFileMode mode, CancellationToken cancellationToken = default)
        => TextFiles.WriteLinesAsync(path, Render(columns, devices, format, splitMultiValues), mode, hasHeader: true, new UTF8Encoding(true), cancellationToken, headerLines: 2);
}

/// <summary>Line-based combining of text exports with an existing file (append / merge).</summary>
public static class TextFiles
{
    public static async Task WriteLinesAsync(string path, string content, ExistingFileMode mode, bool hasHeader, Encoding encoding,
        CancellationToken cancellationToken, int headerLines = 1)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(content);
        var final = content;
        if (mode != ExistingFileMode.Overwrite && File.Exists(path))
        {
            var existing = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            var newLines = SplitLines(content);
            var oldLines = SplitLines(existing);
            var header = hasHeader ? newLines.Take(headerLines).ToList() : [];
            var oldBody = hasHeader && oldLines.Count >= headerLines ? oldLines.Skip(headerLines) : oldLines;
            var newBody = newLines.Skip(header.Count);
            var body = mode == ExistingFileMode.Append
                ? oldBody.Concat(newBody).ToList()
                : oldBody.Concat(newBody).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
            final = string.Concat(header.Concat(body).Select(l => l + "\r\n"));
        }

        await AtomicFile.WriteAsync(path, async s =>
        {
            var bytes = encoding.GetPreamble().Concat(encoding.GetBytes(final)).ToArray();
            await s.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Splits on CRLF/LF line ends outside CSV quotes, so quoted multi-line cells stay one record.</summary>
    public static List<string> SplitLines(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var lines = new List<string>();
        var sb = new StringBuilder();
        var inQuotes = false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c == '"') inQuotes = !inQuotes;
            if (!inQuotes && (c == '\n' || (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')))
            {
                if (c == '\r') i++;
                lines.Add(sb.ToString());
                sb.Clear();
                continue;
            }

            sb.Append(c);
        }

        if (sb.Length > 0) lines.Add(sb.ToString());
        return lines;
    }
}

/// <summary>Self-contained HTML report. All text is HTML-encoded; shares are listed under their device.</summary>
public static class HtmlExporter
{
    public static string Render(IReadOnlyList<ResultColumn> columns, IReadOnlyList<DeviceResult> devices, ColumnFormat format, ScanMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(metadata);
        // Minimal encoding keeps non-ASCII text readable (the document is UTF-8).
        static string E(string s) => s.Replace("&", "&amp;", StringComparison.Ordinal).Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal).Replace("\"", "&quot;", StringComparison.Ordinal).Replace("'", "&#39;", StringComparison.Ordinal);
        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>IPMaster scan results</title>\n<style>")
          .Append("body{font:13px system-ui,sans-serif;margin:16px;color:#1b1b1b}table{border-collapse:collapse}th,td{border:1px solid #c8c8c8;padding:3px 8px;text-align:left;vertical-align:top}")
          .Append("th{background:#eef1f5}tr.share td{background:#fafafa;font-size:12px}tr.share td:first-child{padding-left:24px}")
          .Append("@media (prefers-color-scheme:dark){body{background:#1e1e1e;color:#ddd}th{background:#2b2f36}td,th{border-color:#444}tr.share td{background:#252525}}")
          .Append("</style></head><body>\n");
        sb.Append("<h1>IPMaster scan results</h1>\n<p>Exported ").Append(E(Formats.Timestamp(metadata.ExportedAt)));
        if (metadata.Targets.Count > 0) sb.Append(" · Targets: ").Append(E(string.Join(", ", metadata.Targets)));
        sb.Append(" · ").Append(devices.Count.ToString(CultureInfo.InvariantCulture)).Append(" devices</p>\n<table>\n<thead><tr>");
        foreach (var c in columns) sb.Append("<th>").Append(E(c.Header)).Append("</th>");
        sb.Append("</tr></thead>\n<tbody>\n");
        foreach (var d in devices)
        {
            sb.Append("<tr>");
            foreach (var c in columns) sb.Append("<td>").Append(E(c.Text(d, format))).Append("</td>");
            sb.Append("</tr>\n");
            if (!d.Shares.HasValue) continue;
            foreach (var s in d.Shares.Value!.Where(format.ShareMatches))
            {
                var text = string.Join(" · ", ShareColumns.All.Skip(1).Select(sc => sc.Text(s)).Where(t => t.Length > 0));
                sb.Append("<tr class=\"share\"><td>\\\\").Append(E(d.Key.ToString())).Append('\\').Append(E(s.Name)).Append("</td><td colspan=\"")
                  .Append(Math.Max(1, columns.Count - 1).ToString(CultureInfo.InvariantCulture)).Append("\">").Append(E(text)).Append("</td></tr>\n");
            }
        }

        sb.Append("</tbody></table>\n</body></html>\n");
        return sb.ToString();
    }

    public static Task ExportAsync(string path, IReadOnlyList<ResultColumn> columns, IReadOnlyList<DeviceResult> devices, ColumnFormat format,
        ScanMetadata metadata, CancellationToken cancellationToken = default)
    {
        var bytes = new UTF8Encoding(false).GetBytes(Render(columns, devices, format, metadata));
        return AtomicFile.WriteAsync(path, s => s.WriteAsync(bytes, cancellationToken).AsTask(), cancellationToken);
    }
}

/// <summary>
/// JSON result format <c>ipmaster.results</c> v2: typed observations for every field plus rendered display text.
/// Export-only (XML is the loadable format).
/// </summary>
public static class JsonExporter
{
    public const string SchemaName = "ipmaster.results";
    public const int SchemaVersion = 2;

    public static void Write(Stream stream, IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ScanMetadata metadata,
        ColumnFormat? format = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(metadata);
        format ??= ColumnFormat.Default;
        using var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
        w.WriteStartObject();
        w.WriteString("schema", SchemaName);
        w.WriteNumber("schemaVersion", SchemaVersion);
        w.WriteString("generator", Generator);
        w.WriteString("exportedAt", metadata.ExportedAt);
        w.WriteStartObject("scan");
        if (metadata.StartedAt is { } st) w.WriteString("startedAt", st);
        if (metadata.Elapsed is { } el) w.WriteNumber("elapsedMs", (long)el.TotalMilliseconds);
        w.WriteString("state", metadata.State);
        w.WriteStartArray("targets");
        foreach (var t in metadata.Targets) w.WriteStringValue(t);
        w.WriteEndArray();
        w.WriteEndObject();

        w.WriteStartArray("columns");
        foreach (var c in columns)
        {
            w.WriteStartObject();
            w.WriteString("id", c.Id);
            w.WriteString("header", c.Header);
            w.WriteEndObject();
        }

        w.WriteEndArray();
        w.WriteStartArray("devices");
        foreach (var d in devices)
        {
            w.WriteStartObject();
            DeviceFields.ToJson(w, d);
            w.WriteStartObject("display");
            foreach (var c in columns) w.WriteString(c.Id, c.Text(d, format));
            w.WriteEndObject();
            w.WriteEndObject();
        }

        w.WriteEndArray();
        w.WriteEndObject();
    }

    internal static string Generator => "IPMaster " + (Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3) ?? "0");

    public static Task ExportAsync(string path, IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ScanMetadata metadata,
        ColumnFormat? format = null, CancellationToken cancellationToken = default)
        => AtomicFile.WriteAsync(path, s =>
        {
            Write(s, columns, devices, metadata, format);
            return Task.CompletedTask;
        }, cancellationToken);
}

public sealed record ResultDocument(ScanMetadata Metadata, IReadOnlyList<string> ColumnIds, IReadOnlyList<DeviceResult> Devices);

/// <summary>
/// Lossless, loadable XML results (<c>urn:ipmaster:results</c>, schema 1): every typed observation with state,
/// timestamp and detail, nested shares. The reader prohibits DTDs/external entities and bounds the document size.
/// </summary>
public static class ResultsXml
{
    public const int SchemaVersion = 1;
    public static readonly XNamespace Ns = "urn:ipmaster:results";
    public const long MaxDocumentCharacters = 512L * 1024 * 1024;

    public static XDocument ToDocument(IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ScanMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(metadata);
        var scan = new XElement(Ns + "scan", new XAttribute("state", metadata.State));
        if (metadata.StartedAt is { } st) scan.SetAttributeValue("startedAt", Codecs.Iso(st));
        if (metadata.Elapsed is { } el) scan.SetAttributeValue("elapsedMs", (long)el.TotalMilliseconds);
        foreach (var t in metadata.Targets) scan.Add(new XElement(Ns + "target", t));
        return new XDocument(new XElement(Ns + "ipmasterResults",
            new XAttribute("schemaVersion", SchemaVersion),
            new XAttribute("generator", JsonExporter.Generator),
            new XAttribute("exportedAt", Codecs.Iso(metadata.ExportedAt)),
            scan,
            new XElement(Ns + "columns", columns.Select(c => new XElement(Ns + "column", new XAttribute("id", c.Id), new XAttribute("header", c.Header)))),
            new XElement(Ns + "devices", devices.Select(d => DeviceFields.ToXml(d, Ns)))));
    }

    public static Task ExportAsync(string path, IReadOnlyList<ResultColumn> columns, IEnumerable<DeviceResult> devices, ScanMetadata metadata,
        CancellationToken cancellationToken = default)
    {
        var doc = ToDocument(columns, devices, metadata);
        return AtomicFile.WriteAsync(path, async s =>
        {
            await using var xw = XmlWriter.Create(s, new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false), Async = true });
            await doc.SaveAsync(xw, cancellationToken).ConfigureAwait(false);
        }, cancellationToken);
    }

    public static XmlReaderSettings SafeReaderSettings(long maxCharacters = MaxDocumentCharacters) => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = maxCharacters,
        MaxCharactersFromEntities = 0,
        IgnoreComments = true,
        Async = true,
    };

    public static ResultDocument Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var reader = XmlReader.Create(stream, SafeReaderSettings());
        var doc = XDocument.Load(reader);
        var root = doc.Root ?? throw new FormatException("Empty document.");
        if (root.Name != Ns + "ipmasterResults") throw new FormatException("Not an IPMaster results file.");
        var version = (int?)root.Attribute("schemaVersion") ?? 0;
        if (version > SchemaVersion) throw new FormatException($"Results schema {version} is newer than supported ({SchemaVersion}).");
        var scan = root.Element(Ns + "scan");
        var metadata = new ScanMetadata
        {
            ExportedAt = root.Attribute("exportedAt") is { } ea ? Codecs.ParseIso(ea.Value) : DateTimeOffset.MinValue,
            StartedAt = scan?.Attribute("startedAt") is { } sa ? Codecs.ParseIso(sa.Value) : null,
            Elapsed = scan?.Attribute("elapsedMs") is { } em ? TimeSpan.FromMilliseconds(long.Parse(em.Value, CultureInfo.InvariantCulture)) : null,
            State = (string?)scan?.Attribute("state") ?? "completed",
            Targets = scan?.Elements(Ns + "target").Select(t => t.Value).ToList() ?? [],
        };
        var cols = root.Element(Ns + "columns")?.Elements(Ns + "column").Select(c => (string?)c.Attribute("id") ?? "").Where(id => id.Length > 0).ToList() ?? [];
        var devices = root.Element(Ns + "devices")?.Elements(Ns + "device").Select(e => DeviceFields.FromXml(e, Ns)).ToList() ?? [];
        return new ResultDocument(metadata, cols, devices);
    }

    public static async Task<ResultDocument> LoadAsync(string path, CancellationToken cancellationToken = default)
    {
        await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
        var ms = new MemoryStream();
        await fs.CopyToAsync(ms, cancellationToken).ConfigureAwait(false);
        ms.Position = 0;
        return Read(ms);
    }
}

/// <summary>Writes to a temporary file in the destination directory and renames it into place.</summary>
public static class AtomicFile
{
    public static async Task WriteAsync(string path, Func<Stream, Task> write, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(write);
        var full = Path.GetFullPath(path);
        var dir = Path.GetDirectoryName(full)!;
        Directory.CreateDirectory(dir);
        var tmp = Path.Combine(dir, "." + Path.GetFileName(full) + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp");
        try
        {
            await using (var fs = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.Asynchronous))
            {
                await write(fs).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                await fs.FlushAsync(cancellationToken).ConfigureAwait(false);
                fs.Flush(flushToDisk: true);
            }

            File.Move(tmp, full, overwrite: true);
        }
        finally
        {
            if (File.Exists(tmp))
            {
                try
                {
                    File.Delete(tmp);
                }
                catch (IOException)
                {
                    // best effort
                }
            }
        }
    }
}
