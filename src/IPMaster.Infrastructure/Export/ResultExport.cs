using IPMaster.Core.Results;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Export;

public sealed record ExportRequest
{
    public required string Path { get; init; }

    public required IReadOnlyList<ResultColumn> Columns { get; init; }

    public required IReadOnlyList<DeviceResult> Devices { get; init; }

    public ColumnFormat Format { get; init; } = ColumnFormat.Default;

    public CsvOptions Csv { get; init; } = new();

    public ScanMetadata Metadata { get; init; } = new();
}

/// <summary>Chooses the exporter from the file extension (manual: txt, htm, xml, csv, json, db).</summary>
public static class ResultExport
{
    public static readonly string[] Extensions = [".csv", ".txt", ".htm", ".html", ".xml", ".json", ".db"];

    public static bool IsSupported(string path) => Extensions.Contains(System.IO.Path.GetExtension(path).ToLowerInvariant());

    /// <summary>Append/merge/split apply to text formats only (manual: /append, /merge, /splitmv "for text and CSV files").</summary>
    public static bool IsTextFormat(string path) => System.IO.Path.GetExtension(path).ToLowerInvariant() is ".csv" or ".txt";

    public static Task ExportAsync(ExportRequest r, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(r);
        return System.IO.Path.GetExtension(r.Path).ToLowerInvariant() switch
        {
            ".csv" => CsvExporter.ExportAsync(r.Path, r.Columns, r.Devices, r.Csv, r.Format, cancellationToken),
            ".txt" => TextExporter.ExportAsync(r.Path, r.Columns, r.Devices, r.Format, r.Csv.SplitMultiValues, r.Csv.ExistingFile, cancellationToken),
            ".htm" or ".html" => HtmlExporter.ExportAsync(r.Path, r.Columns, r.Devices, r.Format, r.Metadata, cancellationToken),
            ".xml" => ResultsXml.ExportAsync(r.Path, r.Columns, r.Devices, r.Metadata, cancellationToken),
            ".json" => JsonExporter.ExportAsync(r.Path, r.Columns, r.Devices, r.Metadata, r.Format, cancellationToken),
            ".db" => SqliteExporter.ExportAsync(r.Path, r.Columns, r.Devices, r.Format, cancellationToken),
            var ext => throw new NotSupportedException($"Unsupported output format '{ext}'."),
        };
    }
}
