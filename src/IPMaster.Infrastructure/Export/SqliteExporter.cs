using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using Microsoft.Data.Sqlite;

namespace IPMaster.Infrastructure.Export;

/// <summary>
/// SQLite export (manual <c>/auto:file.db</c>): table DEVICE with one TEXT column per exported column, and table SHARE
/// (name, type, attributes, …) with a foreign key to DEVICE. Column names are user-visible headers, so they are always
/// quoted as identifiers (embedded quotes doubled) and de-duplicated; values are bound as parameters. The database is
/// built in a temporary file and moved into place.
/// </summary>
public static class SqliteExporter
{
    private static readonly string[] ShareParameters = ["$d", "$n", "$t", "$a", "$ac", "$dt", "$df", "$p", "$r"];

    public static async Task ExportAsync(string path, IReadOnlyList<ResultColumn> columns, IReadOnlyList<DeviceResult> devices, ColumnFormat format,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(devices);
        ArgumentNullException.ThrowIfNull(format);
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var tmp = full + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        try
        {
            var cs = new SqliteConnectionStringBuilder { DataSource = tmp, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString();
            await using (var db = new SqliteConnection(cs))
            {
                await db.OpenAsync(cancellationToken).ConfigureAwait(false);
                var names = UniqueNames(columns.Select(c => c.Header));
                await using var tx = (SqliteTransaction)await db.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
                await ExecAsync(db, tx, "PRAGMA foreign_keys = ON;", cancellationToken).ConfigureAwait(false);
                await ExecAsync(db, tx, "CREATE TABLE DEVICE (id INTEGER PRIMARY KEY, " + string.Join(", ", names.Select(n => Quote(n) + " TEXT")) + ");",
                    cancellationToken).ConfigureAwait(false);
                await ExecAsync(db, tx,
                    "CREATE TABLE SHARE (id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL REFERENCES DEVICE(id), name TEXT NOT NULL, type TEXT, " +
                    "attributes TEXT, access TEXT, disk_total INTEGER, disk_free INTEGER, permissions TEXT, remark TEXT);", cancellationToken).ConfigureAwait(false);
                await ExecAsync(db, tx, "CREATE INDEX SHARE_device ON SHARE(device_id);", cancellationToken).ConfigureAwait(false);

                await using var insertDevice = db.CreateCommand();
                insertDevice.Transaction = tx;
                insertDevice.CommandText = "INSERT INTO DEVICE (id, " + string.Join(", ", names.Select(Quote)) + ") VALUES ($id, "
                                           + string.Join(", ", names.Select((_, i) => "$c" + i.ToString(System.Globalization.CultureInfo.InvariantCulture))) + ");";
                var idParam = insertDevice.Parameters.Add("$id", SqliteType.Integer);
                var cellParams = names.Select((_, i) => insertDevice.Parameters.Add("$c" + i.ToString(System.Globalization.CultureInfo.InvariantCulture), SqliteType.Text)).ToArray();

                await using var insertShare = db.CreateCommand();
                insertShare.Transaction = tx;
                insertShare.CommandText = "INSERT INTO SHARE (device_id, name, type, attributes, access, disk_total, disk_free, permissions, remark) " +
                                          "VALUES ($d, $n, $t, $a, $ac, $dt, $df, $p, $r);";
                var sp = ShareParameters.ToDictionary(n => n, n => insertShare.Parameters.Add(n, SqliteType.Text));

                long id = 0;
                foreach (var d in devices)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    idParam.Value = ++id;
                    for (var i = 0; i < columns.Count; i++) cellParams[i].Value = columns[i].Text(d, format);
                    await insertDevice.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                    if (!d.Shares.HasValue) continue;
                    foreach (var s in d.Shares.Value!.Where(format.ShareMatches))
                    {
                        sp["$d"].Value = id;
                        sp["$n"].Value = s.Name;
                        sp["$t"].Value = Formats.ShareKind(s);
                        sp["$a"].Value = s.TypeLetters;
                        sp["$ac"].Value = Formats.ShareAccessText(s);
                        sp["$dt"].Value = s.Disk.HasValue ? s.Disk.Value!.TotalBytes : DBNull.Value;
                        sp["$df"].Value = s.Disk.HasValue ? s.Disk.Value!.FreeBytes : DBNull.Value;
                        sp["$p"].Value = ShareColumns.All.First(c => c.Id == "permissions").Text(s);
                        sp["$r"].Value = s.Remark;
                        await insertShare.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                    }
                }

                await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            }

            File.Move(tmp, full, overwrite: true);
        }
        finally
        {
            if (File.Exists(tmp)) File.Delete(tmp);
        }
    }

    internal static string Quote(string identifier) => "\"" + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";

    internal static List<string> UniqueNames(IEnumerable<string> headers)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "id" };
        var list = new List<string>();
        foreach (var h in headers)
        {
            var name = string.IsNullOrWhiteSpace(h) ? "column" : h.Trim();
            var candidate = name;
            for (var n = 2; !used.Add(candidate); n++) candidate = $"{name} ({n})";
            list.Add(candidate);
        }

        return list;
    }

    private static async Task ExecAsync(SqliteConnection db, SqliteTransaction tx, string sql, CancellationToken ct)
    {
        await using var cmd = db.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }
}
