using System.Globalization;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Scanning;
using Microsoft.Data.Sqlite;

namespace IPMaster.Infrastructure.Monitoring;

/// <summary>
/// Device history in SQLite next to the settings file (HIS-01..06, D-061). Keyed by (network fingerprint, MAC);
/// one row per sighting. Availability counts only complete sessions in which the device's last known address was
/// covered by the scan ("eligible"). Calls are serialised; each opens a short-lived connection.
/// </summary>
public sealed class HistoryStore : IHistoryStore
{
    public const string FileName = "ipmaster.history.db";
    public const int RecentSamples = 24;

    /// <summary>`PRAGMA user_version` of the schema below. A v0.6.0 database (version 0, same tables) is stamped; a newer one is
    /// refused unmodified (review C-13). v2 (D-088) adds <c>network_gateways</c>; IPMaster 0.6.x refuses a v2 file.</summary>
    public const int SchemaVersion = 2;

    private readonly string _connectionString;
    private readonly object _lock = new();
    private bool _initialised;

    public HistoryStore(string directory)
    {
        Path = System.IO.Path.Combine(directory, FileName);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = Path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false }.ToString();
    }

    public string Path { get; }

    private SqliteConnection Open()
    {
        // a first run has no settings folder yet; SQLite cannot create the folder (Device Inventory failed to open)
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path)!);
        var c = new SqliteConnection(_connectionString);
        c.Open();
        if (!_initialised)
        {
            long version;
            using (var cmd = c.CreateCommand())
            {
                cmd.CommandText = "PRAGMA user_version;";
                version = (long)(cmd.ExecuteScalar() ?? 0L);
            }

            if (version > SchemaVersion)
            {
                c.Dispose();
                throw new InvalidOperationException($"The history database was written by a newer IPMaster (schema {version}); it is not modified. History is unavailable in this version.");
            }

            Exec(c, """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS networks (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY, network_id INTEGER NOT NULL REFERENCES networks(id), started TEXT NOT NULL, finished TEXT NOT NULL, complete INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS devices (network_id INTEGER NOT NULL, mac TEXT NOT NULL, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, last_ip TEXT NOT NULL, last_host TEXT NOT NULL,
                    PRIMARY KEY (network_id, mac));
                CREATE TABLE IF NOT EXISTS sightings (session_id INTEGER NOT NULL, network_id INTEGER NOT NULL, mac TEXT NOT NULL, at TEXT NOT NULL, ip TEXT NOT NULL, host TEXT NOT NULL,
                    rtt REAL NULL, online INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS ix_sightings ON sightings (network_id, mac, at);
                CREATE INDEX IF NOT EXISTS ix_sightings_at ON sightings (at);
                CREATE TABLE IF NOT EXISTS network_gateways (network_id INTEGER NOT NULL REFERENCES networks(id), gateway TEXT NOT NULL,
                    PRIMARY KEY (network_id, gateway));
                """);
            if (version < SchemaVersion) Exec(c, $"PRAGMA user_version = {SchemaVersion};");
            _initialised = true;
        }

        return c;
    }

    private static void Exec(SqliteConnection c, string sql, SqliteTransaction? tx = null, params (string, object?)[] args)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }

    private static object? Scalar(SqliteConnection c, string sql, SqliteTransaction? tx = null, params (string, object?)[] args)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        foreach (var (n, v) in args) cmd.Parameters.AddWithValue(n, v ?? DBNull.Value);
        return cmd.ExecuteScalar();
    }

    private static string Iso(DateTimeOffset t) => t.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    private static DateTimeOffset Parse(string s) => DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);

    /// <summary>
    /// The history network of <paramref name="n"/> (D-088). Gateway addresses repeat across unrelated LANs, so the address
    /// only stands in for the gateway MAC when that is unambiguous: a session without the MAC joins the one MAC-identified
    /// network seen behind that address, and the first session with the MAC adopts the address-only network unless
    /// another MAC network already claimed that address. Otherwise each fingerprint is its own network.
    /// </summary>
    private static long NetworkId(SqliteConnection c, SqliteTransaction? tx, NetworkIdentity n, bool create)
    {
        var byMac = n.Gateway is { } g && g != n.Fingerprint;
        long? id = null;
        if (!byMac && n.Gateway is { } address)
        {
            var linked = Ids(c, tx, "SELECT network_id FROM network_gateways WHERE gateway = $g LIMIT 2", address);
            if (linked.Count == 1) id = linked[0];
        }

        id ??= Scalar(c, "SELECT id FROM networks WHERE fingerprint = $f", tx, ("$f", n.Fingerprint)) as long?;
        if (id is null && byMac && create
            && Scalar(c, "SELECT id FROM networks WHERE fingerprint = $g", tx, ("$g", n.Gateway)) is long addressOnly
            && Ids(c, tx, "SELECT network_id FROM network_gateways WHERE gateway = $g LIMIT 1", n.Gateway!).Count == 0)
        {
            Exec(c, "UPDATE networks SET fingerprint = $f WHERE id = $id", tx, ("$f", n.Fingerprint), ("$id", addressOnly));
            id = addressOnly;
        }

        if (id is long existing)
        {
            Exec(c, "UPDATE networks SET name = $n WHERE id = $id AND name <> $n", tx, ("$n", n.Name), ("$id", existing));
        }
        else
        {
            if (!create) return -1;
            Exec(c, "INSERT INTO networks (fingerprint, name, created) VALUES ($f, $n, $c)", tx, ("$f", n.Fingerprint), ("$n", n.Name), ("$c", Iso(DateTimeOffset.UtcNow)));
            id = (long)Scalar(c, "SELECT last_insert_rowid()", tx)!;
        }

        if (byMac && create) Exec(c, "INSERT OR IGNORE INTO network_gateways (network_id, gateway) VALUES ($id, $g)", tx, ("$id", id), ("$g", n.Gateway));
        return id.Value;
    }

    private static List<long> Ids(SqliteConnection c, SqliteTransaction? tx, string sql, string gateway)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$g", gateway);
        using var r = cmd.ExecuteReader();
        var list = new List<long>();
        while (r.Read()) list.Add(r.GetInt64(0));
        return list;
    }

    public IReadOnlySet<string> RecordSession(NetworkIdentity network, DateTimeOffset started, DateTimeOffset finished, bool complete,
        IReadOnlyCollection<DeviceResult> results, Func<string, bool> eligibleIp)
    {
        ArgumentNullException.ThrowIfNull(network);
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(eligibleIp);
        lock (_lock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            var net = NetworkId(c, tx, network, create: true);
            var priorSessions = (long)Scalar(c, "SELECT COUNT(*) FROM sessions WHERE network_id = $n", tx, ("$n", net))!;
            Exec(c, "INSERT INTO sessions (network_id, started, finished, complete) VALUES ($n, $s, $f, $c)", tx,
                ("$n", net), ("$s", Iso(started)), ("$f", Iso(finished)), ("$c", complete ? 1 : 0));
            var session = (long)Scalar(c, "SELECT last_insert_rowid()", tx)!;
            var newcomers = new HashSet<string>(StringComparer.Ordinal);
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var d in results.Where(r => r.Status == DeviceStatus.Online && r.Mac.HasValue))
            {
                var mac = HistoryText.MacKey(d.Mac.Value!);
                if (!seen.Add(mac)) continue;
                var ip = d.Key.ToString();
                var host = d.HostName.Value?.Name ?? "";
                var at = d.LastSeen ?? finished;
                var exists = Scalar(c, "SELECT 1 FROM devices WHERE network_id = $n AND mac = $m", tx, ("$n", net), ("$m", mac)) is not null;
                if (exists)
                {
                    Exec(c, "UPDATE devices SET last_seen = $t, last_ip = $ip, last_host = CASE WHEN $h = '' THEN last_host ELSE $h END WHERE network_id = $n AND mac = $m", tx,
                        ("$t", Iso(at)), ("$ip", ip), ("$h", host), ("$n", net), ("$m", mac));
                }
                else
                {
                    Exec(c, "INSERT INTO devices (network_id, mac, first_seen, last_seen, last_ip, last_host) VALUES ($n, $m, $t, $t, $ip, $h)", tx,
                        ("$n", net), ("$m", mac), ("$t", Iso(at)), ("$ip", ip), ("$h", host));
                    if (priorSessions > 0) newcomers.Add(mac);
                }

                Exec(c, "INSERT INTO sightings (session_id, network_id, mac, at, ip, host, rtt, online) VALUES ($s, $n, $m, $t, $ip, $h, $r, 1)", tx,
                    ("$s", session), ("$n", net), ("$m", mac), ("$t", Iso(at)), ("$ip", ip), ("$h", host), ("$r", d.RoundTrip?.TotalMilliseconds));
            }

            if (complete)
            {
                // Known devices whose last address this session covered but that did not answer: an offline sighting.
                var missing = new List<(string Mac, string Ip, string Host)>();
                using (var cmd = c.CreateCommand())
                {
                    cmd.Transaction = tx;
                    cmd.CommandText = "SELECT mac, last_ip, last_host FROM devices WHERE network_id = $n";
                    cmd.Parameters.AddWithValue("$n", net);
                    using var r = cmd.ExecuteReader();
                    while (r.Read())
                    {
                        if (!seen.Contains(r.GetString(0)) && eligibleIp(r.GetString(1))) missing.Add((r.GetString(0), r.GetString(1), r.GetString(2)));
                    }
                }

                foreach (var (mac, ip, host) in missing)
                {
                    Exec(c, "INSERT INTO sightings (session_id, network_id, mac, at, ip, host, rtt, online) VALUES ($s, $n, $m, $t, $ip, $h, NULL, 0)", tx,
                        ("$s", session), ("$n", net), ("$m", mac), ("$t", Iso(finished)), ("$ip", ip), ("$h", host));
                }
            }

            tx.Commit();
            return newcomers;
        }
    }

    public IReadOnlyDictionary<string, HistoryDevice> Devices(NetworkIdentity network)
    {
        ArgumentNullException.ThrowIfNull(network);
        lock (_lock)
        {
            using var c = Open();
            var net = NetworkId(c, null, network, create: false);
            var result = new Dictionary<string, HistoryDevice>(StringComparer.Ordinal);
            if (net < 0) return result;
            using var cmd = c.CreateCommand();
            cmd.CommandText = """
                SELECT d.mac, d.first_seen, d.last_seen, d.last_ip, d.last_host,
                       (SELECT COUNT(*) FROM sightings s JOIN sessions x ON x.id = s.session_id WHERE s.network_id = d.network_id AND s.mac = d.mac AND x.complete = 1),
                       (SELECT COUNT(*) FROM sightings s JOIN sessions x ON x.id = s.session_id WHERE s.network_id = d.network_id AND s.mac = d.mac AND x.complete = 1 AND s.online = 1)
                FROM devices d WHERE d.network_id = $n
                """;
            cmd.Parameters.AddWithValue("$n", net);
            using (var r = cmd.ExecuteReader())
            {
                while (r.Read())
                {
                    result[r.GetString(0)] = new HistoryDevice(r.GetString(0), Parse(r.GetString(1)), Parse(r.GetString(2)), r.GetString(3), r.GetString(4),
                        r.GetInt32(5), r.GetInt32(6), []);
                }
            }

            foreach (var mac in result.Keys.ToList())
            {
                using var q = c.CreateCommand();
                q.CommandText = "SELECT rtt FROM sightings WHERE network_id = $n AND mac = $m ORDER BY at DESC LIMIT $k";
                q.Parameters.AddWithValue("$n", net);
                q.Parameters.AddWithValue("$m", mac);
                q.Parameters.AddWithValue("$k", RecentSamples);
                var rtts = new List<double?>();
                using var r = q.ExecuteReader();
                while (r.Read()) rtts.Add(r.IsDBNull(0) ? null : r.GetDouble(0));
                rtts.Reverse();
                result[mac] = result[mac] with { RecentRtt = rtts };
            }

            return result;
        }
    }

    public IReadOnlyList<Sighting> Timeline(NetworkIdentity network, string mac, DateTimeOffset? from, int max = 5000)
    {
        ArgumentNullException.ThrowIfNull(network);
        lock (_lock)
        {
            using var c = Open();
            var net = NetworkId(c, null, network, create: false);
            if (net < 0) return [];
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT at, ip, host, rtt, online FROM sightings WHERE network_id = $n AND mac = $m AND at >= $f ORDER BY at DESC LIMIT $k";
            cmd.Parameters.AddWithValue("$n", net);
            cmd.Parameters.AddWithValue("$m", mac);
            cmd.Parameters.AddWithValue("$f", from is { } f ? Iso(f) : "");
            cmd.Parameters.AddWithValue("$k", Math.Clamp(max, 1, 100_000));
            var list = new List<Sighting>();
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(new Sighting(Parse(r.GetString(0)), r.GetString(1), r.GetString(2), r.IsDBNull(3) ? null : r.GetDouble(3), r.GetInt32(4) == 1));
            return list;
        }
    }

    /// <summary>Deletes sightings, sessions and devices older than the retention period (HIS-03).</summary>
    public int Cleanup(int retentionDays, DateTimeOffset now)
    {
        lock (_lock)
        {
            using var c = Open();
            using var tx = c.BeginTransaction();
            var cutoff = Iso(now.AddDays(-Math.Max(1, retentionDays)));
            using var del = c.CreateCommand();
            del.Transaction = tx;
            del.CommandText = "DELETE FROM sightings WHERE at < $c";
            del.Parameters.AddWithValue("$c", cutoff);
            var removed = del.ExecuteNonQuery();
            Exec(c, "DELETE FROM sessions WHERE finished < $c", tx, ("$c", cutoff));
            Exec(c, "DELETE FROM devices WHERE last_seen < $c", tx, ("$c", cutoff));
            tx.Commit();
            return removed;
        }
    }

    public IReadOnlyList<NetworkIdentity> Networks()
    {
        lock (_lock)
        {
            using var c = Open();
            using var cmd = c.CreateCommand();
            cmd.CommandText = "SELECT fingerprint, name FROM networks ORDER BY name";
            var list = new List<NetworkIdentity>();
            using var r = cmd.ExecuteReader();
            while (r.Read()) list.Add(new NetworkIdentity(r.GetString(0), r.GetString(1)));
            return list;
        }
    }
}
