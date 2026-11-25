using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;

namespace IPMaster.Infrastructure.Configuration;

public enum SettingsLoadStatus
{
    Loaded,
    Defaults,
    Migrated,
    RecoveredFromCorruption,

    /// <summary>The file was written by a newer IPMaster; defaults are used and the file is never overwritten.</summary>
    NewerSchemaReadOnly,

    /// <summary>The file is encrypted with a master password (SEC-02); call <see cref="SettingsStore.Unlock"/>. Never overwritten while locked.</summary>
    PasswordRequired,

    /// <summary>The master password did not decrypt the file.</summary>
    WrongPassword,
}

public sealed record SettingsLoadResult(AppSettings Settings, SettingsLoadStatus Status, string? Message);

/// <summary>
/// Versioned JSON settings file with forward migrations and atomic saves (D-005). Portable-first: the file
/// lives next to the executables when that directory is writable, otherwise in the per-user config dir.
/// <c>IPMASTER_CONFIG_DIR</c> overrides the location.
/// </summary>
public sealed class SettingsStore
{
    public const string FileName = "ipmaster.settings.json";

    private static readonly Dictionary<int, Action<JsonObject>> Migrations = new Dictionary<int, Action<JsonObject>>
    {
        // v0 = files without "schemaVersion" (pre-release builds). Structure is identical to v1.
        [0] = _ => { },
    };

    private readonly object _lock = new();
    private bool _readOnly;
    private AppSettings? _base;
    private byte[] _diskHash = [];

    public SettingsStore(string? directory = null, Security.CredentialVault? vault = null)
    {
        Vault = vault ?? new Security.CredentialVault();
        Directory = directory ?? ResolveDefaultDirectory();
        FilePath = Path.Combine(Directory, FileName);
    }

    public string Directory { get; }

    public string FilePath { get; }

    public Security.CredentialVault Vault { get; }

    /// <summary>True while an encrypted file has not been unlocked.</summary>
    public bool IsLocked { get; private set; }

    public static string ResolveDefaultDirectory()
    {
        var env = Environment.GetEnvironmentVariable("IPMASTER_CONFIG_DIR");
        if (!string.IsNullOrWhiteSpace(env)) return env;
        var baseDir = AppContext.BaseDirectory;
        if (IsWritable(baseDir)) return baseDir;
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "IPMaster");
    }

    public SettingsLoadResult Load()
    {
        lock (_lock)
        {
            if (!File.Exists(FilePath)) return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.Defaults, null);
            string text;
            try
            {
                var bytes = File.ReadAllBytes(FilePath);
                _diskHash = Hash(bytes);
                text = Decode(bytes);
            }
            catch (IOException ex)
            {
                return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.Defaults, $"Settings could not be read: {ex.Message}");
            }

            try
            {
                return Parse(text);
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or NotSupportedException)
            {
                var backup = FilePath + $".corrupt-{DateTime.Now:yyyyMMddHHmmss}";
                try
                {
                    File.Copy(FilePath, backup, overwrite: true);
                }
                catch (IOException)
                {
                    // best effort
                }

                return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.RecoveredFromCorruption,
                    $"Settings file was invalid ({ex.Message}); a copy was kept at {backup} and defaults are used.");
            }
        }
    }

    /// <summary>Decrypts a master-password-protected settings file (SEC-02). Wrong password → <see cref="SettingsLoadStatus.WrongPassword"/>.</summary>
    public SettingsLoadResult Unlock(string password)
    {
        ArgumentNullException.ThrowIfNull(password);
        lock (_lock)
        {
            var node = JsonNode.Parse(File.ReadAllText(FilePath)) as JsonObject ?? throw new JsonException("Root is not an object.");
            if (!Security.CredentialVault.IsEncryptedConfig(node)) return Parse(node.ToJsonString());
            var (salt, iterations) = Security.CredentialVault.EnvelopeParameters(node);
            var key = Security.CredentialVault.Derive(password, salt, iterations);
            string json;
            try
            {
                json = Security.CredentialVault.DecryptConfig(key, node);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                IsLocked = true;
                return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.WrongPassword, "The master password is not correct.");
            }

            Vault.UseMasterKey(key);
            return Parse(json);
        }
    }

    internal SettingsLoadResult Parse(string text) => Parse(text, attachVault: true);

    /// <param name="attachVault">False when reading another window's copy: its credentials and vault mode must not replace
    /// this instance's vault state (review C-01).</param>
    private SettingsLoadResult Parse(string text, bool attachVault)
    {
        var node = JsonNode.Parse(text, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true })
                   as JsonObject ?? throw new JsonException("Root is not an object.");
        if (Security.CredentialVault.IsEncryptedConfig(node))
        {
            if (Vault.Master is not { } key)
            {
                IsLocked = true;
                return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.PasswordRequired, "The configuration is protected by a master password.");
            }

            try
            {
                return Parse(Security.CredentialVault.DecryptConfig(key, node), attachVault);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                IsLocked = true;
                return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.WrongPassword, "The master password is not correct.");
            }
        }

        var version = node["schemaVersion"]?.GetValue<int>() ?? 0;
        if (version > AppSettings.CurrentSchemaVersion)
        {
            _readOnly = true;
            return new SettingsLoadResult(new AppSettings(), SettingsLoadStatus.NewerSchemaReadOnly,
                $"Settings were written by a newer version (schema {version}); defaults are used and the file will not be modified.");
        }

        var migrated = false;
        while (version < AppSettings.CurrentSchemaVersion)
        {
            Migrations[version](node);
            version++;
            migrated = true;
        }

        node["schemaVersion"] = AppSettings.CurrentSchemaVersion;
        var settings = node.Deserialize(SettingsJsonContext.Default.AppSettings) ?? new AppSettings();
        settings = settings with { Scan = settings.Scan.Normalize() };
        IsLocked = false;
        _base = settings;
        if (attachVault) Vault.Attach(settings);
        return new SettingsLoadResult(settings, migrated ? SettingsLoadStatus.Migrated : SettingsLoadStatus.Loaded, null);
    }

    public async Task SaveAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (_readOnly) throw new InvalidOperationException("The settings file belongs to a newer version and is not overwritten.");
        var json = JsonSerializer.SerializeToUtf8Bytes(settings with { SchemaVersion = AppSettings.CurrentSchemaVersion }, SettingsJsonContext.Default.AppSettings);
        if (IsLocked) throw new InvalidOperationException("The encrypted settings file has not been unlocked; it is not overwritten.");
        if (settings.Vault.Mode == Core.Security.VaultMode.MasterPassword)
        {
            var key = Vault.Master ?? throw new InvalidOperationException("The master password is not available; settings are not saved unencrypted.");
            json = Security.CredentialVault.EncryptConfig(key, json);
        }

        System.IO.Directory.CreateDirectory(Directory); // first run: the folder may not exist yet (D-100)
        await AtomicFile.WriteAsync(FilePath, s => s.WriteAsync(json, cancellationToken).AsTask(), cancellationToken).ConfigureAwait(false);
        _diskHash = Hash(json);
        _base = settings;
    }

    /// <summary>
    /// Save for several windows (processes) sharing one configuration (UI-21, D-064): under a cross-process lock file,
    /// when another instance changed the file since this one last read or wrote it, its version is merged with ours
    /// property by property (ours wins only where this instance changed something since its base). Returns what was saved.
    /// </summary>
    public async Task<AppSettings> SaveSharedAsync(AppSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);
        await using var gate = await AcquireLockAsync(cancellationToken).ConfigureAwait(false);
        var merged = settings;
        if (_base is { } @base && File.Exists(FilePath))
        {
            byte[] bytes;
            try
            {
                bytes = await File.ReadAllBytesAsync(FilePath, cancellationToken).ConfigureAwait(false);
            }
            catch (IOException)
            {
                bytes = [];
            }

            if (bytes.Length > 0 && !Hash(bytes).AsSpan().SequenceEqual(_diskHash))
            {
                SettingsLoadResult? theirs = null;
                try
                {
                    lock (_lock) theirs = ParseOther(Decode(bytes));
                }
                catch (Exception ex) when (ex is JsonException or InvalidOperationException or NotSupportedException)
                {
                    // the other copy is unreadable: ours replaces it
                }

                if (theirs is { Status: SettingsLoadStatus.PasswordRequired or SettingsLoadStatus.WrongPassword })
                {
                    // Another window protected the file with a master password this one does not hold: writing our copy
                    // would silently store everything unencrypted again (review C-01).
                    throw new InvalidOperationException("Another IPMaster window protected the configuration with a master password. Restart IPMaster (or unlock) before changing settings here.");
                }

                if (theirs is { Status: SettingsLoadStatus.Loaded or SettingsLoadStatus.Migrated }) merged = Merge(@base, settings, theirs.Settings);
            }
        }

        await SaveAsync(merged, cancellationToken).ConfigureAwait(false);
        if (!ReferenceEquals(merged, settings)) Vault.Attach(merged);
        return merged;
    }

    /// <summary>Three-way merge on the JSON form: objects merge per property; other values (arrays included) are atomic.</summary>
    public static AppSettings Merge(AppSettings @base, AppSettings ours, AppSettings theirs)
    {
        ArgumentNullException.ThrowIfNull(@base);
        ArgumentNullException.ThrowIfNull(ours);
        ArgumentNullException.ThrowIfNull(theirs);
        static JsonObject Node(AppSettings s) => (JsonObject)JsonSerializer.SerializeToNode(s, SettingsJsonContext.Default.AppSettings)!;
        var result = MergeNode(Node(@base), Node(ours), Node(theirs));
        var merged = result.Deserialize(SettingsJsonContext.Default.AppSettings) ?? ours;
        return merged with { Scan = merged.Scan.Normalize() };
    }

    private static JsonNode? MergeNode(JsonNode? b, JsonNode? o, JsonNode? t)
    {
        if (JsonNode.DeepEquals(o, b)) return t?.DeepClone();
        if (JsonNode.DeepEquals(t, b)) return o?.DeepClone();
        if (o is JsonObject oo && t is JsonObject to && b is JsonObject bo)
        {
            var r = new JsonObject();
            foreach (var name in oo.Select(p => p.Key).Union(to.Select(p => p.Key)))
            {
                r[name] = MergeNode(bo[name], oo[name], to[name]);
            }

            return r;
        }

        return o?.DeepClone();
    }

    /// <summary>Parses another instance's copy without changing this store's read-only/locked state.</summary>
    private SettingsLoadResult ParseOther(string text)
    {
        var (readOnly, locked, @base) = (_readOnly, IsLocked, _base);
        try
        {
            return Parse(text, attachVault: false);
        }
        finally
        {
            (_readOnly, IsLocked, _base) = (readOnly, locked, @base);
        }
    }

    private static async Task<FileStream> AcquireLockAsync(string path, CancellationToken cancellationToken)
    {
        // a first run (e.g. %APPDATA%\IPMaster) has no folder yet: without it every save waited 5 s and failed (D-100)
        System.IO.Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
            }
            catch (IOException ex) when (attempt < 100 && ex is not (DirectoryNotFoundException or PathTooLongException)) // only a held lock is worth waiting for
            {
                await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private Task<FileStream> AcquireLockAsync(CancellationToken cancellationToken) => AcquireLockAsync(FilePath + ".lock", cancellationToken);

    private static byte[] Hash(ReadOnlySpan<byte> bytes) => System.Security.Cryptography.SHA256.HashData(bytes);

    private static string Decode(byte[] bytes)
    {
        using var reader = new StreamReader(new MemoryStream(bytes), System.Text.Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private static bool IsWritable(string dir)
    {
        try
        {
            var probe = Path.Combine(dir, $".ipmaster-write-test-{Environment.ProcessId}");
            File.WriteAllText(probe, "");
            File.Delete(probe);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    IgnoreReadOnlyProperties = true)]
[JsonSerializable(typeof(AppSettings))]
internal sealed partial class SettingsJsonContext : JsonSerializerContext;
