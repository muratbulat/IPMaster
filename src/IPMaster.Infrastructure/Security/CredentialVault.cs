using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using IPMaster.Core.Configuration;
using IPMaster.Core.Security;

namespace IPMaster.Infrastructure.Security;

/// <summary>
/// Credential vault (SEC-01/02, D-051). One random 256-bit data key encrypts every stored secret (AES-GCM). The data
/// key itself is protected either by Windows DPAPI for the current user (<see cref="VaultMode.OsProtected"/>, not
/// portable) or by a key derived from the master password (<see cref="VaultMode.MasterPassword"/>, portable; the whole
/// settings file is then encrypted as well). Keys live only in memory.
/// </summary>
public sealed class CredentialVault : ISecretSource
{
    private static readonly byte[] DpapiEntropy = "IPMaster credential vault v1"u8.ToArray();
    private static readonly byte[] WrapAad = "ipmaster-vault-key-v1"u8.ToArray();
    private readonly object _lock = new();
    private byte[]? _dataKey;
    private MasterKey? _master;
    private IReadOnlyList<StoredCredential> _credentials = [];

    public VaultMode Mode { get; private set; }

    /// <summary>Why secrets cannot be revealed (null when they can).</summary>
    public string? Problem { get; private set; }

    public bool CanReveal
    {
        get
        {
            lock (_lock) return _dataKey is not null;
        }
    }

    public bool HasMasterKey
    {
        get
        {
            lock (_lock) return _master is not null;
        }
    }

    public static bool OsProtectionAvailable => OperatingSystem.IsWindows();

    internal sealed record MasterKey(byte[] Salt, int Iterations, byte[] FileKey, byte[] WrapKey);

    internal MasterKey? Master
    {
        get
        {
            lock (_lock) return _master;
        }
    }

    /// <summary>Reads the vault state of freshly loaded settings and unwraps the data key when possible.</summary>
    public void Attach(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_lock)
        {
            _credentials = settings.Credentials;
            Mode = settings.Vault.Mode;
            _dataKey = null;
            Problem = null;
            if (Mode == VaultMode.None)
            {
                Problem = settings.Credentials.Count > 0 ? "The vault has no key." : null;
                return;
            }

            byte[] wrapped;
            try
            {
                wrapped = Convert.FromBase64String(settings.Vault.WrappedKey);
            }
            catch (FormatException)
            {
                Problem = "The vault key in the settings file is damaged.";
                return;
            }

            try
            {
                if (Mode == VaultMode.OsProtected)
                {
                    if (!OperatingSystem.IsWindows())
                    {
                        Problem = "Credentials were protected by Windows for another installation; this platform cannot read them.";
                        return;
                    }

                    _dataKey = ProtectedData.Unprotect(wrapped, DpapiEntropy, DataProtectionScope.CurrentUser);
                }
                else if (_master is null)
                {
                    Problem = "The master password has not been entered.";
                }
                else
                {
                    _dataKey = SecretBox.Open(_master.WrapKey, wrapped, WrapAad);
                }
            }
            catch (CryptographicException)
            {
                Problem = Mode == VaultMode.OsProtected
                    ? "Credentials were protected for another Windows user or computer. Re-enter them or use a master password for portable settings."
                    : "The vault key does not match the master password.";
            }
        }
    }

    public ResolvedCredential? Credential(Guid id)
    {
        StoredCredential? c;
        lock (_lock) c = _credentials.FirstOrDefault(x => x.Id == id);
        return c is null ? null : new ResolvedCredential(c.UserName, Reveal(c.Secret));
    }

    public ResolvedCredential? CredentialByTag(string tag)
    {
        StoredCredential? c;
        lock (_lock) c = _credentials.FirstOrDefault(x => string.Equals(x.Tag, tag, StringComparison.OrdinalIgnoreCase));
        return c is null ? null : new ResolvedCredential(c.UserName, Reveal(c.Secret));
    }

    public string Reveal(string protectedText)
    {
        ArgumentNullException.ThrowIfNull(protectedText);
        if (!SecretBox.IsProtected(protectedText)) return protectedText;
        byte[]? key;
        lock (_lock) key = _dataKey;
        if (key is null) throw new InvalidOperationException(Problem ?? "Credentials are locked.");
        return SecretBox.UnprotectText(key, protectedText);
    }

    /// <summary>Encrypts a secret for storage. Call <see cref="EnsureKey"/> first.</summary>
    public string Protect(string plaintext)
    {
        byte[]? key;
        lock (_lock) key = _dataKey;
        if (key is null) throw new InvalidOperationException(Problem ?? "The vault has no key yet.");
        return SecretBox.ProtectText(key, plaintext ?? "");
    }

    /// <summary>
    /// Creates the data key on first use. Windows: protected by DPAPI. Elsewhere a master password is required
    /// because no OS key store is integrated yet (D-051).
    /// </summary>
    public AppSettings EnsureKey(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_lock)
        {
            if (_dataKey is not null) return settings;
            if (settings.Vault.Mode != VaultMode.None) throw new InvalidOperationException(Problem ?? "The vault is locked.");
            if (!OperatingSystem.IsWindows())
            {
                throw new InvalidOperationException("Set a master password (File → Current Config) before storing credentials on this platform.");
            }

            var dek = SecretBox.NewKey();
            var wrapped = ProtectedData.Protect(dek, DpapiEntropy, DataProtectionScope.CurrentUser);
            _dataKey = dek;
            Mode = VaultMode.OsProtected;
            Problem = null;
            return settings with { Vault = new VaultSettings { Mode = VaultMode.OsProtected, WrappedKey = Convert.ToBase64String(wrapped) } };
        }
    }

    /// <summary>Sets or changes the master password; the settings file is encrypted from the next save on.</summary>
    public AppSettings SetMasterPassword(AppSettings settings, string password, int iterations = SecretBox.DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentException.ThrowIfNullOrEmpty(password);
        lock (_lock)
        {
            if (settings.Vault.Mode != VaultMode.None && _dataKey is null) throw new InvalidOperationException(Problem ?? "The vault is locked.");
            var dek = _dataKey ?? SecretBox.NewKey();
            var master = Derive(password, SecretBox.NewSalt(), iterations);
            _master = master;
            _dataKey = dek;
            Mode = VaultMode.MasterPassword;
            Problem = null;
            return settings with
            {
                Vault = new VaultSettings { Mode = VaultMode.MasterPassword, WrappedKey = Convert.ToBase64String(SecretBox.Seal(master.WrapKey, dek, WrapAad)) },
            };
        }
    }

    /// <summary>Removes the master password. Stored secrets move to OS protection (Windows); elsewhere they must be deleted first.</summary>
    public AppSettings RemoveMasterPassword(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_lock)
        {
            if (settings.Vault.Mode != VaultMode.MasterPassword) return settings;
            if (_dataKey is null) throw new InvalidOperationException("Enter the master password first.");
            _master = null;
            if (OperatingSystem.IsWindows())
            {
                var wrapped = ProtectedData.Protect(_dataKey, DpapiEntropy, DataProtectionScope.CurrentUser);
                Mode = VaultMode.OsProtected;
                return settings with { Vault = new VaultSettings { Mode = VaultMode.OsProtected, WrappedKey = Convert.ToBase64String(wrapped) } };
            }

            if (HasStoredSecrets(settings)) throw new InvalidOperationException("Delete stored credentials first: this platform has no OS key store to keep them.");
            _dataKey = null;
            Mode = VaultMode.None;
            return settings with { Vault = new VaultSettings() };
        }
    }

    private static bool HasStoredSecrets(AppSettings s) =>
        s.Credentials.Count > 0 || s.Queries.Items.Any(q => q.Snmp is { } n && (n.Communities.Length > 0 || n.PrivPassword.Length > 0));

    internal static MasterKey Derive(string password, byte[] salt, int iterations)
    {
        var kek = SecretBox.DeriveFromPassword(password, salt, iterations);
        try
        {
            return new MasterKey(salt, iterations, SecretBox.SubKey(kek, "config-file"), SecretBox.SubKey(kek, "vault-key"));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    internal void UseMasterKey(MasterKey key)
    {
        lock (_lock) _master = key;
    }

    // ---------------------------------------------------------------- encrypted configuration file

    private const string EnvelopeMarker = "ipmasterEncryptedConfig";
    private static readonly byte[] ConfigAad = "ipmaster-config-v1"u8.ToArray();

    public static bool IsEncryptedConfig(JsonObject root) => root.ContainsKey(EnvelopeMarker);

    internal static byte[] EncryptConfig(MasterKey key, byte[] json)
    {
        var o = new JsonObject
        {
            [EnvelopeMarker] = 1,
            ["kdf"] = "PBKDF2-HMAC-SHA256",
            ["iterations"] = key.Iterations,
            ["salt"] = Convert.ToBase64String(key.Salt),
            ["cipher"] = "AES-256-GCM",
            ["data"] = Convert.ToBase64String(SecretBox.Seal(key.FileKey, json, ConfigAad)),
        };
        return JsonSerializer.SerializeToUtf8Bytes(o, IndentedOptions);
    }

    private static readonly JsonSerializerOptions IndentedOptions = new() { WriteIndented = true };

    internal static (byte[] Salt, int Iterations) EnvelopeParameters(JsonObject envelope)
    {
        var iterations = SecretBox.CheckIterations(envelope["iterations"]?.GetValue<int>() ?? throw new FormatException("Encrypted settings without iterations."));
        var salt = Convert.FromBase64String(envelope["salt"]?.GetValue<string>() ?? throw new FormatException("Encrypted settings without salt."));
        return (salt, iterations);
    }

    /// <summary>Throws <see cref="CryptographicException"/> for a wrong password.</summary>
    internal static string DecryptConfig(MasterKey key, JsonObject envelope)
    {
        var data = Convert.FromBase64String(envelope["data"]?.GetValue<string>() ?? throw new FormatException("Encrypted settings without data."));
        return Encoding.UTF8.GetString(SecretBox.Open(key.FileKey, data, ConfigAad));
    }

    // ---------------------------------------------------------------- credential export / import

    private const string ExportFormat = "ipmaster-credentials";
    private static readonly byte[] ExportAad = "ipmaster-credential-export-v1"u8.ToArray();

    /// <summary>Encrypted export (SEC-01): plaintext never touches the disk; protected with an export password.</summary>
    public byte[] Export(IReadOnlyList<StoredCredential> credentials, string exportPassword)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        ArgumentException.ThrowIfNullOrEmpty(exportPassword);
        var list = new JsonArray();
        foreach (var c in credentials)
        {
            list.Add(new JsonObject { ["userName"] = c.UserName, ["password"] = Reveal(c.Secret), ["comment"] = c.Comment, ["tag"] = c.Tag });
        }

        var salt = SecretBox.NewSalt();
        var key = SecretBox.DeriveFromPassword(exportPassword, salt, SecretBox.DefaultIterations);
        try
        {
            var o = new JsonObject
            {
                ["format"] = ExportFormat,
                ["version"] = 1,
                ["kdf"] = "PBKDF2-HMAC-SHA256",
                ["iterations"] = SecretBox.DefaultIterations,
                ["salt"] = Convert.ToBase64String(salt),
                ["data"] = Convert.ToBase64String(SecretBox.Seal(key, Encoding.UTF8.GetBytes(list.ToJsonString()), ExportAad)),
            };
            return JsonSerializer.SerializeToUtf8Bytes(o, IndentedOptions);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Decrypts an export and re-protects every secret with this vault's key. Wrong password → CryptographicException.</summary>
    public IReadOnlyList<StoredCredential> Import(ReadOnlySpan<byte> file, string exportPassword)
    {
        if (file.Length > 4 * 1024 * 1024) throw new FormatException("Credential file is too large.");
        var o = JsonNode.Parse(file) as JsonObject ?? throw new FormatException("Not a credential export.");
        if (o["format"]?.GetValue<string>() != ExportFormat) throw new FormatException("Not an IPMaster credential export.");
        var iterations = SecretBox.CheckIterations(o["iterations"]?.GetValue<int>() ?? throw new FormatException("Missing iterations."));
        var salt = Convert.FromBase64String(o["salt"]?.GetValue<string>() ?? "");
        var key = SecretBox.DeriveFromPassword(exportPassword, salt, iterations);
        try
        {
            var plain = SecretBox.Open(key, Convert.FromBase64String(o["data"]?.GetValue<string>() ?? ""), ExportAad);
            var arr = JsonNode.Parse(plain) as JsonArray ?? throw new FormatException("Invalid credential list.");
            return arr.OfType<JsonObject>().Select(x => new StoredCredential
            {
                UserName = x["userName"]?.GetValue<string>() ?? "",
                Secret = Protect(x["password"]?.GetValue<string>() ?? ""),
                Comment = x["comment"]?.GetValue<string>() ?? "",
                Tag = x["tag"]?.GetValue<string>() ?? "",
            }).ToList();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Tags must be unique across all credentials (manual).</summary>
    public static string? ValidateTags(IEnumerable<StoredCredential> credentials)
    {
        ArgumentNullException.ThrowIfNull(credentials);
        var dup = credentials.Where(c => c.Tag.Length > 0).GroupBy(c => c.Tag, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        return dup is null ? null : $"The tag '{dup.Key}' is used more than once.";
    }
}
