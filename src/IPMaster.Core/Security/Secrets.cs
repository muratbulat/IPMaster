using System.Security.Cryptography;
using System.Text;

namespace IPMaster.Core.Security;

/// <summary>Credential Manager entry (SEC-01). <see cref="Secret"/> is protected text, never the plain password.</summary>
public sealed record StoredCredential
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string UserName { get; set; } = "";

    /// <summary>Password (or, for SSH, a private-key path) encrypted by the vault: <c>v1:base64(nonce|ciphertext|tag)</c>.</summary>
    public string Secret { get; set; } = "";

    public string Comment { get; set; } = "";

    /// <summary>Short unique identifier for scripts and applications.</summary>
    public string Tag { get; set; } = "";

    public string Display => Tag.Length > 0 ? $"{UserName} [{Tag}]" : UserName;
}

public enum VaultMode
{
    /// <summary>No key yet: secrets cannot be stored.</summary>
    None,

    /// <summary>Data key protected by the operating system for the current user (Windows DPAPI). Not portable.</summary>
    OsProtected,

    /// <summary>Data key protected by a key derived from the master password; the settings file is encrypted too. Portable.</summary>
    MasterPassword,
}

public sealed record VaultSettings
{
    public VaultMode Mode { get; set; } = VaultMode.None;

    /// <summary>Data key wrapped by DPAPI (OsProtected) or by the master-password key (MasterPassword), base64.</summary>
    public string WrappedKey { get; set; } = "";
}

/// <summary>Plain password with its user name, resolved for one operation; never persisted or logged.</summary>
public sealed record ResolvedCredential(string UserName, string Password)
{
    public override string ToString() => $"{UserName} (password hidden)";

    /// <summary>Splits <c>DOMAIN\user</c> or <c>user@domain</c>.</summary>
    public (string Domain, string User) Split()
    {
        var i = UserName.IndexOf('\\', StringComparison.Ordinal);
        if (i > 0) return (UserName[..i], UserName[(i + 1)..]);
        return ("", UserName);
    }
}

/// <summary>
/// Authenticated encryption primitives (D-051): AES-256-GCM with random 96-bit nonces, PBKDF2-HMAC-SHA256 for
/// passwords and HKDF-SHA256 to separate keys by purpose. All from the .NET runtime (no third-party crypto).
/// </summary>
public static class SecretBox
{
    public const int KeySize = 32;
    public const int SaltSize = 16;
    public const int NonceSize = 12;
    public const int TagSize = 16;

    /// <summary>OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.</summary>
    public const int DefaultIterations = 600_000;

    /// <summary>Upper bound for an iteration count read from a file: a crafted value must not hang an unlock (review C-09).</summary>
    public const int MaxIterations = 10_000_000;

    /// <summary>An iteration count from a file, or FormatException when it is outside 100,000…<see cref="MaxIterations"/>.</summary>
    public static int CheckIterations(int iterations) => iterations is >= 100_000 and <= MaxIterations
        ? iterations
        : throw new FormatException($"Key-derivation iteration count {iterations} is outside the supported range.");

    public const string Prefix = "v1:";

    public static byte[] NewKey() => RandomNumberGenerator.GetBytes(KeySize);

    public static byte[] NewSalt() => RandomNumberGenerator.GetBytes(SaltSize);

    public static byte[] DeriveFromPassword(string password, byte[] salt, int iterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(salt);
        if (iterations is < 100_000 or > MaxIterations) throw new ArgumentOutOfRangeException(nameof(iterations), "Between 100,000 and 10,000,000 iterations are required.");
        return Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, KeySize);
    }

    public static byte[] SubKey(byte[] key, string purpose) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, key, KeySize, salt: null, info: Encoding.UTF8.GetBytes("ipmaster:" + purpose));

    public static byte[] Seal(byte[] key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData)
    {
        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, output.AsSpan(NonceSize, plaintext.Length), output.AsSpan(NonceSize + plaintext.Length), associatedData);
        return output;
    }

    /// <summary>Throws <see cref="CryptographicException"/> when the key is wrong or the data was modified.</summary>
    public static byte[] Open(byte[] key, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> associatedData)
    {
        if (sealedData.Length < NonceSize + TagSize) throw new CryptographicException("Encrypted data is truncated.");
        var plaintext = new byte[sealedData.Length - NonceSize - TagSize];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(sealedData[..NonceSize], sealedData.Slice(NonceSize, plaintext.Length), sealedData[^TagSize..], plaintext, associatedData);
        return plaintext;
    }

    private static readonly byte[] SecretAad = "ipmaster-secret-v1"u8.ToArray();

    public static string ProtectText(byte[] dataKey, string plaintext) =>
        Prefix + Convert.ToBase64String(Seal(dataKey, Encoding.UTF8.GetBytes(plaintext ?? ""), SecretAad));

    public static string UnprotectText(byte[] dataKey, string protectedText)
    {
        ArgumentNullException.ThrowIfNull(protectedText);
        if (protectedText.Length == 0) return "";
        if (!protectedText.StartsWith(Prefix, StringComparison.Ordinal)) throw new CryptographicException("Unknown secret format.");
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(protectedText[Prefix.Length..]);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException("Secret is not valid base64.", ex);
        }

        return Encoding.UTF8.GetString(Open(dataKey, raw, SecretAad));
    }

    public static bool IsProtected(string text) => text.StartsWith(Prefix, StringComparison.Ordinal);
}

/// <summary>Resolves query credentials and protected option values at execution time.</summary>
public interface ISecretSource
{
    /// <summary>False when secrets cannot be decrypted (vault locked, no key, other user's DPAPI key).</summary>
    bool CanReveal { get; }

    ResolvedCredential? Credential(Guid id);

    /// <summary>Decrypts protected text; plain (legacy/empty) text is returned unchanged.</summary>
    string Reveal(string protectedText);
}
