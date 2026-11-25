using IPMaster.Core.Scanning;
using IPMaster.Core.Security;

namespace IPMaster.Infrastructure.Security;

/// <summary>
/// The SNMP communities in <see cref="ScanSettings"/> (UDP/banner probe, router-MIB MAC method) are secrets like the query
/// communities: stored vault-protected, revealed only into the settings of a scan request (review C-14). Legacy
/// plaintext values keep working (<see cref="ISecretSource.Reveal"/> returns plain text unchanged).
/// </summary>
public static class ScanSecrets
{
    /// <summary>Protects both communities when the vault has a key; otherwise (no key on this platform yet) leaves them as they are.</summary>
    public static ScanSettings Protect(ScanSettings settings, CredentialVault vault)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(vault);
        if (!vault.CanReveal) return settings;
        string P(string v) => SecretBox.IsProtected(v) ? v : vault.Protect(v);
        return settings with { SnmpProbeCommunity = P(settings.SnmpProbeCommunity), RouterMibCommunity = P(settings.RouterMibCommunity) };
    }

    /// <summary>Plain communities for a scan or for the Options dialog. A community that cannot be decrypted (vault locked)
    /// becomes empty, so no ciphertext is ever sent on the wire.</summary>
    public static ScanSettings Reveal(ScanSettings settings, ISecretSource vault)
    {
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(vault);
        string R(string v)
        {
            try
            {
                return vault.Reveal(v);
            }
            catch (Exception ex) when (ex is InvalidOperationException or System.Security.Cryptography.CryptographicException or FormatException)
            {
                return "";
            }
        }

        return settings with { SnmpProbeCommunity = R(settings.SnmpProbeCommunity), RouterMibCommunity = R(settings.RouterMibCommunity) };
    }
}
