using System.Globalization;
using System.Text;

namespace IPMaster.Core.Tools;

/// <summary>Display formatting of LDAP attribute values (D-077). Pure; no directory access.</summary>
public static class LdapValues
{
    public const int MaxBinaryBytesShown = 64;

    /// <summary>Attributes that can hold passwords or keys: never displayed, copied or exported.</summary>
    private static readonly HashSet<string> Secret = new(StringComparer.OrdinalIgnoreCase)
    {
        "userPassword", "unicodePwd", "dBCSPwd", "lmPwdHistory", "ntPwdHistory", "supplementalCredentials", "ms-Mcs-AdmPwd", "msLAPS-Password",
        "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory",
        "msFVE-RecoveryPassword", "msFVE-KeyPackage", "msDS-ManagedPassword", "msTPM-OwnerInformation", "msPKI-CredentialRoamingTokens", "msPKIAccountCredentials",
        "msPKIDPAPIMasterKeys", "msPKIRoamingTimeStamp", "trustAuthIncoming", "trustAuthOutgoing", "currentValue", "priorValue",
    };

    private static readonly HashSet<string> Binary = new(StringComparer.OrdinalIgnoreCase)
    {
        "objectGUID", "objectSid", "sIDHistory", "tokenGroups", "msExchMailboxGuid", "userCertificate", "cACertificate", "thumbnailPhoto", "jpegPhoto",
        "logonHours", "msDS-GenerationId", "mS-DS-ConsistencyGuid", "nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity", "replUpToDateVector",
        "repsFrom", "repsTo", "invocationId", "objectGUID;binary", "schemaIDGUID", "attributeSecurityGUID", "msDFSR-ContentSetGuid",
    };

    public static bool IsSecret(string attribute) => Secret.Contains(attribute ?? "");

    /// <summary>True for attributes whose values are binary on the wire (so text decoding would be meaningless).</summary>
    public static bool IsBinary(string attribute) =>
        Binary.Contains(attribute ?? "") || (attribute ?? "").EndsWith(";binary", StringComparison.OrdinalIgnoreCase) || (attribute ?? "").EndsWith("Guid", StringComparison.OrdinalIgnoreCase);

    public static string Format(string attribute, byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (IsSecret(attribute)) return "[redacted: secret attribute]";
        if ((attribute.Equals("objectSid", StringComparison.OrdinalIgnoreCase) || attribute.Equals("sIDHistory", StringComparison.OrdinalIgnoreCase)
                                                                                  || attribute.Equals("tokenGroups", StringComparison.OrdinalIgnoreCase)) && Sid(value) is { } sid)
        {
            return sid;
        }

        if (value.Length == 16 && IsBinary(attribute) && attribute.Contains("guid", StringComparison.OrdinalIgnoreCase)) return new Guid(value).ToString("D");
        if (!IsBinary(attribute) && TryText(value) is { } text) return text;
        return Hex(value);
    }

    public static string Hex(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        var shown = Convert.ToHexString(value.AsSpan(0, Math.Min(value.Length, MaxBinaryBytesShown)));
        return value.Length > MaxBinaryBytesShown
            ? string.Create(CultureInfo.InvariantCulture, $"0x{shown}… ({value.Length} bytes)")
            : string.Create(CultureInfo.InvariantCulture, $"0x{shown} ({value.Length} bytes)");
    }

    /// <summary>UTF-8 text without control characters (other than tab/newline), else null.</summary>
    public static string? TryText(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        try
        {
            var s = new UTF8Encoding(false, true).GetString(value);
            return s.Any(c => char.IsControl(c) && c is not ('\t' or '\n' or '\r')) ? null : s;
        }
        catch (DecoderFallbackException)
        {
            return null;
        }
    }

    /// <summary>Binary SID (MS-DTYP 2.4.2.2) → "S-1-5-21-…", or null if malformed.</summary>
    public static string? Sid(byte[] b)
    {
        ArgumentNullException.ThrowIfNull(b);
        if (b.Length < 8 || b[0] != 1) return null;
        int count = b[1];
        if (b.Length != 8 + (4 * count)) return null;
        ulong authority = 0;
        for (var i = 2; i < 8; i++) authority = (authority << 8) | b[i];
        var sb = new StringBuilder("S-1-").Append(authority.ToString(CultureInfo.InvariantCulture));
        for (var i = 0; i < count; i++) sb.Append('-').Append(BitConverter.ToUInt32(b, 8 + (4 * i)).ToString(CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    /// <summary>Generalized time "20261117083000.0Z" → readable UTC, else the input.</summary>
    public static string Time(string value) =>
        DateTime.TryParseExact(value, ["yyyyMMddHHmmss.0Z", "yyyyMMddHHmmss'Z'", "yyyyMMddHHmmss.fZ"], CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t)
            ? t.ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture)
            : value;
}
