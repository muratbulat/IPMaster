using System.Net;
using System.Security.Cryptography;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using SnmpVersionCode = Lextm.SharpSnmpLib.VersionCode;

namespace IPMaster.Infrastructure.Queries;

/// <summary>Everything needed to talk to one agent. Passwords are plain here and only held for the request.</summary>
public sealed record SnmpTarget(IPEndPoint Endpoint, Core.Queries.SnmpVersion Version, IReadOnlyList<string> Communities,
    string User, SnmpSecurity Security, SnmpAuth Auth, string AuthPassword, SnmpPriv Priv, string PrivPassword)
{
    public override string ToString() => $"{Endpoint} {Version}" + (Version == Core.Queries.SnmpVersion.V3 ? $" user {User} {Security} {Auth}/{Priv}" : "");
}

public sealed record SnmpValue(string Oid, SnmpType Type, byte[]? Octets, string Text)
{
    /// <summary>The decoded value (exact integers, e.g. Counter64 as UInt64).</summary>
    public ISnmpData? Data { get; init; }

    public bool IsMissing => Type is SnmpType.NoSuchObject or SnmpType.NoSuchInstance or SnmpType.EndOfMibView;
}

public enum SnmpPduKind
{
    Get = 0xA0,
    GetNext = 0xA1,
    GetBulk = 0xA5,
}

public sealed class SnmpException(string message, ObservationState state = ObservationState.Failed, int errorStatus = 0) : Exception(message)
{
    public ObservationState State { get; } = state;

    public int ErrorStatus { get; } = errorStatus;
}

/// <summary>
/// SNMP v1/v2c/v3 client on SharpSnmpLib (D-054). Adds what the library lacks for the manual's algorithm list:
/// HMAC-SHA-224 (RFC 7860, via BouncyCastle) and the Blumenthal AES-192/256 key extension ("-B" variants).
/// </summary>
public static class SnmpClient
{
    public const int MaxWalkItems = 2000;

    private static readonly string[] UsmReports =
    [
        "", "unsupported security level", "message not in time window", "unknown user name", "unknown engine id",
        "wrong digest (authentication password or algorithm)", "decryption error (privacy password or algorithm)",
    ];

    public static async Task<IReadOnlyList<SnmpValue>> RequestAsync(SnmpTarget target, IReadOnlyList<string> oids, SnmpPduKind kind,
        CancellationToken ct, int nonRepeaters = 0, int maxRepetitions = 10)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(oids);
        var vars = oids.Select(o => new Variable(new ObjectIdentifier(o))).ToList();
        if (target.Version == Core.Queries.SnmpVersion.V3) return await V3Async(target, vars, kind, nonRepeaters, maxRepetitions, ct).ConfigureAwait(false);
        if (target.Communities.Count == 0) throw new SnmpException("No community string configured.");
        var version = target.Version == Core.Queries.SnmpVersion.V1 ? SnmpVersionCode.V1 : SnmpVersionCode.V2;
        if (kind == SnmpPduKind.GetBulk && version == SnmpVersionCode.V1) kind = SnmpPduKind.GetNext;
        SnmpException? last = null;
        foreach (var community in target.Communities)
        {
            ct.ThrowIfCancellationRequested();
            var c = new OctetString(community);
            var id = Messenger.NextRequestId;
            ISnmpMessage msg = kind switch
            {
                SnmpPduKind.GetNext => new GetNextRequestMessage(id, version, c, vars),
                SnmpPduKind.GetBulk => new GetBulkRequestMessage(id, version, c, nonRepeaters, maxRepetitions, vars),
                _ => new GetRequestMessage(id, version, c, vars),
            };
            using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
            if (target.Communities.Count > 1) attempt.CancelAfter(TimeSpan.FromSeconds(3));
            try
            {
                var response = await msg.GetResponseAsync(target.Endpoint, attempt.Token).ConfigureAwait(false);
                return Values(response);
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                last = new SnmpException($"No answer with one of the community strings.", ObservationState.NoResponse);
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                last = new SnmpException(ex.Message, ObservationState.NoResponse);
            }
        }

        throw last ?? new SnmpException("No answer.", ObservationState.NoResponse);
    }

    /// <summary>Walks the subtree below <paramref name="root"/>; stops at <see cref="MaxWalkItems"/>.</summary>
    public static async Task<IReadOnlyList<SnmpValue>> WalkAsync(SnmpTarget target, string root, CancellationToken ct, int maxItems = MaxWalkItems)
    {
        var result = new List<SnmpValue>();
        var next = root;
        var bulk = target.Version != Core.Queries.SnmpVersion.V1;
        while (result.Count < maxItems)
        {
            var batch = await RequestAsync(target, [next], bulk ? SnmpPduKind.GetBulk : SnmpPduKind.GetNext, ct, 0, 20).ConfigureAwait(false);
            var progressed = false;
            foreach (var v in batch)
            {
                if (v.IsMissing || !IsUnder(v.Oid, root)) return result;
                if (string.Equals(v.Oid, next, StringComparison.Ordinal)) continue;
                result.Add(v);
                next = v.Oid;
                progressed = true;
                if (result.Count >= maxItems) break;
            }

            if (!progressed) break;
        }

        return result;
    }

    public static bool IsUnder(string oid, string root) => oid.StartsWith(root + ".", StringComparison.Ordinal);

    private static async Task<IReadOnlyList<SnmpValue>> V3Async(SnmpTarget t, List<Variable> vars, SnmpPduKind kind, int nonRepeaters, int maxRepetitions,
        CancellationToken ct)
    {
        var discovery = Messenger.GetNextDiscovery(kind switch
        {
            SnmpPduKind.GetNext => SnmpType.GetNextRequestPdu,
            SnmpPduKind.GetBulk => SnmpType.GetBulkRequestPdu,
            _ => SnmpType.GetRequestPdu,
        });
        ReportMessage report;
        try
        {
            report = await discovery.GetResponseAsync(t.Endpoint, ct).ConfigureAwait(false);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            throw new SnmpException(ex.Message, ObservationState.NoResponse);
        }

        var privacy = Privacy(t);
        var user = new OctetString(t.User);
        var requestId = Messenger.NextRequestId;
        var messageId = Messenger.NextMessageId;
        ISnmpMessage request = kind switch
        {
            SnmpPduKind.GetNext => new GetNextRequestMessage(SnmpVersionCode.V3, messageId, requestId, user, OctetString.Empty, vars, privacy, Messenger.MaxMessageSize, report),
            SnmpPduKind.GetBulk => new GetBulkRequestMessage(SnmpVersionCode.V3, messageId, requestId, user, OctetString.Empty, nonRepeaters, maxRepetitions, vars, privacy,
                Messenger.MaxMessageSize, report),
            _ => new GetRequestMessage(SnmpVersionCode.V3, messageId, requestId, user, OctetString.Empty, vars, privacy, Messenger.MaxMessageSize, report),
        };
        ISnmpMessage reply;
        try
        {
            reply = await request.GetResponseAsync(t.Endpoint, ct).ConfigureAwait(false);
        }
        catch (DecryptionException ex)
        {
            throw new SnmpException("Reply could not be decrypted (privacy password or algorithm): " + ex.Message, ObservationState.AccessDenied);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            throw new SnmpException(ex.Message, ObservationState.NoResponse);
        }

        if (reply.Pdu().TypeCode == SnmpType.ReportPdu)
        {
            var oid = reply.Pdu().Variables.FirstOrDefault()?.Id.ToString() ?? "";
            var code = oid.StartsWith("1.3.6.1.6.3.15.1.1.", StringComparison.Ordinal) && int.TryParse(oid.Split('.')[^2], out var c) && c < UsmReports.Length ? c : 0;
            var text = code > 0 ? UsmReports[code] : $"report {oid}";
            throw new SnmpException("Agent rejected the request: " + text, code is 3 or 5 or 6 ? ObservationState.AccessDenied : ObservationState.Failed);
        }

        return Values(reply);
    }

    private static List<SnmpValue> Values(ISnmpMessage response)
    {
        var pdu = response.Pdu();
        if (pdu.ErrorStatus.ToInt32() != 0)
        {
            var status = pdu.ErrorStatus.ToInt32();
            throw new SnmpException($"Agent error {status} ({(ErrorCode)status}) at index {pdu.ErrorIndex.ToInt32()}.",
                status is 16 or 6 ? ObservationState.AccessDenied : ObservationState.Failed, status);
        }

        return pdu.Variables.Select(v => new SnmpValue(v.Id.ToString(), v.Data.TypeCode, v.Data is OctetString os ? os.GetRaw() : null, v.Data.ToString() ?? "") { Data = v.Data }).ToList();
    }

    public static IPrivacyProvider Privacy(SnmpTarget t)
    {
        ArgumentNullException.ThrowIfNull(t);
        if (t.Security == SnmpSecurity.NoAuthNoPriv) return DefaultPrivacyProvider.DefaultPair;
        var auth = Authentication(t.Auth, t.AuthPassword);
        if (t.Security == SnmpSecurity.AuthNoPriv) return new DefaultPrivacyProvider(auth);
        var phrase = new OctetString(t.PrivPassword.Length > 0 ? t.PrivPassword : t.AuthPassword);
#pragma warning disable CS0618 // DES, 3DES, MD5 and SHA-1 are listed by the manual; still deployed on older agents
        return t.Priv switch
        {
            SnmpPriv.Des => new DESPrivacyProvider(phrase, auth),
            SnmpPriv.TripleDes => new TripleDESPrivacyProvider(phrase, auth),
            SnmpPriv.Aes128 => new AESPrivacyProvider(phrase, auth),
            SnmpPriv.Aes192 => new AES192PrivacyProvider(phrase, auth),
            SnmpPriv.Aes256 => new AES256PrivacyProvider(phrase, auth),
            SnmpPriv.Aes192B => new BlumenthalAesPrivacyProvider(24, phrase, auth, t.Auth),
            SnmpPriv.Aes256B => new BlumenthalAesPrivacyProvider(32, phrase, auth, t.Auth),
            _ => throw new SnmpException($"Unsupported privacy algorithm {t.Priv}."),
        };
#pragma warning restore CS0618
    }

    public static IAuthenticationProvider Authentication(SnmpAuth auth, string password)
    {
        if (password.Length < 8) throw new SnmpException("SNMPv3 passwords must have at least 8 characters (RFC 3414).");
        var p = new OctetString(password);
#pragma warning disable CS0618 // protocol-mandated legacy algorithms
        return auth switch
        {
            SnmpAuth.Md5 => new MD5AuthenticationProvider(p),
            SnmpAuth.Sha1 => new SHA1AuthenticationProvider(p),
            SnmpAuth.Sha224 => new Sha224AuthenticationProvider(p),
            SnmpAuth.Sha256 => new SHA256AuthenticationProvider(p),
            SnmpAuth.Sha384 => new SHA384AuthenticationProvider(p),
            _ => new SHA512AuthenticationProvider(p),
        };
#pragma warning restore CS0618
    }

    /// <summary>Raw hash of the authentication protocol (used by the Blumenthal key extension).</summary>
    internal static byte[] Hash(SnmpAuth auth, byte[] data) => auth switch
    {
#pragma warning disable CA5351, CA5350 // protocol-mandated algorithms (RFC 3414)
        SnmpAuth.Md5 => MD5.HashData(data),
        SnmpAuth.Sha1 => SHA1.HashData(data),
#pragma warning restore CA5351, CA5350
        SnmpAuth.Sha224 => Sha224(data),
        SnmpAuth.Sha256 => SHA256.HashData(data),
        SnmpAuth.Sha384 => SHA384.HashData(data),
        _ => SHA512.HashData(data),
    };

    internal static byte[] Sha224(byte[] data)
    {
        var d = new Sha224Digest();
        d.BlockUpdate(data, 0, data.Length);
        var output = new byte[d.GetDigestSize()];
        d.DoFinal(output, 0);
        return output;
    }

    /// <summary>
    /// draft-blumenthal-aes-usm-04 §3.1.2.1: Kul' = Kul || H(Kul) || H(Kul || H(Kul)) … truncated to the key size.
    /// </summary>
    public static byte[] BlumenthalExtend(byte[] localizedKey, int keyBytes, SnmpAuth auth)
    {
        ArgumentNullException.ThrowIfNull(localizedKey);
        var key = localizedKey.ToList();
        while (key.Count < keyBytes) key.AddRange(Hash(auth, key.ToArray()));
        return key.Take(keyBytes).ToArray();
    }
}

/// <summary>HMAC-SHA-224 authentication (RFC 7860 usmHMAC128SHA224AuthProtocol: 16-byte MAC).</summary>
public sealed class Sha224AuthenticationProvider(OctetString phrase) : IAuthenticationProvider
{
    private readonly byte[] _password = phrase?.GetRaw() ?? throw new ArgumentNullException(nameof(phrase));

    public int DigestLength => 16;

    public OctetString CleanDigest => new(new byte[DigestLength]);

    /// <summary>RFC 3414 A.2 password-to-key with SHA-224 (1 MiB of repeated password, then localisation).</summary>
    public byte[] PasswordToKey(byte[] password, byte[] engineId)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentNullException.ThrowIfNull(engineId);
        if (password.Length < 8) throw new ArgumentException("Secret key is too short. Must be >= 8.", nameof(password));
        var digest = new Sha224Digest();
        var buf = new byte[64];
        var index = 0;
        for (var count = 0; count < 1048576; count += 64)
        {
            for (var i = 0; i < 64; i++) buf[i] = password[index++ % password.Length];
            digest.BlockUpdate(buf, 0, 64);
        }

        var ku = new byte[digest.GetDigestSize()];
        digest.DoFinal(ku, 0);
        var local = new byte[ku.Length * 2 + engineId.Length];
        ku.CopyTo(local, 0);
        engineId.CopyTo(local, ku.Length);
        ku.CopyTo(local, ku.Length + engineId.Length);
        return SnmpClient.Sha224(local);
    }

    public OctetString ComputeHash(SnmpVersionCode version, ISegment header, SecurityParameters parameters, ISnmpData data, IPrivacyProvider privacy, byte[]? length)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (parameters.EngineId is null) throw new ArgumentException("Invalid security parameters", nameof(parameters));
        var key = PasswordToKey(_password, parameters.EngineId.GetRaw());
        var message = ByteTool.PackMessage(length, version, header, parameters, data).ToBytes();
        var hmac = new HMac(new Sha224Digest());
        hmac.Init(new KeyParameter(key));
        hmac.BlockUpdate(message, 0, message.Length);
        var full = new byte[hmac.GetMacSize()];
        hmac.DoFinal(full, 0);
        return new OctetString(full.AsSpan(0, DigestLength).ToArray());
    }
}

/// <summary>
/// AES-192/256 privacy (RFC 3826 AES-CFB128 framing) with the Blumenthal key extension (draft-blumenthal-aes-usm-04).
/// IV = engineBoots (4 bytes, big endian) | engineTime (4) | 8-byte salt carried in msgPrivacyParameters.
/// </summary>
public sealed class BlumenthalAesPrivacyProvider(int keyBytes, OctetString phrase, IAuthenticationProvider auth, SnmpAuth authKind) : IPrivacyProvider
{
    private long _salt = BitConverter.ToInt64(RandomNumberGenerator.GetBytes(8));

    public OctetString Salt
    {
        get
        {
            var s = new byte[8];
            System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(s, Interlocked.Increment(ref _salt));
            return new OctetString(s);
        }
    }

    public IAuthenticationProvider AuthenticationProvider => auth;

    public ICollection<OctetString>? EngineIds { get; set; }

    public byte[] PasswordToKey(byte[] secret, byte[] engineId)
    {
        var localized = auth.PasswordToKey(secret, engineId);
        return localized.Length >= keyBytes ? localized[..keyBytes] : SnmpClient.BlumenthalExtend(localized, keyBytes, authKind);
    }

    public ISnmpData Encrypt(ISnmpData data, SecurityParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(parameters);
        if (data.TypeCode != SnmpType.Sequence && data is not ISnmpPdu) throw new ArgumentException("Invalid data type.", nameof(data));
        var key = PasswordToKey(phrase.GetRaw(), parameters.EngineId!.GetRaw());
        return new OctetString(Cfb(true, key, Iv(parameters), data.ToBytes()));
    }

    public ISnmpData Decrypt(ISnmpData data, SecurityParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(parameters);
        if (data is not OctetString octets) throw new ArgumentException($"Cannot decrypt the scope data: {data.TypeCode}.", nameof(data));
        var key = PasswordToKey(phrase.GetRaw(), parameters.EngineId!.GetRaw());
        return DataFactory.CreateSnmpData(Cfb(false, key, Iv(parameters), octets.GetRaw()));
    }

    private static byte[] Iv(SecurityParameters p)
    {
        var salt = p.PrivacyParameters!.GetRaw();
        if (salt.Length != 8) throw new DecryptionException("Invalid privacy parameters.");
        var iv = new byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(iv, p.EngineBoots!.ToInt32());
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(4), p.EngineTime!.ToInt32());
        salt.CopyTo(iv, 8);
        return iv;
    }

    /// <summary>AES-CFB128 on arbitrary lengths: CFB is a stream mode, so zero-padding to whole blocks and truncating is exact.</summary>
    public static byte[] Cfb(bool encrypt, byte[] key, byte[] iv, byte[] input)
    {
        ArgumentNullException.ThrowIfNull(input);
        using var aes = Aes.Create();
        aes.Key = key;
        var padded = new byte[(input.Length + 15) / 16 * 16];
        input.CopyTo(padded, 0);
        var output = encrypt ? aes.EncryptCfb(padded, iv, PaddingMode.None, 128) : aes.DecryptCfb(padded, iv, PaddingMode.None, 128);
        return output[..input.Length];
    }
}

/// <summary>Remote SNMP queries (SNM-01..06).</summary>
public sealed class SnmpQueryProvider : IRemoteQueryProvider
{
    public QueryKind Kind => QueryKind.Snmp;

    public CapabilityStatus Capability { get; } = CapabilityStatus.Yes("SNMP v1/v2c/v3 (SharpSnmpLib).");

    public static SnmpTarget Target(QueryCall call)
    {
        ArgumentNullException.ThrowIfNull(call);
        var o = call.Query.Snmp ?? new SnmpOptions();
        var communities = call.Secrets.Reveal(o.Communities).Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        return new SnmpTarget(new IPEndPoint(call.Device.Address, o.Port), o.Version, communities,
            call.Credential?.UserName ?? "", o.Security, o.Auth, call.Credential?.Password ?? "", o.Priv, call.Secrets.Reveal(o.PrivPassword));
    }

    public async Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        var o = call.Query.Snmp ?? new SnmpOptions();
        var now = DateTimeOffset.UtcNow;
        if (o.Version == Core.Queries.SnmpVersion.V3 && o.Security != SnmpSecurity.NoAuthNoPriv && call.Credential is null)
        {
            return Observation<string>.Of(ObservationState.Failed, now, "SNMPv3 with authentication needs a credential (user name and authentication password).");
        }

        string oid;
        try
        {
            oid = SnmpText.ExpandOid(o.Oid, call.Device.Address, call.Device.Mac.HasValue ? call.Device.Mac.Value : null);
        }
        catch (Exception ex) when (ex is FormatException or InvalidOperationException)
        {
            return Observation<string>.Of(ObservationState.Failed, now, ex.Message);
        }

        try
        {
            var target = Target(call);
            IReadOnlyList<SnmpValue> values = o.Operation switch
            {
                SnmpOperation.Walk => await SnmpClient.WalkAsync(target, oid, cancellationToken).ConfigureAwait(false),
                SnmpOperation.GetNext => await SnmpClient.RequestAsync(target, [oid], SnmpPduKind.GetNext, cancellationToken).ConfigureAwait(false),
                _ => await SnmpClient.RequestAsync(target, [oid], SnmpPduKind.Get, cancellationToken).ConfigureAwait(false),
            };
            var present = values.Where(v => !v.IsMissing).ToList();
            if (present.Count == 0) return Observation<string>.Of(ObservationState.Empty, DateTimeOffset.UtcNow, values.FirstOrDefault()?.Type.ToString());
            var text = o.Operation == SnmpOperation.Walk
                ? string.Join('\n', present.Select(v => $"{v.Oid}: {Render(v, o.Display)}"))
                : string.Join('\n', present.Select(v => Render(v, o.Display)));
            return Observation<string>.Ok(text, DateTimeOffset.UtcNow);
        }
        catch (SnmpException ex)
        {
            return Observation<string>.Of(ex.State, DateTimeOffset.UtcNow, ex.Message);
        }
    }

    public static string Render(SnmpValue v, SnmpDisplay display) =>
        v.Octets is { } bytes ? SnmpText.RenderOctets(bytes, display) : v.Text;

    /// <summary>
    /// SNM-03: finds the authentication and privacy algorithms with the supplied user and passwords only. Tries each
    /// authentication algorithm (AuthNoPriv), then each privacy algorithm with the one that worked. No guessing of
    /// user names or passwords.
    /// </summary>
    public static async Task<(SnmpAuth? Auth, SnmpPriv? Priv, string Message)> DetectAsync(IPEndPoint endpoint, string user, string authPassword,
        string privPassword, CancellationToken ct)
    {
        SnmpAuth? found = null;
        foreach (var a in Enum.GetValues<SnmpAuth>())
        {
            var t = new SnmpTarget(endpoint, Core.Queries.SnmpVersion.V3, [], user, SnmpSecurity.AuthNoPriv, a, authPassword, SnmpPriv.Aes128, "");
            if (await TryAsync(t, ct).ConfigureAwait(false) is null)
            {
                found = a;
                break;
            }
        }

        if (found is null) return (null, null, "No authentication algorithm accepted the user name and password (or the agent did not answer).");
        if (privPassword.Length == 0 && authPassword.Length == 0) return (found, null, $"Authentication: {found}.");
        foreach (var p in Enum.GetValues<SnmpPriv>())
        {
            var t = new SnmpTarget(endpoint, Core.Queries.SnmpVersion.V3, [], user, SnmpSecurity.AuthPriv, found.Value, authPassword, p, privPassword);
            if (await TryAsync(t, ct).ConfigureAwait(false) is null) return (found, p, $"Authentication: {found}; privacy: {p}.");
        }

        return (found, null, $"Authentication: {found}; no privacy algorithm worked with the privacy password (AuthNoPriv only).");
    }

    private static async Task<string?> TryAsync(SnmpTarget t, CancellationToken ct)
    {
        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
        attempt.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            await SnmpClient.RequestAsync(t, ["1.3.6.1.2.1.1.1.0"], SnmpPduKind.Get, attempt.Token).ConfigureAwait(false);
            return null;
        }
        catch (Exception ex) when (ex is SnmpException or OperationCanceledException or CryptographicException or ArgumentException or Lextm.SharpSnmpLib.Messaging.ErrorException)
        {
            ct.ThrowIfCancellationRequested();
            return ex.Message;
        }
    }
}
