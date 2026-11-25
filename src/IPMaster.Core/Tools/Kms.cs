using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

namespace IPMaster.Core.Tools;

public enum LicenseChannel
{
    Unknown,
    Retail,
    Oem,
    VolumeMak,
    VolumeKmsClient,

    /// <summary>A KMS host key (CSVLK) is installed: this computer is a KMS host, never converted here.</summary>
    VolumeKmsHost,
    Subscription,
}

public enum ActivationState
{
    Unknown,
    Unlicensed,
    Licensed,
    Grace,
    Notification,
}

/// <summary>A named KMS server (Tools → KMS Activation Manager). Holds no keys or credentials.</summary>
public sealed record KmsProfile
{
    public string Name { get; set; } = "";

    public string Server { get; set; } = "";

    public int Port { get; set; } = Kms.DefaultPort;

    public string Description { get; set; } = "";
}

/// <summary>One installed Windows or Office product with the licence state the licensing service reports.</summary>
public sealed record KmsProduct
{
    public KmsFamily Family { get; init; }

    public string Name { get; init; } = "";

    public string Version { get; init; } = "";

    /// <summary>Windows EditionID or Office licence family; empty = unknown.</summary>
    public string Edition { get; init; } = "";

    public string Build { get; init; } = "";

    public string Architecture { get; init; } = "";

    public LicenseChannel Channel { get; init; }

    public ActivationState State { get; init; }

    /// <summary>Licensing service code of the state (e.g. 0xC004F074 for a grace reason), when reported.</summary>
    public uint? StatusReason { get; init; }

    /// <summary>Licensed with an expiry (KMS client, subscription) or the end of a grace period; null = none reported.</summary>
    public DateTimeOffset? Expires { get; init; }

    /// <summary>Last five characters of the installed key (all the licensing service exposes).</summary>
    public string PartialKey { get; init; } = "";

    /// <summary>Licensing product (SKU) id, used to address this product only; empty when not a licensing record.</summary>
    public string ProductId { get; init; } = "";

    public string ConfiguredKmsHost { get; init; } = "";

    public int? ConfiguredKmsPort { get; init; }

    /// <summary>The KMS host that last activated this product (reported by the client), not the configured one.</summary>
    public string UsedKmsHost { get; init; } = "";

    public int? UsedKmsPort { get; init; }

    public bool IsServer { get; init; }

    /// <summary>Why detection is incomplete (shown in the details).</summary>
    public string Note { get; init; } = "";

    public GvlkEntry? Key { get; init; }
}

public enum KmsAction
{
    None,

    /// <summary>Already a KMS client: optionally set the host, then activate.</summary>
    Activate,

    /// <summary>Install the matching GVLK (replaces the installed key), optionally set the host and activate.</summary>
    InstallKey,
}

public sealed record KmsPlan(KmsAction Action, string Reason, bool ReplacesKey = false, bool NeedsEntitlement = false);

public sealed record KmsHostCandidate(string Host, int Port, int Priority, int Weight, string Domain);

public enum KmsStepKind
{
    InstallKey,
    SetHost,
    Activate,
}

/// <summary>One step for the licensing service. The elevated helper re-validates every field (keys only from the catalog).</summary>
public sealed record KmsStep
{
    public KmsStepKind Kind { get; set; }

    /// <summary>Licensing product id to change; for InstallKey the product the key is meant for.</summary>
    public string ProductId { get; set; } = "";

    public string Key { get; set; } = "";

    public string Host { get; set; } = "";

    public int Port { get; set; }
}

public sealed record KmsRequest
{
    /// <summary>Windows or Office application id of the product.</summary>
    public string ApplicationId { get; set; } = "";

    public IReadOnlyList<KmsStep> Steps { get; set; } = [];
}

public sealed record KmsStepResult
{
    public KmsStepKind Kind { get; set; }

    public bool Succeeded { get; set; }

    /// <summary>HRESULT from the licensing service; null when the step did not run.</summary>
    public uint? Code { get; set; }

    public string Message { get; set; } = "";
}

public sealed record KmsApplyResult
{
    public IReadOnlyList<KmsStepResult> Steps { get; set; } = [];

    /// <summary>Product id after the steps (a new key gives a new licensing product); empty = not found.</summary>
    public string ProductId { get; set; } = "";

    /// <summary>Set when nothing ran (elevation declined, helper failed, timeout).</summary>
    public string Error { get; set; } = "";
}

public enum KmsOutcome
{
    Cancelled,
    NotRun,
    Failed,

    /// <summary>Steps ran, but the licence after it is not KMS-licensed.</summary>
    NotVerified,
    KeyInstalled,
    Activated,
}

/// <summary>Pure rules of the KMS Activation Manager (D-104): eligibility, validation, verification and the report.</summary>
public static class Kms
{
    public const int DefaultPort = 1688;
    public const string WindowsApplicationId = "55c92734-d682-4d71-983e-d6ec3f16059f";
    public const string OfficeApplicationId = "0ff1ce15-a989-479d-af46-f275c6370663";
    public const string SrvPrefix = "_vlmcs._tcp.";

    public static string ChannelText(LicenseChannel c) => c switch
    {
        LicenseChannel.Retail => "Retail",
        LicenseChannel.Oem => "OEM",
        LicenseChannel.VolumeMak => "Volume MAK",
        LicenseChannel.VolumeKmsClient => "Volume KMS",
        LicenseChannel.VolumeKmsHost => "KMS host",
        LicenseChannel.Subscription => "Subscription",
        _ => "Unknown",
    };

    public static string StateText(ActivationState s) => s.ToString();

    /// <summary>The ProductKeyChannel value of SoftwareLicensingProduct, or (older systems) the "…channel" description.</summary>
    public static LicenseChannel ParseChannel(string? productKeyChannel, string? description)
    {
        var c = (productKeyChannel ?? "").Trim();
        if (c.Length > 0)
        {
            if (c.Equals("Retail", StringComparison.OrdinalIgnoreCase)) return LicenseChannel.Retail;
            if (c.StartsWith("OEM", StringComparison.OrdinalIgnoreCase)) return LicenseChannel.Oem;
            if (c.Equals("Volume:MAK", StringComparison.OrdinalIgnoreCase)) return LicenseChannel.VolumeMak;
            if (c.Equals("Volume:GVLK", StringComparison.OrdinalIgnoreCase)) return LicenseChannel.VolumeKmsClient;
            if (c.Equals("Volume:CSVLK", StringComparison.OrdinalIgnoreCase)) return LicenseChannel.VolumeKmsHost;
        }

        var d = (description ?? "").ToUpperInvariant();
        if (d.Contains("TIMEBASED_SUB", StringComparison.Ordinal) || d.Contains("SUBSCRIPTION", StringComparison.Ordinal)) return LicenseChannel.Subscription;
        if (d.Contains("VOLUME_KMSCLIENT", StringComparison.Ordinal)) return LicenseChannel.VolumeKmsClient;
        if (d.Contains("VOLUME_KMS", StringComparison.Ordinal)) return LicenseChannel.VolumeKmsHost;
        if (d.Contains("VOLUME_MAK", StringComparison.Ordinal)) return LicenseChannel.VolumeMak;
        if (d.Contains("OEM", StringComparison.Ordinal)) return LicenseChannel.Oem;
        if (d.Contains("RETAIL", StringComparison.Ordinal)) return c.Length == 0 ? LicenseChannel.Retail : LicenseChannel.Unknown;
        return LicenseChannel.Unknown;
    }

    /// <summary>SoftwareLicensingProduct.LicenseStatus: 0 unlicensed, 1 licensed, 2/3/4/6 grace, 5 notification.</summary>
    public static ActivationState ParseState(uint? licenseStatus) => licenseStatus switch
    {
        0 => ActivationState.Unlicensed,
        1 => ActivationState.Licensed,
        2 or 3 or 4 or 6 => ActivationState.Grace,
        5 => ActivationState.Notification,
        _ => ActivationState.Unknown,
    };

    /// <summary>What may be done for a product, conservatively: no key unless the SKU matched exactly.</summary>
    public static KmsPlan Plan(KmsProduct p)
    {
        if (p.Channel == LicenseChannel.Subscription) return new(KmsAction.None, "Subscription license. KMS does not apply.");
        if (p.Channel == LicenseChannel.VolumeKmsHost) return new(KmsAction.None, "This computer is a KMS host (CSVLK). Not changed here.");
        if (p.ProductId.Length == 0) return new(KmsAction.None, "No licensing record for this product.");
        if (p.Channel == LicenseChannel.VolumeKmsClient) return new(KmsAction.Activate, "KMS client. Set the host and activate.");
        if (p.Channel == LicenseChannel.Unknown) return new(KmsAction.None, "Unknown license channel. Not changed.");
        if (p.Family is not (KmsFamily.Windows or KmsFamily.WindowsServer) && p.Channel is LicenseChannel.Retail or LicenseChannel.Oem)
        {
            return new(KmsAction.None, "Retail Office. KMS needs volume-licensed Office installed with the Office Deployment Tool.");
        }

        if (p.Key is null) return new(KmsAction.None, "No matching KMS key.");
        return p.Channel switch
        {
            LicenseChannel.VolumeMak => new(KmsAction.InstallKey, "Volume MAK. Install the KMS client key to change to KMS.", ReplacesKey: true, NeedsEntitlement: true),
            _ => new(KmsAction.InstallKey, $"{ChannelText(p.Channel)}. Install the KMS client key only with volume license entitlement.", ReplacesKey: true, NeedsEntitlement: true),
        };
    }

    /// <summary>Host name or IPv4 address and port; null = valid. IPv6 literals are refused (use a host name).</summary>
    public static string? ValidateServer(string host, decimal? port, bool allowEmpty)
    {
        host = (host ?? "").Trim();
        if (host.Length == 0) return allowEmpty ? null : "KMS Server: enter a host name or an IPv4 address.";
        if (IPAddress.TryParse(host, out var ip))
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork) return "KMS Server: IPv6 addresses are not supported. Use a host name.";
        }
        else if (host.Length > 253 || Uri.CheckHostName(host) != UriHostNameType.Dns || host.Split('.').Any(l => l.Length is 0 or > 63))
        {
            return $"KMS Server: '{host}' is not a valid host name or IPv4 address.";
        }

        return port is >= 1 and <= 65535 && decimal.Truncate(port.Value) == port.Value ? null : "Port: enter a number from 1 to 65535.";
    }

    /// <summary>SRV answers ("priority weight port target") of _vlmcs._tcp.&lt;domain&gt;, best first.</summary>
    public static IReadOnlyList<KmsHostCandidate> ParseSrv(IEnumerable<string> data, string domain)
    {
        var list = new List<KmsHostCandidate>();
        foreach (var d in data)
        {
            var parts = d.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 4 || !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var prio)
                || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var weight)
                || !int.TryParse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port is < 1 or > 65535) continue;
            var host = parts[3].TrimEnd('.');
            if (host.Length == 0 || ValidateServer(host, port, false) is not null) continue;
            list.Add(new(host, port, prio, weight, domain));
        }

        return list.OrderBy(c => c.Priority).ThenByDescending(c => c.Weight).ThenBy(c => c.Host, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Steps for a plan: key (if any), host (when given), activation (when asked).</summary>
    public static IReadOnlyList<KmsStep> Steps(KmsProduct p, KmsPlan plan, string host, int port, bool activate)
    {
        var steps = new List<KmsStep>();
        if (plan.Action == KmsAction.None) return steps;
        if (plan.Action == KmsAction.InstallKey) steps.Add(new() { Kind = KmsStepKind.InstallKey, ProductId = p.ProductId, Key = p.Key!.Key });
        if (host.Trim().Length > 0) steps.Add(new() { Kind = KmsStepKind.SetHost, ProductId = p.ProductId, Host = host.Trim(), Port = port });
        if (activate || plan.Action == KmsAction.Activate) steps.Add(new() { Kind = KmsStepKind.Activate, ProductId = p.ProductId });
        return steps;
    }

    /// <summary>Checks a request before anything runs (also in the elevated helper): only catalog keys, valid hosts, GUID ids.</summary>
    public static string? ValidateRequest(KmsRequest r)
    {
        if (r.ApplicationId is not (WindowsApplicationId or OfficeApplicationId)) return "Unknown application id.";
        if (r.Steps.Count is 0 or > 3) return "No steps.";
        foreach (var s in r.Steps)
        {
            if (!Guid.TryParse(s.ProductId, out _)) return "Invalid product id.";
            if (s.Kind == KmsStepKind.InstallKey && !KmsCatalog.IsCatalogKey(s.Key)) return "Only official KMS client setup keys can be installed.";
            if (s.Kind == KmsStepKind.SetHost && ValidateServer(s.Host, s.Port, false) is { } e) return e;
        }

        return null;
    }

    /// <summary>
    /// The outcome from the licence read after the steps — never from exit codes alone: "Activated" needs the KMS client channel
    /// and the Licensed state on the product that was changed.
    /// </summary>
    public static KmsOutcome Verify(KmsApplyResult result, KmsProduct? after, bool activationAsked)
    {
        if (result.Error.Length > 0 && result.Steps.Count == 0) return KmsOutcome.NotRun;
        if (result.Steps.Any(s => !s.Succeeded)) return KmsOutcome.Failed;
        if (after is null) return KmsOutcome.NotVerified;
        var kmsClient = after.Channel == LicenseChannel.VolumeKmsClient;
        if (activationAsked) return kmsClient && after.State == ActivationState.Licensed ? KmsOutcome.Activated : KmsOutcome.NotVerified;
        return kmsClient ? KmsOutcome.KeyInstalled : KmsOutcome.NotVerified;
    }

    public static string OutcomeText(KmsOutcome o) => o switch
    {
        KmsOutcome.Activated => "Activation successful.",
        KmsOutcome.KeyInstalled => "KMS key installed. Not activated.",
        KmsOutcome.NotVerified => "Activation not verified. The license state did not change to KMS Licensed.",
        KmsOutcome.Failed => "Activation failed.",
        KmsOutcome.Cancelled => "Cancelled. License unchanged.",
        _ => "Not run. License unchanged.",
    };

    /// <summary>Short meaning of documented licensing error codes; the code is always shown as well.</summary>
    public static string ErrorText(uint code) => code switch
    {
        0xC004F074 => "No KMS host could be contacted. Check DNS, the host name, port and firewall.",
        0xC004F038 => "The KMS host count is too low. The host activates clients only above its threshold.",
        0xC004F042 => "The KMS host cannot activate this product. Its host key may not cover this version.",
        0xC004F039 => "The KMS host count is too low or the host is not reachable.",
        0xC004F041 => "The KMS host is not activated.",
        0xC004F06C => "The client and KMS host clocks differ too much.",
        0xC004F050 => "The licensing service reports the product key as invalid.",
        0xC004F069 => "The product SKU was not found.",
        0xC004C003 => "The activation server blocked this key.",
        0xC004F035 => "Volume activation needs a qualifying OEM operating system licence on this computer.",
        0x8007232B => "The DNS name does not exist. No KMS SRV record was found.",
        0x8007232A => "DNS server failure.",
        0x80070005 => "Access denied. Administrator access is required.",
        0x800706BA => "The RPC server is unavailable. The KMS host did not answer.",
        _ => "",
    };

    public static string Code(uint code) => "0x" + code.ToString("X8", CultureInfo.InvariantCulture);

    public static string ExpiresText(KmsProduct p) => p.Expires is { } e
        ? e.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
        : p.State == ActivationState.Licensed && p.Channel is LicenseChannel.Retail or LicenseChannel.Oem or LicenseChannel.VolumeMak ? "Not applicable" : "Not reported";

    public static string Host(string host, int? port) => host.Length == 0 ? "Not reported" : port is { } pt ? $"{host}:{pt.ToString(CultureInfo.InvariantCulture)}" : host;

    // ---------------- profiles (the same list operations as the SMTP profiles) ----------------
    public static IReadOnlyList<KmsProfile> Upsert(IReadOnlyList<KmsProfile> list, KmsProfile p) =>
        list.Where(x => !string.Equals(x.Name, p.Name, StringComparison.OrdinalIgnoreCase)).Append(p).ToList();

    public static IReadOnlyList<KmsProfile>? Rename(IReadOnlyList<KmsProfile> list, string oldName, string newName, out string? error)
    {
        newName = newName.Trim();
        error = newName.Length == 0 ? "Enter a name." : list.Any(p => !string.Equals(p.Name, oldName, StringComparison.Ordinal) && string.Equals(p.Name, newName, StringComparison.OrdinalIgnoreCase))
            ? $"A profile named '{newName}' already exists." : null;
        return error is null ? list.Select(p => p.Name == oldName ? p with { Name = newName } : p).ToList() : null;
    }

    public static IReadOnlyList<KmsProfile> Delete(IReadOnlyList<KmsProfile> list, string name) => list.Where(p => p.Name != name).ToList();

    // ---------------- report ----------------
    public sealed record ReportAttempt(string Operation, KmsOutcome Outcome, IReadOnlyList<KmsStepResult> Steps);

    public static string Report(string computer, DateTimeOffset at, KmsProduct p, ReportAttempt? attempt)
    {
        var sb = new StringBuilder();
        void L(string k, string v) => sb.Append(CultureInfo.InvariantCulture, $"{k,-16}{v}").AppendLine();
        sb.AppendLine("Activation Report").AppendLine(new string('-', 40));
        L("Time:", at.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
        L("Computer:", computer);
        L("Product:", p.Name);
        L("Version:", Empty(p.Version));
        L("Edition:", Empty(p.Edition));
        L("Channel:", ChannelText(p.Channel));
        L("Status:", StateText(p.State) + (p.StatusReason is { } r and not 0 ? $" ({Code(r)})" : ""));
        L("Expires:", ExpiresText(p));
        L("Partial key:", p.PartialKey.Length == 0 ? "Not reported" : "*****-" + p.PartialKey);
        L("KMS configured:", Host(p.ConfiguredKmsHost, p.ConfiguredKmsPort));
        L("KMS last used:", Host(p.UsedKmsHost, p.UsedKmsPort));
        L("KMS key:", p.Key is { } k ? $"{k.FamilyName} {k.Version} {k.Edition}" : "No matching KMS key");
        if (p.Note.Length > 0) L("Note:", p.Note);
        if (attempt is not null)
        {
            sb.AppendLine(new string('-', 40));
            L("Operation:", attempt.Operation);
            L("Result:", OutcomeText(attempt.Outcome));
            foreach (var s in attempt.Steps) L($"  {s.Kind}:", (s.Succeeded ? "OK" : "Failed") + (s.Code is { } c and not 0 ? $" {Code(c)}" : "") + (s.Message.Length > 0 ? " " + s.Message : ""));
        }

        return sb.ToString();
    }

    /// <summary>JSON report: the same fields, never the full key.</summary>
    public static string ReportJson(string computer, DateTimeOffset at, KmsProduct p, ReportAttempt? attempt) => JsonSerializer.Serialize(new
    {
        time = at.ToString("o", CultureInfo.InvariantCulture),
        computer,
        product = p.Name,
        version = p.Version,
        edition = p.Edition,
        channel = ChannelText(p.Channel),
        status = StateText(p.State),
        statusReason = p.StatusReason is { } r ? Code(r) : null,
        expires = ExpiresText(p),
        partialKey = p.PartialKey,
        kmsConfigured = Host(p.ConfiguredKmsHost, p.ConfiguredKmsPort),
        kmsLastUsed = Host(p.UsedKmsHost, p.UsedKmsPort),
        matchingKey = p.Key is { } k ? $"{k.FamilyName} {k.Version} {k.Edition}" : null,
        note = p.Note,
        attempt = attempt is null ? null : new
        {
            operation = attempt.Operation,
            result = OutcomeText(attempt.Outcome),
            steps = attempt.Steps.Select(s => new { step = s.Kind.ToString(), ok = s.Succeeded, code = s.Code is { } c ? Code(c) : null, message = s.Message }),
        },
    }, Indented);

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static string Empty(string s) => s.Length == 0 ? "Unknown" : s;
}
