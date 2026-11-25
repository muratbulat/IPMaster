namespace IPMaster.Core.Tools;

/// <summary>One SoftwareLicensingProduct record that has a key installed (the fields the manager reads).</summary>
public sealed record LicenseRecord
{
    public string Id { get; init; } = "";

    public string ApplicationId { get; init; } = "";

    public string Name { get; init; } = "";

    public string Description { get; init; } = "";

    public string LicenseFamily { get; init; } = "";

    public string ProductKeyChannel { get; init; } = "";

    public uint? LicenseStatus { get; init; }

    public uint? StatusReason { get; init; }

    public uint? GraceMinutes { get; init; }

    public string PartialKey { get; init; } = "";

    public string KmsHost { get; init; } = "";

    public int? KmsPort { get; init; }

    public string UsedHost { get; init; } = "";

    public int? UsedPort { get; init; }

    public bool IsAddon { get; init; }
}

/// <summary>The running Windows installation (registry CurrentVersion values).</summary>
public sealed record WindowsInfo(string EditionId, string ProductName, int Build, string DisplayVersion, string InstallationType, string Architecture);

/// <summary>Click-to-Run Office configuration (ProductReleaseIds, VersionToReport); null = not installed.</summary>
public sealed record ClickToRunInfo(IReadOnlyList<string> ProductReleaseIds, string Version);

public static class KmsDetection
{
    /// <summary>
    /// Products from the licensing records: one Windows row (the active, non-add-on OS licence only), one row per installed
    /// Office licence (suite, Project, Visio and single apps stay separate), and Microsoft 365 Apps from Click-to-Run when
    /// the licensing service has no subscription record for it. Missing or ambiguous data stays Unknown, never guessed.
    /// </summary>
    public static IReadOnlyList<KmsProduct> Build(IReadOnlyList<LicenseRecord> records, WindowsInfo win, ClickToRunInfo? c2r, string serviceHost, int? servicePort, DateTimeOffset now)
    {
        var list = new List<KmsProduct> { Windows(records, win, serviceHost, servicePort, now) };
        var office = records.Where(r => string.Equals(r.ApplicationId, Kms.OfficeApplicationId, StringComparison.OrdinalIgnoreCase)).ToList();
        list.AddRange(office.Select(r => Office(r, c2r, serviceHost, servicePort, now)));
        if (c2r is not null && !list.Any(p => p.Channel == LicenseChannel.Subscription))
        {
            foreach (var id in c2r.ProductReleaseIds.Where(IsSubscriptionId).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                list.Add(new KmsProduct
                {
                    Family = KmsFamily.Office, Name = SubscriptionName(id), Version = c2r.Version, Edition = id, Build = c2r.Version, Channel = LicenseChannel.Subscription,
                    State = ActivationState.Unknown, Note = "Subscription licensing is per user. Check it in an Office app: File > Account.",
                });
            }
        }

        return list;
    }

    public static bool IsSubscriptionId(string id) => id.StartsWith("O365", StringComparison.OrdinalIgnoreCase) || id.StartsWith("Microsoft365", StringComparison.OrdinalIgnoreCase);

    private static string SubscriptionName(string id) => id.ToUpperInvariant() switch
    {
        "O365PROPLUSRETAIL" or "O365PROPLUSEEANOTEAMSRETAIL" => "Microsoft 365 Apps for enterprise",
        "O365BUSINESSRETAIL" or "O365BUSINESSEEANOTEAMSRETAIL" => "Microsoft 365 Apps for business",
        _ => "Microsoft 365 (" + id + ")",
    };

    private static KmsProduct Windows(IReadOnlyList<LicenseRecord> records, WindowsInfo win, string serviceHost, int? servicePort, DateTimeOffset now)
    {
        var isServer = !string.Equals(win.InstallationType, "Client", StringComparison.OrdinalIgnoreCase);
        // the registry ProductName still says "Windows 10" on Windows 11; the build decides (22000 = first Windows 11 build)
        var name = !isServer && win.Build >= 22000 ? win.ProductName.Replace("Windows 10", "Windows 11", StringComparison.Ordinal) : win.ProductName;
        var basic = new KmsProduct
        {
            Family = isServer ? KmsFamily.WindowsServer : KmsFamily.Windows, Name = name.Length == 0 ? "Windows" : name, Version = win.DisplayVersion,
            Edition = win.EditionId, Build = win.Build > 0 ? win.Build.ToString(System.Globalization.CultureInfo.InvariantCulture) : "", Architecture = win.Architecture, IsServer = isServer,
        };
        var os = records.Where(r => string.Equals(r.ApplicationId, Kms.WindowsApplicationId, StringComparison.OrdinalIgnoreCase) && !r.IsAddon).ToList();
        if (os.Count == 0) return basic with { Note = "No Windows license record found." };
        if (os.Count > 1) return basic with { Note = "Several Windows licenses are installed. The active license is not clear." };
        var r = os[0];
        var key = KmsCatalog.MatchWindows(win.EditionId, win.Build, isServer, win.ProductName);
        var note = "";
        if (r.LicenseFamily.Length > 0 && win.EditionId.Length > 0 && !string.Equals(r.LicenseFamily, win.EditionId, StringComparison.OrdinalIgnoreCase))
        {
            key = null; // edition and licence disagree: do not offer a key
            note = $"License family '{r.LicenseFamily}' differs from edition '{win.EditionId}'.";
        }

        return Apply(basic, r, serviceHost, servicePort, now) with { Key = key, Note = note };
    }

    private static KmsProduct Office(LicenseRecord r, ClickToRunInfo? c2r, string serviceHost, int? servicePort, DateTimeOffset now)
    {
        var key = KmsCatalog.MatchOffice(r.LicenseFamily);
        var token = KmsCatalog.OfficeToken(r.LicenseFamily);
        var fam = r.LicenseFamily;
        var family = fam.Contains("Project", StringComparison.OrdinalIgnoreCase) ? KmsFamily.Project : fam.Contains("Visio", StringComparison.OrdinalIgnoreCase) ? KmsFamily.Visio : KmsFamily.Office;
        var p = new KmsProduct
        {
            Family = family, Name = key?.Edition ?? OfficeName(r), Version = token is null ? "" : token[(token.IndexOf(':', StringComparison.Ordinal) + 1)..],
            Edition = fam, Build = c2r?.Version ?? "",
        };
        p = Apply(p, r, serviceHost, servicePort, now);
        if (fam.Contains("Subscription", StringComparison.OrdinalIgnoreCase)) p = p with { Channel = LicenseChannel.Subscription };
        return p with { Key = key };
    }

    /// <summary>"Office 21, Office21ProPlus2021VL_KMS_Client_AE edition" → the family part; the raw name otherwise.</summary>
    private static string OfficeName(LicenseRecord r)
    {
        var n = r.Name;
        var comma = n.IndexOf(", ", StringComparison.Ordinal);
        if (comma > 0) n = n[(comma + 2)..];
        if (n.EndsWith(" edition", StringComparison.Ordinal)) n = n[..^8];
        return n.Length == 0 ? "Office (unknown product)" : n;
    }

    private static KmsProduct Apply(KmsProduct p, LicenseRecord r, string serviceHost, int? servicePort, DateTimeOffset now)
    {
        var channel = Kms.ParseChannel(r.ProductKeyChannel, r.Description);
        var state = Kms.ParseState(r.LicenseStatus);
        // GracePeriodRemaining: minutes until a KMS/subscription licence or a grace period ends (as slmgr /xpr reports it)
        var timed = channel is LicenseChannel.VolumeKmsClient or LicenseChannel.Subscription || state is ActivationState.Grace or ActivationState.Notification;
        DateTimeOffset? expires = timed && r.GraceMinutes is > 0 and var m ? now.AddMinutes(m) : null;
        return p with
        {
            Channel = channel,
            State = state,
            StatusReason = r.StatusReason,
            Expires = expires,
            PartialKey = r.PartialKey,
            ProductId = r.Id,
            ConfiguredKmsHost = r.KmsHost.Length > 0 ? r.KmsHost : serviceHost,
            ConfiguredKmsPort = r.KmsHost.Length > 0 ? r.KmsPort : servicePort,
            UsedKmsHost = r.UsedHost,
            UsedKmsPort = r.UsedPort,
        };
    }
}
