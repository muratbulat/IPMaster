using IPMaster.Core.Scanning;

namespace IPMaster.Core.Results;

public enum DeviceCategory
{
    Unknown,
    Computer,
    Printer,
    Camera,
    FileServer,
}

/// <summary>How sure the Device Type is (D-089).</summary>
public enum TypeEvidence
{
    /// <summary>Nothing to go on: the cell is empty.</summary>
    None,

    /// <summary>The device itself showed it (Windows version, RTSP stream, print port, SMB shares).</summary>
    Observed,

    /// <summary>A hint only (ping TTL, NIC vendor): the text says so ("Windows?"), no category glyph.</summary>
    Inferred,

    /// <summary>Observed evidence points to more than one kind of device.</summary>
    Ambiguous,
}

/// <param name="Source">Why: the evidence behind <paramref name="Text"/>, shown as the cell's tooltip.</param>
public sealed record DeviceTypeInfo(DeviceCategory Category, string Text, TypeEvidence Evidence = TypeEvidence.None, string Source = "");

/// <summary>
/// Device Type column (D-072, D-083, D-089), short text. Observed evidence first (Windows version, then RTSP stream, print
/// port, SMB folder shares; more than one of those is Ambiguous); otherwise a guess from the ping reply's TTL, marked with
/// "?" and never given a category; otherwise the NIC vendor. Nothing is looked up online.
/// </summary>
public static class DeviceTypes
{
    private static readonly int[] PrintPorts = [9100, 631, 515];

    public static DeviceTypeInfo Describe(DeviceResult d)
    {
        ArgumentNullException.ThrowIfNull(d);
        if (d.OsVersion.HasValue && !string.IsNullOrWhiteSpace(d.OsVersion.Value))
        {
            return new(DeviceCategory.Computer, d.OsVersion.Value!.Trim(), TypeEvidence.Observed, "Windows version query");
        }

        var observed = new List<(DeviceCategory Category, string Text, string Source)>();
        if (d.RtspStreams.HasValue && d.RtspStreams.Value!.Count > 0) observed.Add((DeviceCategory.Camera, "Camera", "RTSP stream"));
        if (d.TcpPorts.HasValue && d.TcpPorts.Value!.FirstOrDefault(p => p.State == PortState.Open && PrintPorts.Contains(p.Port)) is { } print)
        {
            observed.Add((DeviceCategory.Printer, "Printer", $"Open TCP port {print.Port}"));
        }

        if (d.Shares.HasValue && d.Shares.Value!.Any(s => s.Kind == ShareKind.Folder)) observed.Add((DeviceCategory.FileServer, "File server", "SMB folder shares"));
        if (observed.Count == 1) return new(observed[0].Category, observed[0].Text, TypeEvidence.Observed, observed[0].Source);
        if (observed.Count > 1)
        {
            // e.g. a NAS with a print server, or a printer with a scan-to-folder share: say so instead of picking one
            var text = string.Join(" or ", observed.Select((o, i) => i == 0 ? o.Text : o.Text.ToLowerInvariant()));
            return new(DeviceCategory.Unknown, text, TypeEvidence.Ambiguous, string.Join("; ", observed.Select(o => o.Source)));
        }

        // Initial TTL is OS-specific: 64 (Linux, macOS, iOS, Android, many appliances), 128 (Windows), 255 (routers,
        // switches, some printers and Unix systems); each hop lowers it by one. A hint, not an identification.
        if (d.Ttl.HasValue && d.Ttl.Value > 0)
        {
            var ttl = d.Ttl.Value;
            var (guess, family) = ttl switch
            {
                <= 64 => ("Linux/Unix?", "initial 64: Linux, macOS, iOS, Android and many appliances"),
                <= 128 => ("Windows?", "initial 128: usually Windows"),
                _ => ("Network device?", "initial 255: routers, switches, some printers and Unix systems"),
            };
            return new(DeviceCategory.Unknown, guess, TypeEvidence.Inferred, $"Guess from the ping TTL {ttl} ({family})");
        }

        return d.Vendor.HasValue && !string.IsNullOrWhiteSpace(d.Vendor.Value)
            ? new(DeviceCategory.Unknown, d.Vendor.Value!.Trim(), TypeEvidence.Inferred, "NIC vendor only (no device evidence)")
            : new(DeviceCategory.Unknown, "");
    }
}
