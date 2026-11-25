namespace IPMaster.Core.Wifi;

/// <summary>
/// The parts of a beacon/probe-response body (802.11 information elements) that IPMaster uses (D-097). Parsing never
/// throws: an element whose length runs past the buffer stops parsing and sets <see cref="Malformed"/>; what was read
/// before stays valid. A short element body is ignored rather than guessed.
/// </summary>
public sealed record InformationElements
{
    public static readonly InformationElements None = new();

    /// <summary>Number of elements read; 0 means the OS gave no element data.</summary>
    public int Count { get; init; }

    public bool Malformed { get; init; }

    /// <summary>Country element (regulatory domain), for example "US" or "DE"; null when absent.</summary>
    public string? Country { get; init; }

    public bool Ht { get; init; }

    public bool Vht { get; init; }

    public bool He { get; init; }

    public bool Eht { get; init; }

    /// <summary>Operating width in MHz from the HT/VHT/HE/EHT operation elements; null when there were no elements.</summary>
    public int? ChannelWidthMhz { get; init; }

    /// <summary>Centre channel of an 80/160/320 MHz channel, as the operation element states it.</summary>
    public int? CenterChannel { get; init; }

    /// <summary>HT secondary channel: +1 above, −1 below, 0 none.</summary>
    public int SecondaryChannelOffset { get; init; }

    /// <summary>BSS Load element: stations associated, as the AP reports them.</summary>
    public int? StationCount { get; init; }

    /// <summary>BSS Load element: channel busy time measured by the AP, 0–100 %.</summary>
    public double? ChannelUtilizationPercent { get; init; }

    /// <summary>RSN AKM suite types (00-0F-AC:n); empty when there is no RSN element.</summary>
    public IReadOnlyList<int> AkmSuites { get; init; } = [];

    public bool Wpa1 { get; init; }

    /// <summary>802.11k: RM Enabled Capabilities element present.</summary>
    public bool RadioMeasurement { get; init; }

    /// <summary>802.11v: BSS Transition bit of the Extended Capabilities element.</summary>
    public bool BssTransition { get; init; }

    /// <summary>802.11r: Mobility Domain element or a fast-transition AKM.</summary>
    public bool FastTransition { get; init; }

    public static InformationElements Parse(ReadOnlySpan<byte> data)
    {
        var count = 0;
        var malformed = false;
        string? country = null;
        bool ht = false, vht = false, he = false, eht = false, wpa1 = false, rm = false, btm = false, mobility = false;
        int? htWidth = null, vhtWidth = null, heWidth = null, ehtWidth = null;
        int? vhtCenter = null, heCenter = null, ehtCenter = null;
        var secondary = 0;
        int? stations = null;
        double? utilization = null;
        var akm = new List<int>();
        var i = 0;
        while (i < data.Length)
        {
            if (i + 2 > data.Length)
            {
                malformed = true;
                break;
            }

            int id = data[i], len = data[i + 1];
            if (i + 2 + len > data.Length)
            {
                malformed = true;
                break;
            }

            var body = data.Slice(i + 2, len);
            i += 2 + len;
            count++;
            switch (id)
            {
                case 7 when len >= 2 && IsLetter(body[0]) && IsLetter(body[1]):
                    country = $"{(char)body[0]}{(char)body[1]}".ToUpperInvariant();
                    break;
                case 11 when len >= 5:
                    stations = body[0] | (body[1] << 8);
                    utilization = body[2] * 100.0 / 255;
                    break;
                case 45:
                    ht = true;
                    break;
                case 61 when len >= 2:
                    ht = true;
                    var offset = body[1] & 0x03;
                    var anyWidth = (body[1] & 0x04) != 0;
                    secondary = offset switch { 1 => 1, 3 => -1, _ => 0 };
                    htWidth = anyWidth && secondary != 0 ? 40 : 20;
                    break;
                case 48:
                    ParseRsn(body, akm);
                    break;
                case 54:
                    mobility = true;
                    break;
                case 70:
                    rm = true;
                    break;
                case 127 when len >= 3:
                    btm = (body[2] & 0x08) != 0; // bit 19
                    break;
                case 191:
                    vht = true;
                    break;
                case 192 when len >= 3:
                    vht = true;
                    (vhtWidth, vhtCenter) = VhtWidth(body[0], body[1], body[2]);
                    break;
                case 221 when len >= 4 && body[0] == 0x00 && body[1] == 0x50 && body[2] == 0xF2 && body[3] == 1:
                    wpa1 = true;
                    break;
                case 255 when len >= 1:
                    var ext = body[0];
                    var e = body[1..];
                    switch (ext)
                    {
                        case 35:
                            he = true;
                            break;
                        case 36:
                            he = true;
                            (heWidth, heCenter) = HeSixGhz(e);
                            break;
                        case 108:
                            eht = true;
                            break;
                        case 106:
                            eht = true;
                            (ehtWidth, ehtCenter) = EhtWidth(e);
                            break;
                    }

                    break;
            }
        }

        // the widest operation element wins: an EHT AP also sends HT/VHT/HE operation for older clients
        int? width = count == 0 ? null : new[] { ehtWidth, heWidth, vhtWidth, htWidth }.Max() ?? 20;
        int? center = width switch
        {
            null or <= 40 => null,
            _ when ehtWidth == width => ehtCenter,
            _ when heWidth == width => heCenter,
            _ => vhtCenter,
        };
        return new InformationElements
        {
            Count = count, Malformed = malformed, Country = country, Ht = ht, Vht = vht, He = he, Eht = eht,
            ChannelWidthMhz = width, CenterChannel = center, SecondaryChannelOffset = secondary, StationCount = stations,
            ChannelUtilizationPercent = utilization, AkmSuites = akm, Wpa1 = wpa1, RadioMeasurement = rm, BssTransition = btm,
            FastTransition = mobility || akm.Contains(3) || akm.Contains(4) || akm.Contains(9) || akm.Contains(13) || akm.Contains(25),
        };
    }

    private static bool IsLetter(byte b) => b is >= (byte)'A' and <= (byte)'Z' or >= (byte)'a' and <= (byte)'z';

    private static void ParseRsn(ReadOnlySpan<byte> b, List<int> akm)
    {
        // version (2), group cipher (4), pairwise count (2) + 4 each, AKM count (2) + 4 each
        if (b.Length < 8) return;
        var p = 6;
        if (p + 2 > b.Length) return;
        var pairwise = b[p] | (b[p + 1] << 8);
        p += 2 + (4 * pairwise);
        if (p + 2 > b.Length) return;
        var n = b[p] | (b[p + 1] << 8);
        p += 2;
        for (var k = 0; k < n && p + 4 <= b.Length; k++, p += 4)
        {
            if (b[p] == 0x00 && b[p + 1] == 0x0F && b[p + 2] == 0xAC) akm.Add(b[p + 3]);
        }
    }

    /// <summary>VHT Operation: width 0 = 20/40 (HT decides), 1 = 80, or 160 when CCFS1 is 8 channels from CCFS0; 2 = 160, 3 = 80+80 (legacy).</summary>
    private static (int?, int?) VhtWidth(byte width, byte ccfs0, byte ccfs1) => width switch
    {
        1 when ccfs1 != 0 && Math.Abs(ccfs1 - ccfs0) == 8 => (160, ccfs1),
        1 when ccfs1 != 0 => (160, null), // 80+80: two segments, no single centre
        1 => (80, ccfs0),
        2 => (160, ccfs0),
        3 => (160, null),
        _ => (null, null),
    };

    /// <summary>HE Operation: only the 6 GHz Operation Information states a width (5 GHz HE uses the VHT element).</summary>
    private static (int?, int?) HeSixGhz(ReadOnlySpan<byte> e)
    {
        if (e.Length < 6) return (null, null);
        var parameters = e[0] | (e[1] << 8) | (e[2] << 16);
        var p = 3 + 1 + 2; // parameters, BSS colour, basic HE-MCS
        if ((parameters & (1 << 14)) != 0) p += 3; // VHT operation information
        if ((parameters & (1 << 15)) != 0) p += 1; // max co-hosted BSSID indicator
        if ((parameters & (1 << 17)) == 0 || p + 5 > e.Length) return (null, null);
        var control = e[p + 1];
        byte ccfs0 = e[p + 2], ccfs1 = e[p + 3];
        return (control & 0x03) switch
        {
            0 => (20, null),
            1 => (40, null),
            2 => (80, ccfs0),
            _ => (160, ccfs1 != 0 ? ccfs1 : ccfs0),
        };
    }

    /// <summary>EHT Operation: parameters (1), basic EHT-MCS (4), then the optional information with the width.</summary>
    private static (int?, int?) EhtWidth(ReadOnlySpan<byte> e)
    {
        if (e.Length < 8 || (e[0] & 0x01) == 0) return (null, null);
        var control = e[5] & 0x07;
        byte ccfs0 = e[6], ccfs1 = e[7];
        return control switch
        {
            0 => (20, null),
            1 => (40, null),
            2 => (80, ccfs0),
            3 => (160, ccfs1 != 0 ? ccfs1 : ccfs0),
            4 => (320, ccfs1 != 0 ? ccfs1 : ccfs0),
            _ => (null, null),
        };
    }
}
