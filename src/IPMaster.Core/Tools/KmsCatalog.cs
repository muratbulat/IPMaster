namespace IPMaster.Core.Tools;

public enum KmsFamily
{
    Windows,
    WindowsServer,
    Office,
    Project,
    Visio,
}

/// <summary>
/// One official Generic Volume License Key (KMS client setup key) as Microsoft publishes it. <see cref="Match"/> holds the tokens
/// detection compares against: Windows "EditionID:build" (or "EditionID:client" = any Windows 10/11 client build), Office
/// "Product:year" from the licence family. An entry without tokens is listed but never offered automatically.
/// </summary>
public sealed record GvlkEntry(KmsFamily Family, string Version, string Edition, string Key, bool Legacy, IReadOnlyList<string> Match)
{
    public string Source => Family is KmsFamily.Windows or KmsFamily.WindowsServer ? KmsCatalog.WindowsSource : KmsCatalog.OfficeSource;

    public string FamilyName => Family switch
    {
        KmsFamily.WindowsServer => "Windows Server",
        _ => Family.ToString(),
    };
}

/// <summary>
/// Offline copy of Microsoft's GVLK tables (D-104), reviewed 2026-11-26 against the pages below (Windows page updated 2026-04-02,
/// 82 keys; Office page updated 2026-04-24, 52 keys). GVLKs are public setup keys, not licences: they only make a product a KMS
/// client, and activation still needs an authorised KMS host. No KMS host keys (CSVLK), MAK or retail keys belong here.
/// </summary>
public static class KmsCatalog
{
    public const string WindowsSource = "https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys";
    public const string OfficeSource = "https://learn.microsoft.com/en-us/office/volume-license-activation/gvlks";

    // Windows 10/11 client build numbers of the LTSC/LTSB releases (Enterprise S editions are tied to one build each).
    private const string Ltsb2015 = "10240", Ltsb2016 = "14393", Ltsc2019 = "17763", Ltsc2021 = "19044", Ltsc2024 = "26100";

    private static GvlkEntry W(string version, string edition, string key, params string[] match) => new(KmsFamily.Windows, version, edition, key, false, match);

    private static GvlkEntry WL(string version, string edition, string key, params string[] match) => new(KmsFamily.Windows, version, edition, key, true, match);

    private static GvlkEntry S(string version, string edition, string key, params string[] match) => new(KmsFamily.WindowsServer, version, edition, key, false, match);

    private static GvlkEntry SL(string version, string edition, string key, params string[] match) => new(KmsFamily.WindowsServer, version, edition, key, true, match);

    private static GvlkEntry O(string year, string product, string token, string key)
    {
        var family = token.StartsWith("Project", StringComparison.Ordinal) ? KmsFamily.Project : token.StartsWith("Visio", StringComparison.Ordinal) ? KmsFamily.Visio : KmsFamily.Office;
        return new(family, year, product, key, year is "2016" or "2019", [$"{token}:{year}"]); // Office 2016/2019 support ended 2025-10-14
    }

    public static IReadOnlyList<GvlkEntry> All { get; } =
    [
        // ---- Windows 11 and Windows 10 Semi-Annual Channel ----
        W("Windows 11 / 10", "Pro", "W269N-WFGWX-YVC9B-4J6C9-T83GX", "Professional:client"),
        W("Windows 11 / 10", "Pro N", "MH37W-N47XK-V7XM9-C7227-GCQG9", "ProfessionalN:client"),
        W("Windows 11 / 10", "Pro for Workstations", "NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J", "ProfessionalWorkstation:client"),
        W("Windows 11 / 10", "Pro for Workstations N", "9FNHH-K3HBT-3W4TD-6383H-6XYWF", "ProfessionalWorkstationN:client"),
        W("Windows 11 / 10", "Pro Education", "6TP4R-GNPTD-KYYHQ-7B7DP-J447Y", "ProfessionalEducation:client"),
        W("Windows 11 / 10", "Pro Education N", "YVWGF-BXNMC-HTQYQ-CPQ99-66QFC", "ProfessionalEducationN:client"),
        W("Windows 11 / 10", "Education", "NW6C2-QMPVW-D7KKK-3GKT6-VCFB2", "Education:client"),
        W("Windows 11 / 10", "Education N", "2WH4N-8QGBV-H22JP-CT43Q-MDWWJ", "EducationN:client"),
        W("Windows 11 / 10", "Enterprise", "NPPR9-FWDCX-D2C8J-H872K-2YT43", "Enterprise:client"),
        W("Windows 11 / 10", "Enterprise N", "DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4", "EnterpriseN:client"),
        W("Windows 11 / 10", "Enterprise G", "YYVX9-NTFWV-6MDM3-9PT4T-4M68B", "EnterpriseG:client"),
        W("Windows 11 / 10", "Enterprise G N", "44RPN-FTY23-9VTTB-MP9BX-T84FV", "EnterpriseGN:client"),

        // ---- Windows Enterprise LTSC and LTSB ----
        W("Windows 11 LTSC 2024 / 10 LTSC 2021, 2019", "Enterprise LTSC", "M7XTQ-FN8P6-TTKYV-9D4CC-J462D", "EnterpriseS:" + Ltsc2024, "EnterpriseS:" + Ltsc2021, "EnterpriseS:" + Ltsc2019),
        W("Windows 11 LTSC 2024 / 10 LTSC 2021, 2019", "Enterprise N LTSC", "92NFX-8DJQP-P6BBQ-THF9C-7CG2H", "EnterpriseSN:" + Ltsc2024, "EnterpriseSN:" + Ltsc2021, "EnterpriseSN:" + Ltsc2019),
        W("Windows IoT LTSC 2024 / 2021", "IoT Enterprise LTSC", "KBN8V-HFGQ4-MGXVD-347P6-PDQGT", "IoTEnterpriseS:" + Ltsc2024, "IoTEnterpriseS:" + Ltsc2021),
        W("Windows 10 LTSB 2016", "Enterprise LTSB", "DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ", "EnterpriseS:" + Ltsb2016),
        W("Windows 10 LTSB 2016", "Enterprise N LTSB", "QFFDN-GRT3P-VKWWX-X7T3R-8B639", "EnterpriseSN:" + Ltsb2016),
        W("Windows 10 LTSB 2015", "Enterprise LTSB", "WNMTR-4C88C-JK8YV-HQ7T2-76DF9", "EnterpriseS:" + Ltsb2015),
        W("Windows 10 LTSB 2015", "Enterprise N LTSB", "2F77B-TNFGY-69QQF-B8YKP-D69TJ", "EnterpriseSN:" + Ltsb2015),

        // ---- Earlier Windows client versions ----
        WL("Windows 8.1", "Pro", "GCRJD-8NW9H-F2CDX-CCM8D-9D6T9", "Professional:9600"),
        WL("Windows 8.1", "Pro N", "HMCNV-VVBFX-7HMBH-CTY9B-B4FXY", "ProfessionalN:9600"),
        WL("Windows 8.1", "Enterprise", "MHF9N-XY6XB-WVXMC-BTDCT-MKKG7", "Enterprise:9600"),
        WL("Windows 8.1", "Enterprise N", "TT4HM-HN7YT-62K67-RGRQJ-JFFXW", "EnterpriseN:9600"),
        WL("Windows 8", "Pro", "NG4HW-VH26C-733KW-K6F98-J8CK4", "Professional:9200"),
        WL("Windows 8", "Pro N", "XCVCF-2NXM9-723PB-MHCB7-2RYQQ", "ProfessionalN:9200"),
        WL("Windows 8", "Enterprise", "32JNW-9KQ84-P47T8-D8GGY-CWCK7", "Enterprise:9200"),
        WL("Windows 8", "Enterprise N", "JMNMF-RHW7P-DMY6X-RF3DR-X2BQT", "EnterpriseN:9200"),
        WL("Windows 7", "Professional", "FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4"),
        WL("Windows 7", "Professional N", "MRPKT-YTG23-K7D7T-X2JMM-QY7MG"),
        WL("Windows 7", "Professional E", "W82YF-2Q76Y-63HXB-FGJG9-GF7QX"),
        WL("Windows 7", "Enterprise", "33PXH-7Y6KF-2VJC9-XBBR8-HVTHH"),
        WL("Windows 7", "Enterprise N", "YDRBP-3D83W-TY26F-D46B2-XCKRJ"),
        WL("Windows 7", "Enterprise E", "C29WB-22CC8-VJ326-GHFJW-H9DH4"),
        WL("Windows Vista", "Business", "YFKBB-PQJJV-G996G-VWGXY-2V3X8"),
        WL("Windows Vista", "Business N", "HMBQG-8H2RH-C77VX-27R82-VMQBT"),
        WL("Windows Vista", "Enterprise", "VKK3X-68KWM-X2YGT-QR4M6-4BWMV"),
        WL("Windows Vista", "Enterprise N", "VTC42-BM838-43QHV-84HX6-XJXKV"),

        // ---- Windows Server LTSC ----
        S("Windows Server 2025", "Standard", "TVRH6-WHNXV-R9WG3-9XRFY-MY832", "ServerStandard:26100"),
        S("Windows Server 2025", "Datacenter", "D764K-2NDRG-47T6Q-P8T8W-YP6DF", "ServerDatacenter:26100"),
        S("Windows Server 2025", "Datacenter: Azure Edition", "XGN3F-F394H-FD2MY-PP6FD-8MCRC", "ServerTurbine:26100"),
        S("Windows Server 2022", "Standard", "VDYBN-27WPP-V4HQT-9VMD4-VMK7H", "ServerStandard:20348"),
        S("Windows Server 2022", "Datacenter", "WX4NM-KYWYW-QJJR4-XV3QB-6VM33", "ServerDatacenter:20348"),
        S("Windows Server 2022", "Datacenter: Azure Edition", "NTBV8-9K7Q8-V27C6-M2BTV-KHMXV", "ServerTurbine:20348"),
        S("Windows Server 2019", "Standard", "N69G4-B89J2-4G8F4-WWYCC-J464C", "ServerStandard:17763"),
        S("Windows Server 2019", "Datacenter", "WMDGN-G9PQG-XVVXX-R3X43-63DFG", "ServerDatacenter:17763"),
        S("Windows Server 2019", "Essentials", "WVDHN-86M7X-466P6-VHXV7-YY726", "ServerSolution:17763"),
        S("Windows Server 2016", "Standard", "WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY", "ServerStandard:14393"),
        S("Windows Server 2016", "Datacenter", "CB7KF-BWN84-R7R2Y-793K2-8XDDG", "ServerDatacenter:14393"),
        S("Windows Server 2016", "Essentials", "JCKRF-N37P4-C2D82-9YXRT-4M63B", "ServerSolution:14393"),

        // ---- Windows Server Semi-Annual Channel (version 1809 shares build 17763 with Server 2019: never matched automatically) ----
        SL("Windows Server 20H2, 2004, 1909, 1903, 1809", "Standard", "N2KJX-J94YW-TQVFB-DG9YT-724CC", "ServerStandard:18362", "ServerStandard:18363", "ServerStandard:19041", "ServerStandard:19042"),
        SL("Windows Server 20H2, 2004, 1909, 1903, 1809", "Datacenter", "6NMRW-2C8FM-D24W7-TQWMY-CWH2D", "ServerDatacenter:18362", "ServerDatacenter:18363", "ServerDatacenter:19041", "ServerDatacenter:19042"),
        SL("Windows Server 1803", "Standard", "PTXN8-JFHJM-4WC78-MPCBR-9W4KR", "ServerStandard:17134"),
        SL("Windows Server 1803", "Datacenter", "2HXDN-KRXHB-GPYC7-YCKFJ-7FVDG", "ServerDatacenter:17134"),
        SL("Windows Server 1709", "Standard", "DPCNP-XQFKJ-BJF7R-FRC8D-GF6G4", "ServerStandard:16299"),
        SL("Windows Server 1709", "Datacenter", "6Y6KB-N82V8-D8CQV-23MJW-BWTG6", "ServerDatacenter:16299"),

        // ---- Earlier Windows Server versions ----
        SL("Windows Server 2012 R2", "Standard", "D2N9P-3P6X9-2R39C-7RTCD-MDVJX", "ServerStandard:9600"),
        SL("Windows Server 2012 R2", "Datacenter", "W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9", "ServerDatacenter:9600"),
        SL("Windows Server 2012 R2", "Essentials", "KNC87-3J2TX-XB4WP-VCPJV-M4FWM", "ServerSolution:9600"),
        SL("Windows Server 2012", "Windows Server 2012", "BN3D2-R7TKB-3YPBD-8DRP2-27GG4"),
        SL("Windows Server 2012", "N", "8N2M2-HWPGY-7PGT9-HGDD8-GVGGY"),
        SL("Windows Server 2012", "Single Language", "2WN2H-YGCQR-KFX6K-CD6TF-84YXQ"),
        SL("Windows Server 2012", "Country Specific", "4K36P-JN4VD-GDC6V-KDT89-DYFKP"),
        SL("Windows Server 2012", "Standard", "XC9B7-NBPP2-83J2H-RHMBY-92BT4", "ServerStandard:9200"),
        SL("Windows Server 2012", "MultiPoint Standard", "HM7DN-YVMH3-46JC3-XYTG7-CYQJJ"),
        SL("Windows Server 2012", "MultiPoint Premium", "XNH6W-2V9GX-RGJ4K-Y8X6F-QGJ2G"),
        SL("Windows Server 2012", "Datacenter", "48HP8-DN98B-MYWDG-T2DCC-8W83P", "ServerDatacenter:9200"),
        SL("Windows Server 2012", "Essentials", "HTDQM-NBMMG-KGYDT-2DTKT-J2MPV", "ServerSolution:9200"),
        SL("Windows Server 2008 R2", "Web", "6TPJF-RBVHG-WBW2R-86QPH-6RTM4"),
        SL("Windows Server 2008 R2", "HPC edition", "TT8MH-CG224-D3D7Q-498W2-9QCTX"),
        SL("Windows Server 2008 R2", "Standard", "YC6KT-GKW9T-YTKYR-T4X34-R7VHC"),
        SL("Windows Server 2008 R2", "Enterprise", "489J6-VHDMP-X63PK-3K798-CPX3Y"),
        SL("Windows Server 2008 R2", "Datacenter", "74YFP-3QFB3-KQT8W-PMXWJ-7M648"),
        SL("Windows Server 2008 R2", "for Itanium-based Systems", "GT63C-RJFQ3-4GMB6-BRFB9-CB83V"),
        SL("Windows Server 2008", "Web", "WYR28-R7TFJ-3X2YQ-YCY4H-M249D"),
        SL("Windows Server 2008", "Standard", "TM24T-X9RMF-VWXK6-X8JC9-BFGM2"),
        SL("Windows Server 2008", "Standard without Hyper-V", "W7VD6-7JFBR-RX26B-YKQ3Y-6FFFJ"),
        SL("Windows Server 2008", "Enterprise", "YQGMW-MPWTJ-34KDK-48M3W-X4Q6V"),
        SL("Windows Server 2008", "Enterprise without Hyper-V", "39BXF-X8Q23-P2WWT-38T2F-G3FPG"),
        SL("Windows Server 2008", "HPC", "RCTX3-KWVHP-BR6TB-RB6DM-6X7HP"),
        SL("Windows Server 2008", "Datacenter", "7M67G-PC374-GR742-YH8V4-TCBY3"),
        SL("Windows Server 2008", "Datacenter without Hyper-V", "22XQ2-VRXRG-P8D42-K34TD-G3QQC"),
        SL("Windows Server 2008", "for Itanium-Based Systems", "4DWFP-JF3DJ-B7DTH-78FJB-PDRHK"),

        // ---- Office LTSC 2024 ----
        O("2024", "Office LTSC Professional Plus 2024", "ProPlus", "XJ2XN-FW8RK-P4HMP-DKDBV-GCVGB"),
        O("2024", "Office LTSC Standard 2024", "Standard", "V28N4-JG22K-W66P8-VTMGK-H6HGR"),
        O("2024", "Project Professional 2024", "ProjectPro", "FQQ23-N4YCY-73HQ3-FM9WC-76HF4"),
        O("2024", "Project Standard 2024", "ProjectStd", "PD3TT-NTHQQ-VC7CY-MFXK3-G87F8"),
        O("2024", "Visio LTSC Professional 2024", "VisioPro", "B7TN8-FJ8V3-7QYCP-HQPMV-YY89G"),
        O("2024", "Visio LTSC Standard 2024", "VisioStd", "JMMVY-XFNQC-KK4HK-9H7R3-WQQTV"),
        O("2024", "Access LTSC 2024", "Access", "82FTR-NCHR7-W3944-MGRHM-JMCWD"),
        O("2024", "Excel LTSC 2024", "Excel", "F4DYN-89BP2-WQTWJ-GR8YC-CKGJG"),
        O("2024", "Outlook LTSC 2024", "Outlook", "D2F8D-N3Q3B-J28PV-X27HD-RJWB9"),
        O("2024", "PowerPoint LTSC 2024", "PowerPoint", "CW94N-K6GJH-9CTXY-MG2VC-FYCWP"),
        O("2024", "Skype for Business LTSC 2024", "SkypeForBusiness", "4NKHF-9HBQF-Q3B6C-7YV34-F64P3"),
        O("2024", "Word LTSC 2024", "Word", "MQ84N-7VYDM-FXV7C-6K7CC-VFW9J"),

        // ---- Office LTSC 2021 ----
        O("2021", "Office LTSC Professional Plus 2021", "ProPlus", "FXYTK-NJJ8C-GB6DW-3DYQT-6F7TH"),
        O("2021", "Office LTSC Standard 2021", "Standard", "KDX7X-BNVR8-TXXGX-4Q7Y8-78VT3"),
        O("2021", "Project Professional 2021", "ProjectPro", "FTNWT-C6WBT-8HMGF-K9PRX-QV9H8"),
        O("2021", "Project Standard 2021", "ProjectStd", "J2JDC-NJCYY-9RGQ4-YXWMH-T3D4T"),
        O("2021", "Visio LTSC Professional 2021", "VisioPro", "KNH8D-FGHT4-T8RK3-CTDYJ-K2HT4"),
        O("2021", "Visio LTSC Standard 2021", "VisioStd", "MJVNY-BYWPY-CWV6J-2RKRT-4M8QG"),
        O("2021", "Access LTSC 2021", "Access", "WM8YG-YNGDD-4JHDC-PG3F4-FC4T4"),
        O("2021", "Excel LTSC 2021", "Excel", "NWG3X-87C9K-TC7YY-BC2G7-G6RVC"),
        O("2021", "Outlook LTSC 2021", "Outlook", "C9FM6-3N72F-HFJXB-TM3V9-T86R9"),
        O("2021", "PowerPoint LTSC 2021", "PowerPoint", "TY7XF-NFRBR-KJ44C-G83KF-GX27K"),
        O("2021", "Publisher LTSC 2021", "Publisher", "2MW9D-N4BXM-9VBPG-Q7W6M-KFBGQ"),
        O("2021", "Skype for Business LTSC 2021", "SkypeForBusiness", "HWCXN-K3WBT-WJBKY-R8BD9-XK29P"),
        O("2021", "Word LTSC 2021", "Word", "TN8H9-M34D3-Y64V9-TR72V-X79KV"),

        // ---- Office 2019 ----
        O("2019", "Office Professional Plus 2019", "ProPlus", "NMMKJ-6RK4F-KMJVX-8D9MJ-6MWKP"),
        O("2019", "Office Standard 2019", "Standard", "6NWWJ-YQWMR-QKGCB-6TMB3-9D9HK"),
        O("2019", "Project Professional 2019", "ProjectPro", "B4NPR-3FKK7-T2MBV-FRQ4W-PKD2B"),
        O("2019", "Project Standard 2019", "ProjectStd", "C4F7P-NCP8C-6CQPT-MQHV9-JXD2M"),
        O("2019", "Visio Professional 2019", "VisioPro", "9BGNQ-K37YR-RQHF2-38RQ3-7VCBB"),
        O("2019", "Visio Standard 2019", "VisioStd", "7TQNQ-K3YQQ-3PFH7-CCPPM-X4VQ2"),
        O("2019", "Access 2019", "Access", "9N9PT-27V4Y-VJ2PD-YXFMF-YTFQT"),
        O("2019", "Excel 2019", "Excel", "TMJWT-YYNMB-3BKTF-644FC-RVXBD"),
        O("2019", "Outlook 2019", "Outlook", "7HD7K-N4PVK-BHBCQ-YWQRW-XW4VK"),
        O("2019", "PowerPoint 2019", "PowerPoint", "RRNCX-C64HY-W2MM7-MCH9G-TJHMQ"),
        O("2019", "Publisher 2019", "Publisher", "G2KWX-3NW6P-PY93R-JXK2T-C9Y9V"),
        O("2019", "Skype for Business 2019", "SkypeForBusiness", "NCJ33-JHBBY-HTK98-MYCV8-HMKHJ"),
        O("2019", "Word 2019", "Word", "PBX3G-NWMT6-Q7XBW-PYJGG-WXD33"),

        // ---- Office 2016 ----
        O("2016", "Office Professional Plus 2016", "ProPlus", "XQNVK-8JYDB-WJ9W3-YJ8YR-WFG99"),
        O("2016", "Office Standard 2016", "Standard", "JNRGM-WHDWX-FJJG3-K47QV-DRTFM"),
        O("2016", "Project Professional 2016", "ProjectPro", "YG9NW-3K39V-2T3HJ-93F3Q-G83KT"),
        O("2016", "Project Standard 2016", "ProjectStd", "GNFHQ-F6YQM-KQDGJ-327XX-KQBVC"),
        O("2016", "Visio Professional 2016", "VisioPro", "PD3PC-RHNGV-FXJ29-8JK7D-RJRJK"),
        O("2016", "Visio Standard 2016", "VisioStd", "7WHWN-4T7MP-G96JF-G33KR-W8GF4"),
        O("2016", "Access 2016", "Access", "GNH9Y-D2J4T-FJHGG-QRVH7-QPFDW"),
        O("2016", "Excel 2016", "Excel", "9C2PK-NWTVB-JMPW8-BFT28-7FTBF"),
        O("2016", "OneNote 2016", "OneNote", "DR92N-9HTF2-97XKM-XW2WJ-XW3J6"),
        O("2016", "Outlook 2016", "Outlook", "R69KK-NTPKF-7M3Q4-QYBHW-6MT9B"),
        O("2016", "PowerPoint 2016", "PowerPoint", "J7MQP-HNJ4Y-WJ7YM-PFYGF-BY6C6"),
        O("2016", "Publisher 2016", "Publisher", "F47MM-N3XJP-TQXJ9-BP99D-8K837"),
        O("2016", "Skype for Business 2016", "SkypeForBusiness", "869NQ-FJ69K-466HW-QYCP2-DDBV6"),
        O("2016", "Word 2016", "Word", "WXY84-JN2Q9-RBCCQ-3Q3J3-3PFJ6"),
    ];

    public static bool IsCatalogKey(string key) => All.Any(e => string.Equals(e.Key, key, StringComparison.Ordinal));

    /// <summary>Exactly one entry for the token, else null (an unknown or ambiguous SKU never gets a key).</summary>
    public static GvlkEntry? ByToken(string token)
    {
        var hits = All.Where(e => e.Match.Contains(token, StringComparer.OrdinalIgnoreCase)).Take(2).ToList();
        return hits.Count == 1 ? hits[0] : null;
    }

    /// <summary>
    /// Windows: by EditionID (registry / licence family, never the display name) and build. Build 17763 is both Server 2019 and
    /// Server version 1809, which have different keys: only a product name naming 2019 decides it, otherwise no match.
    /// </summary>
    public static GvlkEntry? MatchWindows(string editionId, int build, bool isServer, string productName)
    {
        if (string.IsNullOrWhiteSpace(editionId) || build <= 0) return null;
        if (isServer && build == 17763 && !productName.Contains("2019", StringComparison.Ordinal)) return null;
        var exact = ByToken($"{editionId}:{build}");
        if (exact is not null) return exact.Family == (isServer ? KmsFamily.WindowsServer : KmsFamily.Windows) ? exact : null;
        return !isServer && build >= 10240 ? ByToken($"{editionId}:client") : null;
    }

    /// <summary>
    /// Office: from the licence family of a volume licence, e.g. "Office21ProPlus2021VL_KMS_Client_AE" or "Office16VisioProVL_MAK".
    /// Retail, subscription and unknown families give null.
    /// </summary>
    public static GvlkEntry? MatchOffice(string licenseFamily) => OfficeToken(licenseFamily) is { } t ? ByToken(t) : null;

    /// <summary>"Product:year" of a volume Office licence family, or null.</summary>
    public static string? OfficeToken(string licenseFamily)
    {
        var m = System.Text.RegularExpressions.Regex.Match(licenseFamily ?? "", @"^Office(?<ns>16|19|21|24)(?<p>[A-Za-z]+?)(?<y>2019|2021|2024)?VL_(?:KMS_Client|MAK)(?:_AE\d*)?$",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(1));
        if (!m.Success) return null;
        var year = m.Groups["ns"].Value switch
        {
            "16" when !m.Groups["y"].Success => "2016",
            "19" when m.Groups["y"].Value == "2019" => "2019",
            "21" when m.Groups["y"].Value == "2021" => "2021",
            "24" when m.Groups["y"].Value == "2024" => "2024",
            _ => null,
        };
        return year is null ? null : $"{m.Groups["p"].Value}:{year}";
    }
}
