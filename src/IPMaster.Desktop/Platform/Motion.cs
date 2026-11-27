using System.Runtime.InteropServices;

namespace IPMaster.Desktop.Platform;

/// <summary>
/// Reduced motion (D-112): Windows "Show animations in Windows" off (SPI_GETCLIENTAREAANIMATION) means no decorative animation.
/// Other systems: Avalonia exposes no such setting, so animations stay on (they are short and never continuous).
/// </summary>
internal static partial class Motion
{
    private const uint SpiGetClientAreaAnimation = 0x1042;

    public static bool Reduced
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            try
            {
                return SystemParametersInfoW(SpiGetClientAreaAnimation, 0, out var on, 0) && on == 0;
            }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
            {
                return false;
            }
        }
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SystemParametersInfoW(uint action, uint param, out int value, uint winIni);
}
