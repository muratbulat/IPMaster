using Avalonia;
using Avalonia.Controls;

namespace IPMaster.Desktop.Platform;

/// <summary>
/// Keeps every window on its screen (D-113). A default or minimum size larger than the screen's working area (a
/// 1366×768 laptop, or 1920×1080 at 150 %) is reduced to that area, so the title bar and the actions stay reachable.
/// Sizes that fit are left exactly as the window set them.
/// </summary>
internal static class ScreenFit
{
    private static bool _registered;

    public static void Register()
    {
        if (_registered) return;
        _registered = true;
        Window.WindowOpenedEvent.AddClassHandler<Window>((w, _) => Apply(w));
    }

    /// <summary>The client size limits for a window whose frame (title bar, borders) takes <paramref name="chrome"/>.</summary>
    internal static (double Width, double Height, double MinWidth, double MinHeight) Fit(double width, double height, double minWidth, double minHeight, Size available, Size chrome)
    {
        var w = Math.Max(200, available.Width - chrome.Width);
        var h = Math.Max(200, available.Height - chrome.Height);
        return (Math.Min(width, w), Math.Min(height, h), Math.Min(minWidth, w), Math.Min(minHeight, h));
    }

    private static void Apply(Window window)
    {
        if (window.WindowState != WindowState.Normal || window.Screens is not { } screens) return;
        var screen = screens.ScreenFromWindow(window) ?? screens.Primary;
        if (screen is null || screen.Scaling <= 0) return;
        var area = screen.WorkingArea;
        var available = new Size(area.Width / screen.Scaling, area.Height / screen.Scaling);
        var chrome = window.FrameSize is { } frame ? new Size(Math.Max(0, frame.Width - window.ClientSize.Width), Math.Max(0, frame.Height - window.ClientSize.Height)) : new Size(16, 40);
        var current = window.ClientSize;
        var (w, h, minW, minH) = Fit(current.Width, current.Height, window.MinWidth, window.MinHeight, available, chrome);
        if (minW < window.MinWidth) window.MinWidth = minW;
        if (minH < window.MinHeight) window.MinHeight = minH;
        if (w >= current.Width - 0.5 && h >= current.Height - 0.5) return;
        window.Width = w;
        window.Height = h;
        // centre on the working area: the owner-centred position was computed for the larger size
        var frameW = (window.Width + chrome.Width) * screen.Scaling;
        var frameH = (window.Height + chrome.Height) * screen.Scaling;
        window.Position = new PixelPoint(area.X + (int)Math.Max(0, (area.Width - frameW) / 2), area.Y + (int)Math.Max(0, (area.Height - frameH) / 2));
    }
}
