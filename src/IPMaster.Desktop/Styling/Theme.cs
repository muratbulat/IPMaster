using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Styling;

namespace IPMaster.Desktop.Styling;

/// <summary>
/// The C# half of the design system (D-098, docs/DEVELOPMENT.md): spacing and size constants, token keys
/// (defined in Tokens.axaml) and resource lookup for code that cannot use <c>{DynamicResource}</c>. Views style controls
/// with classes (<see cref="Classes"/>); only custom-rendered controls look brushes up, through <see cref="ThemedControl"/>.
/// </summary>
internal static class Theme
{
    // spacing (DIP): compact desktop density
    public const double PageMargin = 12;
    public const double SectionGap = 8;
    public const double ControlGap = 8;
    public const double FormRowGap = 6;
    public const double TightGap = 4;
    public const double StatusGap = 6;

    // sizes
    public const double ToolMinWidth = 560;
    public const double ToolMinHeight = 380;
    public const double DialogMinWidth = 360;
    public const double DialogMinHeight = 240;
    public const double MonoFontSize = 12.5;

    public static readonly Thickness Page = new(PageMargin);

    /// <summary>Style classes (Controls.axaml). A role class plus at most one state class.</summary>
    public static class Classes
    {
        public const string Hint = "hint";
        public const string Description = "description";
        public const string Status = "status";
        public const string Label = "label";
        public const string Section = "section";
        public const string Mono = "mono";
        public const string Result = "result";
        public const string Note = "note";
        public const string Banner = "banner";
        public const string Success = "success";
        public const string Warning = "warning";
        public const string Error = "error";
        public const string Info = "info";

        public static readonly string[] States = [Success, Warning, Error, Info];
    }

    /// <summary>Token keys (Tokens.axaml).</summary>
    public static class Keys
    {
        public const string Border = "IpmBorder";
        public const string MatchSurface = "IpmMatchSurface";
        public const string UserHighlight = "IpmUserHighlight";
        public const string TextPrimary = "IpmTextPrimary";
        public const string TextSecondary = "IpmTextSecondary";
        public const string TextOnAccent = "IpmTextOnAccent";
        public const string Success = "IpmSuccess";
        public const string Warning = "IpmWarning";
        public const string Error = "IpmError";
        public const string ChartSurface = "IpmChartSurface";
        public const string ChartText = "IpmChartText";
        public const string ChartGrid = "IpmChartGrid";
        public const string Series1 = "IpmSeries1";
        public const string Series2 = "IpmSeries2";
        public const string Series3 = "IpmSeries3";
        public const string Series4 = "IpmSeries4";
        public const string ChartGood = "IpmChartGood";
        public const string ChartCritical = "IpmChartCritical";
        public const string NodeQueried = "IpmNodeQueried";
        public const string NodeFailed = "IpmNodeFailed";
        public const string NodeUnknown = "IpmNodeUnknown";
        public const string Link = "IpmLink";
        public const string BitNetwork = "IpmBitNetwork";
        public const string BitHost = "IpmBitHost";
        public const string BitReserved = "IpmBitReserved";
    }

    /// <summary>Every theme-dependent token, for the resource-resolution tests.</summary>
    public static readonly string[] AllBrushKeys =
    [
        "IpmResultsSurface", "IpmSubtleSurface", "IpmUserHighlight", "IpmRowHover", "IpmAlternateRow", "IpmMatchSurface", "IpmTabIdle", "IpmTabHover", "IpmTabSelected",
        "IpmBorder", "IpmBorderSubtle", "IpmTextPrimary", "IpmTextSecondary", "IpmTextDisabled", "IpmTextOnAccent", "IpmSuccess", "IpmWarning", "IpmError",
        "IpmInfo", "IpmSuccessSurface", "IpmWarningSurface", "IpmErrorSurface", "IpmInfoSurface", "IpmOnline", "IpmOffline", "IpmChartSurface", "IpmChartText",
        "IpmChartGrid", "IpmSeries1", "IpmSeries2", "IpmSeries3", "IpmSeries4", "IpmChartGood", "IpmChartCritical", "IpmNodeQueried", "IpmNodeFailed",
        "IpmNodeUnknown", "IpmLink", "IpmBitNetwork", "IpmBitHost", "IpmBitReserved",
    ];

    /// <summary>Sets exactly one state class (or none) on a control: replaces local Foreground colours.</summary>
    public static void SetState(StyledElement element, string? state)
    {
        ArgumentNullException.ThrowIfNull(element);
        foreach (var s in Classes.States) element.Classes.Set(s, s == state);
    }

    /// <summary>A token for the given (or the application's current) theme; null when the key is missing.</summary>
    public static IBrush? Brush(string key, ThemeVariant? variant = null)
    {
        var app = Application.Current;
        if (app is null) return null;
        return app.TryGetResource(key, variant ?? app.ActualThemeVariant, out var value) ? value as IBrush : null;
    }
}

/// <summary>
/// Base for custom-rendered controls (charts, graphs): brushes come from tokens for the control's actual theme, and a
/// theme change redraws. Never draw with fixed colours; data series use IpmSeries1..4, states IpmChartGood/Critical.
/// </summary>
internal abstract class ThemedControl : Control
{
    private static readonly IBrush Missing = new SolidColorBrush(Colors.Magenta); // theme-exception: makes a missing token obvious

    protected IBrush Brush(string key) => this.TryFindResource(key, ActualThemeVariant, out var value) && value is IBrush b ? b : global::IPMaster.Desktop.Styling.Theme.Brush(key) ?? Missing;

    protected Pen Pen(string key, double thickness = 1, IDashStyle? dash = null) => new(Brush(key), thickness, dash);

    /// <summary>A token with its alpha scaled (fills under outlines).</summary>
    protected IBrush Tint(string key, double opacity) => Brush(key) is ISolidColorBrush s ? new SolidColorBrush(s.Color, opacity * s.Opacity) : Brush(key);

    protected ThemedControl() => ActualThemeVariantChanged += (_, _) => InvalidateVisual();
}
