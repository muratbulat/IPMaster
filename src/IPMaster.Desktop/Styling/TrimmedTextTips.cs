using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.VisualTree;

namespace IPMaster.Desktop.Styling;

/// <summary>
/// Full values for shortened table cells: every grid cell's text is trimmed with an ellipsis (Controls.axaml), and when
/// the pointer rests on a cell whose text was actually shortened, its tooltip shows the complete value. A tooltip set by
/// the view itself is never replaced. Copying a cell or row still copies the complete value (the data, not the text).
/// </summary>
internal static class TrimmedTextTips
{
    private static readonly AttachedProperty<bool> OwnTipProperty = AvaloniaProperty.RegisterAttached<TextBlock, bool>("OwnTip", typeof(TrimmedTextTips));
    private static bool _registered;

    public static void Register()
    {
        if (_registered) return;
        _registered = true;
        InputElement.PointerEnteredEvent.AddClassHandler<TextBlock>((t, _) => Update(t), handledEventsToo: true);
    }

    /// <summary>True when the text block shows less than its text (ellipsis or cut lines).</summary>
    public static bool IsTrimmed(TextBlock t)
    {
        ArgumentNullException.ThrowIfNull(t);
        return !string.IsNullOrEmpty(t.Text) && t.TextLayout.TextLines.Any(l => l.HasCollapsed);
    }

    private static void Update(TextBlock t)
    {
        if (t.FindAncestorOfType<DataGridCell>() is null) return;
        var ours = t.GetValue(OwnTipProperty);
        if (!ours && ToolTip.GetTip(t) is not null) return; // the view's own tooltip wins
        if (IsTrimmed(t))
        {
            ToolTip.SetTip(t, t.Text);
            t.SetValue(OwnTipProperty, true);
        }
        else if (ours)
        {
            t.ClearValue(ToolTip.TipProperty);
            t.SetValue(OwnTipProperty, false);
        }
    }
}
