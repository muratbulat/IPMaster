using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Small shared pieces for the network utilities in the Tools menu (D-073): one-operation-at-a-time runner with cancellation,
/// a bounded monospace report pane, and copy/export. Deliberately not a framework: each tool keeps its own window layout,
/// built from <see cref="Ui"/> primitives and the design-system classes (D-098, docs/DEVELOPMENT.md).
/// </summary>
internal sealed class ToolRunner : IDisposable
{
    private CancellationTokenSource? _cts;

    public ToolRunner(TextBlock status) => Status = status;

    public TextBlock Status { get; }

    public bool IsBusy => _cts is not null;

    /// <summary>Raised on the UI thread when a run starts or ends (enable/disable buttons).</summary>
    public event EventHandler? BusyChanged;

    /// <summary>Runs one operation; a second call while busy is ignored (no overlapping operations).</summary>
    public async Task RunAsync(string what, Func<CancellationToken, Task<string>> work)
    {
        if (_cts is not null) return;
        _cts = new CancellationTokenSource();
        BusyChanged?.Invoke(this, EventArgs.Empty);
        Status.Text = what + "…";
        try
        {
            Status.Text = await Task.Run(() => work(_cts.Token));
        }
        catch (OperationCanceledException) when (_cts.IsCancellationRequested)
        {
            Status.Text = "Cancelled.";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            Status.Text = "Stopped on an unexpected error: " + ex.Message;
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            BusyChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void Cancel()
    {
        try
        {
            _cts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>Closing the window cancels the running operation.</summary>
    public void Dispose() => Cancel();
}

internal static class ToolKit
{
    public static readonly FontFamily Mono = new("Cascadia Mono, Consolas, Menlo, monospace");

    /// <summary>Upper bound of a report pane (characters); older text is dropped first.</summary>
    public const int MaxReportChars = 1_000_000;

    public static TextBox ReportBox(string name)
    {
        var t = new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, Classes = { Styling.Theme.Classes.Mono },
        };
        ScrollViewer.SetHorizontalScrollBarVisibility(t, Avalonia.Controls.Primitives.ScrollBarVisibility.Auto);
        AutomationProperties.SetName(t, name);
        return t;
    }

    /// <summary>Sets report text on the UI thread, keeping it within <see cref="MaxReportChars"/>.</summary>
    public static void SetReport(TextBox box, string text) =>
        Dispatcher.UIThread.Post(() => box.Text = text.Length > MaxReportChars ? "[… earlier output removed …]\n" + text[^MaxReportChars..] : text);

    public static TextBlock StatusLine() => new() { Classes = { "status" } };

    public static Button CopyButton(Window owner, Func<string> text, string label = "Copy") => Ui.Button(label, () => Ui.CopyAsync(owner, text()));

    public static Button ExportButton(Window owner, Func<string> text, string suggestedName, string label = "Export…") =>
        Ui.Button(label, () => SaveTextAsync(owner, text(), suggestedName));

    public static async Task SaveTextAsync(Window owner, string text, string suggestedName)
    {
        var ext = Path.GetExtension(suggestedName).TrimStart('.');
        var file = await owner.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export", SuggestedFileName = suggestedName, DefaultExtension = ext,
            FileTypeChoices = [new FilePickerFileType(ext.ToUpperInvariant()) { Patterns = ["*." + ext] }],
        });
        if (file?.TryGetLocalPath() is not { } path) return;
        await Core.Results.AtomicFile.WriteAsync(path, async s =>
        {
            await using var w = new StreamWriter(s, new System.Text.UTF8Encoding(false), 64 * 1024, leaveOpen: true);
            await w.WriteAsync(text);
        });
    }

    public static Window NewToolWindow(string title, double width = 1000, double height = 700) => new()
    {
        Title = title, Width = width, Height = height, MinWidth = Styling.Theme.ToolMinWidth, MinHeight = Styling.Theme.ToolMinHeight, WindowStartupLocation = WindowStartupLocation.CenterOwner,
    };

    /// <summary>
    /// The standard tool layout (D-098): configuration (scrollable when tall), actions, the results area, a status line.
    /// The status line is announced to screen readers when it changes.
    /// </summary>
    public static Control Layout(Control inputs, Control actions, Control main, TextBlock status)
    {
        var top = new StackPanel { Spacing = Styling.Theme.SectionGap, Children = { inputs, actions } };
        AutomationProperties.SetLiveSetting(status, AutomationLiveSetting.Polite);
        var statusBorder = new Border { Padding = new Thickness(0, Styling.Theme.StatusGap, 0, 0), Child = status };
        return Ui.Layout(new ScrollViewer { Content = top, MaxHeight = 360, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled }, main, statusBorder);
    }

    public static NumericUpDown Number(decimal value, decimal min, decimal max, string name, double width = 120)
    {
        var n = new NumericUpDown { Value = value, Minimum = min, Maximum = max, Increment = 1, FormatString = "0", Width = width, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(n, name);
        // name the inner edit box too: screen readers and UI Automation reach the value there
        n.TemplateApplied += (_, e) =>
        {
            if (e.NameScope.Find<TextBox>("PART_TextBox") is { } box) AutomationProperties.SetName(box, name);
        };
        return n;
    }

    public static TextBox Text(string name, string placeholder = "", double width = double.NaN, string text = "")
    {
        var t = new TextBox { PlaceholderText = placeholder, Width = width, Text = text, HorizontalAlignment = double.IsNaN(width) ? HorizontalAlignment.Stretch : HorizontalAlignment.Left };
        AutomationProperties.SetName(t, name);
        return t;
    }

    public static ComboBox Combo(string name, IEnumerable<string> items, int selected = 0, double width = 220)
    {
        var c = new ComboBox { ItemsSource = items.ToList(), SelectedIndex = selected, Width = width };
        AutomationProperties.SetName(c, name);
        return c;
    }
}
