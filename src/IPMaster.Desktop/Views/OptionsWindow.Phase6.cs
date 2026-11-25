using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.LogicalTree;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Configuration;
using IPMaster.Core.Navigation;

namespace IPMaster.Desktop.Views;

/// <summary>Shortcuts tab (UI-18), the settings index for the Navigator (UI-17) and revealing a setting.</summary>
public partial class OptionsWindow
{
    private static IReadOnlyList<NavigatorItem>? _index;
    private readonly List<ShortcutRow> _shortcutRows = [];
    private DataGrid? _shortcutGrid;
    private TextBox? _shortcutSearch;

    /// <summary>Commands of the main window (set by it whenever its shortcuts change).</summary>
    public static IReadOnlyList<ShortcutCommand> Catalog { get; set; } = [];

    private sealed class ShortcutRow(ShortcutCommand command, string gesture)
    {
        public ShortcutCommand Command => command;

        public string Name => command.Name;

        public string Category => command.Category;

        public string Gesture => gesture.Length > 0 ? gesture : "—";

        public string Raw => gesture;
    }

    // ---------------- Shortcuts tab ----------------
    private TabItem BuildShortcutsTab()
    {
        _shortcutSearch = new TextBox { PlaceholderText = "Search actions or shortcuts" };
        Avalonia.Automation.AutomationProperties.SetName(_shortcutSearch, "Search shortcuts");
        _shortcutGrid = Ui.Grid(("Action", "Name", 240), ("Menu", "Category", 0), ("Shortcut", "Gesture", 130));
        _shortcutGrid.SelectionMode = DataGridSelectionMode.Single;
        _shortcutGrid.DoubleTapped += async (_, _) => await EditShortcutAsync();
        _shortcutSearch.TextChanged += (_, _) => FilterShortcuts();
        var buttons = Ui.Row(
            Ui.Button("Change…", EditShortcutAsync),
            Ui.Button("Reset All to Defaults", () =>
            {
                if (Vm is not null) Vm.Shortcuts = [];
                LoadShortcuts();
                return Task.CompletedTask;
            }));
        var hint = new TextBlock
        {
            Classes = { "note" },
            TextWrapping = TextWrapping.Wrap,
            Text = "Double-click an action to change its shortcut. Shortcuts work in the main window; shortcuts for external applications are set on the Applications tab.",
        };
        var bottom = new StackPanel { Spacing = 6, Children = { buttons, hint } };
        DataContextChanged += (_, _) => LoadShortcuts();
        return new TabItem { Header = "Shortcuts", Content = Ui.Layout(_shortcutSearch, _shortcutGrid, bottom) };
    }

    private void LoadShortcuts()
    {
        if (Vm is null) return;
        var effective = Shortcuts.Effective(Catalog, Vm.Shortcuts);
        _shortcutRows.Clear();
        _shortcutRows.AddRange(Catalog.Select(c => new ShortcutRow(c, effective[c.Id])));
        FilterShortcuts();
    }

    private void FilterShortcuts()
    {
        if (_shortcutGrid is null) return;
        var q = _shortcutSearch?.Text?.Trim() ?? "";
        _shortcutGrid.ItemsSource = q.Length == 0
            ? _shortcutRows.ToList()
            : _shortcutRows.Where(r => r.Name.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                                       || r.Category.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                                       || r.Raw.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private async Task EditShortcutAsync()
    {
        if (Vm is null || _shortcutGrid?.SelectedItem is not ShortcutRow row) return;
        var effective = Shortcuts.Effective(Catalog, Vm.Shortcuts);
        var gesture = await CaptureShortcutAsync(this, row.Command, effective);
        if (gesture is null) return;
        var overrides = Vm.Shortcuts;
        // a gesture belongs to one action: assigning it here removes it from the others
        foreach (var other in Catalog.Where(c => c.Id != row.Command.Id && gesture.Length > 0 && effective[c.Id] == gesture))
        {
            overrides = Shortcuts.Assign(overrides, other, "");
        }

        Vm.Shortcuts = Shortcuts.Assign(overrides, row.Command, gesture);
        LoadShortcuts();
        _shortcutGrid.SelectedItem = _shortcutRows.FirstOrDefault(r => r.Command.Id == row.Command.Id);
    }

    /// <summary>Records the next key combination. Null = cancelled; "" = no shortcut.</summary>
    private static async Task<string?> CaptureShortcutAsync(Window owner, ShortcutCommand command, IReadOnlyDictionary<string, string> effective)
    {
        var w = Ui.Window("Shortcut — " + command.Name, 460, 240);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var current = effective[command.Id];
        var shown = new TextBlock { FontSize = 20, Text = current.Length > 0 ? current : "(none)" };
        var warn = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
        string? result = null;
        void Show(string g)
        {
            current = g;
            shown.Text = g.Length > 0 ? g : "(none)";
            var users = Catalog.Where(c => c.Id != command.Id && g.Length > 0 && effective.TryGetValue(c.Id, out var e) && e == g).Select(c => c.Name).ToList();
            warn.Text = users.Count > 0 ? $"Already used by {string.Join(", ", users)}; OK moves it to this action." : "";
        }

        w.AddHandler(InputElement.KeyDownEvent, (_, e) =>
        {
            if (e.Key is Key.LeftCtrl or Key.RightCtrl or Key.LeftShift or Key.RightShift or Key.LeftAlt or Key.RightAlt or Key.LWin or Key.RWin) return;
            if (e.Key == Key.Escape && e.KeyModifiers == KeyModifiers.None) return; // Cancel
            e.Handled = true;
            var mods = string.Concat(
                e.KeyModifiers.HasFlag(KeyModifiers.Control) ? "Ctrl+" : "",
                e.KeyModifiers.HasFlag(KeyModifiers.Shift) ? "Shift+" : "",
                e.KeyModifiers.HasFlag(KeyModifiers.Alt) ? "Alt+" : "",
                e.KeyModifiers.HasFlag(KeyModifiers.Meta) ? "Meta+" : "");
            if (Shortcuts.Normalize(mods + e.Key) is not { Length: > 0 } g)
            {
                warn.Text = $"{e.Key} cannot be used in a shortcut.";
                return;
            }

            Show(g);
            if (!g.Contains('+', StringComparison.Ordinal) && !(g.Length >= 2 && g[0] == 'F' && char.IsAsciiDigit(g[1])) && string.IsNullOrEmpty(warn.Text))
            {
                warn.Text = "Without Ctrl, Alt or Win this shortcut does nothing while a text box has the focus.";
            }
        }, RoutingStrategies.Tunnel);
        var buttons = Ui.Row(
            Ui.Button("OK", () =>
            {
                result = current;
                w.Close();
                return Task.CompletedTask;
            }, accent: true),
            Ui.Button("No Shortcut", () =>
            {
                Show("");
                return Task.CompletedTask;
            }),
            Ui.Button("Default", () =>
            {
                Show(Shortcuts.Normalize(command.DefaultGesture) ?? "");
                return Task.CompletedTask;
            }),
            Ui.Button("Cancel", () =>
            {
                w.Close();
                return Task.CompletedTask;
            }));
        foreach (var b in buttons.Children) b.Focusable = false; // keys go to the recorder, buttons are clicked
        w.Content = Ui.Layout(new TextBlock { Text = "Press the new key combination:", TextWrapping = TextWrapping.Wrap },
            new StackPanel { Spacing = 6, Children = { shown, warn } }, buttons);
        await w.ShowDialog(owner);
        return result;
    }

    // ---------------- Navigator index and reveal ----------------
    private static string? SettingText(ILogical c) => c switch
    {
        CheckBox cb => cb.Content as string,
        TextBlock tb when tb.Classes.Contains("label") || tb.Classes.Contains("section") => tb.Text,
        Button b => b.Content as string,
        _ => null,
    };

    /// <summary>Every tab and labelled setting, built once from an unshown options window.</summary>
    public static IReadOnlyList<NavigatorItem> Index()
    {
        if (_index is not null) return _index;
        var w = new OptionsWindow();
        var list = new List<NavigatorItem>();
        for (var i = 0; i < w.Tabs.Items.Count; i++)
        {
            if (w.Tabs.Items[i] is not TabItem { Header: string header } tab) continue;
            list.Add(new NavigatorItem(NavigatorKind.Setting, header + " tab", "Options", $"opt:{i}:"));
            foreach (var c in tab.GetLogicalDescendants())
            {
                var text = SettingText(c);
                if (string.IsNullOrWhiteSpace(text) || text.Length > 90 || text is "OK" or "Cancel") continue;
                list.Add(new NavigatorItem(NavigatorKind.Setting, Navigator.Clean(text.TrimEnd(':')), "Options › " + header, $"opt:{i}:{text}"));
            }
        }

        w.Close();
        _index = list.DistinctBy(x => x.Target).ToList();
        return _index;
    }

    /// <summary>Opens on a tab and scrolls to (and briefly highlights) the setting with this text.</summary>
    public void Reveal(int tab, string text)
    {
        Opened += (_, _) =>
        {
            if (tab < 0 || tab >= Tabs.Items.Count) return;
            Tabs.SelectedIndex = tab;
            if (text.Length == 0) return;
            if (Tabs.Items[tab] is not TabItem item) return;
            var target = item.GetLogicalDescendants().OfType<Control>().FirstOrDefault(c => SettingText(c) == text);
            if (target is not null) Highlight(target, focus: true);
        };
    }

    /// <summary>Scrolls to and briefly highlights a setting (after its tab has been selected).</summary>
    private static void Highlight(Control target, bool focus)
    {
        Dispatcher.UIThread.Post(() =>
        {
            target.BringIntoView();
            if (focus && target is CheckBox or Button) target.Focus(NavigationMethod.Tab);
            var brush = Styling.Theme.Brush(Styling.Theme.Keys.MatchSurface);
            AvaloniaProperty property = target is TextBlock ? TextBlock.BackgroundProperty : TemplatedControl.BackgroundProperty;
            target.SetValue(property, brush);
            DispatcherTimer.RunOnce(() => target.ClearValue(property), TimeSpan.FromSeconds(2.5));
        }, DispatcherPriority.Loaded);
    }

    private int _findIndex = -1;
    private string _findQuery = "";

    /// <summary>Find a setting (bottom left): every tab is searched; Enter moves to the next match (UI-22, D-072).</summary>
    private void FindNextSetting()
    {
        var q = FindSetting.Text?.Trim() ?? "";
        if (q.Length == 0)
        {
            FindResult.Text = "";
            return;
        }

        if (!string.Equals(q, _findQuery, StringComparison.OrdinalIgnoreCase)) _findIndex = -1;
        _findQuery = q;
        var matches = new List<(int Tab, Control Control)>();
        for (var i = 0; i < Tabs.Items.Count; i++)
        {
            if (Tabs.Items[i] is not TabItem tab) continue;
            foreach (var c in tab.GetLogicalDescendants().OfType<Control>())
            {
                if (SettingText(c) is { } t && t.Contains(q, StringComparison.OrdinalIgnoreCase)) matches.Add((i, c));
            }
        }

        if (matches.Count == 0)
        {
            FindResult.Text = "No matching setting.";
            return;
        }

        _findIndex = (_findIndex + 1) % matches.Count;
        var (index, control) = matches[_findIndex];
        Tabs.SelectedIndex = index;
        Highlight(control, focus: false);
        FindResult.Text = string.Create(System.Globalization.CultureInfo.CurrentCulture, $"{_findIndex + 1} of {matches.Count}");
    }
}
