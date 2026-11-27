using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Threading;
using IPMaster.Core.Configuration;
using IPMaster.Core.Navigation;
using IPMaster.Core.Queries;
using IPMaster.Desktop.Platform;

namespace IPMaster.Desktop.Views;

/// <summary>Phase 6: command registry, customisable shortcuts, Navigator, toolbar settings, tray, new windows.</summary>
public partial class MainWindow
{
    /// <summary>Toolbar button name → command id whose shortcut is shown in the tooltip.</summary>
    private static readonly Dictionary<string, string> ToolCommands = new(StringComparer.Ordinal)
    {
        ["Load results"] = "File/Load Results",
        ["Save results"] = "File/Save Results",
        ["Find"] = "View/Find",
        ["Advanced filter"] = "View/Advanced Filter",
        ["Scan options"] = "Options/Scan Options",
    };

    private static readonly HashSet<string> DynamicMenus = new(StringComparer.Ordinal) { "RecentMenu", "BookmarksMenu", "QuickFilterMenu" };

    private readonly Dictionary<string, string> _defaultGestures = new(StringComparer.Ordinal);
    private readonly List<(Control Control, string Name)> _tools = [];
    private List<AppCommand> _commands = [];
    private Dictionary<(Key, KeyModifiers), AppCommand> _keyMap = [];
    private ITray? _tray;

    private sealed record AppCommand(ShortcutCommand Info, MenuItem? Item, Action Invoke);

    private void InitPhase6()
    {
        foreach (var c in ToolbarPanel.Children.Where(c => c is Button))
        {
            var tip = ToolTip.GetTip(c) as string ?? "";
            var i = tip.IndexOf(" (", StringComparison.Ordinal);
            _tools.Add((c, i > 0 ? tip[..i] : tip));
        }

        BuildCommands();
        ApplyShortcuts();
        ApplyToolbar();
        InitTray();
        if (Vm is not null)
        {
            Vm.MenusChanged += (_, _) =>
            {
                ApplyShortcuts();
                ApplyToolbar();
                UpdateTray();
            };
            ((INotifyPropertyChanged)Vm).PropertyChanged += (_, e) =>
            {
                if (e.PropertyName is "BackgroundRunning" or "StartButtonText") UpdateTray();
            };
        }

        PropertyChanged += (_, e) =>
        {
            if (e.Property == WindowStateProperty && WindowState == WindowState.Minimized && Vm?.Settings.View.MinimizeToTray == true && _tray is not null)
            {
                Dispatcher.UIThread.Post(() =>
                {
                    Hide();
                    UpdateTray();
                });
            }
        };
        Closed += (_, _) => _tray?.Dispose();
    }

    // ---------------- commands and shortcuts (UI-18) ----------------
    private static string HeaderText(MenuItem m) => m.Header as string ?? m.Header?.ToString() ?? "";

    /// <summary>Builds the command registry from the menus (internal: the menu tests read it through <see cref="CommandCatalog"/>).</summary>
    internal void BuildCommands()
    {
        _commands = [];
        foreach (var top in MainMenu.Items.OfType<MenuItem>())
        {
            var category = Navigator.Clean(HeaderText(top));
            Walk(top, category);
        }

        _commands.Add(new AppCommand(new ShortcutCommand("Actions/Assign Friendly Name", "Assign Friendly Name", "Actions", "F2"), null, () =>
        {
            if (SelectedNodes().FirstOrDefault() is { } n) _ = AssignFriendlyNameAsync(n);
        }));
        foreach (var t in ToolShortcuts)
        {
            _commands.Add(new AppCommand(new ShortcutCommand(t.Id, t.Name, t.Category, ""), null, () =>
            {
                if (Vm is { } vm) ShowTool(t.Open(this, vm));
            }));
        }
    }

    internal IReadOnlyList<ShortcutCommand> CommandCatalog => _commands.Select(c => c.Info).ToList();

    internal IReadOnlyList<MenuItem> CommandMenuItems => _commands.Where(c => c.Item is not null).Select(c => c.Item!).ToList();

    private void Walk(MenuItem parent, string path)
    {
        foreach (var item in parent.Items.OfType<MenuItem>())
        {
            if (item.Name is { } n && DynamicMenus.Contains(n)) continue;
            var header = Navigator.Clean(HeaderText(item));
            if (header.Length == 0) continue;
            if (item.Items.OfType<MenuItem>().Any())
            {
                Walk(item, path + " › " + header);
                continue;
            }

            var id = item.Name is { Length: > 0 } name ? name : _commandIds.TryGetValue(item, out var stable) ? stable : path.Replace(" › ", "/", StringComparison.Ordinal) + "/" + header;
            if (!_defaultGestures.ContainsKey(id)) _defaultGestures[id] = item.InputGesture?.ToString() ?? "";
            var mi = item;
            _commands.Add(new AppCommand(new ShortcutCommand(id, header, path, _defaultGestures[id]), mi, () => InvokeMenuItem(mi)));
        }
    }

    private static void InvokeMenuItem(MenuItem mi)
    {
        if (mi.Command is { } c)
        {
            if (c.CanExecute(mi.CommandParameter)) c.Execute(mi.CommandParameter);
            return;
        }

        mi.RaiseEvent(new RoutedEventArgs(MenuItem.ClickEvent, mi));
    }

    private static KeyGesture? ParseGesture(string text)
    {
        if (text.Length == 0) return null;
        try
        {
            return KeyGesture.Parse(text);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidOperationException)
        {
            return null;
        }
    }

    private void ApplyShortcuts()
    {
        if (Vm is null) return;
        var effective = Shortcuts.Effective(_commands.Select(c => c.Info), Vm.Settings.View.Shortcuts);
        _keyMap = [];
        foreach (var c in _commands)
        {
            var g = ParseGesture(effective[c.Info.Id]);
            if (c.Item is not null) c.Item.InputGesture = g;
            if (g is not null) _keyMap.TryAdd((g.Key, g.KeyModifiers), c);
        }

        OptionsWindow.Catalog = _commands.Select(c => c.Info).ToList();
        foreach (var (control, name) in _tools)
        {
            var tip = name;
            if (ToolCommands.TryGetValue(name, out var id) && effective.TryGetValue(id, out var g) && g.Length > 0) tip += $" ({g})";
            ToolTip.SetTip(control, tip);
            AutomationProperties.SetName(control, name);
        }
    }

    private bool TryShortcut(KeyEventArgs e)
    {
        if (e.Key is Key.LeftCtrl or Key.RightCtrl or Key.LeftShift or Key.RightShift or Key.LeftAlt or Key.RightAlt or Key.LWin or Key.RWin) return false;
        var commandKey = (e.KeyModifiers & (KeyModifiers.Control | KeyModifiers.Alt | KeyModifiers.Meta)) != 0 || e.Key is >= Key.F1 and <= Key.F24;
        // plain keys keep their meaning while typing
        if (!commandKey && FocusManager?.GetFocusedElement() is TextBox) return false;
        if (!_keyMap.TryGetValue((e.Key, e.KeyModifiers), out var cmd)) return false;
        cmd.Invoke();
        return true;
    }

    // ---------------- Navigator (UI-17) ----------------
    private async void OnNavigator(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var items = _commands.Where(c => c.Info.Id != "Help/Navigator")
            .Select(c => new NavigatorItem(NavigatorKind.Command, c.Info.Name, c.Info.Category, "cmd:" + c.Info.Id, c.Item?.InputGesture?.ToString() ?? ""))
            .ToList();
        items.AddRange(OptionsWindow.Index());
        foreach (var q in Vm.Settings.Queries.Items)
        {
            items.Add(new NavigatorItem(NavigatorKind.Query, q.Name, "Remote Query Manager › " + QueryColumns.DisplayName(q.Kind), $"query:{q.Kind}:{q.Id}"));
        }

        foreach (var a in Vm.Settings.Applications.Applications)
        {
            items.Add(new NavigatorItem(NavigatorKind.Application, a.Name.Replace("|", " › ", StringComparison.Ordinal), "Applications", "app:" + a.Name, a.Hotkey));
        }

        var chosen = await new NavigatorWindow(items).ShowDialog<NavigatorItem?>(this);
        if (chosen is not null) await RunNavigatorItemAsync(chosen);
    }

    private async Task RunNavigatorItemAsync(NavigatorItem it)
    {
        if (Vm is null) return;
        var parts = it.Target.Split(':', 3);
        switch (parts[0])
        {
            case "cmd":
                _commands.FirstOrDefault(c => c.Info.Id == it.Target[4..])?.Invoke();
                break;
            case "opt":
                await ShowOptionsAsync(w => w.Reveal(int.Parse(parts[1], CultureInfo.InvariantCulture), parts[2]));
                break;
            case "query":
                new QueryManagerWindow(Vm, Enum.Parse<QueryKind>(parts[1]), Guid.TryParse(parts[2], out var queryId) ? queryId : null).Show(this);
                break;
            case "app":
                var app = Vm.Settings.Applications.Applications.FirstOrDefault(a => a.Name == it.Target[4..]);
                if (app is not null && SelectedNodes().FirstOrDefault() is { } node) await LaunchApplicationAsync(app, node);
                else await ShowMessageAsync("Applications", "Select a device first: the application is launched for the selected device.");
                break;
        }
    }

    // ---------------- toolbar (UI-23) ----------------
    private void ApplyToolbar()
    {
        if (Vm is null) return;
        var hidden = Vm.Settings.View.HiddenToolbarButtons.ToHashSet(StringComparer.Ordinal);
        foreach (var (control, name) in _tools) control.IsVisible = !hidden.Contains(name);
        // a separator shows only between two groups that both have a visible button
        var seenVisible = false;
        Separator? pending = null;
        foreach (var c in ToolbarPanel.Children)
        {
            if (c is Separator s)
            {
                s.IsVisible = false;
                if (seenVisible) pending = s;
                continue;
            }

            if (!c.IsVisible) continue;
            if (pending is not null)
            {
                pending.IsVisible = true;
                pending = null;
            }

            seenVisible = true;
        }

        ToolbarPanel.Parent!.SetValue(IsVisibleProperty, _tools.Any(t => t.Control.IsVisible));
    }

    private async void OnToolbarSettings(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var hidden = Vm.Settings.View.HiddenToolbarButtons.ToHashSet(StringComparer.Ordinal);
        var boxes = _tools.Select(t => new CheckBox { Content = t.Name, IsChecked = !hidden.Contains(t.Name) }).ToList();
        var w = Ui.Window("Toolbar Settings", 460, 560);
        var list = new StackPanel { Spacing = 2 };
        foreach (var b in boxes) list.Children.Add(b);
        var ok = false;
        var buttons = Ui.Row(
            Ui.Button("Mark All", () =>
            {
                foreach (var b in boxes) b.IsChecked = true;
                return Task.CompletedTask;
            }),
            Ui.Button("Mark None", () =>
            {
                foreach (var b in boxes) b.IsChecked = false;
                return Task.CompletedTask;
            }),
            Ui.Button("OK", () =>
            {
                ok = true;
                w.Close();
                return Task.CompletedTask;
            }, accent: true),
            Ui.Button("Cancel", () =>
            {
                w.Close();
                return Task.CompletedTask;
            }));
        w.Content = Ui.Layout(new TextBlock { Text = "Buttons shown on the toolbar:" }, new ScrollViewer { Content = list }, buttons);
        await w.ShowDialog(this);
        if (!ok) return;
        var newHidden = boxes.Where(b => b.IsChecked != true).Select(b => (string)b.Content!).ToList();
        await Vm.UpdateSettingsAsync(s => s with { View = s.View with { HiddenToolbarButtons = newHidden } });
    }

    // ---------------- tray (UI-19) ----------------
    private void InitTray()
    {
        try
        {
            _tray = ITray.Create("IPMaster", TrayMenu);
            _tray.Activated += (_, _) => RestoreFromTray();
        }
        catch (Exception ex) when (ex is InvalidOperationException or DllNotFoundException or EntryPointNotFoundException or PlatformNotSupportedException)
        {
            _tray = null; // no notification area: minimise normally, notify in the window
        }

        UpdateTray();
    }

    private IReadOnlyList<TrayMenuItem> TrayMenu()
    {
        if (Vm is not { } vm) return [];
        return
        [
            new TrayMenuItem("Show IPMaster", RestoreFromTray),
            TrayMenuItem.Separator,
            new TrayMenuItem(vm.StartButtonText, () =>
            {
                if (vm.StartStopCommand.CanExecute(null)) vm.StartStopCommand.Execute(null);
            }),
            new TrayMenuItem("Background Scanning", () => _ = vm.SetBackgroundAsync(!vm.BackgroundRunning), vm.BackgroundRunning),
            TrayMenuItem.Separator,
            new TrayMenuItem("Exit", Close),
        ];
    }

    /// <summary>The icon shows while minimising to the tray is enabled, background scanning runs, or the window is hidden.</summary>
    private void UpdateTray()
    {
        if (_tray is null || Vm is null) return;
        _tray.IsVisible = Vm.Settings.View.MinimizeToTray || Vm.BackgroundRunning || !IsVisible;
        _tray.Refresh();
    }

    private void RestoreFromTray()
    {
        Show();
        if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
        Activate();
        UpdateTray();
    }

    // ---------------- new window (UI-21) ----------------
    private async void OnNewWindow(object? sender, RoutedEventArgs e) => await OpenNewWindowAsync([]);

    /// <summary>Starts another IPMaster process on the same configuration (D-064), optionally with its own ranges.</summary>
    private async Task OpenNewWindowAsync(IReadOnlyList<string> ranges)
    {
        if (Environment.ProcessPath is not { } exe) return;
        // CreateNoWindow: the executable is console-subsystem (D-103); no console window for a second GUI window
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true };
        if (string.Equals(Path.GetFileNameWithoutExtension(exe), "dotnet", StringComparison.OrdinalIgnoreCase)) psi.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "IPMaster.dll")); // framework-dependent run via the dotnet host
        psi.ArgumentList.Add("--new-window");
        foreach (var r in ranges)
        {
            psi.ArgumentList.Add("--range");
            psi.ArgumentList.Add(r);
        }

        try
        {
            Process.Start(psi)?.Dispose();
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            await ShowMessageAsync("New Window", "New window not started: " + ex.Message);
        }
    }
}
