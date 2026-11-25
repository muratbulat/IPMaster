using Avalonia.Controls;
using Avalonia.Controls.Notifications;
using Avalonia.Interactivity;
using IPMaster.Core.Monitoring;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>Phase 5: monitoring, background scanning, history (menus and dialogs).</summary>
public partial class MainWindow
{
    private WindowNotificationManager? _notifications;
    private ScanLogWindow? _scanLog;

    /// <summary>Background-event notifications: from the tray icon where the platform supports it (Windows), else in the window.</summary>
    private void ShowNotification(string title, string text)
    {
        if (_tray is { SupportsNotifications: true, IsVisible: true })
        {
            _tray.Notify(title, text);
            return;
        }

        _notifications ??= new WindowNotificationManager(this) { Position = NotificationPosition.BottomRight, MaxItems = 4 };
        _notifications.Show(new Notification(title, text, NotificationType.Information, TimeSpan.FromSeconds(8)));
    }

    private void HookContinuous()
    {
        if (Vm is null) return;
        Vm.Notify += (_, n) => ShowNotification(n.Title, n.Text);
    }

    private void AddContinuousItems(ContextMenu menu, IReadOnlyList<DeviceNode> nodes, Func<string, Action, MenuItem> item)
    {
        if (Vm is null) return;
        var devices = nodes.Select(n => n.Result).ToList();
        var mon = new MenuItem { Header = "Monitoring" };
        mon.Items.Add(item("Begin Monitoring", () => Vm.StartMonitoring(devices)));
        mon.Items.Add(item("Stop Monitoring", () => Vm.StopMonitoring(devices)));
        mon.Items.Add(item("Charts and Route…", () =>
        {
            if (Vm.Monitor.Series(devices[0].Key) is null) Vm.StartMonitoring([devices[0]]);
            new PropertiesWindow(Vm, devices[0]).Show(this);
        }));
        menu.Items.Add(mon);
        if (Vm.Settings.History.Enabled)
        {
            menu.Items.Add(item("History…", async () => await OpenHistoryAsync(devices[0])));
        }
    }

    private async Task OpenHistoryAsync(Core.Scanning.DeviceResult d)
    {
        if (Vm is null) return;
        if (!d.Mac.HasValue)
        {
            await ShowMessageAsync("History", "This device has no MAC address, so it is not tracked in history (devices behind routers, for example).");
            return;
        }

        if (Vm.Ops.HistoryView.Network is null) await Vm.Ops.RefreshHistoryAsync();
        if (Vm.Ops.HistoryView.Network is not { } net)
        {
            await ShowMessageAsync("History", "No network has been recorded yet.");
            return;
        }

        new DeviceHistoryWindow(Vm.Ops.History, net, HistoryText.MacKey(d.Mac.Value!), d.HostName.Value?.Name ?? d.Key.ToString(), null).Show(this);
    }

    private async void OnBackgroundSwitch(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await Vm.SetBackgroundAsync(BackgroundSwitch.IsChecked == true);
        // SetCurrentValue keeps the XAML OneWay binding; assigning IsChecked would replace it, and later state changes
        // (a loop ending by itself) would no longer reach the switch.
        BackgroundSwitch.SetCurrentValue(Avalonia.Controls.Primitives.ToggleButton.IsCheckedProperty, Vm.BackgroundRunning);
    }

    private async void OnToggleBackground(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await Vm.SetBackgroundAsync(!Vm.BackgroundRunning);
    }

    private void OnScanLog(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (_scanLog is { IsVisible: true })
        {
            _scanLog.Activate();
            return;
        }

        _scanLog = new ScanLogWindow(Vm.Ops.Log);
        _scanLog.Show(this);
    }

    private async void OnBackgroundEvents(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (await ContinuousDialogs.EventsAsync(this, Vm, Vm.Settings.Background) is { } b) await Vm.UpdateSettingsAsync(s => s with { Background = b });
    }

    private async void OnFileOutput(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (await ContinuousDialogs.FileOutputAsync(this, Vm.Settings.Background) is { } r)
        {
            await Vm.UpdateSettingsAsync(s => s with { Background = s.Background with { SaveAfterRound = r.Save, OutputFile = r.File } });
        }
    }

    private void OnInventory(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        new InventoryWindow(Vm).Show(this);
    }
}
