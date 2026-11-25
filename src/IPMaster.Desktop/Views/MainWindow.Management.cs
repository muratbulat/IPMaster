using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;
using IPMaster.Core.Discovery;
using IPMaster.Core.Management;
using IPMaster.Core.Results;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Discovery;
using IPMaster.Infrastructure.Management;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Desktop.Views;

/// <summary>Phase 3: discovery tools, Wake-on-LAN, remote control, external applications, batch files, drives.</summary>
public partial class MainWindow
{
    private T Service<T>() where T : notnull => Vm!.Services.GetRequiredService<T>();

    // ---------------- discovery ----------------
    private void OnDhcp(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        new DhcpWindow(Service<DhcpDiscovery>(), Vm.Settings.DhcpCustomOptions,
            codes => Vm.UpdateSettingsAsync(s => s with { DhcpCustomOptions = codes })).Show(this);
    }

    private void OnDiscovery(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || (sender as MenuItem)?.Tag is not string tag) return;
        var protocol = Enum.Parse<DiscoveryProtocol>(tag);
        var t = TimeSpan.FromSeconds(4);
        Window w = protocol switch
        {
            DiscoveryProtocol.Ssdp => new DiscoveryWindow("UPnP Device Discovery", protocol, (_, _, ct) => Service<SsdpDiscovery>().DiscoverAsync(t, ct)),
            DiscoveryProtocol.Mdns => new DiscoveryWindow("mDNS Device Discovery", protocol, (_, _, ct) => Service<MdnsDiscovery>().DiscoverAsync(t, ct)),
            DiscoveryProtocol.Wsd => new DiscoveryWindow("WSD Device Discovery", protocol, (_, _, ct) => Service<WsdDiscovery>().DiscoverAsync(t, ct)),
            _ => new DiscoveryWindow("ONVIF Device Discovery", protocol, (u, p, ct) => Service<OnvifDiscovery>().DiscoverAsync(u, p, t, ct)),
        };
        w.Show(this);
    }

    private void OnDuplicateIp(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        new DuplicateIpWindow(Service<DuplicateIpScanner>(), mac => Vm.Oui.Capability.Available ? Vm.Oui.Lookup(mac) ?? "" : "").Show(this);
    }

    private async void OnExternalIp(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (await ManagementDialogs.ExternalIpAsync(this) is { } ip) Vm.SetRanges([new RangeEntryViewModel { Target = ip, Comment = "External address" }], append: true);
    }

    // ---------------- Wake-on-LAN ----------------
    private void OnWolManager(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        new WolManagerWindow(Vm.Settings.Wol, Service<WakeOnLanSender>(), wol => Vm.UpdateSettingsAsync(s => s with { Wol = wol })).Show(this);
    }

    private async Task WakeNodesAsync(IReadOnlyList<DeviceNode> nodes)
    {
        if (Vm is null) return;
        var targets = nodes.Where(n => n.Result.Mac.HasValue).Select(n => WakeOnLan.FromDevice(n.Result, Vm.Settings.Wol)).ToList();
        if (targets.Count == 0)
        {
            await ShowMessageAsync("Wake-On-LAN", "The selected devices have no MAC address. Enable 'Resolve MAC addresses' and rescan.");
            return;
        }

        var results = await Service<WakeOnLanSender>().WakeAllAsync(targets, Vm.Settings.Wol, CancellationToken.None);
        Vm.StatusText = string.Join("; ", results.Select(r => $"{r.Target}: {r.Message}"));
    }

    private async Task SaveToWolManagerAsync(IReadOnlyList<DeviceNode> nodes)
    {
        if (Vm is null) return;
        var added = nodes.Where(n => n.Result.Mac.HasValue).Select(n => WakeOnLan.FromDevice(n.Result, Vm.Settings.Wol)).ToList();
        await Vm.UpdateSettingsAsync(s => s with
        {
            Wol = s.Wol with { Targets = s.Wol.Targets.Where(t => added.All(a => a.Mac != t.Mac)).Concat(added).ToList() },
        });
        Vm.StatusText = added.Count == 0 ? "No MAC address to save." : $"Saved {added.Count} device(s) to the Wake-On-LAN manager.";
    }

    // ---------------- remote control ----------------
    private IReadOnlyList<string> TargetHosts() => SelectedNodes().Where(n => !n.Result.Key.IsV6).Select(n => n.Result.Key.ToString()).ToList();

    private async void OnRemoteShutdown(object? sender, RoutedEventArgs e)
    {
        var hosts = TargetHosts();
        if (hosts.Count == 0)
        {
            await ShowMessageAsync("Remote Shutdown", "Select one or more IPv4 devices first.");
            return;
        }

        await ManagementDialogs.RemoteShutdownAsync(this, hosts, Service<IRemoteControl>());
    }

    private async void OnSendMessage(object? sender, RoutedEventArgs e)
    {
        var hosts = TargetHosts();
        if (hosts.Count == 0)
        {
            await ShowMessageAsync("Send Message", "Select one or more IPv4 devices first.");
            return;
        }

        await ManagementDialogs.SendMessageAsync(this, hosts, Service<IRemoteControl>());
    }

    private async void OnBatchFile(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var devices = SelectedNodes().Select(n => n.Result).ToList();
        if (devices.Count == 0) devices = Vm.Results.Rows.Where(r => !r.IsShare).Select(r => r.Result).ToList();
        var columns = Vm.DisplayColumns;
        var format = Vm.Format;
        var template = await ManagementDialogs.BatchFileAsync(this, Vm.Settings.LastBatchTemplate, t => BatchFile.Generate(t, devices, columns, format));
        if (template is not null) await Vm.UpdateSettingsAsync(s => s with { LastBatchTemplate = template });
    }

    private void OnDisconnectDrive(object? sender, RoutedEventArgs e)
    {
        var handle = TryGetPlatformHandle()?.Handle ?? IntPtr.Zero;
        var r = Shell.DisconnectDialog(handle);
        if (!r.Success && Vm is not null) Vm.StatusText = r.Message;
    }

    // ---------------- connecting ----------------
    /// <summary>Runs the Browsing-tab host check; asks before connecting to a device that does not answer.</summary>
    private async Task<bool> ConfirmReachableAsync(DeviceNode node)
    {
        if (Vm is null) return false;
        Vm.StatusText = $"Checking {node.Result.Key}…";
        if (await Vm.IsReachableAsync(node.Result))
        {
            Vm.StatusText = "";
            return true;
        }

        return await ConfirmAsync("Device not responding", $"{node.Result.Key} did not answer the host check. Connect anyway?");
    }

    private async Task OpenDeviceAsync(DeviceNode node, string scheme)
    {
        if (Vm is null || !await ConfirmReachableAsync(node)) return;
        Vm.StatusText = Shell.OpenUrl(DeviceUrls.For(scheme, node.Result.Address)).Message;
    }

    private async Task LaunchApplicationAsync(ExternalApplication app, DeviceNode node)
    {
        if (Vm is null) return;
        var prompts = await ManagementDialogs.PromptParametersAsync(this, app.Name, CommandTemplate.Prompts(app.CommandLine));
        if (prompts is null || !await ConfirmReachableAsync(node)) return;
        try
        {
            var line = Vm.ExpandApplication(app, node.Result, prompts);
            Vm.StatusText = $"{app.Name}: {Shell.Launch(line).Message}";
        }
        catch (KeyNotFoundException ex)
        {
            await ShowMessageAsync(app.Name, ex.Message);
        }
    }

    private async Task MapDriveAsync(ResultRow share)
    {
        if (Vm is null || !await ConfirmReachableAsync(share.Node)) return;
        var letters = Shell.FreeDriveLetters();
        if (letters.Count == 0)
        {
            await ShowMessageAsync("Map Network Drive", "No free drive letter.");
            return;
        }

        var choice = await Dialogs.ChoiceAsync(this, "Map Network Drive", $"Map {SharePath(share)} to:", letters.Take(8).ToList());
        if (choice is not { } c) return;
        Vm.StatusText = Shell.MapDrive(letters[c], SharePath(share), persistent: false).Message;
    }

    private async Task ShowDiskSpaceAsync(ResultRow share)
    {
        var s = share.Share!;
        var text = s.Disk.HasValue
            ? $"{Formats.Bytes(s.Disk.Value!.FreeBytes)} free of {Formats.Bytes(s.Disk.Value!.TotalBytes)} ({100.0 * s.Disk.Value.FreeBytes / Math.Max(1, s.Disk.Value.TotalBytes):0.#} % free)"
            : "Disk space was not collected. Enable Options → Shares → Determine disk space and rescan.";
        await ShowMessageAsync("Disk Space — " + SharePath(share), text);
    }

    /// <summary>Context-menu entries for devices (manual: Open Device, applications, Wake-On-LAN, remote shutdown, message, batch).</summary>
    private void AddDeviceManagementItems(ContextMenu menu, IReadOnlyList<DeviceNode> nodes, Func<string, Action, MenuItem> item)
    {
        if (Vm is null) return;
        var first = nodes[0];
        var open = new MenuItem { Header = "Open Device" };
        foreach (var (label, scheme) in new[] { ("Web (HTTP)", "http"), ("Web (HTTPS)", "https"), ("FTP", "ftp"), ("SSH", "ssh") })
        {
            open.Items.Add(item(label, async () => await OpenDeviceAsync(first, scheme)));
        }

        menu.Items.Add(open);
        var apps = Vm.Settings.Applications.Applications;
        if (apps.Count > 0)
        {
            var root = new MenuItem { Header = "Applications" };
            foreach (var app in apps.OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                var parts = app.Name.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                var parent = root;
                foreach (var group in parts.SkipLast(1))
                {
                    var g = parent.Items.OfType<MenuItem>().FirstOrDefault(m => m.Header as string == group && m.Tag as string == "group");
                    if (g is null)
                    {
                        g = new MenuItem { Header = group, Tag = "group" };
                        parent.Items.Add(g);
                    }

                    parent = g;
                }

                var mi = item(parts.LastOrDefault() ?? app.Name, async () => await LaunchApplicationAsync(app, first));
                if (app.Hotkey.Length > 0) mi.InputGesture = TryGesture(app.Hotkey);
                parent.Items.Add(mi);
            }

            menu.Items.Add(root);
        }

        var wol = new MenuItem { Header = "Wake-On-LAN" };
        wol.Items.Add(item("Wake", async () => await WakeNodesAsync(nodes)));
        wol.Items.Add(item("Save MAC to WOL Manager", async () => await SaveToWolManagerAsync(nodes)));
        menu.Items.Add(wol);
        menu.Items.Add(item("Remote Shutdown…", () => OnRemoteShutdown(this, new RoutedEventArgs())));
        menu.Items.Add(item("Send Message…", () => OnSendMessage(this, new RoutedEventArgs())));
        menu.Items.Add(item("Create Batch File…", () => OnBatchFile(this, new RoutedEventArgs())));
    }

    private void AddShareManagementItems(ContextMenu menu, ResultRow share, Func<string, Action, MenuItem> item)
    {
        if (OperatingSystem.IsWindows()) menu.Items.Add(item("Map Network Drive…", async () => await MapDriveAsync(share)));
        menu.Items.Add(item("Disk Space", async () => await ShowDiskSpaceAsync(share)));
    }

    private static KeyGesture? TryGesture(string text)
    {
        try
        {
            return KeyGesture.Parse(text);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>Application hotkeys (manual: launch with a single keystroke for the selected device).</summary>
    private bool TryLaunchHotkey(KeyEventArgs e)
    {
        if (Vm is null || SelectedNodes().FirstOrDefault() is not { } node) return false;
        foreach (var app in Vm.Settings.Applications.Applications.Where(a => a.Hotkey.Length > 0))
        {
            if (TryGesture(app.Hotkey) is { } g && g.Matches(e))
            {
                _ = LaunchApplicationAsync(app, node);
                return true;
            }
        }

        return false;
    }
}
