using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Configuration;
using IPMaster.Core.Discovery;
using IPMaster.Core.Network;
using IPMaster.Core.Results;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Discovery;
using Microsoft.Extensions.DependencyInjection;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Device IP Discovery &amp; DHCP Server (D-090): find the address of a device on a direct cable (passive listening,
/// ARP probes) or give it one (isolated DHCP server). Nothing runs until the user starts it; the DHCP server needs an explicit
/// confirmation and refuses to start when another DHCP server answers. Stop, closing the window and exiting IPMaster stop
/// everything and remove the temporary addresses IPMaster added.
/// </summary>
internal sealed class DeviceDiscoveryWindow : Window
{
    private const int MaxEvents = 5000;

    private sealed record Row(CapturedDevice D, string Vendor)
    {
        public string Ip => D.Best?.Address.ToString() ?? "";

        public string Mac => Formats.Mac(D.Mac);

        public string VendorName => Vendor;

        public string Host => D.HostName ?? D.VendorClass ?? "";

        public string Protocols => string.Join(", ", D.Sources.Order());

        public string Assignment => D.Best is { } b ? Describe(b.Assignment) : "MAC only";

        public string Addresses => string.Join(", ", D.Addresses.Select(a => $"{a.Address} ({Describe(a.Assignment)})"));

        public string FirstSeen => D.FirstSeen.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture);

        public string LastSeen => D.LastSeen.ToLocalTime().ToString("HH:mm:ss", CultureInfo.CurrentCulture);

        public string Evidence => D.Best?.Evidence ?? "";
    }

    private static string Describe(IpAssignment a) => a switch
    {
        IpAssignment.Observed => "Observed in use",
        IpAssignment.DhcpRequested => "Requested via DHCP",
        IpAssignment.DhcpAssigned => "Assigned by IPMaster",
        IpAssignment.Probing => "Probing, not in use yet",
        _ => a.ToString(),
    };

    private readonly MainWindowViewModel _vm;
    private readonly INetworkAdapterProvider _adapters;
    private readonly PassiveCapture _capture;
    private readonly ArpProbeSweep _sweep;
    private readonly ITemporaryAddressManager _temporary;
    private readonly DhcpDiscovery _dhcpCheck;
    private readonly DiscoveryBook _book;
    private readonly ObservableCollection<Row> _rows = [];
    private readonly ConcurrentQueue<string> _incoming = new();
    private readonly List<string> _events = [];
    private readonly List<TemporaryAddress> _added = [];
    private readonly Action _removeHook;
    private IReadOnlyList<NetworkAdapterInfo> _adapterList = [];
    private int _version;
    private int _shownVersion = -1;
    private DhcpServerHost? _server;
    private DhcpServerHost? _listener;
    private Func<Task>? _stopCapture;
    private bool _closingDone;

    public DeviceDiscoveryWindow(MainWindowViewModel vm)
    {
        ArgumentNullException.ThrowIfNull(vm);
        _vm = vm;
        _adapters = vm.Services.GetRequiredService<INetworkAdapterProvider>();
        _capture = vm.Services.GetRequiredService<PassiveCapture>();
        _sweep = vm.Services.GetRequiredService<ArpProbeSweep>();
        _temporary = vm.Services.GetRequiredService<ITemporaryAddressManager>();
        _dhcpCheck = vm.Services.GetRequiredService<DhcpDiscovery>();
        _adapterList = _adapters.GetAdapters();
        _book = new DiscoveryBook(_adapterList.Select(a => Formats.ParseMac(a.MacAddress)).OfType<PhysicalAddress>());

        Title = "Device IP Discovery & DHCP Server";
        Width = 1200;
        Height = 860;
        MinWidth = 700;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };

        // ---------------- interface ----------------
        var adapterBox = ToolKit.Combo("Network adapter", _adapterList.Select(a => $"{a.Name} ({string.Join(", ", a.IPv4.Select(x => x.ToString()))})"), 0, 460);
        var adapterInfo = new TextBlock { Classes = { "description" } };
        NetworkAdapterInfo? Adapter() => adapterBox.SelectedIndex >= 0 && adapterBox.SelectedIndex < _adapterList.Count ? _adapterList[adapterBox.SelectedIndex] : null;
        CaptureInterface? CaptureFor(NetworkAdapterInfo a) => _capture.Capability.Available ? _capture.Interfaces().FirstOrDefault(i => i.Adapter.Id == a.Id) : null;
        void ShowAdapter()
        {
            if (Adapter() is not { } a)
            {
                adapterInfo.Text = "No active network adapter.";
                return;
            }

            var link = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == a.Id)?.OperationalStatus.ToString() ?? "unknown";
            var capture = !_capture.Capability.Available ? _capture.Capability.Description
                : CaptureFor(a) is null ? "Npcap cannot use this adapter (it needs an IPv4 address with a /16 to /30 prefix)." : "Packet capture available.";
            adapterInfo.Text = $"MAC {a.MacAddress ?? "—"} · link {link} · {(a.SpeedBitsPerSecond > 0 ? $"{a.SpeedBitsPerSecond / 1_000_000:N0} Mbit/s" : "speed unknown")} · "
                               + $"addresses: {string.Join(", ", a.Addresses.Select(x => x.ToString()))}\n{capture}";
        }

        adapterBox.SelectionChanged += (_, _) => ShowAdapter();
        var interfaceForm = new Form();
        interfaceForm.Add("Adapter", adapterBox);
        interfaceForm.Full(adapterInfo);

        // ---------------- passive ----------------
        var listenDhcp = new CheckBox { Content = "DHCP requests (UDP 67; no Npcap needed)", IsChecked = true };
        var listenCapture = new CheckBox { Content = "ARP, IPv4 and IPv6 traffic (Npcap)", IsChecked = _capture.Capability.Available, IsEnabled = _capture.Capability.Available };
        Button? passiveStart = null;
        Button? passiveStop = null;
        passiveStop = Ui.Button("Stop Listening", async () =>
        {
            await StopPassiveAsync();
            status.Text = "Listening stopped; the port and the capture are released.";
            passiveStart!.IsEnabled = true;
            passiveStop!.IsEnabled = false;
        });
        passiveStart = Ui.Button("Start Listening", () =>
        {
            error.Text = "";
            if (Adapter() is not { } a) return Task.CompletedTask;
            var started = new List<string>();
            if (listenDhcp.IsChecked == true)
            {
                if (_server is not null) started.Add("DHCP requests via the running server");
                else if (a.IPv4.FirstOrDefault() is not { } bind) error.Text = "DHCP listening needs an IPv4 address on the adapter (wait for the automatic 169.254.x.x address, or add one).";
                else
                {
                    try
                    {
                        _listener = DhcpServerHost.Listen(bind.Address, OnClientMessage);
                        started.Add($"DHCP requests on {bind.Address}:67");
                    }
                    catch (InvalidOperationException ex)
                    {
                        error.Text = ex.Message;
                    }
                }
            }

            if (listenCapture.IsChecked == true)
            {
                if (CaptureFor(a) is not { } iface) error.Text += (error.Text.Length > 0 ? " " : "") + "Packet capture is not available on this adapter.";
                else
                {
                    var cts = new CancellationTokenSource();
                    var task = _capture.RunAsync(iface, Observe, cts.Token).ContinueWith(t =>
                    {
                        if (t.IsFaulted) Log("Capture stopped: " + t.Exception!.GetBaseException().Message);
                    }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                    _stopCapture = async () =>
                    {
                        await cts.CancelAsync();
                        await task;
                        cts.Dispose();
                    };
                    started.Add("ARP/IPv4/IPv6 capture");
                }
            }

            if (started.Count == 0) return Task.CompletedTask;
            Log("Listening started: " + string.Join(", ", started) + ". Nothing is sent.");
            status.Text = "Listening (nothing is sent). A device with a static address that sends nothing is not found this way: use Active Discovery.";
            passiveStart!.IsEnabled = false;
            passiveStop!.IsEnabled = true;
            return Task.CompletedTask;
        }, accent: true);
        passiveStop.IsEnabled = false;
        var passiveForm = new Form();
        passiveForm.Full(Ui.Row(listenDhcp, listenCapture));
        passiveForm.Full(Visible("Listens only: nothing is sent. Finds devices that talk: DHCP clients (MAC, host name, the address they ask for), ARP and "
                                 + "IP traffic. An IP seen this way is reported as observed, requested or probing; IPMaster never claims it is static."));
        passiveForm.Full(Ui.Row(passiveStart, passiveStop));

        // ---------------- active ----------------
        var candidates = ToolKit.Text("Candidate addresses", "e.g. 192.168.0.120, 192.168.70.0/24, 10.0.0.1-10.0.0.50");
        var presets = ToolKit.Combo("Factory defaults", ["Insert a factory default…", .. ManagementDefaults.All.Select(d => $"{d.Product}: {d.Candidates}")], 0, 420);
        presets.SelectionChanged += (_, _) =>
        {
            if (presets.SelectedIndex <= 0) return;
            var value = ManagementDefaults.All[presets.SelectedIndex - 1].Candidates;
            if (char.IsDigit(value[0])) candidates.Text = string.IsNullOrWhiteSpace(candidates.Text) ? value : candidates.Text.TrimEnd() + ", " + value;
            presets.SelectedIndex = 0;
        };
        var listenSeconds = ToolKit.Number(2, 1, 30, "Wait for replies (s)", 90);
        var runner = new ToolRunner(status);
        var probe = Ui.Button("Send ARP Probes", async () =>
        {
            error.Text = "";
            if (Adapter() is not { } a) return;
            var list = CandidateList.Parse(candidates.Text ?? "", out var why);
            if (list is null)
            {
                error.Text = why;
                return;
            }

            if (CaptureFor(a) is not { } iface)
            {
                error.Text = _sweep.Capability.Available ? "Npcap cannot use this adapter (it needs an IPv4 address with a /16 to /30 prefix)." : _sweep.Capability.Description;
                return;
            }

            var wait = TimeSpan.FromSeconds((double)(listenSeconds.Value ?? 2));
            Log($"Sending {list.Count:N0} ARP probe(s) on {a.Name} (sender 0.0.0.0).");
            await runner.RunAsync("Probing", async ct =>
            {
                var found = await _sweep.RunAsync(iface, list, wait, null, Observe, ct);
                return $"{list.Count:N0} probe(s) sent, {found.Count} device(s) answered.";
            });
        }, accent: true);
        var cancelProbe = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        probe.IsEnabled = _sweep.Capability.Available;
        var activeForm = new Form();
        activeForm.Add("Candidates", candidates);
        activeForm.Add("Defaults", presets);
        activeForm.Add("Wait", listenSeconds);
        activeForm.Full(Visible("Sends one ARP probe (RFC 5227, sender 0.0.0.0) to each candidate, at most 4,096; never the whole address space. A device answers "
                                + "for its own address even when the laptop has no address in that subnet. Firmware that ignores probes is not found, and ARP "
                                + "does not cross routers. " + (_sweep.Capability.Available ? "" : _sweep.Capability.Description)));
        activeForm.Full(Ui.Row(probe, cancelProbe));

        // ---------------- DHCP server ----------------
        var server = ToolKit.Text("Server address", text: "192.168.88.1", width: 160);
        var mask = ToolKit.Text("Subnet mask", text: "255.255.255.0", width: 160);
        var poolStart = ToolKit.Text("Pool start", text: "192.168.88.100", width: 160);
        var poolEnd = ToolKit.Text("Pool end", text: "192.168.88.110", width: 160);
        var lease = ToolKit.Number(10, 1, 1440, "Lease time (minutes)", 100);
        var gateway = ToolKit.Text("Default gateway", "not advertised", 160);
        var dns = ToolKit.Text("DNS servers", "optional, comma-separated", 220);
        var reservations = ToolKit.Text("Reservations", "optional: 00-11-22-33-44-55=192.168.88.120, …");
        var addServerAddress = new CheckBox { Content = "Add the server address to the adapter while the server runs (administrator rights)", IsChecked = true };
        var leases = new TextBlock { TextWrapping = TextWrapping.Wrap };
        Button? serverStart = null;
        Button? serverStop = null;
        serverStop = Ui.Button("Stop Server", async () =>
        {
            var problems = await StopServerAsync();
            error.Text = problems ?? "";
            status.Text = "DHCP server stopped; port 67 is released.";
            serverStart!.IsEnabled = true;
            serverStop!.IsEnabled = false;
        });
        serverStart = Ui.Button("Start DHCP Server…", async () =>
        {
            error.Text = "";
            if (Adapter() is not { } a) return;
            var config = ParseConfig(server.Text, mask.Text, poolStart.Text, poolEnd.Text, (int)(lease.Value ?? 10), gateway.Text, dns.Text, reservations.Text, out var why);
            if (config is null || config.Validate() is { Count: > 0 } invalid)
            {
                error.Text = config is null ? why : string.Join(" ", config!.Validate());
                return;
            }

            var prefix = BitCount(config.SubnetMask);
            var ok = await Dialogs.MessageAsync(this, "Start DHCP server",
                $"Start a DHCP server on '{a.Name}'?\n\nServer {config.ServerAddress}/{prefix}, pool {config.PoolStart} – {config.PoolEnd}, lease {config.LeaseTime.TotalMinutes:0} min, "
                + $"gateway {(config.Router?.ToString() ?? "not advertised")}.\n\nUse it only on an isolated connection you are authorised to configure: a cable to one device, "
                + "or a lab switch. On a production network a second DHCP server hands out wrong addresses to other computers. IPMaster first checks whether a DHCP "
                + "server already answers on this adapter and does not start if one does; that check is a precaution, not a guarantee.\n\n"
                + "Is this connection isolated, and are you authorised to run a DHCP server on it?", confirm: true);
            if (!ok) return;
            serverStart!.IsEnabled = false;
            status.Text = "Preparing the DHCP server…";
            var start = await StartServerAsync(a, config, prefix, addServerAddress.IsChecked == true);
            if (start is not null)
            {
                error.Text = start;
                status.Text = "The DHCP server was not started.";
                serverStart.IsEnabled = true;
                return;
            }

            status.Text = $"DHCP server running on {config.ServerAddress}:67 ({a.Name}). Stop it before connecting the laptop to another network.";
            serverStop!.IsEnabled = true;
        }, accent: true);
        serverStop.IsEnabled = false;
        var dhcpForm = new Form();
        dhcpForm.Add("Server / Mask", Ui.Row(server, mask));
        dhcpForm.Add("Pool", Ui.Row(poolStart, poolEnd));
        dhcpForm.Add("Lease / Gateway", Ui.Row(lease, gateway));
        dhcpForm.Add("DNS", dns);
        dhcpForm.Add("Reservations", reservations);
        dhcpForm.Full(addServerAddress);
        dhcpForm.Full(Visible("Never starts on its own. Answers only on the selected adapter, keeps leases in memory only, and gives devices that use a static "
                              + "address nothing (they do not ask). Requires a confirmation that the connection is isolated and authorised."));
        dhcpForm.Full(Ui.Row(serverStart, serverStop));
        dhcpForm.Full(leases);

        var tabs = new TabControl
        {
            Items =
            {
                new TabItem { Header = "Passive Discovery", Content = passiveForm.Grid },
                new TabItem { Header = "Active Discovery", Content = activeForm.Grid },
                new TabItem { Header = "Isolated DHCP Server", Content = dhcpForm.Grid },
            },
        };

        // ---------------- devices ----------------
        var grid = Ui.Grid(("IP Address", nameof(Row.Ip), 130), ("MAC Address", nameof(Row.Mac), 140), ("Vendor", nameof(Row.VendorName), 150),
            ("Host / Vendor class", nameof(Row.Host), 150), ("Protocols", nameof(Row.Protocols), 120), ("IP Assignment", nameof(Row.Assignment), 160),
            ("First Seen", nameof(Row.FirstSeen), 95), ("Last Seen", nameof(Row.LastSeen), 95), ("Evidence", nameof(Row.Evidence), 0));
        grid.ItemsSource = _rows;
        grid.SelectionMode = DataGridSelectionMode.Single;
        Avalonia.Automation.AutomationProperties.SetName(grid, "Discovered devices");
        Row? Selected() => grid.SelectedItem as Row;
        string SelectedIp() => Selected()?.D.Addresses.Where(x => x.Address.AddressFamily == AddressFamily.InterNetwork).OrderBy(x => x.Assignment == IpAssignment.Probing).FirstOrDefault()?.Address.ToString() ?? "";

        var deviceActions = Ui.Row(
            Ui.Button("Copy IP", () => Ui.CopyAsync(this, SelectedIp())),
            Ui.Button("Copy MAC", () => Ui.CopyAsync(this, Selected()?.Mac ?? "")),
            Ui.Button("Add Laptop Address…", async () => error.Text = await AddLaptopAddressAsync(Adapter(), SelectedIp()) ?? ""),
            Ui.Button("Add to Range List", () =>
            {
                if (SelectedIp() is { Length: > 0 } ip)
                {
                    _vm.SetRanges([RangeEntryViewModel.From(new RangeEntry { Target = ip })], append: true);
                    status.Text = $"{ip} added to the main window's ranges: start a scan there for ping, ports and details.";
                }

                return Task.CompletedTask;
            }),
            Ui.Button("TCP…", () => Open(new TcpTesterWindow(SelectedIp()))),
            Ui.Button("HTTPS…", () => Open(new HttpTesterWindow($"https://{SelectedIp()}/"))),
            Ui.Button("TLS…", () => Open(new TlsInspectorWindow(SelectedIp()))),
            Ui.Button("Redfish…", () => Open(new HttpTesterWindow($"https://{SelectedIp()}/redfish/v1/"))));

        Task Open(Window w)
        {
            if (SelectedIp().Length > 0) w.Show(this);
            return Task.CompletedTask;
        }

        // ---------------- events ----------------
        var eventFilter = ToolKit.Text("Event filter", "filter events", 220);
        var eventsBox = ToolKit.ReportBox("Events");
        eventsBox.MinHeight = 60; // up to 150 px; gives way at small window sizes (it scrolls inside)
        eventsBox.MaxHeight = 150;
        void ShowEvents()
        {
            var f = eventFilter.Text?.Trim() ?? "";
            eventsBox.Text = string.Join('\n', f.Length == 0 ? _events : _events.Where(e => e.Contains(f, StringComparison.OrdinalIgnoreCase)));
        }

        eventFilter.TextChanged += (_, _) => ShowEvents();
        var eventActions = Ui.Row(eventFilter,
            ToolKit.CopyButton(this, () => eventsBox.Text ?? "", "Copy Events"),
            ToolKit.ExportButton(this, () => string.Join('\n', _events), "device-discovery-events.txt", "Export Events…"),
            ToolKit.ExportButton(this, DevicesCsv, "discovered-devices.csv", "Export Devices…"),
            Ui.Button("Clear", () =>
            {
                _book.Clear();
                _events.Clear();
                Interlocked.Increment(ref _version);
                ShowEvents();
                return Task.CompletedTask;
            }));

        var main = new DockPanel();
        var deviceHeader = new StackPanel { Spacing = 6, Children = { error, deviceActions } };
        DockPanel.SetDock(deviceHeader, Dock.Top);
        var bottom = new StackPanel { Spacing = 6, Margin = new Thickness(0, 6, 0, 0), Children = { eventActions, eventsBox } };
        DockPanel.SetDock(bottom, Dock.Bottom);
        main.Children.Add(deviceHeader);
        main.Children.Add(bottom);
        main.Children.Add(grid);
        Content = ToolKit.Layout(new StackPanel { Spacing = 8, Children = { interfaceForm.Grid, tabs } }, new Panel(), main, status);

        // batched UI updates
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
        timer.Tick += (_, _) =>
        {
            var newEvents = false;
            while (_incoming.TryDequeue(out var line))
            {
                _events.Add(line);
                newEvents = true;
            }

            if (_events.Count > MaxEvents) _events.RemoveRange(0, _events.Count - MaxEvents);
            if (newEvents) ShowEvents();
            var v = Volatile.Read(ref _version);
            if (v != _shownVersion)
            {
                _shownVersion = v;
                var selected = Selected()?.D.Mac;
                _rows.Clear();
                foreach (var d in _book.Devices) _rows.Add(new Row(d, _vm.Oui.Capability.Available ? _vm.Oui.Lookup(d.Mac) ?? "" : ""));
                if (selected is not null) grid.SelectedItem = _rows.FirstOrDefault(r => r.D.Mac.Equals(selected));
            }

            leases.Text = _server is { } s && s.Leases.Count > 0
                ? "Leases: " + string.Join("  ·  ", s.Leases.Select(l => $"{l.Address} → {Formats.Mac(l.Mac)} {l.State} until {l.Expires.ToLocalTime():HH:mm:ss}{(l.HostName is { } h ? " (" + h + ")" : "")}"))
                : _server is null ? "" : "No leases yet.";
        };
        timer.Start();
        ShowAdapter();

        _removeHook = vm.AddShutdownHook(StopAllAsync);
        Closing += async (_, e) =>
        {
            if (_closingDone) return;
            e.Cancel = true;
            runner.Cancel();
            var problems = await StopAllAsync();
            timer.Stop();
            _removeHook();
            if (problems is not null) await Dialogs.MessageAsync(this, "Device IP Discovery", problems, confirm: false);
            _closingDone = true;
            Close();
        };
    }

    private static TextBlock Visible(string text) => new() { Text = text, Classes = { "hint" } };

    private void Log(string text) => _incoming.Enqueue($"{DateTime.Now:HH:mm:ss}  {text}");

    private void Observe(DiscoveryObservation o)
    {
        if (_book.Add(o))
        {
            Interlocked.Increment(ref _version);
            Log($"{o.Source}: {Formats.Mac(o.Mac)} {o.Evidence}" + (o.HostName is { } h ? $" (host {h})" : ""));
        }
    }

    private void OnClientMessage(DhcpMessage m)
    {
        foreach (var o in FrameObservations.FromDhcp(m, DateTimeOffset.UtcNow)) Observe(o);
    }

    private void OnServerEvent(DhcpEvent e)
    {
        Log("DHCP server: " + e.Text);
        if (FrameObservations.FromServerEvent(e) is { } o) Observe(o);
    }

    /// <summary>Checks, adds the server address if asked, refuses when another DHCP server answers, then binds. Null on success.</summary>
    private async Task<string?> StartServerAsync(NetworkAdapterInfo adapter, DhcpServerConfig config, int prefix, bool addAddress)
    {
        if (_listener is not null)
        {
            await _listener.StopAsync(); // the server receives the same requests on port 67 and reports them too
            _listener = null;
        }

        TemporaryAddress? added = null;
        if (!adapter.IPv4.Any(x => x.Address.Equals(config.ServerAddress)))
        {
            if (!addAddress) return $"{config.ServerAddress} is not an address of '{adapter.Name}'. Tick 'Add the server address' or assign it first.";
            var problems = TemporaryAddressPlanner.Check(_adapters.GetAdapters(), adapter, config.ServerAddress, prefix);
            if (problems.Count > 0) return string.Join(" ", problems);
            try
            {
                added = await _temporary.AddAsync(adapter, config.ServerAddress, prefix, CancellationToken.None);
                _added.Add(added);
                Log($"Temporary address {config.ServerAddress}/{prefix} added to {adapter.Name}.");
            }
            catch (InvalidOperationException ex)
            {
                return ex.Message;
            }
        }

        var (offers, checkError) = await _dhcpCheck.DiscoverAsync([], TimeSpan.FromSeconds(3), CancellationToken.None, config.ServerAddress);
        if (checkError is not null || offers.Count > 0)
        {
            await RemoveAsync(added);
            return offers.Count > 0
                ? $"Not started: a DHCP server already answers on this adapter ({string.Join(", ", offers.Select(o => $"{o.ServerDisplay} offering {o.OfferedAddress}").Distinct())}). This is not an isolated connection."
                : "Not started: the check for another DHCP server failed: " + checkError;
        }

        try
        {
            _server = DhcpServerHost.Start(config, config.ServerAddress, OnServerEvent, onClientMessage: OnClientMessage);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            await RemoveAsync(added);
            return ex.Message;
        }

        var host = _server;
        _ = host.Completion.ContinueWith(t =>
        {
            if (t.IsFaulted) Log("DHCP server stopped: " + t.Exception!.GetBaseException().Message + " (adapter disconnected?)");
        }, CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        Log($"DHCP server started on {config.ServerAddress}:67, pool {config.PoolStart} – {config.PoolEnd}.");
        return null;
    }

    private async Task<string?> StopServerAsync()
    {
        if (_server is { } s)
        {
            _server = null;
            await s.DisposeAsync();
            Log("DHCP server stopped.");
        }

        var failures = new List<string>();
        foreach (var a in _added.ToList())
        {
            try
            {
                await _temporary.RemoveAsync(a, CancellationToken.None);
                _added.Remove(a);
                Log($"Temporary address {a.Address} removed from {a.AdapterName}.");
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
            {
                failures.Add($"{a.Address} could not be removed ({ex.Message}). {a.Recovery}");
            }
        }

        return failures.Count > 0 ? string.Join("\n", failures) : null;
    }

    private async Task StopPassiveAsync()
    {
        if (_listener is { } l)
        {
            _listener = null;
            await l.DisposeAsync();
        }

        if (_stopCapture is { } stop)
        {
            _stopCapture = null;
            await stop();
        }

        Log("Listening stopped.");
    }

    /// <summary>Stops everything and removes temporary addresses; returns what could not be undone (with recovery steps).</summary>
    private async Task<string?> StopAllAsync()
    {
        await StopPassiveAsync();
        return await StopServerAsync();
    }

    private async Task RemoveAsync(TemporaryAddress? a)
    {
        if (a is null) return;
        try
        {
            await _temporary.RemoveAsync(a, CancellationToken.None);
            _added.Remove(a);
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or System.ComponentModel.Win32Exception)
        {
            Log($"Temporary address {a.Address} could not be removed: {ex.Message} {a.Recovery}");
        }
    }

    private async Task<string?> AddLaptopAddressAsync(NetworkAdapterInfo? adapter, string deviceIp)
    {
        if (adapter is null || !IPAddress.TryParse(deviceIp, out var device)) return "Select a device with an IPv4 address first.";
        if (!_temporary.Capability.Available) return _temporary.Capability.Description;
        var inUse = _book.Devices.SelectMany(d => d.Addresses).Select(a => a.Address).Concat(_adapters.GetAdapters().SelectMany(a => a.IPv4).Select(a => a.Address)).ToHashSet();
        if (TemporaryAddressPlanner.Suggest(device, 24, inUse) is not { } suggestion) return "No free neighbour address next to the device in its /24.";
        var problems = TemporaryAddressPlanner.Check(_adapters.GetAdapters(), adapter, suggestion, 24);
        if (problems.Count > 0) return string.Join(" ", problems);
        var ok = await Dialogs.MessageAsync(this, "Add laptop address",
            $"Add {suggestion}/24 to '{adapter.Name}' to reach {device}?\n\nThe address is added next to the existing ones, without a default gateway, to the active "
            + "configuration only: IPMaster removes it when you stop, close this window or exit, and Windows drops it on an adapter restart or reboot. "
            + "Administrator rights are needed. If the device uses another prefix than /24, assign an address by hand.", confirm: true);
        if (!ok) return null;
        try
        {
            var added = await _temporary.AddAsync(adapter, suggestion, 24, CancellationToken.None);
            _added.Add(added);
            Log($"Temporary address {suggestion}/24 added to {adapter.Name}. If IPMaster cannot remove it: {added.Recovery}");
            return null;
        }
        catch (InvalidOperationException ex)
        {
            return ex.Message;
        }
    }

    private string DevicesCsv()
    {
        using var w = new StringWriter(CultureInfo.InvariantCulture);
        CsvExporter.WriteRow(w, ["ip", "mac", "vendor", "host", "vendor_class", "protocols", "assignment", "addresses", "first_seen_utc", "last_seen_utc", "evidence"], ',', true);
        foreach (var r in _rows)
        {
            CsvExporter.WriteRow(w, [r.Ip, r.Mac, r.Vendor, r.D.HostName ?? "", r.D.VendorClass ?? "", r.Protocols, r.Assignment, r.Addresses,
                r.D.FirstSeen.ToString("O", CultureInfo.InvariantCulture), r.D.LastSeen.ToString("O", CultureInfo.InvariantCulture), r.Evidence], ',', true);
        }

        return w.ToString();
    }

    private static DhcpServerConfig? ParseConfig(string? server, string? mask, string? start, string? end, int leaseMinutes, string? gateway, string? dns,
        string? reservations, out string error)
    {
        error = "";
        static IPAddress? Ip(string? s) => IPAddress.TryParse(s?.Trim(), out var a) && a.AddressFamily == AddressFamily.InterNetwork ? a : null;
        if (Ip(server) is not { } srv || Ip(mask) is not { } m || Ip(start) is not { } s || Ip(end) is not { } e)
        {
            error = "Enter the server address, subnet mask and pool start and end as IPv4 addresses.";
            return null;
        }

        IPAddress? router = null;
        if (!string.IsNullOrWhiteSpace(gateway) && (router = Ip(gateway)) is null)
        {
            error = "The gateway is not an IPv4 address (leave it empty to advertise none).";
            return null;
        }

        var dnsList = new List<IPAddress>();
        foreach (var d in (dns ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (Ip(d) is not { } a)
            {
                error = $"DNS server '{d}' is not an IPv4 address.";
                return null;
            }

            dnsList.Add(a);
        }

        var reserved = new Dictionary<string, IPAddress>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in (reservations ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = r.Split('=', 2, StringSplitOptions.TrimEntries);
            if (parts.Length != 2 || Ip(parts[1]) is not { } a)
            {
                error = $"Reservation '{r}': use MAC=IPv4.";
                return null;
            }

            reserved[parts[0]] = a;
        }

        return new DhcpServerConfig
        {
            ServerAddress = srv, SubnetMask = m, PoolStart = s, PoolEnd = e, LeaseTime = TimeSpan.FromMinutes(leaseMinutes), Router = router, DnsServers = dnsList,
            Reservations = reserved,
        };
    }

    private static int BitCount(IPAddress mask) => System.Numerics.BitOperations.PopCount(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes()));
}
