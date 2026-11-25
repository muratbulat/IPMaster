using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Text;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Monitoring;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Network Path &amp; MTU Analyzer (D-093): continuous traceroute (the existing <see cref="IRouteTracer"/>) with
/// per-hop statistics, path-change log, end-to-end latency chart, and path MTU discovery with don't-fragment pings.
/// Loss at a router that later hops do not show is labelled ICMP rate limiting, not forwarding loss.
/// </summary>
internal sealed class PathAnalyzerWindow : Window
{
    private sealed record HopRow(HopStats H)
    {
        public int Ttl => H.Ttl;

        public string Address => H.Address?.ToString() ?? "*";

        public string Last => Ms(H.LastMs);

        public string Average => Ms(H.AverageMs);

        public string Best => Ms(H.MinMs);

        public string Worst => Ms(H.MaxMs);

        public string Jitter => Ms(H.JitterMs);

        public string Loss => $"{H.LossPercent:0.#} % ({H.Lost}/{H.Sent})";

        public string Note => H.Note;

        private static string Ms(double? v) => v is { } x ? $"{x:0} ms" : "—";
    }

    private Action? _stop;

    public PathAnalyzerWindow(IRouteTracer tracer, string? target = null)
    {
        ArgumentNullException.ThrowIfNull(tracer);
        Title = "Network Path & MTU Analyzer";
        Width = 1150;
        Height = 820;
        MinWidth = 680;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var host = ToolKit.Text("Destination", "host or IPv4/IPv6 address", 260, target ?? "");
        var interval = ToolKit.Number(5, 1, 3600, "Interval in seconds", 70);
        var maxHops = ToolKit.Number(30, 1, 64, "Maximum hops", 60);
        var timeout = ToolKit.Number(1000, 100, 10_000, "Timeout per hop in milliseconds", 80);
        var rows = new ObservableCollection<HopRow>();
        var grid = Ui.Grid(("Hop", nameof(HopRow.Ttl), 62), ("Address", nameof(HopRow.Address), 150), ("Last", nameof(HopRow.Last), 75), ("Avg", nameof(HopRow.Average), 75),
            ("Best", nameof(HopRow.Best), 75), ("Worst", nameof(HopRow.Worst), 75), ("Jitter", nameof(HopRow.Jitter), 75), ("Loss", nameof(HopRow.Loss), 120),
            ("Note", nameof(HopRow.Note), 0));
        grid.ItemsSource = rows;
        Avalonia.Automation.AutomationProperties.SetName(grid, "Hops");
        var changes = ToolKit.ReportBox("Path changes");
        changes.Height = 110;
        var chart = new LatencyChart { Height = 170, Window = TimeSpan.FromMinutes(10) };
        var mtuResult = new SelectableTextBlock { TextWrapping = TextWrapping.Wrap };
        PathTracker? tracker = null;
        PathMtuResult? lastMtu = null;

        async Task<IPAddress?> Resolve(string name, CancellationToken ct)
        {
            if (IPAddress.TryParse(name, out var ip)) return ip;
            try
            {
                return (await Dns.GetHostAddressesAsync(name, ct)).OrderBy(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 0 : 1).FirstOrDefault();
            }
            catch (System.Net.Sockets.SocketException)
            {
                return null;
            }
        }

        void Refresh()
        {
            if (tracker is null) return;
            rows.Clear();
            foreach (var h in tracker.Hops) rows.Add(new HopRow(h));
            changes.Text = string.Join('\n', tracker.Changes.Select(c => $"{c.At.ToLocalTime():HH:mm:ss}  hop {c.Ttl}: {c.Before?.ToString() ?? "*"} → {c.After}"));
            chart.Samples = tracker.EndToEnd;
            chart.InvalidateVisual();
            status.Text = $"{tracker.Traces} trace(s) to {tracker.Destination} · end-to-end loss {tracker.EndToEndLossPercent:0.#} % · last {DateTime.Now:HH:mm:ss}";
        }

        Button? start = null;
        Button? stop = null;
        stop = Ui.Button("Stop", () =>
        {
            _stop?.Invoke();
            return Task.CompletedTask;
        });
        start = Ui.Button("Start Tracing", async () =>
        {
            var name = host.Text?.Trim() ?? "";
            if (name.Length == 0)
            {
                status.Text = "Enter the destination.";
                return;
            }

            var every = TimeSpan.FromSeconds((double)(interval.Value ?? 5));
            var hops = (int)(maxHops.Value ?? 30);
            var wait = TimeSpan.FromMilliseconds((double)(timeout.Value ?? 1000));
            var cts = new CancellationTokenSource();
            var ct = cts.Token;
            _stop = cts.Cancel;
            start!.IsEnabled = false;
            stop!.IsEnabled = true;
            var destination = await Resolve(name, ct);
            if (destination is null)
            {
                status.Text = $"'{name}' could not be resolved.";
                _stop = null;
                cts.Dispose();
                start.IsEnabled = true;
                stop.IsEnabled = false;
                return;
            }

            tracker = new PathTracker(destination);
            var t = tracker;
            status.Text = $"Tracing {destination}…";
            _ = Task.Run(async () =>
            {
                using var timer = new PeriodicTimer(every); // a trace longer than the interval skips ticks
                try
                {
                    do
                    {
                        var trace = await tracer.TraceAsync(destination, hops, wait, ct);
                        t.Add(trace, DateTimeOffset.UtcNow);
                        Dispatcher.UIThread.Post(Refresh);
                    }
                    while (await timer.WaitForNextTickAsync(ct));
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                }
            }, CancellationToken.None).ContinueWith(task => Dispatcher.UIThread.Post(() =>
            {
                _stop = null;
                cts.Dispose();
                start.IsEnabled = true;
                stop.IsEnabled = false;
                status.Text = task.IsFaulted ? "Tracing stopped on an error: " + task.Exception!.GetBaseException().Message : status.Text + " · stopped";
            }), TaskScheduler.Default);
        }, accent: true);
        stop.IsEnabled = false;

        var mtuRunner = new ToolRunner(status);
        var mtu = Ui.Button("Discover Path MTU", async () =>
        {
            var name = host.Text?.Trim() ?? "";
            var wait = TimeSpan.FromMilliseconds(Math.Max(1000, (double)(timeout.Value ?? 1000)));
            await mtuRunner.RunAsync("Discovering the path MTU", async ct =>
            {
                var destination = await Resolve(name, ct);
                if (destination is null) return $"'{name}' could not be resolved.";
                if (destination.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return "Path MTU discovery uses IPv4 don't-fragment pings: enter an IPv4 destination.";
                var r = await PathMtu.DiscoverAsync((size, token) => PathProbes.MtuProbeAsync(destination, size, wait, token), 1500, ct);
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    lastMtu = r;
                    mtuResult.Text = $"{destination}: {r.Evidence} ({r.Probes} probe(s))";
                });
                return r.Mtu is { } m ? $"Path MTU {(r.AtLeast ? "≥ " : "")}{m} bytes." : "Path MTU unknown.";
            });
        });

        var report = ToolKit.ExportButton(this, () =>
        {
            var sb = new StringBuilder();
            if (tracker is { } t)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"Path to {t.Destination}: {t.Traces} trace(s), end-to-end loss {t.EndToEndLossPercent:0.#} %");
                sb.AppendLine("hop\taddress\tlast_ms\tavg_ms\tbest_ms\tworst_ms\tjitter_ms\tloss_pct\tsent\tlost\taddresses_seen\tnote");
                foreach (var h in t.Hops)
                {
                    static string F(double? v) => v?.ToString("0.#", CultureInfo.InvariantCulture) ?? "";
                    sb.AppendLine(string.Join('\t', h.Ttl.ToString(CultureInfo.InvariantCulture), h.Address?.ToString() ?? "*", F(h.LastMs), F(h.AverageMs), F(h.MinMs), F(h.MaxMs),
                        F(h.JitterMs), F(h.LossPercent), h.Sent.ToString(CultureInfo.InvariantCulture), h.Lost.ToString(CultureInfo.InvariantCulture),
                        string.Join(' ', h.AddressesSeen), h.Note));
                }

                sb.AppendLine().AppendLine("Path changes:");
                foreach (var c in t.Changes) sb.AppendLine(CultureInfo.InvariantCulture, $"{c.At:O}\thop {c.Ttl}\t{c.Before?.ToString() ?? "*"} -> {c.After}");
            }

            if (lastMtu is { } m) sb.AppendLine().AppendLine("Path MTU: " + m.Evidence);
            return sb.ToString();
        }, "path-report.txt", "Export Report…");

        var inputs = new WrapPanel
        {
            Children =
            {
                SnmpTargetForm.Pair("Destination", host), SnmpTargetForm.Pair("Interval (s)", interval), SnmpTargetForm.Pair("Max hops", maxHops),
                SnmpTargetForm.Pair("Timeout (ms)", timeout),
            },
        };
        var hint = Ui.Explained("One ICMP probe per hop per trace; path MTU uses IPv4 don't-fragment pings.",
            "One ICMP probe per hop per trace. Routers often limit or skip ICMP replies: loss at a hop that later hops do not show is labelled rate "
                   + "limiting, not forwarding loss. Path MTU uses IPv4 don't-fragment pings between 576 and 1500 bytes.");
        var lower = new StackPanel { Spacing = 6, Margin = new Thickness(0, 6, 0, 0), Children = { mtuResult, new TextBlock { Text = "Path changes", Classes = { "section" } }, changes, chart } };
        var main = new DockPanel();
        DockPanel.SetDock(lower, Dock.Bottom);
        main.Children.Add(lower);
        main.Children.Add(grid);
        Content = ToolKit.Layout(new StackPanel { Spacing = 4, Children = { inputs, hint } }, Ui.Row(start, stop, mtu, report), main, status);
        Closing += (_, _) =>
        {
            _stop?.Invoke();
            mtuRunner.Dispose();
        };
    }
}
