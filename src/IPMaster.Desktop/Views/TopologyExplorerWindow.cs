using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Text.Json;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Nodes on a circle; solid line = link seen from both ends, dashed = one end; dashed box = not queried.</summary>
internal sealed class TopologyCanvas : Styling.ThemedControl
{
    public TopologyGraph Graph { get; set; } = new([], []);

    public override void Render(DrawingContext context)
    {
        var b = Bounds;
        var nodes = Graph.Nodes;
        if (nodes.Count == 0 || b.Width < 100 || b.Height < 100) return;
        var text = Brush(Styling.Theme.Keys.TextPrimary);
        var center = new Point(b.Width / 2, b.Height / 2);
        var radius = Math.Min(b.Width, b.Height) / 2 - 60;
        var at = new Dictionary<string, Point>();
        for (var i = 0; i < nodes.Count; i++)
        {
            var angle = 2 * Math.PI * i / nodes.Count - Math.PI / 2;
            at[nodes[i].Id] = nodes.Count == 1 ? center : new Point(center.X + radius * Math.Cos(angle), center.Y + radius * Math.Sin(angle));
        }

        foreach (var l in Graph.Links)
        {
            var pen = Pen(Styling.Theme.Keys.Link, 1.5, l.Evidence == LinkEvidence.BothEnds ? null : DashStyle.Dash);
            context.DrawLine(pen, at[l.FromNode], at[l.ToNode]);
        }

        foreach (var n in nodes)
        {
            var p = at[n.Id];
            var label = new FormattedText(n.Label, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, Typeface.Default, 11, text);
            var box = new Rect(p.X - label.Width / 2 - 6, p.Y - 11, label.Width + 12, 22);
            var key = n.State switch { NodeState.Queried => Styling.Theme.Keys.NodeQueried, NodeState.QueryFailed => Styling.Theme.Keys.NodeFailed, _ => Styling.Theme.Keys.NodeUnknown };
            context.DrawRectangle(Tint(key, 0.25), Pen(key, 1, dash: n.State == NodeState.Queried ? null : DashStyle.Dash), box, 4, 4);
            context.DrawText(label, new Point(box.X + 6, box.Y + 4));
        }
    }
}

/// <summary>
/// Tools → LLDP / CDP Topology Explorer (D-092): read-only SNMP walks of LLDP-MIB and CISCO-CDP-MIB on the given devices
/// (optionally following neighbours' management addresses, bounded). Links come only from what devices report; each
/// link and node says how it is known.
/// </summary>
internal sealed class TopologyExplorerWindow : Window
{
    private sealed record LinkRow(string From, string FromPort, string To, string ToPort, string Protocol, string Evidence);

    private sealed record NodeRow(string Name, string Chassis, string Addresses, string State, string Detail);

    public TopologyExplorerWindow(string? seed = null)
    {
        Title = "LLDP / CDP Topology Explorer";
        Width = 1200;
        Height = 820;
        MinWidth = 700;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var agent = new SnmpTargetForm(seed);
        agent.Host.Width = 320;
        agent.Host.PlaceholderText = "devices: 10.0.0.1, 10.0.0.2, switch.lab";
        var follow = new CheckBox { Content = "Follow neighbours' management addresses (same credentials)" };
        var maxDevices = ToolKit.Number(20, 1, TopologyCollector.MaxDevicesLimit, "Maximum devices", 70);
        var timeout = ToolKit.Number(3, 1, 60, "Timeout in seconds", 60);
        var links = new ObservableCollection<LinkRow>();
        var nodes = new ObservableCollection<NodeRow>();
        var canvas = new TopologyCanvas { MinHeight = 260 };
        TopologyGraph graph = new([], []);

        var linkGrid = Ui.Grid(("Device", nameof(LinkRow.From), 160), ("Port", nameof(LinkRow.FromPort), 140), ("Neighbour", nameof(LinkRow.To), 180),
            ("Neighbour port", nameof(LinkRow.ToPort), 140), ("Protocol", nameof(LinkRow.Protocol), 80), ("Evidence", nameof(LinkRow.Evidence), 0));
        linkGrid.ItemsSource = links;
        Avalonia.Automation.AutomationProperties.SetName(linkGrid, "Links");
        var nodeGrid = Ui.Grid(("Device", nameof(NodeRow.Name), 180), ("Chassis ID", nameof(NodeRow.Chassis), 160), ("Addresses", nameof(NodeRow.Addresses), 180),
            ("State", nameof(NodeRow.State), 150), ("Detail", nameof(NodeRow.Detail), 0));
        nodeGrid.ItemsSource = nodes;
        Avalonia.Automation.AutomationProperties.SetName(nodeGrid, "Devices");

        void Show(TopologyGraph g)
        {
            graph = g;
            string Name(string id) => g.Nodes.First(n => n.Id == id).Label;
            links.Clear();
            foreach (var l in g.Links)
            {
                links.Add(new LinkRow(Name(l.FromNode), l.FromPort, Name(l.ToNode), l.ToPort, l.Protocol.ToString().ToUpperInvariant(),
                    l.Evidence == LinkEvidence.BothEnds ? "Seen from both ends" : "Seen from one end"));
            }

            nodes.Clear();
            foreach (var n in g.Nodes)
            {
                nodes.Add(new NodeRow(n.Name, n.ChassisId, string.Join(", ", n.Addresses), n.State switch
                {
                    NodeState.Queried => "Queried",
                    NodeState.QueryFailed => "Query failed",
                    _ => "Not queried (from a neighbour table)",
                }, n.Detail));
            }

            canvas.Graph = g;
            canvas.InvalidateVisual();
        }

        var explore = Ui.Button("Explore", async () =>
        {
            Styling.Theme.SetState(status, null);
            if (agent.Validate() is { } missing)
            {
                status.Text = missing;
                return;
            }

            var names = (agent.Host.Text ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().ToList();
            var targetFor = agent.For();
            var (doFollow, max, wait) = (follow.IsChecked == true, (int)(maxDevices.Value ?? 20), TimeSpan.FromSeconds((double)(timeout.Value ?? 3)));
            await runner.RunAsync("Exploring", async ct =>
            {
                var seeds = new List<IPAddress>();
                foreach (var n in names)
                {
                    if (IPAddress.TryParse(n, out var ip)) seeds.Add(ip);
                    else
                    {
                        try
                        {
                            seeds.Add((await Dns.GetHostAddressesAsync(n, ct)).First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork));
                        }
                        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or InvalidOperationException)
                        {
                            return $"'{n}' could not be resolved.";
                        }
                    }
                }

                var done = 0;
                var reports = await TopologyCollector.ExploreAsync(seeds, targetFor, doFollow, max, wait,
                    r => Dispatcher.UIThread.Post(() => status.Text = $"{++done} device(s) queried; last {r.Address}{(r.Error is null ? $": {r.Neighbors.Count} neighbour(s)" : " failed")}…"), ct);
                var g = TopologyBuilder.Build(reports);
                await Dispatcher.UIThread.InvokeAsync(() => Show(g));
                var failed = reports.Count(r => r.Error is not null);
                return $"{reports.Count} device(s) queried{(failed > 0 ? $" ({failed} failed)" : "")}, {g.Nodes.Count} device(s) known, {g.Links.Count} link(s): "
                       + $"{g.Links.Count(l => l.Evidence == LinkEvidence.BothEnds)} seen from both ends."
                       + (reports.Count >= max && doFollow ? $" Stopped at the limit of {max} devices." : "");
            });
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        runner.BusyChanged += (_, _) =>
        {
            explore.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        cancel.IsEnabled = false;
        var exportDot = ToolKit.ExportButton(this, () => TopologyBuilder.ToDot(graph), "topology.dot", "Export DOT…");
        var exportCsv = ToolKit.ExportButton(this, () =>
        {
            using var w = new StringWriter(CultureInfo.InvariantCulture);
            CsvExporter.WriteRow(w, ["device", "port", "neighbour", "neighbour_port", "protocol", "evidence"], ',', true);
            foreach (var l in links) CsvExporter.WriteRow(w, [l.From, l.FromPort, l.To, l.ToPort, l.Protocol, l.Evidence], ',', true);
            return w.ToString();
        }, "topology-links.csv", "Export CSV…");
        var exportJson = ToolKit.ExportButton(this, () => JsonSerializer.Serialize(graph, TopologyJson.Options), "topology.json", "Export JSON…");

        var options = new WrapPanel { Children = { SnmpTargetForm.Pair("Max devices", maxDevices), SnmpTargetForm.Pair("Timeout (s)", timeout), follow } };
        var hint = Ui.Explained("Read-only SNMP (LLDP-MIB, CISCO-CDP-MIB); links only as devices report them.",
            "Read-only SNMP (LLDP-MIB, CISCO-CDP-MIB). A link is shown only where a device reports it; 'seen from both ends' means both devices list each "
                   + "other. Devices known only from a neighbour table are not queried unless you follow management addresses (bounded by Max devices).");
        var tabs = new TabControl
        {
            Items =
            {
                new TabItem { Header = "Links", Content = linkGrid },
                new TabItem { Header = "Devices", Content = nodeGrid },
                new TabItem { Header = "Graph", Content = canvas },
            },
        };
        Content = ToolKit.Layout(new StackPanel { Spacing = 4, Children = { agent.Row, options, hint } }, Ui.Row(explore, cancel, exportCsv, exportJson, exportDot), tabs, status);
        Closed += (_, _) => runner.Dispose();
    }
}

internal static class TopologyJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true, Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };
}
