using System.Net;
using Avalonia.Controls;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → DNS Diagnostics (D-073): direct queries to chosen servers, server comparison, forward/reverse check.</summary>
internal sealed class DnsDiagnosticsView : UserControl, IDisposable
{
    private Action? _dispose;

    private static readonly string[] AutoType = ["Auto (A, or PTR for an address)"];

    private sealed record Input(string Name, DnsType? Type, List<IPEndPoint> Servers, DnsQueryOptions Options, bool Os);


    public DnsDiagnosticsView(string? target = null)
    {
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var report = ToolKit.ReportBox("DNS report");

        var name = ToolKit.Text("Name or IP address", "www.example.test, 192.0.2.10 or 2001:db8::10", text: target ?? "");
        var types = AutoType.Concat(DnsWire.QueryTypes.Select(t => t.ToString())).ToList();
        var type = ToolKit.Combo("Record type", types, 0, 240);
        var system = DnsClient.SystemServers();
        var useSystem = new RadioButton { Content = "System DNS servers (" + (system.Count == 0 ? "none found" : string.Join(", ", system)) + ")", GroupName = "dnssrv", IsChecked = system.Count > 0 };
        var useCustom = new RadioButton { Content = "Custom", GroupName = "dnssrv", IsChecked = system.Count == 0 };
        var custom = ToolKit.Text("Custom DNS servers", "192.0.2.53, [2001:db8::53]:5353 (several to compare)");
        var port = ToolKit.Number(53, 1, 65535, "Port");
        var timeout = ToolKit.Number(3, 1, 30, "Timeout in seconds");
        var retries = ToolKit.Number(1, 0, 5, "Retries");
        var recursion = new CheckBox { Content = "Recursion desired (RD)", IsChecked = true };
        var transport = ToolKit.Combo("Transport", ["UDP, TCP when truncated", "UDP only", "TCP only"], 0, 240);
        var osResolver = new CheckBox { Content = "Also ask the OS resolver (A/AAAA; uses cache and hosts file)" };

        var f = new Form();
        f.Add("Name or IP", name);
        f.Add("Record Type", type);
        f.Add("DNS Servers", new StackPanel { Spacing = 4, Children = { useSystem, Ui.Row(useCustom, custom) } });
        custom.Width = 420;
        f.Add("Port / Timeout (s) / Retries", Ui.Row(port, timeout, retries));
        f.Add("Transport", Ui.Row(transport, recursion));
        f.Full(osResolver);
        f.Full(Form.Hint("Direct queries go to the servers above; the OS resolver is shown separately because it may answer from its cache, the hosts file or other name services."));
        var error = new TextBlock { Classes = { "error" }, TextWrapping = Avalonia.Media.TextWrapping.Wrap };
        f.Full(error);

        bool Collect(out List<IPEndPoint> servers, out DnsQueryOptions options)
        {
            options = new DnsQueryOptions
            {
                Timeout = TimeSpan.FromSeconds((double)(timeout.Value ?? 3)), Retries = (int)(retries.Value ?? 1), Recursion = recursion.IsChecked == true,
                Transport = transport.SelectedIndex switch { 1 => DnsTransport.Udp, 2 => DnsTransport.Tcp, _ => DnsTransport.UdpWithTcpFallback },
            };
            servers = [];
            error.Text = "";
            if (string.IsNullOrWhiteSpace(name.Text))
            {
                error.Text = "Enter a name or an IP address.";
                return false;
            }

            var p = (int)(port.Value ?? 53);
            if (useSystem.IsChecked == true)
            {
                servers = system.Select(a => new IPEndPoint(a, p)).ToList();
                if (servers.Count == 0) error.Text = "No system DNS servers were found; enter custom servers.";
                return servers.Count > 0;
            }

            if (!DnsDiagnostics.TryParseServers(custom.Text ?? "", p, out servers, out var e))
            {
                error.Text = e;
                return false;
            }

            return true;
        }

        DnsType? SelectedType() => type.SelectedIndex <= 0 ? null : DnsWire.QueryTypes[type.SelectedIndex - 1];

        // every input is read here, on the UI thread; the operation itself runs on the thread pool with plain values
        Button Run(string label, string what, Func<Input, CancellationToken, Task<(string Report, string Summary)>> op, bool accent = false)
        {
            var b = Ui.Button(label, async () =>
            {
                if (!Collect(out var servers, out var options)) return;
                var input = new Input(name.Text!.Trim(), SelectedType(), servers, options, osResolver.IsChecked == true);
                await runner.RunAsync(what, async ct =>
                {
                    var (text, summary) = await op(input, ct);
                    ToolKit.SetReport(report, text);
                    return summary;
                });
            }, accent);
            return b;
        }

        var query = Run("Query", "Querying", (i, ct) => DnsDiagnostics.QueryAsync(i.Name, i.Type, i.Servers, i.Options, i.Os, ct), accent: true);
        var compare = Run("Compare Servers", "Comparing servers", (i, ct) => DnsDiagnostics.CompareAsync(i.Name, i.Type, i.Servers, i.Options, ct));
        ToolTip.SetTip(compare, "Asks every listed server the same question and compares the record sets (order ignored; TTL differences listed separately).");
        var reverse = Run("Check Forward/Reverse", "Checking forward and reverse records", (i, ct) => DnsDiagnostics.ForwardReverseAsync(i.Name, i.Servers[0], i.Options, ct));
        ToolTip.SetTip(reverse, "Resolves the name (A and AAAA), then the PTR of every address, then those names again: Confirmed, MissingPtr, Mismatch or Inconclusive. Uses the first server.");
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            cancel.IsEnabled = runner.IsBusy;
            query.IsEnabled = compare.IsEnabled = reverse.IsEnabled = !runner.IsBusy;
        };
        var actions = Ui.Row(query, compare, reverse, cancel, ToolKit.CopyButton(this, () => report.Text ?? ""), ToolKit.ExportButton(this, () => report.Text ?? "", "dns-report.txt"));
        Content = ToolKit.Layout(f.Grid, actions, report, status);
        _dispose = runner.Dispose; // the tabbed window disposes its tabs when it closes
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape && runner.IsBusy)
            {
                runner.Cancel();
                e.Handled = true;
            }
        };
    }

    /// <summary>Cancels the running operation (the window closed).</summary>
    public void Dispose() => _dispose?.Invoke();
}
