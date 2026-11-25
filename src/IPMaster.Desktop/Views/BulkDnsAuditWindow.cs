using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using System.Text.Json;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Bulk DNS Audit (D-094): forward, reverse and forward-confirmed reverse lookups of many names and addresses
/// against one or more DNS servers, with consistency findings. Read-only queries; DNS records are never changed.
/// </summary>
internal sealed class BulkDnsAuditWindow : Window
{
    private sealed record FindingRow(DnsAuditEntry Entry, DnsFinding F)
    {
        public string Input => Entry.Input;

        public string Level => F.Level.ToString();

        public string Finding => F.Text;
    }

    public BulkDnsAuditWindow()
    {
        Title = "Bulk DNS Audit";
        Width = 1150;
        Height = 800;
        MinWidth = 680;
        MinHeight = 460;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var servers = ToolKit.Text("DNS servers", "comma-separated", 360, string.Join(", ", DnsClient.SystemServers().Take(3)));
        var timeout = ToolKit.Number(3, 1, 30, "Timeout in seconds", 60);
        var entries = new TextBox
        {
            AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, Height = 110, FontFamily = ToolKit.Mono,
            PlaceholderText = "names and addresses, one per line (# comments)",
        };
        Avalonia.Automation.AutomationProperties.SetName(entries, "Names and addresses");
        var problemsOnly = new CheckBox { Content = "Warnings and errors only" };
        var rows = new ObservableCollection<FindingRow>();
        IReadOnlyList<DnsAuditEntry> results = [];
        var details = ToolKit.ReportBox("Lookups of the selected entry");
        details.Height = 140;
        var grid = Ui.Grid(("Name or address", nameof(FindingRow.Input), 220), ("Level", nameof(FindingRow.Level), 80), ("Finding", nameof(FindingRow.Finding), 0));
        grid.ItemsSource = rows;
        grid.SelectionMode = DataGridSelectionMode.Single;
        Avalonia.Automation.AutomationProperties.SetName(grid, "Findings");
        grid.SelectionChanged += (_, _) =>
        {
            if (grid.SelectedItem is not FindingRow r) return;
            details.Text = string.Join('\n', r.Entry.Lookups.Select(l => $"{l.Server,-22} {l.Type,-5} {l.Name,-40} {l.Status,-18} {string.Join(", ", l.Values)}{(l.Chain.Length > 0 ? "   (" + l.Chain + ")" : "")}"));
        };

        void Show()
        {
            rows.Clear();
            foreach (var e in results)
            {
                foreach (var f in DnsAudit.Analyze(e).Where(f => problemsOnly.IsChecked != true || f.Level >= AuditLevel.Warning)) rows.Add(new FindingRow(e, f));
            }
        }

        problemsOnly.IsCheckedChanged += (_, _) => Show();

        var run = Ui.Button("Run Audit", async () =>
        {
            var inputs = DnsAudit.ParseInput(entries.Text ?? "");
            var serverList = new List<IPEndPoint>();
            foreach (var s in (servers.Text ?? "").Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (IPAddress.TryParse(s, out var ip)) serverList.Add(new IPEndPoint(ip, 53)); // also bare IPv6
                else if (IPEndPoint.TryParse(s, out var ep) && ep.Port != 0) serverList.Add(ep); // 192.0.2.53:5353, [2001:db8::53]:53
                else
                {
                    status.Text = $"'{s}' is not a server address (IP or IP:port).";
                    return;
                }
            }

            if (inputs.Count == 0 || serverList.Count == 0)
            {
                status.Text = inputs.Count == 0 ? "Enter names or addresses." : "Enter at least one DNS server.";
                return;
            }

            if (inputs.Count > DnsAuditRunner.MaxEntries)
            {
                status.Text = $"At most {DnsAuditRunner.MaxEntries:N0} entries per audit.";
                return;
            }

            var options = new DnsQueryOptions { Timeout = TimeSpan.FromSeconds((double)(timeout.Value ?? 3)), Retries = 1 };
            rows.Clear();
            details.Text = "";
            await runner.RunAsync("Auditing", async ct =>
            {
                var done = 0;
                var r = await DnsAuditRunner.RunAsync(inputs, serverList, options, _ => Dispatcher.UIThread.Post(() => status.Text = $"{++done:N0} of {inputs.Count:N0}…"), ct);
                var findings = r.SelectMany(DnsAudit.Analyze).ToList();
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    results = r;
                    Show();
                });
                return $"{r.Count:N0} entr{(r.Count == 1 ? "y" : "ies")} on {serverList.Count} server(s): {findings.Count(f => f.Level == AuditLevel.Error)} error(s), "
                       + $"{findings.Count(f => f.Level == AuditLevel.Warning)} warning(s), {findings.Count(f => f.Level == AuditLevel.Ok)} confirmed.";
            });
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            run.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        var import = Ui.Button("Import File…", async () =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Import names and addresses", AllowMultiple = false });
            if (files.Count == 0 || files[0].TryGetLocalPath() is not { } path) return;
            var info = new FileInfo(path);
            if (info.Length > 4 * 1024 * 1024)
            {
                status.Text = "The file is larger than 4 MB.";
                return;
            }

            entries.Text = await File.ReadAllTextAsync(path);
        });
        var exportCsv = ToolKit.ExportButton(this, () =>
        {
            using var w = new StringWriter(CultureInfo.InvariantCulture);
            CsvExporter.WriteRow(w, ["input", "level", "finding"], ',', true);
            foreach (var e in results)
            {
                foreach (var f in DnsAudit.Analyze(e)) CsvExporter.WriteRow(w, [e.Input, f.Level.ToString(), f.Text], ',', true);
            }

            return w.ToString();
        }, "dns-audit.csv", "Export CSV…");
        var exportJson = ToolKit.ExportButton(this, () => JsonSerializer.Serialize(results.Select(e => new { e.Input, e.IsAddress, e.Lookups, Findings = DnsAudit.Analyze(e) }),
            TopologyJson.Options), "dns-audit.json", "Export JSON…");

        var form = new Form();
        form.Add("Servers", Ui.Row(servers, SnmpTargetForm.Pair("Timeout (s)", timeout)));
        form.Add("Entries", entries);
        form.Full(new TextBlock
        {
            Text = "Read-only: A/AAAA (CNAME chains followed), PTR of every address, and the PTR names looked up again (forward-confirmed reverse DNS). "
                   + "Several names for one address or several addresses for one name are normal and shown as information. DNS records are never changed.",
            Classes = { "description" },
        });
        var main = new DockPanel();
        var top = Ui.Row(problemsOnly);
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(details, Dock.Bottom);
        details.Margin = new Avalonia.Thickness(0, 6, 0, 0);
        main.Children.Add(top);
        main.Children.Add(details);
        main.Children.Add(grid);
        Content = ToolKit.Layout(form.Grid, Ui.Row(run, cancel, import, exportCsv, exportJson), main, status);
        Closed += (_, _) => runner.Dispose();
    }
}
