using System.Collections.ObjectModel;
using System.Globalization;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Threading;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → NTP Time Checker (D-078). Compares only; the local clock is never changed.</summary>
internal sealed class NtpCheckerWindow : Window
{
    private sealed record Row(string Server, string Address, string Outcome, string Offset, string Delay, string Jitter, string Stratum, string Reference, string Leap);

    public NtpCheckerWindow(string? target = null)
    {
        Title = "NTP Time Checker";
        Width = 1050;
        Height = 720;
        MinWidth = 600;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var rows = new ObservableCollection<Row>();
        var results = new List<NtpServerResult>();

        var servers = ToolKit.Text("NTP servers", "one per line: host name or IP address, optionally :port", text: target ?? ConfiguredServers());
        servers.AcceptsReturn = true;
        servers.Height = 90;
        var samples = ToolKit.Number(4, 1, NtpChecker.MaxSamples, "Samples per server");
        var interval = ToolKit.Number(2, 1, 60, "Seconds between samples");
        var timeout = ToolKit.Number(3, 1, 30, "Timeout in seconds");
        var f = new Form();
        f.Add("Servers", servers);
        f.Add("Samples / Interval (s) / Timeout (s)", Ui.Row(samples, interval, timeout));
        f.Full(Form.Hint("Only compares: the local clock is never changed. Positive offset = this computer is behind the server. Each query uses a random nonce and replies that "
                         + "do not echo it are ignored; a Kiss-o'-Death (e.g. RATE) stops further queries to that server."));
        var error = new TextBlock { Classes = { "error" } };
        f.Full(error);

        var grid = new DataGrid { ItemsSource = rows, IsReadOnly = true, AutoGenerateColumns = false, MinHeight = 120, MaxHeight = 240, CanUserReorderColumns = true };
        void Col(string header, string path, double width) => grid.Columns.Add(new DataGridTextColumn { Header = header, Binding = new Binding(path), Width = new DataGridLength(width) });
        Col("Server", nameof(Row.Server), 180);
        Col("Address", nameof(Row.Address), 120);
        Col("Outcome", nameof(Row.Outcome), 120);
        Col("Offset (ms)", nameof(Row.Offset), 105);
        Col("Delay (ms)", nameof(Row.Delay), 100);
        Col("Jitter (ms)", nameof(Row.Jitter), 100);
        Col("Stratum", nameof(Row.Stratum), 95);
        Col("Reference", nameof(Row.Reference), 120);
        Col("Leap", nameof(Row.Leap), 110);
        Avalonia.Automation.AutomationProperties.SetName(grid, "Server summary");
        var report = ToolKit.ReportBox("NTP report");
        var main = new DockPanel();
        DockPanel.SetDock(grid, Avalonia.Controls.Dock.Top);
        grid.Margin = new Avalonia.Thickness(0, 0, 0, 8);
        main.Children.Add(grid);
        main.Children.Add(report);

        static string Ms(TimeSpan? t, string format) => t is { } v ? v.TotalMilliseconds.ToString(format, CultureInfo.InvariantCulture) : "—";
        static Row ToRow(NtpServerResult r)
        {
            var best = r.Best;
            var last = r.Samples.LastOrDefault();
            var outcome = best is not null ? $"OK ({r.Good.Count}/{r.Samples.Count})" : last?.Outcome.ToString() ?? "—";
            var p = best?.Packet ?? last?.Packet;
            return new Row(r.Server, r.Address, outcome, Ms(best?.Offset, "+0.000;-0.000"), Ms(best?.Delay, "0.000"), Ms(r.Jitter, "0.000"),
                p is null ? "—" : p.Stratum.ToString(CultureInfo.InvariantCulture), p is null ? "—" : p.IsKissOfDeath ? "KoD " + p.KissCode : p.ReferenceId, p?.Leap.ToString() ?? "—");
        }

        var check = Ui.Button("Check", async () =>
        {
            error.Text = "";
            var list = (servers.Text ?? "").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (list.Count == 0)
            {
                error.Text = "Enter at least one server.";
                return;
            }

            if (list.Count > NtpChecker.MaxServers)
            {
                error.Text = $"At most {NtpChecker.MaxServers} servers per check.";
                return;
            }

            var o = new NtpOptions
            {
                Samples = (int)(samples.Value ?? 4), Interval = TimeSpan.FromSeconds((double)(interval.Value ?? 2)), Timeout = TimeSpan.FromSeconds((double)(timeout.Value ?? 3)),
            };
            rows.Clear();
            results.Clear();
            report.Text = "";
            await runner.RunAsync("Querying " + list.Count + " server(s)", async ct =>
            {
                // servers in parallel (at most 8), samples per server sequential with the interval
                var queried = await Task.WhenAll(list.Select(s => HostPort.Split(s) is var (host, port) ? NtpChecker.QueryAsync(host, o with { Port = port }, null, ct) : NtpChecker.QueryAsync(s, o, null, ct)));
                var done = queried.Zip(list, (r, line) => r with { Server = line }).ToArray(); // show the entered host:port
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    results.AddRange(done);
                    foreach (var r in done) rows.Add(ToRow(r));
                    ToolKit.SetReport(report, NtpChecker.Report(done));
                });
                var ok = done.Count(r => r.Best is not null);
                return $"{ok} of {done.Length} server(s) answered with a usable time.";
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
            check.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        var actions = Ui.Row(check, cancel, ToolKit.CopyButton(this, () => report.Text ?? "", "Copy Report"), ToolKit.ExportButton(this, () => report.Text ?? "", "ntp-report.txt", "Export Report…"));
        Content = ToolKit.Layout(f.Grid, actions, main, status);
        Closed += (_, _) => runner.Dispose();
    }

    /// <summary>The Windows Time service's configured servers (read-only registry access), else empty.</summary>
    private static string ConfiguredServers()
    {
        if (!OperatingSystem.IsWindows()) return "";
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\W32Time\Parameters");
            var value = key?.GetValue("NtpServer") as string ?? "";
            return string.Join('\n', value.Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(s => s.Split(',')[0]).Where(s => s.Length > 0).Take(NtpChecker.MaxServers));
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return "";
        }
    }
}
