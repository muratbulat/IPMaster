using System.Security.Cryptography.X509Certificates;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → TLS Certificate Inspector (D-075).</summary>
internal sealed class TlsInspectorWindow : Window
{
    public TlsInspectorWindow(string? target = null)
    {
        Title = "TLS Certificate Inspector";
        Width = 1000;
        Height = 760;
        MinWidth = 560;
        MinHeight = 420;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var report = ToolKit.ReportBox("TLS report");
        TlsInspection? last = null;

        var server = ToolKit.Text("Server", "host name or IP address", text: target ?? "");
        var port = ToolKit.Number(443, 1, 65535, "Port");
        var mode = ToolKit.Combo("Mode", ["Direct TLS", "SMTP STARTTLS"], 0, 200);
        mode.SelectionChanged += (_, _) =>
        {
            if (mode.SelectedIndex == 1 && port.Value == 443) port.Value = 587;
            if (mode.SelectedIndex == 0 && port.Value is 25 or 587) port.Value = 443;
        };
        var sni = ToolKit.Text("SNI server name", "default: the server name (none for an IP address)");
        var expected = ToolKit.Text("Expected certificate name", "default: the SNI name");
        var timeout = ToolKit.Number(10, 1, 120, "Timeout in seconds");
        var revocation = ToolKit.Combo("Revocation check", ["Online (CRL/OCSP)", "Offline (cached data only)", "Not checked"], 0, 240);
        var f = new Form();
        f.Add("Server / Port", Ui.Row(server, port));
        server.Width = 360;
        f.Add("Mode", mode);
        f.Add("SNI", sni);
        f.Add("Expected Name", expected);
        f.Add("Timeout (s) / Revocation", Ui.Row(timeout, revocation));
        f.Full(Form.Hint("One TLS handshake is made and closed; nothing else is sent (SMTP STARTTLS: greeting, EHLO and STARTTLS only, no login or mail). "
                         + "Validation problems are recorded and the certificate is still shown for diagnosis, clearly marked untrusted. One handshake shows one negotiated protocol and cipher, not everything the server supports."));
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
        f.Full(error);
        var verdict = Ui.Banner("", "success", visible: false);
        ((TextBlock)verdict.Child!).FontWeight = FontWeight.SemiBold;

        var inspect = Ui.Button("Inspect", async () =>
        {
            error.Text = "";
            if (string.IsNullOrWhiteSpace(server.Text))
            {
                error.Text = "Enter a server name or address.";
                return;
            }

            var request = new TlsInspectRequest
            {
                Host = server.Text.Trim(), Port = (int)(port.Value ?? 443), Mode = mode.SelectedIndex == 1 ? TlsMode.SmtpStartTls : TlsMode.DirectTls,
                Sni = sni.Text ?? "", ExpectedName = expected.Text ?? "", Timeout = TimeSpan.FromSeconds((double)(timeout.Value ?? 10)),
                Revocation = revocation.SelectedIndex switch { 1 => X509RevocationMode.Offline, 2 => X509RevocationMode.NoCheck, _ => X509RevocationMode.Online },
            };
            verdict.IsVisible = false;
            await runner.RunAsync("Inspecting " + request.Host, async ct =>
            {
                var i = await TlsInspector.InspectAsync(request, ct);
                last = i;
                ToolKit.SetReport(report, TlsInspector.Report(i, DateTime.UtcNow));
                return i.Outcome == TlsInspectOutcome.Inspected ? $"{i.Protocol}, {i.CipherSuite} — {(i.Trusted ? "trusted" : "UNTRUSTED")}" : $"{i.Outcome}: {i.Detail}";
            });
            if (last is { Outcome: TlsInspectOutcome.Inspected } r)
            {
                verdict.IsVisible = true;
                Styling.Theme.SetState(verdict, r.Trusted ? "success" : "error");
                ((TextBlock)verdict.Child!).Text = r.Trusted
                    ? "✔ Trusted: the chain is valid on this computer and the name matches."
                    : "✖ UNTRUSTED: " + (r.ExpectedNameMatches == false ? "the name does not match; " : "") + (r.PolicyErrors != System.Net.Security.SslPolicyErrors.None ? r.PolicyErrors + ". " : "") + "Shown for diagnosis only.";
            }
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            inspect.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        var exportCert = Ui.Button("Export Certificate…", async () =>
        {
            if (last is not { Presented.Count: > 0 } r)
            {
                status.Text = "Inspect a server first.";
                return;
            }

            await ToolKit.SaveTextAsync(this, string.Concat(r.Presented.Select(c => c.Pem + "\n")), "certificate-chain.pem");
        });
        ToolTip.SetTip(exportCert, "Saves the certificates the server presented (PEM).");
        var actions = Ui.Row(inspect, cancel, ToolKit.CopyButton(this, () => report.Text ?? "", "Copy Report"), ToolKit.ExportButton(this, () => report.Text ?? "", "tls-report.txt", "Export Report…"), exportCert);
        var main = new DockPanel();
        DockPanel.SetDock(verdict, Dock.Top);
        verdict.Margin = new Thickness(0, 0, 0, 6);
        main.Children.Add(verdict);
        main.Children.Add(report);
        Content = ToolKit.Layout(f.Grid, actions, main, status);
        Closed += (_, _) => runner.Dispose();
    }
}
