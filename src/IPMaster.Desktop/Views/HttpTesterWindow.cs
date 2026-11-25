using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → HTTP / API Tester (D-076). Nothing is sent until Send is pressed.</summary>
internal sealed class HttpTesterWindow : Window
{
    public HttpTesterWindow(string? target = null)
    {
        Title = "HTTP / API Tester";
        Width = 1100;
        Height = 800;
        MinWidth = 620;
        MinHeight = 460;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var tester = new HttpApiTester();
        HttpTestResult? last = null;

        var method = ToolKit.Combo("Method", HttpApiTester.Methods, 0, 110);
        var host = target is not null && System.Net.IPAddress.TryParse(target, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? $"[{target}]" : target;
        var url = ToolKit.Text("URL", "https://host/path", text: host is null ? "" : $"http://{host}/");
        url.FontFamily = ToolKit.Mono;

        static TextBox Lines(string name, string placeholder)
        {
            var t = ToolKit.Text(name, placeholder);
            t.AcceptsReturn = true;
            t.TextWrapping = TextWrapping.NoWrap;
            t.FontFamily = ToolKit.Mono;
            t.MinHeight = 120;
            return t;
        }

        var parameters = Lines("Query parameters", "one per line: name=value");
        var headers = Lines("Request headers", "one per line: Name: value");
        var auth = ToolKit.Combo("Authentication", ["None", "Basic", "Bearer token"], 0, 180);
        var user = ToolKit.Text("User name", "", 240);
        var secret = ToolKit.Text("Password or token", "session only; never saved or shown in reports", 360);
        secret.PasswordChar = '•';
        var bodyKind = ToolKit.Combo("Body type", ["None", "Text", "JSON", "Form (urlencoded)", "Multipart form"], 0, 200);
        var body = Lines("Body", "text or JSON; for forms one field per line: name=value (multipart: name=@C:\\path\\file)");
        var timeout = ToolKit.Number(30, 1, 600, "Timeout in seconds");
        var redirects = ToolKit.Number(5, 0, 20, "Redirect limit");
        var proxy = ToolKit.Combo("Proxy", ["System proxy", "No proxy", "Custom proxy"], 0, 180);
        var proxyUrl = ToolKit.Text("Proxy URL", "http://proxy:8080", 260);
        var cookies = new CheckBox { Content = "Keep session cookies (this window only)" };
        var validate = new CheckBox { Content = "Validate server certificate", IsChecked = true };
        var maxBody = ToolKit.Number(10, 1, 200, "Response size limit in MB");

        var authForm = new Form();
        authForm.Add("Type", auth);
        authForm.Add("User Name (Basic)", user);
        authForm.Add("Password / Token", secret);
        authForm.Full(Form.Hint("Credentials are kept for this session only and are removed from requests that a redirect sends to another origin. Reports and exports never contain them."));
        var bodyPanel = new DockPanel();
        var bodyTop = Ui.Row(bodyKind);
        DockPanel.SetDock(bodyTop, Dock.Top);
        bodyTop.Margin = new Thickness(0, 0, 0, 6);
        bodyPanel.Children.Add(bodyTop);
        bodyPanel.Children.Add(body);
        var settings = new Form();
        settings.Add("Timeout (s) / Redirects", Ui.Row(timeout, redirects));
        settings.Add("Proxy", Ui.Row(proxy, proxyUrl));
        settings.Add("Response Limit (MB)", maxBody);
        settings.Full(cookies);
        settings.Full(validate);
        settings.Full(Form.Hint("Requests are never retried automatically. A redirect that would resend a POST/PUT/PATCH/DELETE body (307/308) is shown, not followed."));
        var requestTabs = new TabControl
        {
            Classes = { "compact" }, MinHeight = 190,
            Items =
            {
                new TabItem { Header = "Parameters", Content = parameters },
                new TabItem { Header = "Headers", Content = headers },
                new TabItem { Header = "Authentication", Content = authForm.Grid },
                new TabItem { Header = "Body", Content = bodyPanel },
                new TabItem { Header = "Settings", Content = settings.Grid },
            },
        };

        var certBanner = Ui.Banner("⚠ Certificate validation is OFF: any server certificate is accepted for these requests.", "warning", visible: false);
        validate.IsCheckedChanged += (_, _) => certBanner.IsVisible = validate.IsChecked != true;

        var responseBody = ToolKit.ReportBox("Response body");
        responseBody.TextWrapping = TextWrapping.Wrap;
        var responseHeaders = ToolKit.ReportBox("Response headers");
        var timing = ToolKit.ReportBox("Timing");
        var redirectsBox = ToolKit.ReportBox("Redirects");
        var diagnostics = ToolKit.ReportBox("Diagnostics");
        var pretty = new ToggleButton { Content = "Formatted JSON", IsChecked = true };
        var search = ToolKit.Text("Search in body", "search", 220);
        search.KeyDown += (_, e) =>
        {
            if (e.Key != Avalonia.Input.Key.Enter || string.IsNullOrEmpty(search.Text) || responseBody.Text is not { } text) return;
            var from = responseBody.SelectionEnd;
            var at = text.IndexOf(search.Text, from, StringComparison.OrdinalIgnoreCase);
            if (at < 0) at = text.IndexOf(search.Text, StringComparison.OrdinalIgnoreCase);
            if (at >= 0)
            {
                responseBody.SelectionStart = at;
                responseBody.SelectionEnd = at + search.Text.Length;
                responseBody.CaretIndex = at + search.Text.Length;
                responseBody.Focus();
            }

            e.Handled = true;
        };
        void ShowBody()
        {
            if (last is not null) responseBody.Text = HttpApiTester.FormatBody(last, pretty.IsChecked == true);
        }

        pretty.IsCheckedChanged += (_, _) => ShowBody();
        var saveBody = Ui.Button("Save Body…", async () =>
        {
            if (last is not { Body.Length: > 0 } r) return;
            var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Save Response Body", SuggestedFileName = "response.bin" });
            if (file?.TryGetLocalPath() is { } p) await File.WriteAllBytesAsync(p, r.Body); // raw bytes, also for binary content
        });
        var bodyBar = Ui.Row(pretty, search, ToolKit.CopyButton(this, () => responseBody.Text ?? "", "Copy Body"), saveBody);
        var bodyTab = new DockPanel();
        DockPanel.SetDock(bodyBar, Dock.Top);
        bodyBar.Margin = new Thickness(0, 0, 0, 6);
        bodyTab.Children.Add(bodyBar);
        bodyTab.Children.Add(responseBody);
        var responseTabs = new TabControl
        {
            Classes = { "compact" },
            Items =
            {
                new TabItem { Header = "Body", Content = bodyTab },
                new TabItem { Header = "Headers", Content = responseHeaders },
                new TabItem { Header = "Timing", Content = timing },
                new TabItem { Header = "Redirects", Content = redirectsBox },
                new TabItem { Header = "Diagnostics", Content = diagnostics },
            },
        };
        var summary = new SelectableTextBlock { FontWeight = FontWeight.SemiBold, FontSize = 15, TextWrapping = TextWrapping.Wrap };
        AutomationProperties.SetLiveSetting(summary, AutomationLiveSetting.Polite);

        static List<KeyValuePair<string, string>> Pairs(string? text, char sep) =>
            (text ?? "").Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Trim().Length > 0)
                .Select(l => l.IndexOf(sep, StringComparison.Ordinal) is var i and > 0 ? new KeyValuePair<string, string>(l[..i].Trim(), l[(i + 1)..].Trim()) : new KeyValuePair<string, string>(l.Trim(), "")).ToList();

        var send = Ui.Button("Send", async () =>
        {
            var kind = (HttpBodyKind)bodyKind.SelectedIndex;
            var request = new HttpTestRequest
            {
                Method = (string)method.SelectedItem!, Url = url.Text ?? "", Parameters = Pairs(parameters.Text, '='), Headers = Pairs(headers.Text, ':'),
                Auth = (HttpAuthKind)auth.SelectedIndex, UserName = user.Text ?? "", Secret = secret.Text ?? "", BodyKind = kind,
                BodyText = kind is HttpBodyKind.Text or HttpBodyKind.Json ? body.Text ?? "" : "", Form = kind is HttpBodyKind.FormUrlEncoded or HttpBodyKind.Multipart ? Pairs(body.Text, '=') : [],
                Timeout = TimeSpan.FromSeconds((double)(timeout.Value ?? 30)), MaxRedirects = (int)(redirects.Value ?? 5), Proxy = (HttpProxyMode)proxy.SelectedIndex,
                ProxyUrl = proxyUrl.Text ?? "", UseCookies = cookies.IsChecked == true, ValidateCertificate = validate.IsChecked == true,
                MaxResponseBytes = (long)(maxBody.Value ?? 10) * 1024 * 1024,
            };
            await runner.RunAsync($"{request.Method} {HttpApiTester.Redact(request.Url)}", async ct =>
            {
                var r = await tester.SendAsync(request, ct);
                last = r;
                var report = HttpApiTester.Report(request, r);
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    summary.Text = r.Outcome == HttpTestOutcome.Response
                        ? $"{r.Status} {r.Reason}  ·  {r.Version}  ·  {r.Body.Length:N0} bytes  ·  {r.Total.TotalMilliseconds:0} ms" + (r.Status >= 400 ? "  ·  HTTP error response" : "")
                        : $"No response: {r.Outcome} — {r.Detail}";
                    if (r.Outcome != HttpTestOutcome.Response || r.Status >= 400) Styling.Theme.SetState(summary, "error");
                    else Styling.Theme.SetState(summary, null); // null would draw nothing; clearing restores the theme colour
                    ShowBody();
                    responseHeaders.Text = HttpApiTester.HeadersText(r);
                    timing.Text = report.Split('\n').FirstOrDefault(l => l.StartsWith("Total:", StringComparison.Ordinal)) + "\n\nDetailed DNS/TLS phases are not shown: .NET does not expose them reliably per request.";
                    redirectsBox.Text = r.Redirects.Count == 0 ? "No redirects." : string.Join('\n', r.Redirects.Select(h => $"{h.Method} {h.Url}\n   → {h.Status} {h.Location}{(h.Note.Length > 0 ? "\n   " + h.Note : "")}"));
                    diagnostics.Text = report;
                });
                return r.Outcome == HttpTestOutcome.Response ? "Response received." : r.Outcome.ToString();
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
            send.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        var line = new DockPanel();
        var left = Ui.Row(method);
        DockPanel.SetDock(left, Dock.Left);
        left.Margin = new Thickness(0, 0, 8, 0);
        var right = Ui.Row(send, cancel, ToolKit.ExportButton(this, () => diagnostics.Text ?? "", "http-report.txt", "Export Report…"));
        DockPanel.SetDock(right, Dock.Right);
        right.Margin = new Thickness(8, 0, 0, 0);
        line.Children.Add(left);
        line.Children.Add(right);
        line.Children.Add(url);

        var top = new StackPanel { Spacing = 8, Children = { line, certBanner, requestTabs } };
        var main = new DockPanel();
        DockPanel.SetDock(summary, Dock.Top);
        summary.Margin = new Thickness(0, 4, 0, 4);
        main.Children.Add(summary);
        main.Children.Add(responseTabs);
        Content = Ui.Layout(top, main, status);
        Closed += (_, _) =>
        {
            runner.Dispose();
            tester.Dispose();
        };
    }
}
