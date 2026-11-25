using System.DirectoryServices.Protocols;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using IPMaster.Core.Results;
using IPMaster.Core.Targets;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → LDAP / Active Directory Tester (D-077). Read-only: bind, RootDSE and paged search.</summary>
internal sealed class LdapTesterWindow : Window
{
    public LdapTesterWindow(string? target = null)
    {
        Title = "LDAP / Active Directory Tester";
        Width = 1150;
        Height = 820;
        MinWidth = 640;
        MinHeight = 480;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        LdapResult? last = null;

        var server = ToolKit.Text("Server", "domain controller or LDAP server", 320, target ?? "");
        var port = ToolKit.Number(389, 1, 65535, "Port");
        var security = ToolKit.Combo("Connection security", ["None (unencrypted)", "STARTTLS", "LDAPS"], 1, 200);
        security.SelectionChanged += (_, _) =>
        {
            if (security.SelectedIndex == 2 && port.Value == 389) port.Value = 636;
            if (security.SelectedIndex != 2 && port.Value == 636) port.Value = 389;
        };
        var bind = ToolKit.Combo("Bind", ["Anonymous", "Simple (DN or user@domain + password)", "Integrated (Windows: Kerberos/NTLM)"], 2, 300);
        var user = ToolKit.Text("User", "CN=…,DC=… or user@domain (integrated: empty = current account)", 380);
        var password = ToolKit.Text("Password", "session only; never saved, shown or exported", 260);
        password.PasswordChar = '•';
        var allowPlain = new CheckBox { Content = "Allow a password over an unencrypted connection (this window only)" };
        var pin = ToolKit.Text("Accepted certificate SHA-256", "optional: SHA-256 of one certificate to accept", 520);
        pin.FontFamily = ToolKit.Mono;
        var timeout = ToolKit.Number(15, 1, 300, "Timeout in seconds");
        var baseDn = ToolKit.Text("Base DN", "e.g. DC=corp,DC=example,DC=com (Read RootDSE fills it)", 460);
        var scope = ToolKit.Combo("Scope", ["Base", "One level", "Subtree"], 2, 140);
        var filter = ToolKit.Text("Filter", "(objectClass=*)", text: "(objectClass=*)");
        filter.FontFamily = ToolKit.Mono;
        var attributes = ToolKit.Text("Attributes", "comma-separated; empty = all user attributes", 460, "cn, name, dNSHostName, objectClass, whenChanged");
        var pageSize = ToolKit.Number(200, 1, 5000, "Page size");
        var maxEntries = ToolKit.Number(1000, 1, LdapTester.MaxEntriesLimit, "Maximum entries");
        var quickAttr = ToolKit.Text("Value search attribute", "attribute", 160, "cn");
        var quickValue = ToolKit.Text("Value search text", "literal value (special characters are escaped)", 280);
        var quick = Ui.Button("Use as Filter", () =>
        {
            filter.Text = $"({(quickAttr.Text ?? "cn").Trim()}={ActiveDirectoryFilters.Escape(quickValue.Text ?? "")})";
            return Task.CompletedTask;
        });
        ToolTip.SetTip(quick, "Builds an equality filter; * ( ) \\ and NUL in the value are escaped (RFC 4515), so they match literally.");

        var f = new Form();
        f.Add("Server / Port", Ui.Row(server, port));
        f.Add("Security / Timeout (s)", Ui.Row(security, timeout));
        f.Add("Bind", bind);
        f.Add("User / Password", Ui.Row(user, password));
        f.Full(allowPlain);
        f.Add("Certificate Exception", pin);
        var sf = new Form();
        sf.Add("Base DN / Scope", Ui.Row(baseDn, scope));
        sf.Add("Filter", filter);
        sf.Add("Value Search", Ui.Row(quickAttr, quickValue, quick));
        sf.Add("Attributes", attributes);
        sf.Add("Page Size / Max Entries", Ui.Row(pageSize, maxEntries));
        f.Full(Form.Hint("Read-only: binds and searches only, nothing in the directory is changed. Referrals are not followed. Server certificates are validated (trust chain and name); "
                         + "the only exception is the exact certificate entered above. Secret attributes (passwords, LAPS, BitLocker keys) are never shown."));
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
        var plainWarning = Ui.Banner("⚠ A simple bind over an unencrypted connection sends the password readable on the network.", "warning", visible: false);
        void UpdateWarning() => plainWarning.IsVisible = allowPlain.IsChecked == true && security.SelectedIndex == 0 && bind.SelectedIndex == 1;
        allowPlain.IsCheckedChanged += (_, _) => UpdateWarning();
        security.SelectionChanged += (_, _) => UpdateWarning();
        bind.SelectionChanged += (_, _) => UpdateWarning();
        f.Full(plainWarning);

        var dns = new ListBox { MinWidth = 280 };
        Avalonia.Automation.AutomationProperties.SetName(dns, "Entries");
        var details = ToolKit.ReportBox("Entry attributes");
        dns.SelectionChanged += (_, _) =>
        {
            if (last is null || dns.SelectedIndex < 0 || dns.SelectedIndex >= last.Entries.Count) return;
            var e = last.Entries[dns.SelectedIndex];
            details.Text = "dn: " + (e.Dn.Length == 0 ? "(RootDSE)" : e.Dn) + "\n" + string.Join("\n", e.Attributes.SelectMany(a => a.Values.Select(v => $"{a.Name}: {v}")));
        };
        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("2*,6,3*") };
        split.Children.Add(dns);
        var splitter = new GridSplitter { ResizeDirection = GridResizeDirection.Columns };
        Grid.SetColumn(splitter, 1);
        split.Children.Add(splitter);
        Grid.SetColumn(details, 2);
        split.Children.Add(details);
        var summary = new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, FontWeight = FontWeight.SemiBold, Margin = new Thickness(0, 0, 0, 6) };
        Avalonia.Automation.AutomationProperties.SetLiveSetting(summary, Avalonia.Automation.AutomationLiveSetting.Polite);
        var main = new DockPanel();
        DockPanel.SetDock(summary, Dock.Top);
        DockPanel.SetDock(error, Dock.Top);
        main.Children.Add(error);
        main.Children.Add(summary);
        main.Children.Add(split);

        LdapProfile? Profile()
        {
            error.Text = "";
            if (string.IsNullOrWhiteSpace(server.Text))
            {
                error.Text = "Enter a server.";
                return null;
            }

            return new LdapProfile
            {
                Server = server.Text.Trim(), Port = (int)(port.Value ?? 0), Security = (LdapSecurity)security.SelectedIndex, Bind = (LdapBindKind)bind.SelectedIndex,
                User = user.Text ?? "", Password = password.Text ?? "", AllowPlaintextPassword = allowPlain.IsChecked == true, PinnedSha256 = LdapTester.NormalizeThumbprint(pin.Text ?? ""),
                Timeout = TimeSpan.FromSeconds((double)(timeout.Value ?? 15)),
            };
        }

        void Show(LdapResult r)
        {
            last = r;
            summary.Text = $"{r.Outcome}" + (r.Detail.Length > 0 ? " — " + r.Detail : "") + (r.Pages > 0 ? $"  ·  {r.Entries.Count:N0} entries, {r.Pages} page(s)" : "") + $"  ·  {r.Duration.TotalMilliseconds:0} ms";
            if (r.Outcome is LdapOutcome.Success or LdapOutcome.NoEntries) Styling.Theme.SetState(summary, null);
            else Styling.Theme.SetState(summary, "error");
            dns.ItemsSource = r.Entries.Select(e => e.Dn.Length == 0 ? "(RootDSE)" : e.Dn).ToList();
            details.Text = "";
            if (r.Entries.Count > 0) dns.SelectedIndex = 0;
        }

        async Task Run(string what, Func<LdapProfile, CancellationToken, Task<LdapResult>> op)
        {
            if (Profile() is not { } p) return;
            LdapResult? result = null;
            await runner.RunAsync(what, async ct =>
            {
                result = await op(p, ct);
                return result.Outcome.ToString();
            });
            if (result is not null) Show(result);
        }

        var test = Ui.Button("Test Bind", () => Run("Binding", LdapTester.BindTestAsync));
        var rootDse = Ui.Button("Read RootDSE", async () =>
        {
            await Run("Reading RootDSE", LdapTester.RootDseAsync);
            if (last is { Outcome: LdapOutcome.Success, Entries: [var dse, ..] } && string.IsNullOrWhiteSpace(baseDn.Text))
            {
                var nc = dse.Attributes.FirstOrDefault(a => a.Name.Equals("defaultNamingContext", StringComparison.OrdinalIgnoreCase))
                         ?? dse.Attributes.FirstOrDefault(a => a.Name.Equals("namingContexts", StringComparison.OrdinalIgnoreCase));
                if (nc is { Values: [var first, ..] }) baseDn.Text = first;
            }
        });
        var search = Ui.Button("Search", () =>
        {
            var spec = new LdapSearchSpec
            {
                BaseDn = baseDn.Text ?? "", Scope = scope.SelectedIndex switch { 0 => SearchScope.Base, 1 => SearchScope.OneLevel, _ => SearchScope.Subtree },
                Filter = filter.Text ?? "", Attributes = (attributes.Text ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                PageSize = (int)(pageSize.Value ?? 200), MaxEntries = (int)(maxEntries.Value ?? 1000),
            };
            if (ActiveDirectoryFilters.Validate(spec.Filter) is { } problem)
            {
                error.Text = problem;
                return Task.CompletedTask;
            }

            return Run("Searching", (p, ct) => LdapTester.SearchAsync(p, spec, ct));
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            test.IsEnabled = rootDse.IsEnabled = search.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        var exportCsv = Ui.Button("Export CSV…", async () =>
        {
            if (last is not { Entries.Count: > 0 } r) return;
            var names = r.Entries.SelectMany(e => e.Attributes.Select(a => a.Name)).Distinct(StringComparer.OrdinalIgnoreCase).Take(200).ToList();
            using var w = new StringWriter(System.Globalization.CultureInfo.InvariantCulture);
            CsvExporter.WriteRow(w, ["dn", .. names], ',', protectFormulas: true);
            foreach (var e in r.Entries)
            {
                CsvExporter.WriteRow(w, [e.Dn, .. names.Select(n => string.Join("; ", e.Attributes.FirstOrDefault(a => a.Name.Equals(n, StringComparison.OrdinalIgnoreCase))?.Values ?? []))], ',',
                    protectFormulas: true);
            }

            await ToolKit.SaveTextAsync(this, w.ToString(), "ldap-results.csv");
        });
        var actions = Ui.Row(test, rootDse, search, cancel, ToolKit.CopyButton(this, () => last is null ? "" : LdapTester.Report(last), "Copy Report"),
            ToolKit.ExportButton(this, () => last is null ? "" : LdapTester.Report(last), "ldap-report.txt", "Export Report…"), exportCsv);
        Content = ToolKit.Layout(new TabControl { Classes = { "compact" }, Items = { new TabItem { Header = "Connection", Content = f.Grid }, new TabItem { Header = "Search", Content = sf.Grid } } }, actions, main, status);
        Closed += (_, _) => runner.Dispose();
    }
}
