using Avalonia;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using IPMaster.Core.Targets;
using IPMaster.Desktop.ViewModels;
using IPMaster.Infrastructure.Targets;

namespace IPMaster.Desktop.Views;

/// <summary>Manual "Get from Active Directory" (TGT-13): base domain, filter (presets), preview, add to ranges.</summary>
internal static class ActiveDirectoryWindow
{
    public static async Task<IReadOnlyList<string>?> ShowAsync(Window owner, MainWindowViewModel vm)
    {
        var w = Ui.Window("Import from Active Directory", 900, 600);
        var server = new TextBox { PlaceholderText = "domain controller or domain (empty = this computer's domain)", MinWidth = 300 };
        var baseDn = new TextBox { PlaceholderText = "DC=corp,DC=example,DC=com", MinWidth = 360 };
        var preset = Form.Combo(ActiveDirectoryFilters.Presets.Select(p => p.Name), 1);
        var text = new TextBox { PlaceholderText = "text", Width = 160, IsEnabled = false };
        var filter = new TextBox { Text = ActiveDirectoryFilters.Presets[1].Template, FontFamily = new FontFamily("Cascadia Mono, Consolas, monospace") };
        var credItems = new List<(Guid? Id, string Label)> { (null, "Current account") };
        credItems.AddRange(vm.Settings.Credentials.Select(c => ((Guid?)c.Id, c.Display)));
        var cred = Form.Combo(credItems.Select(c => c.Label), 0);
        var grid = Ui.Grid(("Name", "Name", 180), ("DNS Host Name", "DnsHostName", 280), ("Operating System", "OperatingSystem", 0));
        var status = new TextBlock { TextWrapping = TextWrapping.Wrap, Classes = { "status" } };
        void Rebuild()
        {
            var p = ActiveDirectoryFilters.Presets[Math.Max(0, preset.SelectedIndex)];
            text.IsEnabled = p.NeedsText;
            filter.Text = ActiveDirectoryFilters.Build(p, text.Text ?? "");
        }

        preset.SelectionChanged += (_, _) => Rebuild();
        text.TextChanged += (_, _) => Rebuild();
        Core.Security.ResolvedCredential? Credential() => credItems[Math.Max(0, cred.SelectedIndex)].Id is { } id ? vm.Vault.Credential(id) : null;

        IReadOnlyList<AdComputer> found = [];
        var detect = Ui.Button("Detect", async () =>
        {
            status.Text = "Reading the default naming context…";
            try
            {
                baseDn.Text = await ActiveDirectoryImport.DefaultBaseAsync(server.Text ?? "", Credential(), CancellationToken.None);
                status.Text = baseDn.Text.Length > 0 ? "Base detected." : "The directory did not report a default naming context.";
            }
            catch (Exception ex) when (ex is System.DirectoryServices.Protocols.LdapException or System.DirectoryServices.Protocols.DirectoryOperationException or InvalidOperationException
                                           or PlatformNotSupportedException or DllNotFoundException)
            {
                status.Text = "No directory reachable: " + ex.Message;
            }
        });
        var search = Ui.Button("Search", async () =>
        {
            if (ActiveDirectoryFilters.Validate(filter.Text ?? "") is { } err)
            {
                status.Text = err;
                return;
            }

            status.Text = "Searching…";
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                found = await ActiveDirectoryImport.SearchAsync(server.Text ?? "", baseDn.Text ?? "", filter.Text!, Credential(), cts.Token);
                grid.ItemsSource = found;
                status.Text = $"{found.Count} computer(s)" + (found.Count >= ActiveDirectoryImport.MaxResults ? " (limit reached)" : "") + ".";
            }
            catch (Exception ex) when (ex is System.DirectoryServices.Protocols.LdapException or System.DirectoryServices.Protocols.DirectoryOperationException
                                           or InvalidOperationException or ArgumentException or OperationCanceledException or PlatformNotSupportedException or DllNotFoundException)
            {
                status.Text = "Search failed: " + ex.Message;
            }
        }, accent: true);
        IReadOnlyList<string>? result = null;
        var add = Ui.Button("Add to Ranges", () =>
        {
            var chosen = grid.SelectedItems.Count > 0 ? grid.SelectedItems.OfType<AdComputer>().ToList() : found.ToList();
            result = chosen.Select(c => c.Target).Where(t => t.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            w.Close();
            return Task.CompletedTask;
        });
        var f = new Form();
        f.Add("Server", server);
        f.Add("Base", Form.WithButton(baseDn, detect));
        f.Add("Filter preset", Ui.Row(preset, text));
        f.Add("LDAP filter", filter);
        f.Add("Authentication", cred);
        f.Full(Form.Hint("LDAP with Negotiate (Kerberos/NTLM) signing and sealing. Host names are added as targets and resolved when the scan starts. Select rows to add only those."));
        w.Content = Ui.Layout(new StackPanel { Spacing = 8, Children = { f.Grid, Ui.Row(search) } }, grid,
            new StackPanel { Spacing = 6, Children = { status, Ui.Row(add, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })) } });
        await w.ShowDialog(owner);
        return result;
    }
}
