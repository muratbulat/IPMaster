using Avalonia.Controls;
using Avalonia.Interactivity;
using IPMaster.Core.Queries;
using IPMaster.Core.Security;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>Phase 4: query managers, credential manager, master password, single-column rescan.</summary>
public partial class MainWindow
{
    private void OnQueryManager(object? sender, RoutedEventArgs e)
    {
        if (Vm is null || (sender as MenuItem)?.Tag is not string tag) return;
        new QueryManagerWindow(Vm, Enum.Parse<QueryKind>(tag)).Show(this);
    }

    private async void OnCredentialManager(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        await CredentialManagerWindow.ShowAsync(this, Vm);
    }

    /// <summary>Startup: the settings file is encrypted (SEC-02). Cancel keeps defaults and never overwrites the file.</summary>
    private async Task UnlockAtStartupAsync()
    {
        if (Vm is not { NeedsMasterPassword: true }) return;
        var message = "The configuration is protected by a master password.";
        while (true)
        {
            var pw = await PasswordDialog.AskAsync(this, "Master Password", message, confirm: false);
            if (pw is null)
            {
                Vm.StatusText = "Configuration locked: defaults are shown and nothing is saved until you restart and enter the master password.";
                return;
            }

            if (await Vm.UnlockAsync(pw)) return;
            message = "Wrong password. Try again.";
        }
    }

    private async void OnSetMasterPassword(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (Vm.NeedsMasterPassword)
        {
            await ShowMessageAsync("Master Password", "The configuration is locked. Restart IPMaster and enter the current master password first.");
            return;
        }

        var pw = await PasswordDialog.AskAsync(this, "Set Master Password",
            "The configuration file (ranges, queries, credentials) will be encrypted with this password (AES-256-GCM, PBKDF2 600,000 iterations). It is needed at every start; " +
            "the command line accepts /mpass:- (stdin) or the IPMASTER_MPASS variable. A forgotten password cannot be recovered.", confirm: true);
        if (pw is null) return;
        try
        {
            await Vm.SetMasterPasswordAsync(pw);
            Vm.StatusText = "Master password set; the configuration is now encrypted.";
        }
        catch (InvalidOperationException ex)
        {
            await ShowMessageAsync("Master Password", ex.Message);
        }
    }

    private async void OnRemoveMasterPassword(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        if (Vm.Settings.Vault.Mode != VaultMode.MasterPassword)
        {
            await ShowMessageAsync("Master Password", "No master password is set.");
            return;
        }

        if (!await ConfirmAsync("Remove Master Password", "Store the configuration unencrypted again? Credentials stay encrypted with a key protected by Windows for your account (not portable).")) return;
        try
        {
            await Vm.RemoveMasterPasswordAsync();
            Vm.StatusText = "Master password removed.";
        }
        catch (InvalidOperationException ex)
        {
            await ShowMessageAsync("Master Password", ex.Message);
        }
    }

    private async void OnImportActiveDirectory(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var targets = await ActiveDirectoryWindow.ShowAsync(this, Vm);
        if (targets is not { Count: > 0 }) return;
        Vm.SetRanges(targets.Select(t => new RangeEntryViewModel { Target = t, Comment = "Active Directory" }).ToList(), append: true);
        Vm.StatusText = $"Added {targets.Count} computer(s) from Active Directory.";
    }

    /// <summary>Context menu "Rescan Column": reruns one query column for the selected devices (SCN-04).</summary>
    private void AddQueryRescanItems(ContextMenu menu, IReadOnlyList<DeviceNode> nodes, Func<string, Action, MenuItem> item)
    {
        if (Vm is null) return;
        var queries = Vm.Settings.Queries.Enabled.ToList();
        if (queries.Count == 0) return;
        var root = new MenuItem { Header = "Rescan Column" };
        foreach (var group in queries.GroupBy(q => q.Kind).OrderBy(g => g.Key))
        {
            foreach (var q in group)
            {
                var id = q.Id;
                root.Items.Add(item($"{QueryColumns.DisplayName(q.Kind)}: {q.Name}", async () => await Vm.RescanColumnAsync(nodes.Select(n => n.Result).ToList(), id)));
            }
        }

        menu.Items.Add(root);
    }
}
