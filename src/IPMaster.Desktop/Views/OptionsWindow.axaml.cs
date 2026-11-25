using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using IPMaster.Core.Management;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

public partial class OptionsWindow : Window
{
    private static readonly System.Text.Json.JsonSerializerOptions Indented = new() { WriteIndented = true };

    public OptionsWindow()
    {
        InitializeComponent();
        Tabs.Items.Add(BuildShortcutsTab());
        FindSetting.KeyDown += (_, e) =>
        {
            if (e.Key != Avalonia.Input.Key.Enter) return;
            FindNextSetting();
            e.Handled = true; // Enter here searches; it does not press OK
        };
        FindSetting.TextChanged += (_, _) => FindNextSetting(); // live: the first match as you type; Enter = next
    }

    private OptionsViewModel? Vm => DataContext as OptionsViewModel;

    private void OnOk(object? sender, RoutedEventArgs e)
    {
        if (Vm?.Validate() is { } error)
        {
            ErrorText.Text = error;
            return;
        }

        Close(true);
    }

    private void OnCancel(object? sender, RoutedEventArgs e) => Close(false);

    private async void OnEditApplications(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var list = await Dialogs.ManageListAsync(this, "Applications", Vm.Applications, a => a.Name, a => a.CommandLine + (a.Hotkey.Length > 0 ? $"   [{a.Hotkey}]" : ""),
            (a, n) => a with { Name = n },
            new Dialogs.ListTransfer<ExternalApplication>(l => System.Text.Json.JsonSerializer.Serialize(l, Indented),
                t => System.Text.Json.JsonSerializer.Deserialize<List<ExternalApplication>>(t) ?? []),
            (w, existing, _) => EditApplicationAsync(w, existing));
        if (list is null) return;
        Vm.Applications = list.ToList();
        Vm.RefreshApplicationsSummary();
    }

    private async void OnEditVariables(object? sender, RoutedEventArgs e)
    {
        if (Vm is null) return;
        var list = await Dialogs.ManageListAsync(this, "Variables", Vm.Variables, v => v.Name,
            v => v.FromEnvironment ? $"environment variable %{v.Value}%" : "text (value hidden)", (v, n) => v with { Name = n },
            new Dialogs.ListTransfer<GlobalVariable>(l => System.Text.Json.JsonSerializer.Serialize(l, Indented),
                t => System.Text.Json.JsonSerializer.Deserialize<List<GlobalVariable>>(t) ?? []),
            (w, existing, _) => EditVariableAsync(w, existing));
        if (list is null) return;
        Vm.Variables = list.ToList();
        Vm.RefreshApplicationsSummary();
    }

    private static async Task<ExternalApplication?> EditApplicationAsync(Window owner, ExternalApplication? existing)
    {
        var w = Ui.Window("Application", 640, 260);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var name = new TextBox { Text = existing?.Name ?? "", PlaceholderText = "RDP tools | Remote Desktop" };
        var cmd = new TextBox { Text = existing?.CommandLine ?? "", PlaceholderText = "mstsc /v:%0", FontFamily = new FontFamily("Consolas, Menlo, monospace") };
        var hotkey = new TextBox { Text = existing?.Hotkey ?? "", PlaceholderText = "e.g. Ctrl+Shift+R", Width = 180 };
        var error = new TextBlock { Classes = { "error" } };
        ExternalApplication? result = null;
        var ok = Ui.Button("OK", () =>
        {
            if (string.IsNullOrWhiteSpace(name.Text) || string.IsNullOrWhiteSpace(cmd.Text))
            {
                error.Text = "Name and command line are required.";
                return Task.CompletedTask;
            }

            if (!string.IsNullOrWhiteSpace(hotkey.Text))
            {
                try
                {
                    Avalonia.Input.KeyGesture.Parse(hotkey.Text.Trim());
                }
                catch (ArgumentException)
                {
                    error.Text = "Hotkey must look like Ctrl+Shift+R or F6.";
                    return Task.CompletedTask;
                }
            }

            result = new ExternalApplication { Name = name.Text.Trim(), CommandLine = cmd.Text.Trim(), Hotkey = hotkey.Text?.Trim() ?? "" };
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        w.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(16), Spacing = 8,
            Children =
            {
                new TextBlock { Text = "Name" }, name, new TextBlock { Text = "Command line" }, cmd,
                Ui.Row(new TextBlock { Text = "Hotkey", VerticalAlignment = Avalonia.Layout.VerticalAlignment.Center }, hotkey),
                error, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })),
            },
        };
        await w.ShowDialog(owner);
        return result;
    }

    private static async Task<GlobalVariable?> EditVariableAsync(Window owner, GlobalVariable? existing)
    {
        var w = Ui.Window("Variable", 460, 240);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var name = new TextBox { Text = existing?.Name ?? "" };
        var value = new TextBox { Text = existing?.Value ?? "" };
        var env = new CheckBox { Content = "Value is the name of an environment variable", IsChecked = existing?.FromEnvironment == true };
        var error = new TextBlock { Classes = { "error" } };
        GlobalVariable? result = null;
        var ok = Ui.Button("OK", () =>
        {
            if (string.IsNullOrWhiteSpace(name.Text) || name.Text.Any(c => c is '{' or '}' or '$'))
            {
                error.Text = "Enter a name without braces or $.";
                return Task.CompletedTask;
            }

            result = new GlobalVariable { Name = name.Text.Trim(), Value = value.Text ?? "", FromEnvironment = env.IsChecked == true };
            w.Close();
            return Task.CompletedTask;
        }, accent: true);
        w.Content = new StackPanel
        {
            Margin = new Avalonia.Thickness(16), Spacing = 8,
            Children =
            {
                new TextBlock { Text = "Name (use as {$Name})" }, name, new TextBlock { Text = "Value" }, value, env,
                new TextBlock
                {
                    Classes = { "hint", "warning" },
                    Text = "Values are stored in the settings file in plain text; use environment variables (or the credential manager, planned) for secrets.",
                },
                error, Ui.Row(ok, Ui.Button("Cancel", () => { w.Close(); return Task.CompletedTask; })),
            },
        };
        await w.ShowDialog(owner);
        return result;
    }
}
