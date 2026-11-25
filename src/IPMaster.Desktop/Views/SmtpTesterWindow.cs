using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Tools;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → SMTP Client Tester: non-modal utility window. All network work runs in the view-model's tester service.</summary>
internal sealed class SmtpTesterWindow : Window
{
    private static readonly FontFamily Mono = new("Cascadia Mono, Consolas, Menlo, monospace");
    private readonly SmtpTesterViewModel _vm;

    public SmtpTesterWindow(SmtpTesterViewModel vm)
    {
        _vm = vm;
        DataContext = vm;
        Title = "SMTP Client Tester";
        Width = 1240;
        Height = 860;
        MinWidth = 820;
        MinHeight = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        vm.ConfirmSend = ConfirmSendAsync;

        var left = new DockPanel();
        var actions = Actions();
        DockPanel.SetDock(actions, Dock.Bottom);
        left.Children.Add(actions);
        left.Children.Add(new TabControl { Items = { new TabItem { Header = "Connection", Content = Scroll(ConnectionForm()) }, new TabItem { Header = "Message", Content = Scroll(MessageForm()) } } });

        var root = new Grid { ColumnDefinitions = new ColumnDefinitions("540,6,*"), Margin = new Thickness(12, 0, 12, 0) };
        root.Children.Add(left);
        var splitter = new GridSplitter { ResizeDirection = GridResizeDirection.Columns, Background = Brushes.Transparent };
        Grid.SetColumn(splitter, 1);
        root.Children.Add(splitter);
        var right = Results();
        Grid.SetColumn(right, 2);
        root.Children.Add(right);

        var dock = new DockPanel();
        var top = Profiles();
        DockPanel.SetDock(top, Dock.Top);
        dock.Children.Add(top);
        var banner = Banner("⚠ Certificate validation is OFF for this profile: any server certificate is accepted. Use only for diagnostics; other features and profiles are not affected.", nameof(vm.CertificateWarning));
        DockPanel.SetDock(banner, Dock.Top);
        dock.Children.Add(banner);
        var lab = Banner("⚠ Lab override: credentials may be sent over an UNENCRYPTED connection. Use only on an isolated test network.", nameof(vm.PlaintextWarning));
        DockPanel.SetDock(lab, Dock.Top);
        dock.Children.Add(lab);
        var status = new Border
        {
            Padding = new Thickness(12, 4),
            BorderThickness = new Thickness(0, 1, 0, 0),
            Child = Bound(new TextBlock { TextWrapping = TextWrapping.Wrap }, TextBlock.TextProperty, nameof(vm.Status)),
        };
        status.Bind(Border.BorderBrushProperty, status.GetResourceObservable("SystemControlForegroundBaseLowBrush"));
        DockPanel.SetDock(status, Dock.Bottom);
        dock.Children.Add(status);
        dock.Children.Add(root);
        Content = dock;

        Closed += (_, _) => vm.Dispose();
        vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(vm.LogText)) ScrollLogToEnd();
        };
        KeyDown += (_, e) =>
        {
            if (e.Key == Avalonia.Input.Key.Escape && vm.IsBusy)
            {
                vm.Cancel();
                e.Handled = true;
            }
        };
    }

    private TextBox? _logBox;

    // ---------------- binding helpers ----------------
    private static T Bound<T>(T control, AvaloniaProperty property, string path, BindingMode mode = BindingMode.OneWay) where T : Control
    {
        control.Bind(property, new Binding(path) { Mode = mode });
        return control;
    }

    private static TextBox Text(string path, string name, string placeholder = "", bool multiline = false, double height = double.NaN)
    {
        var t = new TextBox { PlaceholderText = placeholder, AcceptsReturn = multiline, TextWrapping = multiline ? TextWrapping.Wrap : TextWrapping.NoWrap, Height = height };
        AutomationProperties.SetName(t, name);
        return Bound(t, TextBox.TextProperty, path, BindingMode.TwoWay);
    }

    private static NumericUpDown Number(string path, string name, decimal min, decimal max)
    {
        var n = new NumericUpDown { Minimum = min, Maximum = max, Increment = 1, FormatString = "0", Width = 140, HorizontalAlignment = HorizontalAlignment.Left };
        AutomationProperties.SetName(n, name);
        return Bound(n, NumericUpDown.ValueProperty, path, BindingMode.TwoWay);
    }

    private static ComboBox Combo(IEnumerable<string> items, string path, string name)
    {
        var c = new ComboBox { ItemsSource = items.ToList(), MinWidth = 220 };
        AutomationProperties.SetName(c, name);
        return Bound(c, SelectingItemsControl.SelectedIndexProperty, path, BindingMode.TwoWay);
    }

    private static CheckBox Check(string text, string path)
    {
        var c = new CheckBox { Content = text };
        return Bound(c, ToggleButton.IsCheckedProperty, path, BindingMode.TwoWay);
    }

    private static Control Scroll(Control c) => new ScrollViewer { Content = c, Padding = new Thickness(0, 8, 12, 8) };

    private static Border Banner(string text, string visiblePath)
    {
        var b = Ui.Banner(text, "warning");
        b.Margin = new Thickness(12, 0, 12, 6);
        AutomationProperties.SetName(b, text);
        return Bound(b, IsVisibleProperty, visiblePath);
    }

    // ---------------- profiles ----------------
    private Control Profiles()
    {
        var combo = new ComboBox { ItemsSource = _vm.ProfileNames, MinWidth = 240, PlaceholderText = "(no profile)" };
        AutomationProperties.SetName(combo, "Profile");
        Bound(combo, SelectingItemsControl.SelectedItemProperty, nameof(_vm.SelectedProfile), BindingMode.TwoWay);
        var row = Ui.Row(
            new TextBlock { Text = "Profile", VerticalAlignment = VerticalAlignment.Center },
            combo,
            Ui.Button("Load", () =>
            {
                if (_vm.SelectedProfile is { } n) _vm.LoadProfile(n);
                return Task.CompletedTask;
            }),
            Ui.Button("Save", async () =>
            {
                var name = _vm.SelectedProfile ?? await Dialogs.PromptAsync(this, "Save Profile", "Profile name:", _vm.Server.Trim());
                if (!string.IsNullOrWhiteSpace(name)) await _vm.SaveProfileAsync(name);
            }),
            Ui.Button("Save As…", async () =>
            {
                if (await Dialogs.PromptAsync(this, "Save Profile As", "Profile name:", _vm.SelectedProfile ?? _vm.Server.Trim()) is { } name) await _vm.SaveProfileAsync(name);
            }),
            Ui.Button("Rename…", async () =>
            {
                if (_vm.SelectedProfile is not { } old) return;
                if (await Dialogs.PromptAsync(this, "Rename Profile", "New name:", old) is { } name && await _vm.RenameProfileAsync(old, name) is { } error)
                {
                    await Dialogs.MessageAsync(this, "Rename Profile", error, false);
                }
            }),
            Ui.Button("Delete", async () =>
            {
                if (_vm.SelectedProfile is { } n && await Dialogs.MessageAsync(this, "Delete Profile", $"Delete the profile '{n}'?", true)) await _vm.DeleteProfileAsync(n);
            }),
            Check("Include message fields in the profile", nameof(_vm.SaveMessageWithProfile)));
        row.Margin = new Thickness(12, 10, 12, 8);
        foreach (var c in row.Children.OfType<Control>()) c.VerticalAlignment = VerticalAlignment.Center;
        return Bound(row, IsEnabledProperty, nameof(_vm.IsIdle));
    }

    // ---------------- connection ----------------
    private Control ConnectionForm()
    {
        var f = new Form();
        f.Add("SMTP Server", Text(nameof(_vm.Server), "SMTP Server", "mail.example.com, 192.0.2.10 or 2001:db8::25"));
        var presets = Ui.Row(Number(nameof(_vm.Port), "Port", 1, 65535));
        foreach (var p in new[] { 25, 587, 465 })
        {
            var b = new Button { Content = p.ToString(System.Globalization.CultureInfo.InvariantCulture) };
            ToolTip.SetTip(b, p switch { 25 => "Relay / MX (STARTTLS)", 587 => "Submission (STARTTLS)", _ => "Submission (implicit TLS)" });
            AutomationProperties.SetName(b, $"Preset port {p}");
            b.Click += (_, _) => _vm.ApplyPreset(p);
            presets.Children.Add(b);
        }

        f.Add("Port", presets);
        f.Add("Connection Security", Combo(SmtpTesterViewModel.SecurityNames, nameof(_vm.SecurityIndex), "Connection Security"));
        f.Add("Connection Timeout (s)", Number(nameof(_vm.ConnectTimeout), "Connection Timeout in seconds", 1, 600));
        f.Add("Operation Timeout (s)", Number(nameof(_vm.OperationTimeout), "Operation Timeout in seconds", 1, 600));
        f.Add("Local EHLO Name", Text(nameof(_vm.EhloName), "Local EHLO Name", $"default: {_vm.DefaultEhlo}"));
        f.Add("Authentication", Combo(SmtpTesterViewModel.AuthNames, nameof(_vm.AuthIndex), "Authentication"));

        var cred = new ComboBox { ItemsSource = _vm.Credentials, HorizontalAlignment = HorizontalAlignment.Stretch };
        AutomationProperties.SetName(cred, "Password source");
        Bound(cred, SelectingItemsControl.SelectedItemProperty, nameof(_vm.Credential), BindingMode.TwoWay);
        f.Add("Password Source", Bound(cred, IsEnabledProperty, nameof(_vm.UsesAuth)));
        f.Add("Username", Bound(Text(nameof(_vm.UserName), "Username"), IsEnabledProperty, nameof(_vm.UsesAuth)));

        var pass = Text(nameof(_vm.Password), "Password");
        Bound(pass, TextBox.PasswordCharProperty, nameof(_vm.PasswordChar));
        pass.Width = 220;
        var reveal = new ToggleButton { Content = "Show" };
        AutomationProperties.SetName(reveal, "Show password");
        Bound(reveal, ToggleButton.IsCheckedProperty, nameof(_vm.RevealPassword), BindingMode.TwoWay);
        var store = Ui.Button("Save to Credential Manager…", async () =>
        {
            if (await _vm.SavePasswordToCredentialManagerAsync() is { } error) await Dialogs.MessageAsync(this, "Credential Manager", error, false);
        });
        ToolTip.SetTip(store, "Encrypts the password in IPMaster's Credential Manager so a profile can refer to it. Profiles never contain passwords.");
        f.Add("Password", Bound(Ui.Row(pass, reveal), IsEnabledProperty, nameof(_vm.TypedPassword)));
        f.Add("", Bound(store, IsEnabledProperty, nameof(_vm.TypedPassword)));
        var mech = new ComboBox { ItemsSource = SmtpTesterViewModel.Mechanisms, MinWidth = 220 };
        AutomationProperties.SetName(mech, "Authentication Mechanism");
        Bound(mech, SelectingItemsControl.SelectedIndexProperty, nameof(_vm.MechanismIndex), BindingMode.TwoWay);
        f.Add("Authentication Mechanism", Bound(mech, IsEnabledProperty, nameof(_vm.UsesAuth)));
        f.Full(Check("Validate Server Certificate", nameof(_vm.ValidateCertificate)));
        f.Full(Bound(Check("Allow password authentication over an unencrypted connection (isolated lab diagnostics only)", nameof(_vm.AllowPlaintextAuth)), IsEnabledProperty, nameof(_vm.UsesAuth)));
        f.Full(Form.Hint("TLS validates the certificate against, and sends SNI for, the name entered in SMTP Server. Connecting by IP address usually fails the certificate name check — the result explains it. "
                         + "STARTTLS Required never falls back to plaintext. Auto chooses the strongest password mechanism the server offers; OAuth (XOAUTH2/OAUTHBEARER) is not supported."));
        return f.Grid;
    }

    // ---------------- message ----------------
    private Control MessageForm()
    {
        var f = new Form();
        f.Add("Envelope Sender", Text(nameof(_vm.EnvelopeSender), "Envelope Sender", "default: the From address"));
        f.Add("Envelope Recipients", Text(nameof(_vm.EnvelopeRecipients), "Envelope Recipients", "default: To + Cc + Bcc (separate with , or ;)"));
        f.Full(Bound(new TextBlock { TextWrapping = TextWrapping.Wrap, Classes = { "hint" } }, TextBlock.TextProperty, nameof(_vm.EnvelopePreview)));
        f.Add("From", Text(nameof(_vm.From), "From", "Name <sender@example.com>"));
        f.Add("To", Text(nameof(_vm.To), "To", "one or more addresses"));
        f.Add("Cc", Text(nameof(_vm.Cc), "Cc"));
        f.Add("Bcc", Text(nameof(_vm.Bcc), "Bcc", "envelope only: never written to the headers"));
        f.Add("Subject", Text(nameof(_vm.Subject), "Subject"));
        var body = Text(nameof(_vm.Body), "Message Body", "", multiline: true, height: 170);
        body.FontFamily = Mono;
        f.Add("Message Body", body);
        f.Add("Body Format", Combo(SmtpTesterViewModel.BodyFormatNames, nameof(_vm.BodyFormatIndex), "Body Format"));

        var list = new ListBox { ItemsSource = _vm.Attachments, Height = 90 };
        AutomationProperties.SetName(list, "Attachments");
        var add = Ui.Button("Add…", async () =>
        {
            var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Add Attachments", AllowMultiple = true });
            foreach (var file in files)
            {
                if (file.TryGetLocalPath() is { } p && !_vm.Attachments.Contains(p)) _vm.Attachments.Add(p);
            }
        });
        var remove = Ui.Button("Remove", () =>
        {
            if (list.SelectedItem is string s) _vm.Attachments.Remove(s);
            return Task.CompletedTask;
        });
        var att = new DockPanel();
        var buttons = new StackPanel { Spacing = 4, Margin = new Thickness(6, 0, 0, 0), Children = { add, remove } };
        DockPanel.SetDock(buttons, Dock.Right);
        att.Children.Add(buttons);
        att.Children.Add(list);
        f.Add("Attachments", att);
        var gen = Ui.Button("Generate Test Message", () =>
        {
            _vm.GenerateTestMessage();
            return Task.CompletedTask;
        });
        ToolTip.SetTip(gen, "Fills Subject and Body with a clearly marked diagnostic message, a timestamp and a unique test id.");
        f.Full(gen);
        f.Full(Form.Hint("Envelope addresses default to the message fields; override them to test MAIL FROM / RCPT TO separately. Bcc recipients are only in the envelope. Message content and attachments are summarised in the log, not logged."));
        return f.Grid;
    }

    // ---------------- actions ----------------
    private Control Actions()
    {
        Button Act(string text, Func<Task> run, string tip, bool accent = false)
        {
            var b = Ui.Button(text, run, accent);
            ToolTip.SetTip(b, tip);
            return Bound(b, IsEnabledProperty, nameof(_vm.IsIdle));
        }

        var cancel = Ui.Button("Cancel", () =>
        {
            _vm.Cancel();
            return Task.CompletedTask;
        });
        ToolTip.SetTip(cancel, "Stop the running operation and close the connection (Esc).");
        Bound(cancel, IsEnabledProperty, nameof(_vm.IsBusy));
        var row = new WrapPanel { Margin = new Thickness(0, 8, 12, 10) };
        foreach (var b in new Control[]
                 {
                     Act("Test Connection", _vm.TestConnectionAsync, "DNS, TCP, greeting/EHLO, TLS and authentication. Sends no MAIL FROM, RCPT TO or message."),
                     Act("Test Recipient Acceptance", _vm.TestRecipientsAsync, "MAIL FROM and RCPT TO for each recipient, then RSET. Never sends DATA."),
                     Act("Send Test Email", _vm.SendAsync, "Submits the message after a confirmation showing the server and recipients.", accent: true),
                     cancel,
                 })
        {
            b.Margin = new Thickness(0, 0, 8, 4);
            row.Children.Add(b);
        }

        var validation = Bound(new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 12, 0) }, TextBlock.TextProperty, nameof(_vm.ValidationText));
        AutomationProperties.SetLiveSetting(validation, AutomationLiveSetting.Assertive);
        return new StackPanel { Children = { validation, row } };
    }

    // ---------------- results and log ----------------
    private Control Results()
    {
        var summary = Bound(new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, FontWeight = FontWeight.SemiBold, Margin = new Thickness(0, 4, 0, 6) }, TextBlock.TextProperty, nameof(_vm.Summary));
        AutomationProperties.SetLiveSetting(summary, AutomationLiveSetting.Polite);
        var stageList = new ItemsControl { ItemsSource = _vm.Stages, ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<SmtpStageRow>((r, _) => StageRow(r), supportsRecycling: false) };
        var stages = new Border
        {
            BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(4), Padding = new Thickness(8, 4),
            Child = new ScrollViewer { Content = stageList },
        };
        stages.Bind(Border.BorderBrushProperty, stages.GetResourceObservable("SystemControlForegroundBaseLowBrush"));
        AutomationProperties.SetName(stageList, "Results by stage");
        var recipients = new ItemsControl { ItemsSource = _vm.Recipients, ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<SmtpRecipientRow>((r, _) => RecipientRow(r), supportsRecycling: false) };
        AutomationProperties.SetName(recipients, "Recipients");
        var recipientsBox = new DockPanel { Children = { Header("Recipients") } };
        DockPanel.SetDock(recipientsBox.Children[0], Dock.Top);
        recipientsBox.Children.Add(new ScrollViewer { Content = recipients });
        _vm.Recipients.CollectionChanged += (_, _) => recipientsBox.IsVisible = _vm.Recipients.Count > 0;
        recipientsBox.IsVisible = false;

        _logBox = new TextBox
        {
            IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, FontFamily = Mono, FontSize = 12,
        };
        ScrollViewer.SetHorizontalScrollBarVisibility(_logBox, ScrollBarVisibility.Auto);
        AutomationProperties.SetName(_logBox, "SMTP Session Log");
        Bound(_logBox, TextBox.TextProperty, nameof(_vm.LogText));
        var logHeader = new DockPanel { Margin = new Thickness(0, 8, 0, 4) };
        var logButtons = Ui.Row(
            Ui.Button("Copy Log", () => Ui.CopyAsync(this, _vm.ExportLog())),
            Ui.Button("Save Log…", SaveLogAsync),
            Ui.Button("Clear Log", () =>
            {
                _vm.ClearLog();
                return Task.CompletedTask;
            }));
        DockPanel.SetDock(logButtons, Dock.Right);
        logHeader.Children.Add(logButtons);
        var logTitle = new TextBlock { Text = "SMTP Session Log", FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center };
        ToolTip.SetTip(logTitle, "Passwords, authentication data and message content are never recorded; Copy and Save export the same redacted text.");
        logHeader.Children.Add(logTitle);

        var g = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,2*,Auto,Auto,3*"), Margin = new Thickness(0, 8, 0, 0) };
        void Put(Control c, int row)
        {
            Grid.SetRow(c, row);
            g.Children.Add(c);
        }

        Put(Header("Results"), 0);
        Put(summary, 1);
        Put(stages, 2);
        recipientsBox.MaxHeight = 170;
        recipientsBox.Margin = new Thickness(0, 6, 0, 0);
        Put(recipientsBox, 3);
        Put(logHeader, 4);
        Put(_logBox, 5);
        return g;
    }

    /// <summary>Stage | result | time on one line; details, explanation and the server's own reply wrap below.</summary>
    private static Control StageRow(SmtpStageRow? r)
    {
        if (r is null) return new TextBlock();
        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("230,120,*") };
        var stage = new TextBlock { Text = r.Stage, FontWeight = FontWeight.SemiBold };
        var result = new TextBlock { Text = r.Outcome, FontWeight = r.Raw == StageOutcome.Failed ? FontWeight.Bold : FontWeight.Normal };
        if (r.Raw == StageOutcome.Failed) Styling.Theme.SetState(result, "error");
        Grid.SetColumn(result, 1);
        var time = new TextBlock { Text = r.Duration, Classes = { "label" } };
        Grid.SetColumn(time, 2);
        head.Children.Add(stage);
        head.Children.Add(result);
        head.Children.Add(time);
        var panel = new StackPanel { Margin = new Thickness(0, 3, 0, 5), Children = { head } };
        if (r.Summary.Length > 0) panel.Children.Add(new SelectableTextBlock { Text = r.Summary, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(14, 1, 0, 0) });
        if (r.Explanation.Length > 0) panel.Children.Add(new SelectableTextBlock { Text = "→ " + r.Explanation, TextWrapping = TextWrapping.Wrap, FontStyle = FontStyle.Italic, Margin = new Thickness(14, 1, 0, 0) });
        if (r.Response.Length > 0) panel.Children.Add(new SelectableTextBlock { Text = "Server: " + r.Response, TextWrapping = TextWrapping.Wrap, FontFamily = Mono, FontSize = 12, Classes = { "label" }, Margin = new Thickness(14, 1, 0, 0) });
        AutomationProperties.SetName(panel, $"{r.Stage}: {r.Outcome}. {r.Summary} {r.Explanation}");
        return panel;
    }

    private static Control RecipientRow(SmtpRecipientRow? r)
    {
        if (r is null) return new TextBlock();
        var head = new Grid { ColumnDefinitions = new ColumnDefinitions("230,120,*") };
        var result = new TextBlock { Text = r.Result };
        if (r.Result.Contains("Rejected", StringComparison.Ordinal)) Styling.Theme.SetState(result, "error");
        Grid.SetColumn(result, 1);
        var code = new TextBlock { Text = r.Code, FontFamily = Mono };
        Grid.SetColumn(code, 2);
        head.Children.Add(new TextBlock { Text = r.Address, FontWeight = FontWeight.SemiBold });
        head.Children.Add(result);
        head.Children.Add(code);
        var panel = new StackPanel { Margin = new Thickness(0, 2, 0, 4), Children = { head } };
        panel.Children.Add(new SelectableTextBlock { Text = "Server: " + r.Response, TextWrapping = TextWrapping.Wrap, FontFamily = Mono, FontSize = 12, Classes = { "label" }, Margin = new Thickness(14, 1, 0, 0) });
        if (r.Explanation.Length > 0) panel.Children.Add(new SelectableTextBlock { Text = "→ " + r.Explanation, TextWrapping = TextWrapping.Wrap, FontStyle = FontStyle.Italic, Margin = new Thickness(14, 1, 0, 0) });
        AutomationProperties.SetName(panel, $"{r.Address}: {r.Result}, {r.Response}. {r.Explanation}");
        return panel;
    }

    private static TextBlock Header(string text) => new() { Text = text, FontWeight = FontWeight.SemiBold, Margin = new Thickness(0, 0, 0, 4) };

    private void ScrollLogToEnd()
    {
        if (_logBox?.Text is { } t) _logBox.CaretIndex = t.Length;
    }

    private async Task SaveLogAsync()
    {
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Save SMTP Session Log",
            SuggestedFileName = $"smtp-session-{DateTime.Now:yyyyMMdd-HHmmss}.log",
            DefaultExtension = "log",
            FileTypeChoices = [new FilePickerFileType("Log file") { Patterns = ["*.log", "*.txt"] }],
        });
        if (file is null) return;
        await using var s = await file.OpenWriteAsync();
        s.SetLength(0);
        await using var w = new StreamWriter(s, new System.Text.UTF8Encoding(false));
        await w.WriteAsync(_vm.ExportLog()); // the same redacted text the window shows
        _vm.Status = "Log saved (secrets were never recorded).";
    }

    private async Task<SmtpSendDecision?> ConfirmSendAsync(string summary)
    {
        var d = Ui.Window("Send Test Email", 560, 360);
        d.Height = double.NaN;
        d.MinHeight = 0;
        d.SizeToContent = SizeToContent.Height;
        d.ShowInTaskbar = false;
        var partial = new CheckBox { Content = "If some recipients are rejected, send to the accepted recipients anyway" };
        ToolTip.SetTip(partial, "Default: abort before DATA when any recipient is rejected, so nothing is submitted.");
        SmtpSendDecision? result = null;
        var send = Ui.Button("Send", () =>
        {
            result = new SmtpSendDecision(partial.IsChecked == true);
            d.Close();
            return Task.CompletedTask;
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            d.Close();
            return Task.CompletedTask;
        });
        cancel.IsCancel = true;
        d.Content = new StackPanel
        {
            Margin = new Thickness(16), Spacing = 12,
            Children = { new SelectableTextBlock { Text = summary, TextWrapping = TextWrapping.Wrap }, partial, Ui.Row(send, cancel) },
        };
        d.Opened += (_, _) => cancel.Focus();
        await d.ShowDialog(this);
        return result;
    }
}
