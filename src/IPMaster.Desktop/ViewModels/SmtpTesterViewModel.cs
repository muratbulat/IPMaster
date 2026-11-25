using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Text;
using Avalonia.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using IPMaster.Core.Security;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.ViewModels;

/// <summary>One row of the results summary. The outcome is a symbol plus a word (never colour alone).</summary>
public sealed record SmtpStageRow(string Stage, string Outcome, string Duration, string Summary, string Explanation, string Response, StageOutcome Raw);

public sealed record SmtpRecipientRow(string Address, string Result, string Code, string Response, string Explanation);

/// <summary>Choices of the Credential list: typed per session (index 0) or a Credential Manager entry.</summary>
public sealed record SmtpCredentialChoice(Guid? Id, string Display)
{
    public override string ToString() => Display;
}

/// <summary>Decision taken in the send confirmation.</summary>
public sealed record SmtpSendDecision(bool SendToAcceptedOnly);

/// <summary>Tools → SMTP Client Tester. Network work happens in <see cref="ISmtpTester"/>; this class holds UI state only.</summary>
public sealed partial class SmtpTesterViewModel : ObservableObject, IDisposable
{
    public static readonly IReadOnlyList<string> SecurityNames = ["None", "STARTTLS Required", "Implicit TLS"];
    public static readonly IReadOnlyList<string> AuthNames = ["None", "Username and Password"];
    public static readonly IReadOnlyList<string> BodyFormatNames = ["Plain Text", "HTML"];

    private readonly MainWindowViewModel _main;
    private readonly ISmtpTester _tester;
    private readonly ConcurrentQueue<SmtpLogEntry> _pending = new();
    private readonly StringBuilder _log = new();
    private readonly DispatcherTimer _flush;
    private CancellationTokenSource? _cts;

    public SmtpTesterViewModel(MainWindowViewModel main, ISmtpTester tester)
    {
        _main = main;
        _tester = tester;
        DefaultEhlo = SmtpMessages.DefaultEhloName();
        _flush = new DispatcherTimer(TimeSpan.FromMilliseconds(120), DispatcherPriority.Background, (_, _) => FlushLog());
        _flush.Start();
        RefreshProfiles();
        RefreshCredentials();
        foreach (var s in Enum.GetValues<SmtpStage>()) Stages.Add(Row(new StageResult(s, StageOutcome.NotRun, null, "")));
    }

    /// <summary>Asks the view to confirm a submission (summary text) and how to treat rejected recipients; null = cancelled.</summary>
    public Func<string, Task<SmtpSendDecision?>>? ConfirmSend { get; set; }

    public string DefaultEhlo { get; }

    // ---------------- connection ----------------
    [ObservableProperty] public partial string Server { get; set; } = "";
    [ObservableProperty] public partial decimal? Port { get; set; } = 587;
    [ObservableProperty] public partial int SecurityIndex { get; set; } = (int)SmtpConnectionSecurity.StartTlsRequired;
    [ObservableProperty] public partial decimal? ConnectTimeout { get; set; } = 15;
    [ObservableProperty] public partial decimal? OperationTimeout { get; set; } = 30;
    [ObservableProperty] public partial string EhloName { get; set; } = "";
    [ObservableProperty] public partial int AuthIndex { get; set; }
    [ObservableProperty] public partial string UserName { get; set; } = "";
    [ObservableProperty] public partial string Password { get; set; } = "";
    [ObservableProperty] public partial bool RevealPassword { get; set; }
    [ObservableProperty] public partial int MechanismIndex { get; set; }
    [ObservableProperty] public partial bool ValidateCertificate { get; set; } = true;
    [ObservableProperty] public partial bool AllowPlaintextAuth { get; set; }
    [ObservableProperty] public partial SmtpCredentialChoice? Credential { get; set; }

    public ObservableCollection<SmtpCredentialChoice> Credentials { get; } = [];

    public static IReadOnlyList<string> Mechanisms => SmtpText.Mechanisms;

    public bool UsesAuth => AuthIndex == (int)SmtpAuthMode.UsernamePassword;

    public bool TypedPassword => UsesAuth && Credential?.Id is null;

    public bool CertificateWarning => !ValidateCertificate;

    public bool PlaintextWarning => UsesAuth && AllowPlaintextAuth;

    public char PasswordChar => RevealPassword ? '\0' : '•';

    partial void OnAuthIndexChanged(int value)
    {
        OnPropertyChanged(nameof(UsesAuth));
        OnPropertyChanged(nameof(TypedPassword));
        OnPropertyChanged(nameof(PlaintextWarning));
    }

    partial void OnCredentialChanged(SmtpCredentialChoice? value)
    {
        OnPropertyChanged(nameof(TypedPassword));
        if (value?.Id is { } id && _main.Settings.Credentials.FirstOrDefault(c => c.Id == id) is { } c) UserName = c.UserName;
    }

    partial void OnValidateCertificateChanged(bool value) => OnPropertyChanged(nameof(CertificateWarning));

    partial void OnAllowPlaintextAuthChanged(bool value) => OnPropertyChanged(nameof(PlaintextWarning));

    partial void OnRevealPasswordChanged(bool value) => OnPropertyChanged(nameof(PasswordChar));

    /// <summary>Port presets: fill port and suggested security; both stay editable.</summary>
    public void ApplyPreset(int port)
    {
        Port = port;
        SecurityIndex = (int)SmtpText.SuggestedSecurity(port);
        Status = port switch
        {
            25 => "Port 25: server-to-server relay/MX. STARTTLS suggested; many networks block outbound port 25.",
            465 => "Port 465: message submission over implicit TLS.",
            _ => "Port 587: message submission with STARTTLS, usually with authentication.",
        };
    }

    // ---------------- message ----------------
    [ObservableProperty] public partial string EnvelopeSender { get; set; } = "";
    [ObservableProperty] public partial string EnvelopeRecipients { get; set; } = "";
    [ObservableProperty] public partial string From { get; set; } = "";
    [ObservableProperty] public partial string To { get; set; } = "";
    [ObservableProperty] public partial string Cc { get; set; } = "";
    [ObservableProperty] public partial string Bcc { get; set; } = "";
    [ObservableProperty] public partial string Subject { get; set; } = "";
    [ObservableProperty] public partial string Body { get; set; } = "";
    [ObservableProperty] public partial int BodyFormatIndex { get; set; }

    public ObservableCollection<string> Attachments { get; } = [];

    public string EnvelopePreview
    {
        get
        {
            var env = SmtpMessages.Build(Template(), false, out _);
            var sender = string.IsNullOrWhiteSpace(EnvelopeSender) ? env.Sender.Address + " (from From)" : env.Sender.Address;
            var rcpts = env.Recipients.Count == 0 ? "(none)" : string.Join(", ", env.Recipients.Select(r => r.Address));
            var notes = SmtpMessages.EnvelopeNotes(Template());
            return $"Envelope: MAIL FROM {sender}; RCPT TO {rcpts}{(string.IsNullOrWhiteSpace(EnvelopeRecipients) ? " (To + Cc + Bcc)" : "")}"
                   + (notes.Count > 0 ? " ⚠ " + string.Join(" ", notes) : "");
        }
    }

    partial void OnEnvelopeSenderChanged(string value) => OnPropertyChanged(nameof(EnvelopePreview));

    partial void OnEnvelopeRecipientsChanged(string value) => OnPropertyChanged(nameof(EnvelopePreview));

    partial void OnFromChanged(string value) => OnPropertyChanged(nameof(EnvelopePreview));

    partial void OnToChanged(string value) => OnPropertyChanged(nameof(EnvelopePreview));

    partial void OnCcChanged(string value) => OnPropertyChanged(nameof(EnvelopePreview));

    partial void OnBccChanged(string value) => OnPropertyChanged(nameof(EnvelopePreview));

    public void GenerateTestMessage()
    {
        var (subject, body, id) = SmtpText.GenerateTestMessage(DateTimeOffset.Now, Guid.NewGuid(), $"{Server}:{Port}", (SmtpBodyFormat)BodyFormatIndex);
        Subject = subject;
        Body = body;
        Status = $"Test message {id} generated.";
    }

    public SmtpMessageTemplate Template() => new()
    {
        EnvelopeSender = EnvelopeSender, EnvelopeRecipients = EnvelopeRecipients, From = From, To = To, Cc = Cc, Bcc = Bcc,
        Subject = Subject, Body = Body, BodyFormat = (SmtpBodyFormat)Math.Clamp(BodyFormatIndex, 0, 1), Attachments = Attachments.ToList(),
    };

    // ---------------- run state ----------------
    [ObservableProperty] public partial bool IsBusy { get; set; }
    [ObservableProperty] public partial string Status { get; set; } = "Ready";
    [ObservableProperty] public partial string ValidationText { get; set; } = "";
    [ObservableProperty] public partial string Summary { get; set; } = "";
    [ObservableProperty] public partial string LogText { get; set; } = "";

    public bool IsIdle => !IsBusy;

    partial void OnIsBusyChanged(bool value) => OnPropertyChanged(nameof(IsIdle));

    public ObservableCollection<SmtpStageRow> Stages { get; } = [];

    public ObservableCollection<SmtpRecipientRow> Recipients { get; } = [];

    /// <summary>Log already redacted at the source (<see cref="SmtpSessionLogger"/>); export uses the same text.</summary>
    public string ExportLog()
    {
        FlushLog();
        return _log.ToString();
    }

    public void ClearLog()
    {
        FlushLog();
        _log.Clear();
        LogText = "";
    }

    private void FlushLog()
    {
        if (_pending.IsEmpty) return;
        while (_pending.TryDequeue(out var e))
        {
            SmtpText.AppendBounded(_log, e.Format()); // bounded across all runs of this window (review S-05)
        }

        LogText = _log.ToString();
    }

    public Task TestConnectionAsync() => RunAsync(SmtpOperation.Connection);

    public Task TestRecipientsAsync() => RunAsync(SmtpOperation.Recipients);

    public Task SendAsync() => RunAsync(SmtpOperation.Send);

    public void Cancel()
    {
        if (_cts is not { IsCancellationRequested: false } cts) return;
        try
        {
            cts.Cancel();
            Status = "Cancelling…";
        }
        catch (ObjectDisposedException)
        {
            // the operation finished at the same moment
        }
    }

    /// <summary>Connection settings as a profile (no password).</summary>
    public SmtpProfile Connection() => new()
    {
        Server = Server.Trim(),
        Port = (int)(Port ?? 0),
        Security = (SmtpConnectionSecurity)Math.Clamp(SecurityIndex, 0, 2),
        ConnectTimeoutSeconds = (int)(ConnectTimeout ?? 15),
        OperationTimeoutSeconds = (int)(OperationTimeout ?? 30),
        EhloName = EhloName.Trim(),
        AuthMode = (SmtpAuthMode)Math.Clamp(AuthIndex, 0, 1),
        UserName = UserName.Trim(),
        CredentialId = Credential?.Id,
        Mechanism = SmtpText.Mechanisms[Math.Clamp(MechanismIndex, 0, SmtpText.Mechanisms.Count - 1)],
        ValidateCertificate = ValidateCertificate,
        AllowPlaintextAuth = AllowPlaintextAuth,
    };

    /// <summary>Actionable validation; empty = ready.</summary>
    public IReadOnlyList<string> Validate(SmtpOperation op)
    {
        var e = new List<string>();
        var host = Server.Trim().Trim('[', ']');
        if (host.Length == 0) e.Add("SMTP Server: enter a host name or an IPv4/IPv6 address.");
        else if (Uri.CheckHostName(host) == UriHostNameType.Unknown) e.Add($"SMTP Server: '{host}' is not a valid host name or IP address.");
        if (Port is not (>= 1 and <= 65535)) e.Add("Port: enter a number from 1 to 65535.");
        if (ConnectTimeout is not (>= 1 and <= 600)) e.Add("Connection Timeout: 1–600 seconds.");
        if (OperationTimeout is not (>= 1 and <= 600)) e.Add("Operation Timeout: 1–600 seconds.");
        if (EhloName.Trim().Length > 0 && Uri.CheckHostName(EhloName.Trim().Trim('[', ']')) == UriHostNameType.Unknown) e.Add("Local EHLO Name: enter a host name or an address literal.");
        if (UsesAuth)
        {
            if (UserName.Trim().Length == 0) e.Add("Username: required for authentication.");
            if (Credential?.Id is null && Password.Length == 0) e.Add("Password: type it (kept for this session only) or choose a stored credential.");
            if ((SmtpConnectionSecurity)SecurityIndex == SmtpConnectionSecurity.None && !AllowPlaintextAuth)
            {
                e.Add("Authentication over an unencrypted connection is disabled: choose STARTTLS Required or Implicit TLS (or tick the lab override).");
            }
        }

        if (op != SmtpOperation.Connection)
        {
            SmtpMessages.Build(Template(), op == SmtpOperation.Send, out var msgErrors, createMessage: false);
            e.AddRange(msgErrors);
        }

        return e;
    }

    private async Task RunAsync(SmtpOperation op)
    {
        if (IsBusy) return; // one operation per window
        var errors = Validate(op);
        ValidationText = string.Join(Environment.NewLine, errors);
        if (errors.Count > 0)
        {
            Status = "Fix the highlighted settings first.";
            return;
        }

        string? password = null;
        if (UsesAuth)
        {
            if (Credential?.Id is { } id)
            {
                try
                {
                    password = _main.Vault.Credential(id)?.Password;
                }
                catch (InvalidOperationException ex)
                {
                    ValidationText = "The stored credential cannot be read: " + ex.Message;
                    return;
                }

                if (password is null)
                {
                    ValidationText = "The stored credential no longer exists; choose another one.";
                    return;
                }
            }
            else
            {
                password = Password;
            }
        }

        var decision = new SmtpSendDecision(false);
        if (op == SmtpOperation.Send)
        {
            var env = SmtpMessages.Build(Template(), true, out _, createMessage: false);
            var summary = $"Submit this message to {Server.Trim()}:{Port} ({SecurityNames[SecurityIndex]})?\n\n"
                          + $"Envelope sender: {env.Sender.Address}\nRecipients ({env.Recipients.Count}): {string.Join(", ", env.Recipients.Select(r => r.Address))}\n"
                          + $"Subject: {Subject}\nAttachments: {Attachments.Count}\n\nThe server's acceptance does not prove delivery to the inbox.";
            if (ConfirmSend is null || await ConfirmSend(summary) is not { } d)
            {
                Status = "Send cancelled; nothing was sent.";
                return;
            }

            decision = d;
        }

        IsBusy = true;
        Recipients.Clear();
        Summary = "";
        for (var i = 0; i < Stages.Count; i++) Stages[i] = Row(new StageResult((SmtpStage)i, StageOutcome.NotRun, null, ""));
        Status = op switch { SmtpOperation.Connection => "Testing the connection…", SmtpOperation.Recipients => "Testing recipient acceptance…", _ => "Sending the test message…" };
        _cts = new CancellationTokenSource();
        try
        {
            var request = new SmtpTestRequest
            {
                Operation = op, Connection = Connection(), Password = password, Message = Template(), SendToAcceptedOnly = decision.SendToAcceptedOnly,
            };
            var report = await Task.Run(() => _tester.RunAsync(request, _pending.Enqueue, _cts.Token));
            FlushLog();
            for (var i = 0; i < Stages.Count; i++) Stages[i] = Row(report.Stages[i]);
            foreach (var r in report.Recipients)
            {
                Recipients.Add(new SmtpRecipientRow(r.Address, r.Accepted ? "✔ Accepted" : "✖ Rejected", r.EnhancedCode is null ? r.Code.ToString(System.Globalization.CultureInfo.InvariantCulture) : $"{r.Code} {r.EnhancedCode}", r.Response, r.Explanation ?? ""));
            }

            Summary = SummaryText(report);
            var rejected = report.Recipients.Count(r => !r.Accepted);
            Status = report.Succeeded && rejected > 0 && op == SmtpOperation.Send ? $"Finished: submitted to the accepted recipients only; {rejected} recipient(s) were rejected." : report.Succeeded ? "Finished: all stages passed." : report.Stages.Any(s => s.Outcome == StageOutcome.Cancelled) ? "Cancelled." : "Finished with failures — see the explanations.";
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // the tester reports every failure as a stage; this only guards the async-void button handler (review S-02)
            FlushLog();
            Summary = "✖ The test stopped on an unexpected error: " + ex.Message;
            Status = "Stopped on an unexpected error.";
        }
        finally
        {
            _cts.Dispose();
            _cts = null;
            IsBusy = false;
        }
    }

    private static string SummaryText(SmtpTestReport r)
    {
        var failed = r.Stages.FirstOrDefault(s => s.Outcome == StageOutcome.Failed);
        var cancelled = r.Stages.FirstOrDefault(s => s.Outcome == StageOutcome.Cancelled);
        var sb = new StringBuilder();
        sb.Append(failed is not null ? "✖ " : cancelled is not null ? "■ " : "✔ ").Append(r.Operation switch
        {
            SmtpOperation.Connection => "Connection test",
            SmtpOperation.Recipients => "Envelope acceptance check (no DATA sent; acceptance does not guarantee relay authorisation or delivery)",
            _ => "Test email",
        }).Append(System.Globalization.CultureInfo.CurrentCulture, $" — {r.Elapsed.TotalSeconds:0.00} s.");
        if (failed is not null) sb.Append(System.Globalization.CultureInfo.CurrentCulture, $" Failed at {SmtpText.StageName(failed.Stage)}: {failed.Explanation ?? failed.Summary}");
        else if (cancelled is not null) sb.Append(System.Globalization.CultureInfo.CurrentCulture, $" Cancelled at {SmtpText.StageName(cancelled.Stage)}. {cancelled.Explanation}");
        if (r.Operation == SmtpOperation.Send && r.FinalResponse is { } f) sb.Append(System.Globalization.CultureInfo.CurrentCulture, $" Server reply: {f}{(r.QueueId is { } q ? $" (queue id {q})" : "")}. Acceptance does not prove inbox delivery.");
        if (r.Operation != SmtpOperation.Send) sb.Append(r.DataSent ? " (!) DATA was sent." : " No message content was sent.");
        return sb.ToString();
    }

    private static SmtpStageRow Row(StageResult s) => new(
        SmtpText.StageName(s.Stage),
        s.Outcome switch
        {
            StageOutcome.Success => "✔ Success",
            StageOutcome.Warning => "⚠ Warning",
            StageOutcome.Failed => "✖ Failed",
            StageOutcome.Skipped => "– Skipped",
            StageOutcome.Cancelled => "■ Cancelled",
            _ => "· Not run",
        },
        s.Duration is { } d ? $"{d.TotalMilliseconds:0} ms" : "",
        s.Summary,
        s.Explanation ?? "",
        s.ServerResponse ?? "",
        s.Outcome);

    // ---------------- profiles ----------------
    public ObservableCollection<string> ProfileNames { get; } = [];

    [ObservableProperty] public partial string? SelectedProfile { get; set; }
    [ObservableProperty] public partial bool SaveMessageWithProfile { get; set; }

    public void RefreshProfiles()
    {
        var keep = SelectedProfile;
        ProfileNames.Clear();
        foreach (var p in _main.Settings.Tools.SmtpProfiles.OrderBy(p => p.Name, StringComparer.CurrentCultureIgnoreCase)) ProfileNames.Add(p.Name);
        SelectedProfile = keep is not null && ProfileNames.Contains(keep) ? keep : null;
    }

    public void RefreshCredentials()
    {
        var keep = Credential?.Id;
        Credentials.Clear();
        Credentials.Add(new SmtpCredentialChoice(null, "Typed below (this session only, not saved)"));
        foreach (var c in _main.Settings.Credentials) Credentials.Add(new SmtpCredentialChoice(c.Id, $"Credential Manager: {c.Display}"));
        Credential = Credentials.FirstOrDefault(c => c.Id == keep) ?? Credentials[0];
    }

    public void LoadProfile(string name)
    {
        if (_main.Settings.Tools.SmtpProfiles.FirstOrDefault(p => p.Name == name) is not { } p) return;
        Server = p.Server;
        Port = p.Port;
        SecurityIndex = (int)p.Security;
        ConnectTimeout = p.ConnectTimeoutSeconds;
        OperationTimeout = p.OperationTimeoutSeconds;
        EhloName = p.EhloName;
        AuthIndex = (int)p.AuthMode;
        Password = "";
        RefreshCredentials();
        Credential = Credentials.FirstOrDefault(c => c.Id == p.CredentialId) ?? Credentials[0];
        UserName = p.UserName;
        MechanismIndex = Math.Max(0, SmtpText.Mechanisms.ToList().IndexOf(p.Mechanism));
        ValidateCertificate = p.ValidateCertificate;
        AllowPlaintextAuth = p.AllowPlaintextAuth;
        SaveMessageWithProfile = p.Message is not null;
        if (p.Message is { } m)
        {
            EnvelopeSender = m.EnvelopeSender;
            EnvelopeRecipients = m.EnvelopeRecipients;
            From = m.From;
            To = m.To;
            Cc = m.Cc;
            Bcc = m.Bcc;
            Subject = m.Subject;
            Body = m.Body;
            BodyFormatIndex = (int)m.BodyFormat;
            Attachments.Clear();
            foreach (var a in m.Attachments) Attachments.Add(a);
        }

        SelectedProfile = name;
        Status = $"Profile '{name}' loaded{(p.CredentialId is null && p.AuthMode == SmtpAuthMode.UsernamePassword ? "; type the password (passwords are never saved in profiles)" : "")}.";
    }

    /// <summary>Saves the current settings under a name (replacing a profile of that name). The password is never stored.</summary>
    public async Task SaveProfileAsync(string name)
    {
        name = name.Trim();
        if (name.Length == 0) return;
        var profile = Connection() with { Name = name, Message = SaveMessageWithProfile ? Template() : null };
        await _main.UpdateSettingsAsync(s => s with
        {
            Tools = s.Tools with { SmtpProfiles = s.Tools.SmtpProfiles.Where(p => p.Name != name).Append(profile).ToList() },
        });
        RefreshProfiles();
        SelectedProfile = name;
        Status = $"Profile '{name}' saved{(TypedPassword ? " without the password (session only)" : "")}.";
    }

    public async Task<string?> RenameProfileAsync(string oldName, string newName)
    {
        newName = newName.Trim();
        if (newName.Length == 0 || newName == oldName) return null;
        if (_main.Settings.Tools.SmtpProfiles.Any(p => p.Name == newName)) return $"A profile named '{newName}' already exists.";
        await _main.UpdateSettingsAsync(s => s with
        {
            Tools = s.Tools with { SmtpProfiles = s.Tools.SmtpProfiles.Select(p => p.Name == oldName ? p with { Name = newName } : p).ToList() },
        });
        RefreshProfiles();
        SelectedProfile = newName;
        return null;
    }

    public async Task DeleteProfileAsync(string name)
    {
        await _main.UpdateSettingsAsync(s => s with { Tools = s.Tools with { SmtpProfiles = s.Tools.SmtpProfiles.Where(p => p.Name != name).ToList() } });
        RefreshProfiles();
        Status = $"Profile '{name}' deleted.";
    }

    /// <summary>Stores the typed password in the Credential Manager (encrypted by the vault) and selects it.</summary>
    public async Task<string?> SavePasswordToCredentialManagerAsync()
    {
        if (UserName.Trim().Length == 0 || Password.Length == 0) return "Enter the username and password first.";
        try
        {
            _main.EnsureVaultKey();
            var c = new StoredCredential
            {
                UserName = UserName.Trim(), Secret = _main.Vault.Protect(Password), Comment = $"SMTP {Server.Trim()}:{Port}",
            };
            await _main.SaveCredentialsAsync(_main.Settings.Credentials.Append(c).ToList());
            RefreshCredentials();
            Credential = Credentials.First(x => x.Id == c.Id);
            Password = "";
            Status = "Password stored in the Credential Manager (encrypted); profiles refer to it without containing it.";
            return null;
        }
        catch (InvalidOperationException ex)
        {
            return "The Credential Manager cannot store secrets right now: " + ex.Message;
        }
    }

    public void Dispose()
    {
        _flush.Stop();
        _cts?.Cancel();
        Password = "";
    }
}
