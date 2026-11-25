using Avalonia.Input.Platform;
using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;

namespace IPMaster.Desktop.Views;

internal static partial class Dialogs
{
    private static Grid Form(params (string Label, Control Field)[] rows)
    {
        var g = new Grid { ColumnDefinitions = new ColumnDefinitions("Auto,*"), RowSpacing = 6, ColumnSpacing = 10 };
        for (var i = 0; i < rows.Length; i++)
        {
            g.RowDefinitions.Add(new RowDefinition(GridLength.Auto));
            var l = new TextBlock { Text = rows[i].Label, VerticalAlignment = VerticalAlignment.Center };
            Grid.SetRow(l, i);
            Grid.SetRow(rows[i].Field, i);
            Grid.SetColumn(rows[i].Field, 1);
            g.Children.Add(l);
            g.Children.Add(rows[i].Field);
        }

        return g;
    }

    /// <summary>Manual "Assign Friendly Name": name plus associated data fields.</summary>
    public static async Task<FriendlyEntry?> FriendlyEntryAsync(Window owner, FriendlyEntry entry, IReadOnlyList<string> parameters, bool keyEditable)
    {
        var w = Shell("Friendly Name", 480, 300);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var key = new TextBox { Text = entry.Key, IsReadOnly = !keyEditable };
        var name = new TextBox { Text = entry.Name };
        var fields = parameters.Select(p => (p, new TextBox { Text = entry.Data.GetValueOrDefault(p) ?? "" })).ToList();
        var rows = new List<(string, Control)> { ("Key", key), ("Friendly name", name) };
        rows.AddRange(fields.Select(f => (f.p, (Control)f.Item2)));
        var error = new TextBlock { Classes = { "error" } };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        FriendlyEntry? result = null;
        ok.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(key.Text))
            {
                error.Text = "A key is required.";
                return;
            }

            result = new FriendlyEntry
            {
                Key = FriendlyNameMap.NormalizeKey(key.Text.Trim()),
                Name = name.Text?.Trim() ?? "",
                Data = fields.ToDictionary(f => f.p, f => f.Item2.Text?.Trim() ?? ""),
            };
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 8 };
        panel.Children.Add(Form(rows.ToArray()));
        panel.Children.Add(new TextBlock { Text = "Clear the name and all fields to remove the entry.", Classes = { "note" } });
        panel.Children.Add(error);
        panel.Children.Add(Buttons(ok, cancel));
        w.Content = panel;
        w.Opened += (_, _) => name.Focus();
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>Manual "Virtual columns" manager and editor.</summary>
    public static Task<IReadOnlyList<VirtualColumnDefinition>?> VirtualColumnsAsync(Window owner, AppSettings settings)
    {
        var baseColumns = ColumnSet.Build(settings.Scan, settings.FriendlyNames, []);
        return ManageListAsync(owner, "Virtual Columns", settings.VirtualColumns, v => v.Name,
            v => v.Source + (v.Regex.Length > 0 ? $"   regex: {v.Regex} → {v.Replacement}" : ""), (v, n) => v with { Name = n }, null,
            async (w, existing, index) =>
            {
                var earlier = ColumnSet.Build(settings.Scan, settings.FriendlyNames, settings.VirtualColumns.Take(index).ToList());
                return await VirtualColumnEditAsync(w, existing, earlier.Count > 0 ? earlier : baseColumns);
            });
    }

    private static async Task<VirtualColumnDefinition?> VirtualColumnEditAsync(Window owner, VirtualColumnDefinition? existing, IReadOnlyList<ResultColumn> available)
    {
        var w = Shell("Virtual Column", 620, 360);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var name = new TextBox { Text = existing?.Name ?? "" };
        var source = new TextBox { Text = existing?.Source ?? "", PlaceholderText = "[Host Name] - [MAC Address]" };
        var regex = new TextBox { Text = existing?.Regex ?? "", PlaceholderText = @"optional, e.g. i[0-9]-(\d+)" };
        var replacement = new TextBox { Text = existing?.Replacement ?? "", PlaceholderText = "e.g. $1" };
        var picker = new ComboBox { ItemsSource = available.Select(c => c.Header).ToList(), PlaceholderText = "Insert column…", MinWidth = 220 };
        picker.SelectionChanged += (_, _) =>
        {
            if (picker.SelectedItem is string h)
            {
                source.Text += $"[{h}]";
                picker.SelectedIndex = -1;
            }
        };
        var error = new TextBlock { Classes = { "error" }, TextWrapping = TextWrapping.Wrap };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        VirtualColumnDefinition? result = null;
        ok.Click += (_, _) =>
        {
            var def = new VirtualColumnDefinition { Name = name.Text?.Trim() ?? "", Source = source.Text ?? "", Regex = regex.Text ?? "", Replacement = replacement.Text ?? "" };
            if (ColumnSet.Validate(def, available) is { } e)
            {
                error.Text = e;
                return;
            }

            result = def;
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 8 };
        panel.Children.Add(Form(("Name", name), ("Source", source), ("", picker), ("Regular expression", regex), ("Replacement", replacement)));
        panel.Children.Add(new TextBlock
        {
            Text = "Refer to columns as [Column Name]. Only built-in columns and virtual columns defined earlier can be used, so definitions cannot form cycles. Regular expressions time out after 100 ms.",
            Classes = { "note" },
        });
        panel.Children.Add(error);
        panel.Children.Add(Buttons(ok, cancel));
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>Manual "Change Column View". Returns the column id and its new style (null = reset to default).</summary>
    public static async Task<(string ColumnId, ColumnStyle? Style)?> ColumnViewAsync(Window owner, IReadOnlyList<ResultColumn> columns, string? currentId,
        IReadOnlyList<ColumnStyle> styles)
    {
        var w = Shell("Change Column View", 560, 520);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var column = new ComboBox { ItemsSource = columns.Select(c => c.Header).ToList(), MinWidth = 260 };
        var bg = new TextBox { PlaceholderText = "#RRGGBB" };
        var fg = new TextBox { PlaceholderText = "#RRGGBB" };
        var bold = new CheckBox { Content = "Bold" };
        var italic = new CheckBox { Content = "Italic" };
        var underline = new CheckBox { Content = "Underline" };
        var strike = new CheckBox { Content = "Strikethrough" };
        var regex = new TextBox { PlaceholderText = "e.g. ^(.{3}).*" };
        var replacement = new TextBox { PlaceholderText = "e.g. $1" };
        string[] conditions = ["None (all cells)", "Equal", "Not equal", "Contains", "Doesn't contain", "Less than", "Greater than", "Regex"];
        var condition = new ComboBox { ItemsSource = conditions, SelectedIndex = 0, MinWidth = 200 };
        var value = new TextBox();

        void Load()
        {
            var id = column.SelectedIndex >= 0 ? columns[column.SelectedIndex].Id : null;
            var s = styles.FirstOrDefault(x => x.ColumnId == id) ?? new ColumnStyle();
            bg.Text = s.Background;
            fg.Text = s.Foreground;
            bold.IsChecked = s.Bold;
            italic.IsChecked = s.Italic;
            underline.IsChecked = s.Underline;
            strike.IsChecked = s.Strikethrough;
            regex.Text = s.Regex;
            replacement.Text = s.Replacement;
            condition.SelectedIndex = (int)s.Condition;
            value.Text = s.ConditionValue;
        }

        column.SelectionChanged += (_, _) => Load();
        column.SelectedIndex = Math.Max(0, columns.ToList().FindIndex(c => c.Id == currentId));
        Load();

        var error = new TextBlock { Classes = { "error" } };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var reset = new Button { Content = "Reset to Default View" };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        (string, ColumnStyle?)? result = null;
        static bool ValidColor(string? s) => string.IsNullOrWhiteSpace(s) || Color.TryParse(s.Trim(), out _);
        ok.Click += (_, _) =>
        {
            if (!ValidColor(bg.Text) || !ValidColor(fg.Text))
            {
                error.Text = "Colours must look like #RRGGBB or a colour name.";
                return;
            }

            if (SafeRegex.Validate(regex.Text ?? "") is { } re || ((StyleCondition)condition.SelectedIndex == StyleCondition.Regex && SafeRegex.Validate(value.Text ?? "") is { } re2 && (re = re2) is not null))
            {
                error.Text = "Regular expression: " + re;
                return;
            }

            result = (columns[column.SelectedIndex].Id, new ColumnStyle
            {
                Background = bg.Text?.Trim() ?? "",
                Foreground = fg.Text?.Trim() ?? "",
                Bold = bold.IsChecked == true,
                Italic = italic.IsChecked == true,
                Underline = underline.IsChecked == true,
                Strikethrough = strike.IsChecked == true,
                Regex = regex.Text ?? "",
                Replacement = replacement.Text ?? "",
                Condition = (StyleCondition)Math.Max(0, condition.SelectedIndex),
                ConditionValue = value.Text ?? "",
            });
            w.Close();
        };
        reset.Click += (_, _) =>
        {
            result = (columns[column.SelectedIndex].Id, null);
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var fonts = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
        fonts.Children.Add(bold);
        fonts.Children.Add(italic);
        fonts.Children.Add(underline);
        fonts.Children.Add(strike);
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 8 };
        panel.Children.Add(Form(("Column", column), ("Background colour", bg), ("Text colour", fg), ("Font", fonts), ("Regular expression", regex),
            ("Replacement expression", replacement), ("Highlighting condition", condition), ("Condition value", value)));
        panel.Children.Add(new TextBlock
        {
            Text = "The regular expression changes how values are displayed in the grid; exports keep the original values. The condition is evaluated on the original value; with None, the formatting applies to every cell.",
            Classes = { "note" },
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(error);
        panel.Children.Add(Buttons(ok, reset, cancel));
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }
}

/// <summary>Manual "Friendly names and comments" manager: identify-by columns, associated data, entries, CSV import/export
/// (append, merge or replace) and clipboard copy/paste.</summary>
internal sealed class FriendlyNamesWindow : Window
{
    private static readonly (string Label, string[] Ids)[] IdentifyPresets =
    [
        ("No mapping (friendly names disabled)", []),
        ("Identify by: MAC Address", ["mac"]),
        ("Identify by: IP Address", ["ip"]),
        ("Identify by: Host Name", ["hostName"]),
        ("Identify by: NetBIOS Name", ["netbios"]),
        ("Identify by: MAC Address + IP Address", ["mac", "ip"]),
        ("Identify by: Host Name + IP Address", ["hostName", "ip"]),
    ];

    private readonly ObservableCollection<FriendlyEntry> _entries;
    private readonly DataGrid _grid = new() { IsReadOnly = true, HeadersVisibility = DataGridHeadersVisibility.Column, SelectionMode = DataGridSelectionMode.Extended };
    private readonly TextBox _find = new() { PlaceholderText = "Find", Width = 220 };
    private readonly ComboBox _identify = new() { ItemsSource = IdentifyPresets.Select(p => p.Label).ToList(), MinWidth = 340 };
    private readonly TextBox _parameters = new() { PlaceholderText = "Asset tag, Location, Owner", Width = 360 };
    private readonly TextBlock _status = new() { Classes = { "hint" }, VerticalAlignment = VerticalAlignment.Center };
    private FriendlyNameSettings? _result;

    private FriendlyNamesWindow(FriendlyNameSettings settings)
    {
        Title = "Friendly Names / Comments";
        Width = 860;
        Height = 560;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _entries = new ObservableCollection<FriendlyEntry>(settings.Entries);
        var preset = Array.FindIndex(IdentifyPresets, p => p.Ids.SequenceEqual(settings.IdentifyBy));
        _identify.SelectedIndex = preset >= 0 ? preset : 1;
        _parameters.Text = string.Join(", ", settings.Parameters);
        _parameters.LostFocus += (_, _) => RebuildColumns();
        _find.TextChanged += (_, _) => Refresh();
        RebuildColumns();

        Button B(string text, Func<Task> action)
        {
            var b = new Button { Content = text };
            b.Click += async (_, _) => await action();
            return b;
        }

        var top = new StackPanel { Spacing = 6 };
        var r1 = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        r1.Children.Add(_identify);
        r1.Children.Add(_find);
        var r2 = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        r2.Children.Add(new TextBlock { Text = "Associated data:", VerticalAlignment = VerticalAlignment.Center });
        r2.Children.Add(_parameters);
        top.Children.Add(r1);
        top.Children.Add(r2);

        var side = new StackPanel { Spacing = 6, Width = 120, Margin = new Thickness(8, 0, 0, 0) };
        side.Children.Add(B("Add…", AddAsync));
        side.Children.Add(B("Edit…", EditAsync));
        side.Children.Add(B("Delete", () =>
        {
            foreach (var e in _grid.SelectedItems.OfType<FriendlyEntry>().ToList()) _entries.Remove(e);
            Refresh();
            return Task.CompletedTask;
        }));
        side.Children.Add(B("Import…", ImportAsync));
        side.Children.Add(B("Export…", ExportAsync));
        side.Children.Add(B("Copy", async () =>
        {
            var selected = _grid.SelectedItems.OfType<FriendlyEntry>().ToList();
            if (Clipboard is not null) await Clipboard.SetTextAsync(FriendlyNameMap.ExportCsv(Current() with { Entries = selected.Count > 0 ? selected : _entries.ToList() }));
            _status.Text = "Copied as CSV.";
        }));
        side.Children.Add(B("Paste", async () =>
        {
            var text = Clipboard is null ? null : await Clipboard.TryGetTextAsync();
            if (!string.IsNullOrWhiteSpace(text)) Apply(FriendlyNameMap.ImportCsv(Current(), text, ImportMode.Merge, out var n), $"Pasted {n} entr(ies).");
        }));
        _grid.DoubleTapped += async (_, _) => await EditAsync();

        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" }, MinWidth = 80 };
        var cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 80 };
        ok.Click += (_, _) =>
        {
            _result = Current();
            Close();
        };
        cancel.Click += (_, _) => Close();
        var bottom = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        buttons.Children.Add(ok);
        buttons.Children.Add(cancel);
        DockPanel.SetDock(buttons, Dock.Right);
        bottom.Children.Add(buttons);
        bottom.Children.Add(_status);

        var panel = new DockPanel { Margin = new Thickness(12) };
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(bottom, Dock.Bottom);
        DockPanel.SetDock(side, Dock.Right);
        top.Margin = new Thickness(0, 0, 0, 8);
        panel.Children.Add(top);
        panel.Children.Add(bottom);
        panel.Children.Add(side);
        panel.Children.Add(_grid);
        Content = panel;
    }

    public static async Task<FriendlyNameSettings?> ShowAsync(Window owner, FriendlyNameSettings settings, IReadOnlyList<ResultColumn> columns)
    {
        _ = columns;
        var w = new FriendlyNamesWindow(settings);
        await w.ShowDialog(owner);
        return w._result;
    }

    private IReadOnlyList<string> Parameters() =>
        (_parameters.Text ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().ToList();

    private FriendlyNameSettings Current() => new()
    {
        IdentifyBy = IdentifyPresets[Math.Max(0, _identify.SelectedIndex)].Ids,
        Parameters = Parameters(),
        Entries = _entries.ToList(),
    };

    private void Apply(FriendlyNameSettings s, string message)
    {
        _entries.Clear();
        foreach (var e in s.Entries) _entries.Add(e);
        _parameters.Text = string.Join(", ", s.Parameters);
        RebuildColumns();
        _status.Text = message;
    }

    private void RebuildColumns()
    {
        _grid.Columns.Clear();
        _grid.Columns.Add(new DataGridTextColumn { Header = "Key", Binding = new ReflectionBinding(nameof(FriendlyEntry.Key)), Width = new DataGridLength(200) });
        _grid.Columns.Add(new DataGridTextColumn { Header = "Friendly name", Binding = new ReflectionBinding(nameof(FriendlyEntry.Name)), Width = new DataGridLength(200) });
        foreach (var p in Parameters())
        {
            _grid.Columns.Add(new DataGridTemplateColumn
            {
                Header = p,
                Width = new DataGridLength(140),
                CellTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<FriendlyEntry>((e, _) =>
                    new TextBlock { Text = e?.Data.GetValueOrDefault(p) ?? "", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0) }),
            });
        }

        Refresh();
    }

    private void Refresh()
    {
        var q = _find.Text?.Trim() ?? "";
        _grid.ItemsSource = q.Length == 0
            ? _entries
            : _entries.Where(e => e.Key.Contains(q, StringComparison.CurrentCultureIgnoreCase) || e.Name.Contains(q, StringComparison.CurrentCultureIgnoreCase)
                                  || e.Data.Values.Any(v => v.Contains(q, StringComparison.CurrentCultureIgnoreCase))).ToList();
    }

    private async Task AddAsync()
    {
        var e = await Dialogs.FriendlyEntryAsync(this, new FriendlyEntry(), Parameters(), keyEditable: true);
        if (e is null) return;
        var list = FriendlyNameMap.Upsert(_entries.ToList(), e);
        Apply(Current() with { Entries = list }, "");
    }

    private async Task EditAsync()
    {
        if (_grid.SelectedItem is not FriendlyEntry selected) return;
        var e = await Dialogs.FriendlyEntryAsync(this, selected, Parameters(), keyEditable: true);
        if (e is null) return;
        var list = _entries.Where(x => x != selected).ToList();
        Apply(Current() with { Entries = FriendlyNameMap.Upsert(list, e) }, "");
    }

    private async Task ImportAsync()
    {
        var files = await StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = "Import friendly names", FileTypeFilter = [new FilePickerFileType("CSV") { Patterns = ["*.csv", "*.txt"] }],
        });
        var path = files.Count > 0 ? files[0].TryGetLocalPath() : null;
        if (path is null) return;
        if (new FileInfo(path).Length > 16 * 1024 * 1024)
        {
            _status.Text = "File is larger than 16 MB.";
            return;
        }

        var mode = await Dialogs.ChoiceAsync(this, "Import", "How should the imported entries be combined with the list?",
            ["Append (add new keys only)", "Merge (add new keys, update existing)", "Replace the list"]);
        if (mode is not { } m) return;
        var s = FriendlyNameMap.ImportCsv(Current(), await File.ReadAllTextAsync(path), (ImportMode)m, out var n);
        Apply(s, $"Imported {n} entr(ies).");
    }

    private async Task ExportAsync()
    {
        var file = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export friendly names", DefaultExtension = "csv", SuggestedFileName = "friendly-names",
            FileTypeChoices = [new FilePickerFileType("CSV") { Patterns = ["*.csv"] }],
        });
        if (file?.TryGetLocalPath() is not { } path) return;
        var bytes = new System.Text.UTF8Encoding(true).GetPreamble().Concat(System.Text.Encoding.UTF8.GetBytes(FriendlyNameMap.ExportCsv(Current()))).ToArray();
        await AtomicFile.WriteAsync(path, s => s.WriteAsync(bytes).AsTask());
        _status.Text = $"Exported {_entries.Count} entr(ies).";
    }
}
