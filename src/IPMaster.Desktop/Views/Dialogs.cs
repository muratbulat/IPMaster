using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using IPMaster.Core.Network;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>Small code-built dialogs (message/confirm, multi-line text editor, adapter detection).</summary>
internal static partial class Dialogs
{
    private static Window Shell(string title, double width, double height) => new()
    {
        Title = title,
        Width = width,
        Height = height,
        MinWidth = 320,
        MinHeight = 160,
        WindowStartupLocation = WindowStartupLocation.CenterOwner,
        ShowInTaskbar = false,
        CanMinimize = false,
    };

    private static StackPanel Buttons(params Button[] buttons)
    {
        var p = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Spacing = 8, Margin = new Thickness(0, 12, 0, 0) };
        foreach (var b in buttons)
        {
            b.MinWidth = 80;
            p.Children.Add(b);
        }

        return p;
    }

    public static async Task<bool> MessageAsync(Window owner, string title, string message, bool confirm)
    {
        var w = Shell(title, 480, 220);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var ok = new Button { Content = confirm ? "Yes" : "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "No", IsCancel = true, IsVisible = confirm };
        ok.Click += (_, _) => w.Close(true);
        cancel.Click += (_, _) => w.Close(false);
        var panel = new DockPanel { Margin = new Thickness(16) };
        var buttons = confirm ? Buttons(ok, cancel) : Buttons(ok);
        DockPanel.SetDock(buttons, Dock.Bottom);
        panel.Children.Add(buttons);
        panel.Children.Add(new SelectableTextBlock { Text = message, TextWrapping = TextWrapping.Wrap, MaxHeight = 400 });
        w.Content = panel;
        return await w.ShowDialog<bool>(owner);
    }

    /// <summary>Multi-line text editor with optional file loading. Returns null when cancelled.</summary>
    public static async Task<string?> EditTextAsync(Window owner, string title, string description, string initial, bool allowLoadFile,
        Func<string, string?>? validate = null)
    {
        var w = Shell(title, 560, 460);
        var box = new TextBox { Text = initial, AcceptsReturn = true, TextWrapping = TextWrapping.NoWrap, FontFamily = new FontFamily("Consolas, Menlo, monospace") };
        var status = new TextBlock { Classes = { "hint", "error" }, Margin = new Thickness(0, 6, 0, 0) };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        var load = new Button { Content = "Load from File…", IsVisible = allowLoadFile, HorizontalAlignment = HorizontalAlignment.Left };
        ok.Click += (_, _) =>
        {
            var error = validate?.Invoke(box.Text ?? "");
            if (error is not null)
            {
                status.Text = error;
                return;
            }

            w.Close(box.Text ?? "");
        };
        cancel.Click += (_, _) => w.Close(null);
        load.Click += async (_, _) =>
        {
            var files = await w.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions
            {
                Title = "Load targets",
                AllowMultiple = false,
                FileTypeFilter = [new FilePickerFileType("Text files") { Patterns = ["*.txt", "*.csv", "*.lst"] }, FilePickerFileTypes.All],
            });
            var path = files.Count > 0 ? files[0].TryGetLocalPath() : null;
            if (path is null) return;
            var info = new FileInfo(path);
            if (info.Length > 16 * 1024 * 1024)
            {
                status.Text = "File is larger than 16 MB.";
                return;
            }

            box.Text = await File.ReadAllTextAsync(path);
        };

        var bottom = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
        var right = Buttons(ok, cancel);
        right.Margin = default;
        DockPanel.SetDock(right, Dock.Right);
        bottom.Children.Add(right);
        bottom.Children.Add(load);

        var panel = new DockPanel { Margin = new Thickness(16) };
        var top = new TextBlock { Text = description, Classes = { "note" }, Margin = new Thickness(0, 0, 0, 8) };
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(bottom, Dock.Bottom);
        DockPanel.SetDock(status, Dock.Bottom);
        panel.Children.Add(top);
        panel.Children.Add(bottom);
        panel.Children.Add(status);
        panel.Children.Add(box);
        w.Content = panel;
        return await w.ShowDialog<string?>(owner);
    }

    public sealed record AdapterChoice(string Adapter, AdapterAddress Address, string Range);

    /// <summary>
    /// Local IP range detection (D-101; IP Address Tools → Local Range, D-111): searchable, filterable adapter groups
    /// (<see cref="AdapterPickerViewModel"/>). <paramref name="add"/> receives the chosen, deduplicated ranges and whether to append,
    /// after the large-scan confirmation; what it returns is shown on the status line.
    /// </summary>
    public static Control AdapterPicker(Func<IReadOnlyList<NetworkAdapterInfo>> adapters, ulong largeThreshold, Func<IReadOnlyList<AdapterChoice>, bool, string> add)
    {
        var vm = new AdapterPickerViewModel(adapters(), largeThreshold);
        var panel = new DockPanel { Margin = Styling.Theme.Page };
        var status = new TextBlock { Classes = { "status" }, TextWrapping = TextWrapping.Wrap };

        var search = ToolKit.Text("Search adapters", "name, description, MAC, address, gateway or type");
        search.Bind(TextBox.TextProperty, new ReflectionBinding(nameof(AdapterPickerViewModel.Search)) { Source = vm, Mode = BindingMode.TwoWay });
        var filters = new WrapPanel { ItemSpacing = Styling.Theme.TightGap, LineSpacing = Styling.Theme.TightGap };
        foreach (var (label, filter) in new[] { ("All", AdapterFilter.All), ("Likely physical", AdapterFilter.Physical), ("Ethernet", AdapterFilter.Ethernet),
                     ("Wi-Fi", AdapterFilter.WiFi), ("Virtual", AdapterFilter.Virtual), ("VPN", AdapterFilter.Vpn) })
        {
            var rb = new RadioButton { Content = label, GroupName = "adapterFilter", IsChecked = filter == AdapterFilter.All, Margin = new Thickness(0, 0, 6, 0) };
            rb.IsCheckedChanged += (_, _) =>
            {
                if (rb.IsChecked == true) vm.Filter = filter;
            };
            filters.Children.Add(rb);
        }

        CheckBox Family(string text, string path)
        {
            var cb = new CheckBox { Content = text, Margin = new Thickness(8, 0, 0, 0) };
            cb.Bind(ToggleButton.IsCheckedProperty, new ReflectionBinding(path) { Source = vm, Mode = BindingMode.TwoWay });
            return cb;
        }

        filters.Children.Add(Family("IPv4", nameof(AdapterPickerViewModel.ShowIPv4)));
        filters.Children.Add(Family("IPv6", nameof(AdapterPickerViewModel.ShowIPv6)));

        TextBlock Line(string path, string cls)
        {
            var t = new TextBlock { Classes = { cls }, TextWrapping = TextWrapping.Wrap };
            t.Bind(TextBlock.TextProperty, new ReflectionBinding(path) { Source = vm });
            t.Bind(Visual.IsVisibleProperty, new ReflectionBinding(path) { Source = vm, Converter = Avalonia.Data.Converters.StringConverters.IsNotNullOrEmpty });
            return t;
        }

        var summary = Line(nameof(AdapterPickerViewModel.Summary), "status");
        Avalonia.Automation.AutomationProperties.SetLiveSetting(summary, Avalonia.Automation.AutomationLiveSetting.Polite);
        var notes = new StackPanel
        {
            Spacing = 2,
            Children = { new TextBlock { Text = vm.DefaultNote, Classes = { "hint" }, IsVisible = vm.DefaultNote.Length > 0 }, Line(nameof(AdapterPickerViewModel.RefreshNote), "hint"), summary,
                Line(nameof(AdapterPickerViewModel.Warning), "warning") },
        };

        var list = new StackPanel { Spacing = 0 };
        void BuildList()
        {
            list.Children.Clear();
            if (vm.Groups.Count == 0) list.Children.Add(new TextBlock { Text = "No active network adapters with IP addresses were found.", Classes = { "description" }, Margin = new Thickness(4, 8) });
            foreach (var g in vm.Groups)
            {
                var groupBox = new CheckBox { IsThreeState = true, VerticalAlignment = VerticalAlignment.Center };
                groupBox.Bind(ToggleButton.IsCheckedProperty, new ReflectionBinding(nameof(AdapterGroupItem.GroupChecked)) { Source = g, Mode = BindingMode.TwoWay });
                Avalonia.Automation.AutomationProperties.SetName(groupBox, "Select all addresses of " + g.Title);
                var header = new StackPanel
                {
                    Orientation = Orientation.Horizontal, Spacing = 6,
                    Children =
                    {
                        groupBox, new TextBlock { Text = g.Title, FontWeight = FontWeight.SemiBold, VerticalAlignment = VerticalAlignment.Center },
                        new TextBlock { Text = g.Subtitle, Classes = { "label" }, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis },
                    },
                };
                var body = new StackPanel { Spacing = 2, Margin = new Thickness(28, 0, 0, 4) };
                body.Children.Add(new TextBlock { Text = g.Details, Classes = { "hint" } });
                foreach (var a in g.Addresses)
                {
                    var cb = new CheckBox { Content = a.Text, IsEnabled = a.Eligible };
                    cb.Bind(ToggleButton.IsCheckedProperty, new ReflectionBinding(nameof(AdapterAddressItem.IsSelected)) { Source = a, Mode = BindingMode.TwoWay });
                    cb.Bind(Visual.IsVisibleProperty, new ReflectionBinding(nameof(AdapterAddressItem.IsShown)) { Source = a });
                    if (!a.Eligible) ToolTip.SetTip(cb, a.Detail);
                    body.Children.Add(cb);
                }

                var expander = new Expander { Header = header, Content = body, HorizontalAlignment = HorizontalAlignment.Stretch, Padding = new Thickness(4, 0), Margin = new Thickness(0, 0, 0, 2) };
                expander.Bind(Expander.IsExpandedProperty, new ReflectionBinding(nameof(AdapterGroupItem.IsExpanded)) { Source = g, Mode = BindingMode.TwoWay });
                expander.Bind(Visual.IsVisibleProperty, new ReflectionBinding(nameof(AdapterGroupItem.IsShown)) { Source = g });
                Avalonia.Automation.AutomationProperties.SetName(expander, g.Title);
                list.Children.Add(expander);
            }
        }

        BuildList();
        var append = new CheckBox { Content = "Append to the current ranges instead of replacing them" };
        var addButton = new Button { Content = "Add Selected Ranges", Classes = { "accent" } };
        addButton.Bind(Avalonia.Input.InputElement.IsEnabledProperty, new ReflectionBinding(nameof(AdapterPickerViewModel.CanSubmit)) { Source = vm });
        addButton.Click += async (_, _) =>
        {
            if (!vm.CanSubmit || TopLevel.GetTopLevel(panel) is not Window owner) return;
            if (vm.IsLarge && !await MessageAsync(owner, "Large scan", vm.Warning + "\n\nAdd these ranges anyway?", confirm: true)) return;
            status.Text = add(vm.Result().Select(r => new AdapterChoice(r.Adapter, r.Address, r.Range)).ToList(), append.IsChecked == true);
        };
        var tools = Ui.Row(
            Ui.Button("Select Visible", () =>
            {
                vm.SelectVisible();
                return Task.CompletedTask;
            }),
            Ui.Button("Clear Visible", () =>
            {
                vm.ClearVisible();
                return Task.CompletedTask;
            }),
            Ui.Button("Clear All", () =>
            {
                vm.ClearAll();
                return Task.CompletedTask;
            }),
            Ui.Button("Refresh", () =>
            {
                vm.Refresh(adapters());
                BuildList();
                return Task.CompletedTask;
            }));

        var top = new StackPanel { Spacing = Styling.Theme.FormRowGap, Children = { search, filters, notes } };
        var bottom = new StackPanel { Spacing = Styling.Theme.FormRowGap, Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0), Children = { tools, append, Buttons(addButton), status } };
        var scroller = new ScrollViewer { Content = list, HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
        var surface = new Border { Child = scroller, BorderThickness = new Thickness(1), Padding = new Thickness(4), Margin = new Thickness(0, Styling.Theme.SectionGap, 0, 0) };
        surface.Bind(Border.BorderBrushProperty, surface.GetResourceObservable("IpmBorder"));
        DockPanel.SetDock(top, Dock.Top);
        DockPanel.SetDock(bottom, Dock.Bottom);
        panel.Children.Add(top);
        panel.Children.Add(bottom);
        panel.Children.Add(surface);
        return panel;
    }

    public static async Task<string?> PromptAsync(Window owner, string title, string label, string initial)
    {
        var w = Shell(title, 460, 170);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var box = new TextBox { Text = initial };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        ok.Click += (_, _) => w.Close(box.Text ?? "");
        cancel.Click += (_, _) => w.Close(null);
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 8 };
        panel.Children.Add(new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap });
        panel.Children.Add(box);
        panel.Children.Add(Buttons(ok, cancel));
        w.Content = panel;
        w.Opened += (_, _) => box.Focus();
        return await w.ShowDialog<string?>(owner);
    }

    /// <summary>Radio-button choice. Returns the selected index or null when cancelled.</summary>
    public static async Task<int?> ChoiceAsync(Window owner, string title, string message, IReadOnlyList<string> options)
    {
        var w = Shell(title, 480, 220);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        var radios = options.Select((o, i) => new RadioButton { Content = o, GroupName = "choice", IsChecked = i == 0 }).ToList();
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        int? result = null;
        ok.Click += (_, _) =>
        {
            result = radios.FindIndex(r => r.IsChecked == true);
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 6 };
        panel.Children.Add(new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap });
        foreach (var r in radios) panel.Children.Add(r);
        panel.Children.Add(Buttons(ok, cancel));
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>Manual "Loading and rescanning" dialog.</summary>
    public static async Task<(ViewModels.LoadMode Mode, bool Append)?> LoadOptionsAsync(Window owner)
    {
        var w = Shell("Load Results", 460, 300);
        w.Height = double.NaN;
        w.MinHeight = 0;
        w.SizeToContent = SizeToContent.Height;
        string[] modes =
        [
            "Do not rescan; just load the file", "Rescan all devices listed in the file", "Rescan previously undiscovered devices",
            "Rescan both listed and undiscovered devices",
        ];
        var radios = modes.Select((m, i) => new RadioButton { Content = m, GroupName = "mode", IsChecked = i == 0 }).ToList();
        var clear = new RadioButton { Content = "Clear the current report", GroupName = "target", IsChecked = true };
        var append = new RadioButton { Content = "Append to the current report", GroupName = "target" };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        (ViewModels.LoadMode, bool)? result = null;
        ok.Click += (_, _) =>
        {
            result = ((ViewModels.LoadMode)radios.FindIndex(r => r.IsChecked == true), append.IsChecked == true);
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var panel = new StackPanel { Margin = new Thickness(16), Spacing = 6 };
        foreach (var r in radios) panel.Children.Add(r);
        panel.Children.Add(new Separator());
        panel.Children.Add(clear);
        panel.Children.Add(append);
        panel.Children.Add(Buttons(ok, cancel));
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }

    /// <summary>Visible columns: tick to show, reorder with the arrows, and choose how many leftmost columns are frozen.</summary>
    public static async Task<(IReadOnlyList<Core.Results.ColumnLayout> Layout, int Frozen)?> ColumnsAsync(Window owner,
        IReadOnlyList<Core.Results.ResultColumn> enabled, IReadOnlyList<Core.Results.ColumnLayout> layout, int frozen)
    {
        var w = Shell("Visible Columns", 420, 520);
        var saved = layout.ToDictionary(l => l.Id, StringComparer.OrdinalIgnoreCase);
        var ordered = Core.Results.ColumnCatalog.Arrange(enabled, layout.Select(l => l with { Visible = true }).ToList());
        var items = new System.Collections.ObjectModel.ObservableCollection<ViewModels.CheckItem>(
            ordered.Select(c => new ViewModels.CheckItem(c.Id, c.Header, !saved.TryGetValue(c.Id, out var l) || l.Visible)));
        var list = new ListBox { ItemsSource = items, SelectionMode = SelectionMode.Single };
        list.ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<ViewModels.CheckItem>((item, _) =>
            new CheckBox { [!ContentControl.ContentProperty] = new Avalonia.Data.ReflectionBinding("Name"), [!CheckBox.IsCheckedProperty] = new Avalonia.Data.ReflectionBinding("IsChecked") { Mode = Avalonia.Data.BindingMode.TwoWay }, IsEnabled = item?.Id != "ip" });
        var up = new Button { Content = "▲ Up" };
        var down = new Button { Content = "▼ Down" };
        up.Click += (_, _) =>
        {
            var i = list.SelectedIndex;
            if (i > 0) items.Move(i, i - 1);
        };
        down.Click += (_, _) =>
        {
            var i = list.SelectedIndex;
            if (i >= 0 && i < items.Count - 1) items.Move(i, i + 1);
        };
        var frozenBox = new NumericUpDown { Value = frozen, Minimum = 0, Maximum = 10, Width = 120, FormatString = "0" };
        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        (IReadOnlyList<Core.Results.ColumnLayout>, int)? result = null;
        ok.Click += (_, _) =>
        {
            result = (items.Select(i => new Core.Results.ColumnLayout
            {
                Id = i.Id,
                Visible = i.IsChecked || i.Id == "ip",
                Width = saved.TryGetValue(i.Id, out var l) ? l.Width : 0,
            }).ToList(), (int)(frozenBox.Value ?? 0));
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var side = new StackPanel { Spacing = 6, Margin = new Thickness(8, 0, 0, 0) };
        side.Children.Add(up);
        side.Children.Add(down);
        var bottom = new StackPanel { Spacing = 6, Margin = new Thickness(0, 8, 0, 0) };
        var frozenRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        frozenRow.Children.Add(new TextBlock { Text = "Frozen leftmost columns:", VerticalAlignment = VerticalAlignment.Center });
        frozenRow.Children.Add(frozenBox);
        bottom.Children.Add(new TextBlock { Text = "Only columns produced by the enabled scan options are listed.", Classes = { "note" } });
        bottom.Children.Add(frozenRow);
        bottom.Children.Add(Buttons(ok, cancel));
        var panel = new DockPanel { Margin = new Thickness(16) };
        DockPanel.SetDock(bottom, Dock.Bottom);
        DockPanel.SetDock(side, Dock.Right);
        panel.Children.Add(bottom);
        panel.Children.Add(side);
        panel.Children.Add(list);
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }

    private static readonly System.Text.Json.JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public sealed record ListTransfer<T>(Func<IReadOnlyList<T>, string> Export, Func<string, IReadOnlyList<T>> Import);

    public static ListTransfer<Core.Configuration.Bookmark> BookmarkTransfer { get; } = new(
        list => System.Text.Json.JsonSerializer.Serialize(list, IndentedJson),
        text => System.Text.Json.JsonSerializer.Deserialize<List<Core.Configuration.Bookmark>>(text) ?? []);

    /// <summary>Generic list manager (bookmarks, saved filters): rename, delete, reorder, optional export/import.</summary>
    public static async Task<IReadOnlyList<T>?> ManageListAsync<T>(Window owner, string title, IReadOnlyList<T> source, Func<T, string> name,
        Func<T, string> info, Func<T, string, T> rename, ListTransfer<T>? transfer, Func<Window, T?, int, Task<T?>>? edit = null)
    {
        var w = Shell(title, 620, 440);
        var items = new System.Collections.ObjectModel.ObservableCollection<T>(source);
        var list = new ListBox { ItemsSource = items };
        list.ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<T>((item, _) =>
        {
            var p = new StackPanel();
            p.Children.Add(new TextBlock { Text = item is null ? "" : name(item), FontWeight = FontWeight.SemiBold });
            p.Children.Add(new TextBlock { Text = item is null ? "" : info(item), Classes = { "hint" }, TextTrimming = TextTrimming.CharacterEllipsis });
            return p;
        });
        var status = new TextBlock { Classes = { "hint" } };
        Button B(string text, Func<Task> action)
        {
            var b = new Button { Content = text, HorizontalAlignment = HorizontalAlignment.Stretch };
            b.Click += async (_, _) => await action();
            return b;
        }

        var side = new StackPanel { Spacing = 6, Margin = new Thickness(8, 0, 0, 0), Width = 120 };
        if (edit is not null)
        {
            side.Children.Add(B("Add…", async () =>
            {
                if (await edit(w, default, items.Count) is { } added) items.Add(added);
            }));
            side.Children.Add(B("Edit…", async () =>
            {
                if (list.SelectedItem is not T item) return;
                var i = list.SelectedIndex;
                if (await edit(w, item, i) is { } changed) items[i] = changed;
            }));
        }

        side.Children.Add(B("Rename…", async () =>
        {
            if (list.SelectedItem is not T item) return;
            var n = await PromptAsync(w, "Rename", "Name:", name(item));
            if (!string.IsNullOrWhiteSpace(n)) items[list.SelectedIndex] = rename(item, n.Trim());
        }));
        side.Children.Add(B("Delete", () =>
        {
            if (list.SelectedIndex >= 0) items.RemoveAt(list.SelectedIndex);
            return Task.CompletedTask;
        }));
        side.Children.Add(B("Move up", () =>
        {
            var i = list.SelectedIndex;
            if (i > 0) items.Move(i, i - 1);
            return Task.CompletedTask;
        }));
        if (transfer is not null)
        {
            var type = new FilePickerFileType("JSON") { Patterns = ["*.json"] };
            side.Children.Add(B("Export…", async () =>
            {
                var file = await w.StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions { Title = "Export", DefaultExtension = "json", FileTypeChoices = [type] });
                if (file?.TryGetLocalPath() is not { } path) return;
                await File.WriteAllTextAsync(path, transfer.Export(items.ToList()));
                status.Text = $"Exported {items.Count} item(s).";
            }));
            side.Children.Add(B("Import…", async () =>
            {
                var files = await w.StorageProvider.OpenFilePickerAsync(new FilePickerOpenOptions { Title = "Import", FileTypeFilter = [type] });
                var path = files.Count > 0 ? files[0].TryGetLocalPath() : null;
                if (path is null) return;
                if (new FileInfo(path).Length > 4 * 1024 * 1024)
                {
                    status.Text = "File is larger than 4 MB.";
                    return;
                }

                try
                {
                    var imported = transfer.Import(await File.ReadAllTextAsync(path));
                    foreach (var i in imported) items.Add(i);
                    status.Text = $"Imported {imported.Count} item(s).";
                }
                catch (System.Text.Json.JsonException ex)
                {
                    status.Text = "Import failed: " + ex.Message;
                }
            }));
        }

        var ok = new Button { Content = "OK", IsDefault = true, Classes = { "accent" } };
        var cancel = new Button { Content = "Cancel", IsCancel = true };
        IReadOnlyList<T>? result = null;
        ok.Click += (_, _) =>
        {
            result = items.ToList();
            w.Close();
        };
        cancel.Click += (_, _) => w.Close();
        var bottom = new DockPanel { Margin = new Thickness(0, 8, 0, 0) };
        var buttons = Buttons(ok, cancel);
        buttons.Margin = default;
        DockPanel.SetDock(buttons, Dock.Right);
        bottom.Children.Add(buttons);
        bottom.Children.Add(status);
        var panel = new DockPanel { Margin = new Thickness(16) };
        DockPanel.SetDock(bottom, Dock.Bottom);
        DockPanel.SetDock(side, Dock.Right);
        panel.Children.Add(bottom);
        panel.Children.Add(side);
        panel.Children.Add(list);
        w.Content = panel;
        await w.ShowDialog(owner);
        return result;
    }
}
