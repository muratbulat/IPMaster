using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using IPMaster.Core.Queries;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Built-in examples of one query family (D-110): search, list and preview. Choosing one only returns it; the manager
/// adds it disabled through its normal save path. Nothing runs here.
/// </summary>
internal sealed class QueryExamplesWindow : Window
{
    private readonly IReadOnlyList<QueryExample> _all;
    private readonly ListBox _list = new() { MinWidth = 220 };
    private readonly TextBox _search = new() { PlaceholderText = "Search examples" };
    private readonly SelectableTextBlock _name = new() { Classes = { "section" }, TextWrapping = TextWrapping.Wrap };
    private readonly SelectableTextBlock _purpose = new() { TextWrapping = TextWrapping.Wrap };
    private readonly SelectableTextBlock _platform = new() { Classes = { "description" }, TextWrapping = TextWrapping.Wrap };
    private readonly SelectableTextBlock _requirements = new() { Classes = { "description" }, TextWrapping = TextWrapping.Wrap };
    private readonly TextBox _config = new()
    {
        IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MinHeight = 90, Classes = { "mono" },
    };

    private readonly Button _add;

    public QueryExamplesWindow(QueryKind kind)
    {
        _all = QueryExamples.For(kind);
        Title = QueryKindPanel.TitleFor(kind) + " Examples";
        Width = 820;
        Height = 520;
        MinWidth = 560;
        MinHeight = 380;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        AutomationProperties.SetName(_search, "Search examples");
        AutomationProperties.SetName(_list, "Examples");
        AutomationProperties.SetName(_config, "Configuration");
        _list.ItemTemplate = new Avalonia.Controls.Templates.FuncDataTemplate<QueryExample>((e, _) => new TextBlock { Text = e is null ? "" : $"{e.Name}  ·  {e.Category}" });
        _list.SelectionChanged += (_, _) => ShowPreview();
        _list.DoubleTapped += (_, _) => Accept();
        _list.KeyDown += (_, e) =>
        {
            if (e.Key != Key.Enter) return;
            Accept();
            e.Handled = true;
        };
        _search.TextChanged += (_, _) => Filter();
        _search.KeyDown += (_, e) =>
        {
            if (e.Key != Key.Down || _list.ItemCount == 0) return;
            _list.SelectedIndex = Math.Max(_list.SelectedIndex, 0);
            (_list.ContainerFromIndex(_list.SelectedIndex) as Control)?.Focus();
            e.Handled = true;
        };

        _add = Ui.Button("Add", () =>
        {
            Accept();
            return Task.CompletedTask;
        }, accent: true);
        _add.IsDefault = true;
        var cancel = Ui.Button("Cancel", () =>
        {
            Close(null);
            return Task.CompletedTask;
        });
        cancel.IsCancel = true;

        var preview = new ScrollViewer
        {
            Content = new StackPanel
            {
                Spacing = Styling.Theme.TightGap,
                Children = { _name, _purpose, _platform, _requirements, new TextBlock { Text = "Configuration", Classes = { "label" } }, _config },
            },
        };
        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("2*,3*"), ColumnSpacing = Styling.Theme.SectionGap };
        split.Children.Add(_list);
        Grid.SetColumn(preview, 1);
        split.Children.Add(preview);

        var bottom = new StackPanel
        {
            Spacing = Styling.Theme.TightGap,
            Children =
            {
                new TextBlock
                {
                    Text = "Examples are added disabled and nothing runs. Use Test… to try one; enabled queries take part in scans.",
                    TextWrapping = TextWrapping.Wrap, Classes = { "hint" },
                },
                Ui.Row(_add, cancel),
            },
        };
        Content = Ui.Layout(_search, split, bottom);
        Filter();
        Opened += (_, _) => _search.Focus();
    }

    /// <summary>The example currently shown in the preview.</summary>
    public QueryExample? Selected => _list.SelectedItem as QueryExample;

    public string PreviewText => string.Join("\n", _name.Text, _purpose.Text, _platform.Text, _requirements.Text, _config.Text);

    public string SearchText
    {
        get => _search.Text ?? "";
        set => _search.Text = value;
    }

    public IReadOnlyList<QueryExample> Visible => _list.ItemsSource as IReadOnlyList<QueryExample> ?? [];

    public void Select(QueryExample example) => _list.SelectedItem = example;

    private void Filter()
    {
        var keep = Selected;
        var text = SearchText.Trim();
        var visible = _all.Where(e => e.Matches(text)).ToList();
        _list.ItemsSource = visible;
        _list.SelectedItem = keep is not null && visible.Contains(keep) ? keep : visible.FirstOrDefault();
        ShowPreview();
    }

    private void ShowPreview()
    {
        var e = Selected;
        _add.IsEnabled = e is not null;
        _name.Text = e?.Name ?? "No example matches the search.";
        _purpose.Text = e?.Description ?? "";
        _platform.Text = e is null ? "" : "Platform: " + e.Platform;
        _requirements.Text = e is null ? "" : "Requirements: " + e.Requirements;
        _config.Text = e is null ? "" : QueryExample.Preview(e.Create());
    }

    private void Accept()
    {
        if (Selected is { } e) Close(e);
    }
}
