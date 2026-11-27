using Avalonia;
using Avalonia.Controls;
using IPMaster.Core.Queries;
using IPMaster.Desktop.ViewModels;

namespace IPMaster.Desktop.Views;

/// <summary>
/// Tools → Remote Management → Remote Query Manager (D-111): one non-modal window for the 14 query types that were separate
/// Options → Remote … windows. A category and a type selector choose the <see cref="QueryKindPanel"/>; every panel reads and saves
/// the one <see cref="QuerySettings.Items"/> list, so ids, column ids, names, dependencies and enabled states are unchanged.
/// </summary>
internal sealed class QueryManagerWindow : Window
{
    internal static readonly (string Name, QueryKind[] Kinds)[] Categories =
    [
        ("Windows", [QueryKind.Wmi, QueryKind.Registry, QueryKind.Files, QueryKind.Services, QueryKind.Groups, QueryKind.Performance]),
        ("Scripts", [QueryKind.PowerShell, QueryKind.Script, QueryKind.Python, QueryKind.Ssh]),
        ("Network & Data", [QueryKind.Snmp, QueryKind.Nmap, QueryKind.Xml, QueryKind.Json]),
    ];

    private readonly MainWindowViewModel _vm;
    private readonly Dictionary<QueryKind, QueryKindPanel> _panels = [];
    private readonly ContentControl _host = new();
    private readonly ComboBox _category;
    private readonly ComboBox _type;
    private bool _switching;

    public QueryManagerWindow(MainWindowViewModel vm, QueryKind kind, Guid? select = null)
    {
        _vm = vm;
        Title = "Remote Query Manager";
        Width = 1000;
        Height = 620;
        MinWidth = Styling.Theme.ToolMinWidth + 80;
        MinHeight = Styling.Theme.ToolMinHeight;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _category = ToolKit.Combo("Query category", Categories.Select(c => c.Name), 0, 180);
        _type = ToolKit.Combo("Query type", [], 0, 200);
        _category.SelectionChanged += (_, _) =>
        {
            if (_switching || _category.SelectedIndex < 0) return;
            FillTypes(Categories[_category.SelectedIndex].Kinds[0]);
        };
        _type.SelectionChanged += (_, _) =>
        {
            if (!_switching && _type.SelectedIndex >= 0 && _category.SelectedIndex >= 0) ShowPanel(Categories[_category.SelectedIndex].Kinds[_type.SelectedIndex]);
        };
        var selector = Ui.Row(SnmpTargetForm.Pair("Category", _category), SnmpTargetForm.Pair("Type", _type));
        var top = new Border { Margin = new Thickness(Styling.Theme.PageMargin, Styling.Theme.PageMargin, Styling.Theme.PageMargin, 0), Child = selector };
        var panel = new DockPanel();
        DockPanel.SetDock(top, Dock.Top);
        panel.Children.Add(top);
        panel.Children.Add(_host);
        Content = panel;
        Opened += (_, _) => ShowQueries(kind, select);
    }

    /// <summary>The query type on screen.</summary>
    public QueryKind Kind { get; private set; }

    internal QueryKindPanel? Current => _host.Content as QueryKindPanel;

    /// <summary>Shows one query type and, when given, selects one item (Navigator → saved query). Returns false when the item is not of that type.</summary>
    public bool ShowQueries(QueryKind kind, Guid? select = null)
    {
        FillTypes(kind);
        return select is not { } id || Current!.Select(id);
    }

    private void FillTypes(QueryKind kind)
    {
        var c = Array.FindIndex(Categories, x => x.Kinds.Contains(kind));
        _switching = true;
        try
        {
            _category.SelectedIndex = c;
            _type.ItemsSource = Categories[c].Kinds.Select(QueryColumns.DisplayName).ToList();
            _type.SelectedIndex = Array.IndexOf(Categories[c].Kinds, kind);
        }
        finally
        {
            _switching = false;
        }

        ShowPanel(kind);
    }

    private void ShowPanel(QueryKind kind)
    {
        if (!_panels.TryGetValue(kind, out var p)) _panels[kind] = p = new QueryKindPanel(_vm, kind);
        Kind = kind;
        _host.Content = p;
        p.Activate();
    }
}
