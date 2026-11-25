using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using IPMaster.Core.Navigation;

namespace IPMaster.Desktop.Views;

/// <summary>Help → Navigator (F1): type to find a command, setting, remote query or application (UI-17).</summary>
internal sealed class NavigatorWindow : Window
{
    private readonly IReadOnlyList<NavigatorItem> _items;
    private readonly TextBox _search;
    private readonly ListBox _list;
    private readonly TextBlock _count;

    public NavigatorWindow(IReadOnlyList<NavigatorItem> items)
    {
        _items = items;
        Title = "Navigator";
        Width = 600;
        Height = 500;
        MinWidth = 360;
        MinHeight = 260;
        ShowInTaskbar = false;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        _search = new TextBox { PlaceholderText = "Type to find commands, settings, remote queries and applications" };
        AutomationProperties.SetName(_search, "Search");
        _list = new ListBox { ItemTemplate = new FuncDataTemplate<NavigatorItem>((it, _) => Row(it), supportsRecycling: false) };
        AutomationProperties.SetName(_list, "Results");
        _count = new TextBlock { Opacity = 0.7 };
        _search.TextChanged += (_, _) => Filter();
        _search.KeyDown += OnSearchKeyDown;
        _list.DoubleTapped += (_, _) => Choose();
        _list.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Enter)
            {
                Choose();
                e.Handled = true;
            }
        };
        KeyDown += (_, e) =>
        {
            if (e.Key == Key.Escape) Close(null);
        };
        Content = Ui.Layout(_search, _list, new TextBlock { Text = "Enter or double-click opens the selected item.", Classes = { "hint" } } is var hint
            ? new StackPanel { Spacing = 2, Children = { _count, hint } }
            : null);
        Opened += (_, _) => _search.Focus();
        Filter();
    }

    private static Control Row(NavigatorItem? it)
    {
        if (it is null) return new TextBlock();
        var kind = it.Kind switch
        {
            NavigatorKind.Command => "Command",
            NavigatorKind.Setting => "Setting",
            NavigatorKind.Query => "Remote query",
            _ => "Application",
        };
        var detail = $"{kind} · {it.Path}" + (it.Keywords.Length > 0 && it.Kind is NavigatorKind.Command or NavigatorKind.Application ? $" · {it.Keywords}" : "");
        var panel = new StackPanel { Orientation = Orientation.Vertical, Margin = new Avalonia.Thickness(2) };
        panel.Children.Add(new TextBlock { Text = it.Title, FontWeight = FontWeight.SemiBold });
        panel.Children.Add(new TextBlock { Text = detail, Classes = { "hint" } });
        AutomationProperties.SetName(panel, $"{it.Title}, {detail}");
        return panel;
    }

    private void Filter()
    {
        var found = Navigator.Search(_items, _search.Text);
        _list.ItemsSource = found;
        _list.SelectedIndex = found.Count > 0 ? 0 : -1;
        _count.Text = found.Count == 1 ? "1 match" : $"{found.Count} matches";
    }

    private void OnSearchKeyDown(object? sender, KeyEventArgs e)
    {
        var n = _list.ItemCount;
        switch (e.Key)
        {
            case Key.Down when n > 0:
                _list.SelectedIndex = Math.Min(_list.SelectedIndex + 1, n - 1);
                _list.ScrollIntoView(_list.SelectedIndex);
                e.Handled = true;
                break;
            case Key.Up when n > 0:
                _list.SelectedIndex = Math.Max(_list.SelectedIndex - 1, 0);
                _list.ScrollIntoView(_list.SelectedIndex);
                e.Handled = true;
                break;
            case Key.Enter:
                Choose();
                e.Handled = true;
                break;
        }
    }

    private void Choose()
    {
        if (_list.SelectedItem is NavigatorItem it) Close(it);
    }
}
