using System.Collections.ObjectModel;
using System.Globalization;
using System.Net;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Data;
using Avalonia.Media;
using Avalonia.Threading;
using IPMaster.Core.Queries;
using IPMaster.Core.Results;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;
using IPMaster.Infrastructure.Tools;

namespace IPMaster.Desktop.Views;

/// <summary>Tools → SNMP Tester / MIB Browser (D-080). Read-only: GET, GETNEXT, GETBULK, WALK, BULKWALK; there is no SET.</summary>
internal sealed class SnmpTesterWindow : Window
{
    private static readonly string[] Operations = ["GET", "GETNEXT", "GETBULK", "WALK", "BULKWALK"];

    public SnmpTesterWindow(string? target = null)
    {
        Title = "SNMP Tester";
        Width = 1100;
        Height = 680;
        MinWidth = 640;
        MinHeight = 400;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        var status = ToolKit.StatusLine();
        var runner = new ToolRunner(status);
        var rows = new ObservableCollection<SnmpTestRow>();
        SnmpTestRequest? lastRequest = null;
        SnmpTestResult? last = null;

        // --- MIB tree (built-in standard objects) ---
        var description = new SelectableTextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 6, 0, 0), MaxHeight = 96, Classes = { "hint" } };
        var tree = new TreeView { MinWidth = 200 };
        Avalonia.Automation.AutomationProperties.SetName(tree, "MIB tree");
        static TreeViewItem Item(MibTreeNode n) => new()
        {
            Header = $"{n.Name}  ({n.Oid})", Tag = n, IsExpanded = n.Oid.Length <= 11, // down to mib-2
            ItemsSource = n.Children.Select(Item).ToList(),
        };
        tree.ItemsSource = new[] { Item(MibTree.Build()) };

        // --- request form ---
        var agent = new SnmpTargetForm(target);
        var operation = ToolKit.Combo("Operation", Operations, 0, 110);
        var oids = ToolKit.Text("OIDs", "OID (several: separate with spaces)", text: "1.3.6.1.2.1.1.1.0");
        oids.FontFamily = ToolKit.Mono;
        var nonRepeaters = ToolKit.Number(0, 0, 32, "Non-repeaters", 50);
        var maxRepetitions = ToolKit.Number(20, 1, 100, "Max-repetitions", 50);
        var maxItems = ToolKit.Number(5000, 1, SnmpTester.MaxItemsLimit, "Item limit", 80);
        var timeout = ToolKit.Number(3, 1, 60, "Timeout in seconds", 50);
        var retries = ToolKit.Number(1, 0, 3, "Retries", 50);

        // compact inline label + control pairs; rows wrap on narrow windows
        static Control L(string label, params Control[] controls) => SnmpTargetForm.Pair(label, controls);

        var bulkPair = L("Non-rep / Max-rep", nonRepeaters, maxRepetitions);
        var agentRow = agent.Row;
        var optionRow = new WrapPanel { Children = { bulkPair, L("Limit", maxItems), L("Timeout (s)", timeout), L("Retries", retries) } };
        void Visibility() => bulkPair.IsVisible = operation.SelectedIndex is 2 or 4; // GETBULK, BULKWALK

        operation.SelectionChanged += (_, _) => Visibility();
        Visibility();
        void Error(string text)
        {
            status.Text = text;
            Styling.Theme.SetState(status, "error");
        }

        tree.SelectionChanged += (_, _) =>
        {
            if (tree.SelectedItem is not TreeViewItem { Tag: MibTreeNode n }) return;
            description.Text = n.Entry is { } e ? $"{e.Name} ({e.Module}) {e.Oid}\n{e.Description}" : $"{n.Name} {n.Oid}";
            var isScalar = n.Entry is { IsColumn: false } && n.Oid.EndsWith(".0", StringComparison.Ordinal);
            oids.Text = n.Oid;
            operation.SelectedIndex = isScalar ? 0 : agent.Version.SelectedIndex == 0 ? 3 : 4; // scalar: GET; anything else: walk it
        };

        // --- results ---
        var grid = new DataGrid { ItemsSource = rows, IsReadOnly = true, AutoGenerateColumns = false, CanUserReorderColumns = true };
        grid.Columns.Add(new DataGridTextColumn { Header = "OID", Binding = new Binding(nameof(SnmpTestRow.Oid)), Width = new DataGridLength(230) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Name", Binding = new Binding(nameof(SnmpTestRow.Name)), Width = new DataGridLength(260) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Type", Binding = new Binding(nameof(SnmpTestRow.Type)), Width = new DataGridLength(130) });
        grid.Columns.Add(new DataGridTextColumn { Header = "Value", Binding = new Binding(nameof(SnmpTestRow.Value)), Width = new DataGridLength(1, DataGridLengthUnitType.Star) });
        Avalonia.Automation.AutomationProperties.SetName(grid, "Values");

        var run = Ui.Button("Send", async () =>
        {
            Styling.Theme.SetState(status, null);
            if (agent.Validate() is { } missing)
            {
                Error(missing);
                return;
            }

            var list = (oids.Text ?? "").Split([' ', '\n', '\r', '\t', ','], StringSplitOptions.RemoveEmptyEntries).ToList();
            var invalid = list.FirstOrDefault(o => !SnmpOid.TryParse(o, out _));
            if (invalid is not null || list.Count == 0)
            {
                Error(invalid is null ? "Enter an OID." : $"Not a numeric OID: {invalid}");
                return;
            }

            var resolve = agent.Snapshot();
            var input = (Name: agent.Host.Text?.Trim() ?? "", Op: (SnmpTestOperation)operation.SelectedIndex, Oids: list, NonRep: (int)(nonRepeaters.Value ?? 0), MaxRep: (int)(maxRepetitions.Value ?? 20),
                Max: (int)(maxItems.Value ?? 5000), Timeout: TimeSpan.FromSeconds((double)(timeout.Value ?? 3)), Retries: (int)(retries.Value ?? 1));
            rows.Clear();
            await runner.RunAsync($"{Operations[(int)input.Op]} {input.Name}", async ct =>
            {
                var (snmpTarget, resolveError) = await resolve(ct);
                if (snmpTarget is null) return resolveError!;

                var request = new SnmpTestRequest
                {
                    Target = snmpTarget,
                    Operation = input.Op, Oids = input.Oids, NonRepeaters = input.NonRep, MaxRepetitions = input.MaxRep, MaxItems = input.Max, Timeout = input.Timeout,
                    Retries = input.Retries,
                };
                var result = await SnmpTester.RunAsync(request, n => Dispatcher.UIThread.Post(() => status.Text = $"{n:N0} value(s) so far…"), ct);
                await Dispatcher.UIThread.InvokeAsync(() =>
                {
                    lastRequest = request;
                    last = result;
                    foreach (var row in result.Rows) rows.Add(row);
                });
                return $"{result.Outcome}" + (result.Detail.Length > 0 ? " — " + result.Detail : "") + $" · {result.Rows.Count:N0} value(s), {result.Duration.TotalMilliseconds:0} ms";
            });
            if (last is { Outcome: not (SnmpTestOutcome.Success or SnmpTestOutcome.NoSuchObject) }) Styling.Theme.SetState(status, "error");
        }, accent: true);
        var cancel = Ui.Button("Cancel", () =>
        {
            runner.Cancel();
            return Task.CompletedTask;
        });
        cancel.IsEnabled = false;
        runner.BusyChanged += (_, _) =>
        {
            run.IsEnabled = !runner.IsBusy;
            cancel.IsEnabled = runner.IsBusy;
        };
        var exportCsv = Ui.Button("CSV…", () =>
        {
            using var w = new StringWriter(CultureInfo.InvariantCulture);
            CsvExporter.WriteRow(w, ["oid", "name", "type", "value"], ',', true);
            foreach (var r in rows) CsvExporter.WriteRow(w, [r.Oid, r.Name, r.Type, r.Value], ',', true);
            return ToolKit.SaveTextAsync(this, w.ToString(), "snmp-values.csv");
        });
        ToolTip.SetTip(exportCsv, "Export values as CSV");
        var copy = ToolKit.CopyButton(this, () => last is null || lastRequest is null ? "" : SnmpTester.Report(lastRequest, last));
        ToolTip.SetTip(copy, "Copy report");

        // request row: operation, OIDs (stretch), actions
        var requestRow = new DockPanel { Margin = new Thickness(0, 0, 0, 4) };
        var opPair = L("Operation", operation);
        DockPanel.SetDock(opPair, Dock.Left);
        var buttons = Ui.Row(run, cancel, copy, exportCsv);
        buttons.Margin = new Thickness(8, 0, 0, 0);
        DockPanel.SetDock(buttons, Dock.Right);
        requestRow.Children.Add(opPair);
        requestRow.Children.Add(buttons);
        requestRow.Children.Add(oids);
        var inputs = new StackPanel { Children = { agentRow, requestRow, optionRow } };

        var left = new DockPanel();
        DockPanel.SetDock(description, Dock.Bottom);
        left.Children.Add(description);
        left.Children.Add(tree);
        var right = grid;
        var split = new Grid { ColumnDefinitions = new ColumnDefinitions("260,6,*") };
        split.Children.Add(left);
        var splitter = new GridSplitter { ResizeDirection = GridResizeDirection.Columns };
        Grid.SetColumn(splitter, 1);
        split.Children.Add(splitter);
        Grid.SetColumn(right, 2);
        split.Children.Add(right);
        Content = Ui.Layout(inputs, split, status);
        Closed += (_, _) => runner.Dispose();
    }
}
