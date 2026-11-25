using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using Avalonia.Controls;
using IPMaster.Core.Results;

namespace IPMaster.Tests;

/// <summary>Type-aware header sorting (ValueOrder): addresses, numbers with units, durations, dates, natural text, empties.</summary>
public class ValueOrderTests
{
    private static string[] Sorted(params string?[] values) =>
        [.. values.OrderBy(v => v, Comparer<string?>.Create((a, b) => ValueOrder.Compare(a, b, culture: CultureInfo.InvariantCulture))).Select(v => v ?? "<null>")];

    [Fact]
    public void Ip_addresses_sort_by_address_not_text()
    {
        Assert.Equal(["192.168.1.2", "192.168.1.10", "192.168.1.100"], Sorted("192.168.1.100", "192.168.1.2", "192.168.1.10"));
        Assert.Equal(["10.0.0.0/8", "10.0.0.0/24", "172.16.0.1", "::1", "2001:db8::2", "2001:db8::10", "fe80::1"],
            Sorted("fe80::1", "2001:db8::10", "172.16.0.1", "::1", "10.0.0.0/24", "2001:db8::2", "10.0.0.0/8")); // IPv4 first, then IPv6
    }

    [Fact]
    public void Numbers_sort_by_value_with_units_normalised()
    {
        Assert.Equal(["9 ms", "85 ms", "1.2 s"], Sorted("85 ms", "1.2 s", "9 ms"));
        Assert.Equal(["900 kbps", "12.5 MB/s", "1 Gbps"], Sorted("1 Gbps", "900 kbps", "12.5 MB/s")); // 100 Mbit/s < 1 Gbit/s
        Assert.Equal(["512 MB", "1 GB", "2 GiB"], Sorted("2 GiB", "512 MB", "1 GB"));
        Assert.Equal(["-90 dBm", "-67 dBm", "-48 dBm"], Sorted("-48 dBm", "-90 dBm", "-67 dBm"));
        Assert.Equal(["2", "10", "100"], Sorted("100", "2", "10"));
        Assert.Equal(["8 sec", "1 min 20 sec", "13 min 20 sec", "2 h 2 min", "3 days 16 h 53 min"],
            Sorted("13 min 20 sec", "3 days 16 h 53 min", "8 sec", "2 h 2 min", "1 min 20 sec"));
        Assert.Equal(["5 %", "68 %"], Sorted("68 %", "5 %"));
    }

    [Fact]
    public void Dates_sort_chronologically_and_text_naturally()
    {
        Assert.Equal(["2026-01-05 09:00", "2026-11-24 08:00", "2026-11-24 17:30"], Sorted("2026-11-24 17:30", "2026-01-05 09:00", "2026-11-24 08:00"));
        Assert.Equal(["host2", "Host10", "host100"], Sorted("host100", "Host10", "host2"));
        Assert.Equal(["3 items", "10 items"], Sorted("10 items", "3 items")); // unknown unit: natural text, still numeric-aware
    }

    [Fact]
    public void Empty_values_sort_last_and_kinds_do_not_mix()
    {
        var sorted = Sorted("", "alpha", "—", "5", "10.0.0.1");
        Assert.Equal(["10.0.0.1", "5", "alpha"], sorted[..3]); // address, number, text
        Assert.Equal(["", "—"], sorted[3..].Order()); // both "no value": last, equal to each other
        Assert.Equal(["1", "<null>"], Sorted(null, "1"));
        Assert.Equal(["1.5", "2"], Sorted("2", "1.5")); // a decimal is a number, not the address 1.0.0.5
    }
}

[Collection("Headless UI")]
public class GridSortingTests
{
    public sealed record Row(string Address, string Latency, string Name);

    private static List<Row> Order(DataGrid g) => [.. g.CollectionView.Cast<Row>()];

    [Fact]
    public Task Header_sorting_is_type_aware_keeps_selection_and_places_new_rows() => HeadlessUi.Run(() =>
    {
        var rows = new ObservableCollection<Row>
        {
            new("192.168.1.100", "85 ms", "host10"), new("192.168.1.2", "9 ms", "host2"), new("192.168.1.10", "—", "Host1"),
        };
        var grid = IPMaster.Desktop.Views.Ui.Grid(("IP Address", nameof(Row.Address), 140), ("Latency", nameof(Row.Latency), 90), ("Host Name", nameof(Row.Name), 0));
        grid.ItemsSource = rows;
        var window = new Window { Content = grid, Width = 600, Height = 300 };
        window.Show();
        try
        {
            UiDesignSystemTests.Dispatch();
            Assert.True(grid.CanUserSortColumns);
            Assert.All(grid.Columns, c => Assert.NotNull(c.CustomSortComparer));
            grid.SelectedItem = rows[0];

            grid.Columns[0].Sort(ListSortDirection.Ascending);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["192.168.1.2", "192.168.1.10", "192.168.1.100"], Order(grid).Select(r => r.Address));
            Assert.Same(rows[0], grid.SelectedItem); // the selection survives the sort

            grid.Columns[1].Sort(ListSortDirection.Ascending);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["9 ms", "85 ms", "—"], Order(grid).Select(r => r.Latency)); // not "85 ms" before "9 ms"; no value last

            grid.Columns[2].Sort(ListSortDirection.Descending);
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["host10", "host2", "Host1"], Order(grid).Select(r => r.Name));

            rows.Add(new Row("10.0.0.1", "1 ms", "host3")); // a live update keeps the active sort
            UiDesignSystemTests.Dispatch();
            Assert.Equal(["host10", "host3", "host2", "Host1"], Order(grid).Select(r => r.Name));
        }
        finally
        {
            window.Close();
        }
    });
}
