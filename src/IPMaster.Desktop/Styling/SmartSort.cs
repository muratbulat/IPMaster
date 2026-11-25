using System.Collections;
using System.Collections.Concurrent;
using System.Reflection;
using Avalonia.Controls;
using Avalonia.Interactivity;
using IPMaster.Core.Results;

namespace IPMaster.Desktop.Styling;

/// <summary>
/// Header-click sorting by value for every grid (<see cref="ValueOrder"/>): IP addresses by address, numbers with units by
/// value, dates chronologically, text in natural order. Applied to each bound column of each DataGrid when it loads;
/// columns that already have their own comparer, and grids that sort themselves (the results grid), are left alone.
/// The DataGrid keeps the selection, the active sort and inserts new rows in sorted position.
/// </summary>
internal static class SmartSort
{
    private static bool _registered;

    public static void Register()
    {
        if (_registered) return;
        _registered = true;
        Control.LoadedEvent.AddClassHandler<DataGrid>((g, _) => Apply(g), RoutingStrategies.Direct);
    }

    public static void Apply(DataGrid grid)
    {
        ArgumentNullException.ThrowIfNull(grid);
        foreach (var column in grid.Columns)
        {
            if (column.CustomSortComparer is not null) continue;
            var path = column.SortMemberPath is { Length: > 0 } p ? p
                : column is DataGridBoundColumn { Binding: { } b } ? b.GetType().GetProperty("Path")?.GetValue(b)?.ToString() : null;
            if (string.IsNullOrEmpty(path) || path.Contains('[', StringComparison.Ordinal)) continue; // indexers: the grid sorts itself
            column.CustomSortComparer = new PathComparer(path);
        }
    }

    /// <summary>Compares rows by the displayed value of one property path ("Address", "Stats.Latency").</summary>
    internal sealed class PathComparer(string path) : IComparer
    {
        private static readonly ConcurrentDictionary<(Type, string), PropertyInfo?> Cache = new();
        private readonly string[] _parts = path.Split('.');

        public int Compare(object? x, object? y) => ValueOrder.Compare(Text(x), Text(y));

        private string? Text(object? row)
        {
            var value = row;
            foreach (var part in _parts)
            {
                if (value is null) return null;
                var prop = Cache.GetOrAdd((value.GetType(), part), k => k.Item1.GetProperty(k.Item2));
                value = prop?.GetValue(value);
            }

            return value switch
            {
                null => null,
                IFormattable f => f.ToString(null, System.Globalization.CultureInfo.CurrentCulture),
                _ => value.ToString(),
            };
        }
    }
}
