namespace IPMaster.Core.Navigation;

public enum NavigatorKind
{
    Command,
    Setting,
    Query,
    Application,
}

/// <summary>One searchable entry of the Navigator (UI-17). <see cref="Path"/> is shown as context ("View › Tree").</summary>
public sealed record NavigatorItem(NavigatorKind Kind, string Title, string Path, string Target, string Keywords = "");

/// <summary>
/// Ranked, case-insensitive search: every typed word must match the title, path or keywords. Title matches rank above
/// path/keyword matches; a word starting a title word ranks above a match inside a word. Ties keep the input order.
/// </summary>
public static class Navigator
{
    public static IReadOnlyList<NavigatorItem> Search(IReadOnlyList<NavigatorItem> items, string? query, int max = 200)
    {
        ArgumentNullException.ThrowIfNull(items);
        var words = (query ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length == 0) return items.Take(max).ToList();
        var ranked = new List<(NavigatorItem Item, int Score, int Index)>();
        for (var i = 0; i < items.Count; i++)
        {
            var it = items[i];
            var total = 0;
            foreach (var w in words)
            {
                var s = Score(it, w);
                if (s == 0)
                {
                    total = 0;
                    break;
                }

                total += s;
            }

            if (total > 0) ranked.Add((it, total, i));
        }

        return ranked.OrderByDescending(r => r.Score).ThenBy(r => r.Index).Take(max).Select(r => r.Item).ToList();
    }

    private static int Score(NavigatorItem it, string word)
    {
        var title = Clean(it.Title);
        if (title.StartsWith(word, StringComparison.OrdinalIgnoreCase)) return 100;
        if (StartsWord(title, word)) return 60;
        if (title.Contains(word, StringComparison.OrdinalIgnoreCase)) return 40;
        if (StartsWord(it.Path, word) || StartsWord(it.Keywords, word)) return 20;
        if (it.Path.Contains(word, StringComparison.OrdinalIgnoreCase) || it.Keywords.Contains(word, StringComparison.OrdinalIgnoreCase)) return 10;
        return 0;
    }

    private static bool StartsWord(string text, string word)
    {
        for (var i = text.IndexOf(word, StringComparison.OrdinalIgnoreCase); i >= 0; i = text.IndexOf(word, i + 1, StringComparison.OrdinalIgnoreCase))
        {
            if (i == 0 || !char.IsLetterOrDigit(text[i - 1])) return true;
        }

        return false;
    }

    /// <summary>Removes access-key underscores and trailing ellipses from menu headers.</summary>
    public static string Clean(string header)
    {
        ArgumentNullException.ThrowIfNull(header);
        var s = header.Replace("__", "\u0001", StringComparison.Ordinal).Replace("_", "", StringComparison.Ordinal).Replace("\u0001", "_", StringComparison.Ordinal);
        return s.TrimEnd('…', '.', ' ');
    }
}
