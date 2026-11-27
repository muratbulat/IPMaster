namespace IPMaster.Core.Configuration;

/// <summary>An action that can carry a keyboard shortcut (UI-18). The id is stable across versions and languages.</summary>
public sealed record ShortcutCommand(string Id, string Name, string Category, string DefaultGesture);

/// <summary>Gesture text normalisation and the effective shortcut map (defaults + user overrides).</summary>
public static class Shortcuts
{
    private static readonly string[] ModifierOrder = ["Ctrl", "Shift", "Alt", "Meta"];

    /// <summary>
    /// Normalises "ctrl + shift + f5" → "Ctrl+Shift+F5". Returns null for text that is not a gesture: no key, only
    /// modifiers, a repeated modifier, or an unknown token. Empty text stays empty (= no shortcut).
    /// </summary>
    public static string? Normalize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var parts = text.Split('+', StringSplitOptions.TrimEntries);
        // "Ctrl++" means Ctrl and the plus key
        if (text.TrimEnd().EndsWith("++", StringComparison.Ordinal)) parts = [.. parts[..^2], "Plus"];
        var mods = new List<string>();
        string? key = null;
        foreach (var p in parts)
        {
            if (p.Length == 0) return null;
            var mod = Modifier(p);
            if (mod is not null)
            {
                if (mods.Contains(mod)) return null;
                mods.Add(mod);
                continue;
            }

            if (key is not null) return null;
            key = Key(p);
            if (key is null) return null;
        }

        if (key is null) return null;
        return string.Join("+", ModifierOrder.Where(mods.Contains).Append(key));
    }

    private static string? Modifier(string p) => p.ToUpperInvariant() switch
    {
        "CTRL" or "CONTROL" => "Ctrl",
        "SHIFT" => "Shift",
        "ALT" => "Alt",
        "META" or "WIN" or "CMD" or "COMMAND" => "Meta",
        _ => null,
    };

    private static string? Key(string p)
    {
        if (p.Length == 1)
        {
            var c = char.ToUpperInvariant(p[0]);
            if (c is >= 'A' and <= 'Z') return c.ToString();
            if (c is >= '0' and <= '9') return "D" + c;
            return null;
        }

        var u = p.ToUpperInvariant();
        if (u[0] == 'F' && int.TryParse(u.AsSpan(1), out var f) && f is >= 1 and <= 24) return "F" + f;
        if (u.Length == 2 && u[0] == 'D' && char.IsAsciiDigit(u[1])) return u;
        return u switch
        {
            "ENTER" or "RETURN" => "Enter",
            "ESC" or "ESCAPE" => "Escape",
            "DEL" or "DELETE" => "Delete",
            "INS" or "INSERT" => "Insert",
            "SPACE" => "Space",
            "TAB" => "Tab",
            "BACK" or "BACKSPACE" => "Back",
            "HOME" => "Home",
            "END" => "End",
            "PAGEUP" or "PGUP" => "PageUp",
            "PAGEDOWN" or "PGDN" => "PageDown",
            "UP" => "Up",
            "DOWN" => "Down",
            "LEFT" => "Left",
            "RIGHT" => "Right",
            "PLUS" or "OEMPLUS" => "OemPlus",
            "MINUS" or "OEMMINUS" => "OemMinus",
            _ => null,
        };
    }

    /// <summary>
    /// Command ids renamed by the Options/Tools reorganisation (D-111): old id → new id. Saved shortcuts keep their old ids (an
    /// older version still reads them); <see cref="Effective"/> applies them to the new command, <see cref="Assign"/> replaces them.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> LegacyIds = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        ["Options/IP Address/Auto Detect Local IP Range"] = "Tools/IP Address Tools",
        ["Options/IP Address/Detect IP Range from Host Name"] = "Tools/IP Address Tools/From Host Name",
        ["Options/IP Address/Detect External IP Address"] = "Tools/IP Address Tools/External IP",
        ["Options/Wake-On-LAN Manager"] = "Tools/Wake-on-LAN Manager",
        ["Options/Credential Manager"] = "Tools/Credential Manager",
        ["Options/Remote WMI"] = "Tools/Remote Query Manager",
        ["Options/Remote Registry"] = "Tools/Remote Query Manager/Registry",
        ["Options/Remote Files"] = "Tools/Remote Query Manager/Files",
        ["Options/Remote Services"] = "Tools/Remote Query Manager/Services",
        ["Options/Remote Groups"] = "Tools/Remote Query Manager/Groups",
        ["Options/Remote Performance"] = "Tools/Remote Query Manager/Performance",
        ["Options/Remote PowerShell"] = "Tools/Remote Query Manager/PowerShell",
        ["Options/Remote Scripting"] = "Tools/Remote Query Manager/Script",
        ["Options/Remote SNMP"] = "Tools/Remote Query Manager/Snmp",
        ["Options/Remote SSH"] = "Tools/Remote Query Manager/Ssh",
        ["Options/Remote XML"] = "Tools/Remote Query Manager/Xml",
        ["Options/Remote JSON"] = "Tools/Remote Query Manager/Json",
        ["Options/Integration with Nmap"] = "Tools/Remote Query Manager/Nmap",
        ["Options/Remote Python"] = "Tools/Remote Query Manager/Python",
        ["Tools/DNS Diagnostics"] = "Tools/DNS Tools",
        ["Tools/Bulk DNS Audit"] = "Tools/DNS Tools/Bulk Audit",
        ["Tools/SNMP Tester"] = "Tools/SNMP Tools",
        ["Tools/SNMP Interface Monitor"] = "Tools/SNMP Tools/Interface Monitor",
    };

    /// <summary>Effective gesture per command id: the override when one exists (empty = removed), else the default.</summary>
    public static IReadOnlyDictionary<string, string> Effective(IEnumerable<ShortcutCommand> commands, IEnumerable<ShortcutBinding> overrides)
    {
        ArgumentNullException.ThrowIfNull(commands);
        ArgumentNullException.ThrowIfNull(overrides);
        var map = commands.ToDictionary(c => c.Id, c => Normalize(c.DefaultGesture) ?? "", StringComparer.Ordinal);
        var list = overrides.ToList();
        var direct = list.Select(o => o.CommandId).Where(map.ContainsKey).ToHashSet(StringComparer.Ordinal);
        var renamed = new HashSet<string>(StringComparer.Ordinal);
        foreach (var o in list)
        {
            var id = o.CommandId;
            if (!map.ContainsKey(id))
            {
                // a renamed command keeps the user's key (D-111), unless the user set the new command too; the first old entry wins
                if (!LegacyIds.TryGetValue(id, out var to) || !map.ContainsKey(to) || direct.Contains(to) || !renamed.Add(to)) continue;
                id = to;
            }

            map[id] = Normalize(o.Gesture) ?? map[id];
        }

        return map;
    }

    /// <summary>Gestures used by more than one command (the dialog refuses to create these; a hand-edited file may contain them).</summary>
    public static IReadOnlyList<(string Gesture, IReadOnlyList<string> CommandIds)> Conflicts(IReadOnlyDictionary<string, string> effective)
    {
        ArgumentNullException.ThrowIfNull(effective);
        return effective.Where(p => p.Value.Length > 0)
            .GroupBy(p => p.Value, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => (g.Key, (IReadOnlyList<string>)g.Select(p => p.Key).Order(StringComparer.Ordinal).ToList()))
            .OrderBy(c => c.Key, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>Sets one command's gesture; stores only differences from the default.</summary>
    public static IReadOnlyList<ShortcutBinding> Assign(IReadOnlyList<ShortcutBinding> overrides, ShortcutCommand command, string gesture)
    {
        ArgumentNullException.ThrowIfNull(overrides);
        ArgumentNullException.ThrowIfNull(command);
        var g = Normalize(gesture) ?? throw new ArgumentException($"'{gesture}' is not a keyboard shortcut.", nameof(gesture));
        var rest = overrides.Where(o => o.CommandId != command.Id && LegacyIds.GetValueOrDefault(o.CommandId) != command.Id).ToList(); // the old id is replaced too
        if (g != (Normalize(command.DefaultGesture) ?? "")) rest.Add(new ShortcutBinding { CommandId = command.Id, Gesture = g });
        return rest;
    }
}
