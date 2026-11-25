using IPMaster.Core.Configuration;
using IPMaster.Core.Navigation;
using IPMaster.Infrastructure.Configuration;

namespace IPMaster.Tests;

public class ShortcutTests
{
    private static readonly ShortcutCommand Load = new("File/Load Results", "Load Results", "File", "Ctrl+L");
    private static readonly ShortcutCommand Save = new("File/Save Results", "Save Results", "File", "Ctrl+S");
    private static readonly ShortcutCommand Nav = new("Help/Navigator", "Navigator", "Help", "F1");
    private static readonly ShortcutCommand Exit = new("File/Exit", "Exit", "File", "");

    [Theory]
    [InlineData("ctrl + shift + f5", "Ctrl+Shift+F5")]
    [InlineData("Shift+Ctrl+A", "Ctrl+Shift+A")]
    [InlineData("Control+Return", "Ctrl+Enter")]
    [InlineData("Alt+1", "Alt+D1")]
    [InlineData("Ctrl+D1", "Ctrl+D1")]
    [InlineData("win+del", "Meta+Delete")]
    [InlineData("Ctrl++", "Ctrl+OemPlus")]
    [InlineData("F12", "F12")]
    [InlineData("", "")]
    [InlineData("  ", "")]
    public void Gestures_normalise(string input, string expected) => Assert.Equal(expected, Shortcuts.Normalize(input));

    [Theory]
    [InlineData("Ctrl")]
    [InlineData("Ctrl+Shift")]
    [InlineData("Ctrl+Ctrl+A")]
    [InlineData("Ctrl+A+B")]
    [InlineData("Ctrl+NumPad1")]
    [InlineData("F25")]
    [InlineData("Ctrl+")]
    public void Non_gestures_are_rejected(string input) => Assert.Null(Shortcuts.Normalize(input));

    [Fact]
    public void Overrides_replace_or_remove_defaults_and_unknown_ids_are_ignored()
    {
        var eff = Shortcuts.Effective([Load, Save, Nav, Exit],
        [
            new ShortcutBinding { CommandId = Load.Id, Gesture = "ctrl+shift+o" },
            new ShortcutBinding { CommandId = Nav.Id, Gesture = "" },
            new ShortcutBinding { CommandId = "Gone/Removed Command", Gesture = "Ctrl+Q" },
            new ShortcutBinding { CommandId = Save.Id, Gesture = "not a key" }, // invalid → default kept
        ]);
        Assert.Equal("Ctrl+Shift+O", eff[Load.Id]);
        Assert.Equal("", eff[Nav.Id]);
        Assert.Equal("Ctrl+S", eff[Save.Id]);
        Assert.Equal("", eff[Exit.Id]);
        Assert.False(eff.ContainsKey("Gone/Removed Command"));
    }

    [Fact]
    public void Assign_stores_only_differences_and_conflicts_are_reported()
    {
        var o = Shortcuts.Assign([], Exit, "Ctrl+Q");
        Assert.Single(o);
        o = Shortcuts.Assign(o, Load, "ctrl+l"); // same as default → nothing stored
        Assert.Single(o);
        o = Shortcuts.Assign(o, Exit, ""); // back to its (empty) default → no override left
        Assert.Empty(o);
        o = Shortcuts.Assign(o, Nav, ""); // removing a default shortcut is stored as ""
        Assert.Equal("", Assert.Single(o).Gesture);
        Assert.Throws<ArgumentException>(() => Shortcuts.Assign(o, Exit, "Ctrl+Shift"));

        var clash = Shortcuts.Effective([Load, Save, Nav], [new ShortcutBinding { CommandId = Save.Id, Gesture = "Ctrl+L" }]);
        var c = Assert.Single(Shortcuts.Conflicts(clash));
        Assert.Equal("Ctrl+L", c.Gesture);
        Assert.Equal([Load.Id, Save.Id], c.CommandIds);
    }
}

public class NavigatorTests
{
    private static readonly NavigatorItem[] Items =
    [
        new(NavigatorKind.Command, "Load Results", "File", "cmd:1", "Ctrl+L"),
        new(NavigatorKind.Command, "Device Inventory", "Reports", "cmd:2"),
        new(NavigatorKind.Setting, "Resolve host names", "Options › Additional", "opt:1:Resolve host names"),
        new(NavigatorKind.Setting, "Display inactive devices", "Options › General", "opt:0:Display inactive devices"),
        new(NavigatorKind.Query, "Disk Free", "Remote queries › Wmi", "query:Wmi:x"),
        new(NavigatorKind.Command, "Collapse All", "View › Tree", "cmd:3"),
    ];

    [Fact]
    public void Empty_query_lists_everything_in_order()
    {
        Assert.Equal(Items, Navigator.Search(Items, "  "));
        Assert.Equal(2, Navigator.Search(Items, null, max: 2).Count);
    }

    [Fact]
    public void Title_prefix_ranks_above_word_start_and_path_matches()
    {
        var r = Navigator.Search(Items, "dev");
        // "Device Inventory" (title prefix) before "Display inactive devices" (word inside the title)
        Assert.Equal(["Device Inventory", "Display inactive devices"], r.Select(i => i.Title));
        Assert.Equal("Collapse All", Assert.Single(Navigator.Search(Items, "tree")).Title); // path
        Assert.Equal("Load Results", Assert.Single(Navigator.Search(Items, "ctrl+l")).Title); // keywords
    }

    [Fact]
    public void Every_word_must_match()
    {
        Assert.Equal("Resolve host names", Assert.Single(Navigator.Search(Items, "host additional")).Title);
        Assert.Empty(Navigator.Search(Items, "host general"));
        Assert.Empty(Navigator.Search(Items, "zzz"));
    }

    [Theory]
    [InlineData("_Load Results…", "Load Results")]
    [InlineData("Remote W_MI…", "Remote WMI")]
    [InlineData("Save__As...", "Save_As")]
    public void Menu_headers_are_cleaned(string header, string expected) => Assert.Equal(expected, Navigator.Clean(header));
}

public class SharedSettingsTests
{
    [Fact]
    public void Merge_keeps_both_windows_changes_and_ours_wins_on_the_same_value()
    {
        var @base = new AppSettings();
        var ours = @base with { View = @base.View with { DarkMode = true, GridLines = false } };
        var theirs = @base with
        {
            View = @base.View with { GridLines = true, CellSeparator = " | " },
            Bookmarks = [new Bookmark { Name = "Lab", Ranges = [new RangeEntry { Target = "10.0.0.0/24" }] }],
        };
        var m = SettingsStore.Merge(@base, ours, theirs);
        Assert.True(m.View.DarkMode);          // only ours changed it
        Assert.Equal(" | ", m.View.CellSeparator); // only theirs changed it
        Assert.Equal("Lab", Assert.Single(m.Bookmarks).Name);
        Assert.False(m.View.GridLines);        // both changed: ours wins
    }

    [Fact]
    public async Task Two_stores_on_one_file_do_not_lose_each_others_changes()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-shared-").FullName;
        try
        {
            var a = new SettingsStore(dir);
            var b = new SettingsStore(dir);
            var sa = a.Load().Settings;
            await a.SaveAsync(sa);
            sa = a.Load().Settings;
            var sb = b.Load().Settings;

            var savedB = await b.SaveSharedAsync(sb with { View = sb.View with { DarkMode = true } });
            Assert.True(savedB.View.DarkMode);
            var savedA = await a.SaveSharedAsync(sa with { AutoLoadSaveRecent = true });
            Assert.True(savedA.AutoLoadSaveRecent);
            Assert.True(savedA.View.DarkMode); // B's change merged in, not overwritten

            var onDisk = new SettingsStore(dir).Load().Settings;
            Assert.True(onDisk.AutoLoadSaveRecent);
            Assert.True(onDisk.View.DarkMode);
            Assert.False(File.Exists(Path.Combine(dir, SettingsStore.FileName + ".lock")));

            // no external change: what was passed in is saved as is
            var again = savedA with { View = savedA.View with { GridLines = false } };
            Assert.Same(again, await a.SaveSharedAsync(again));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task Concurrent_shared_saves_are_serialised_by_the_lock()
    {
        var dir = Directory.CreateTempSubdirectory("ipm-shared-").FullName;
        try
        {
            var stores = Enumerable.Range(0, 4).Select(_ => new SettingsStore(dir)).ToList();
            await stores[0].SaveAsync(new AppSettings());
            var loaded = stores.Select(s => s.Load().Settings).ToList();
            await Task.WhenAll(stores.Select((s, i) => s.SaveSharedAsync(loaded[i] with
            {
                Bookmarks = [],
                SavedFilters = [],
                RecentFiles = [$"file{i}.xml"],
            })));
            var final = new SettingsStore(dir).Load();
            Assert.Equal(SettingsLoadStatus.Loaded, final.Status); // never a torn or corrupt file
            Assert.Single(final.Settings.RecentFiles);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
