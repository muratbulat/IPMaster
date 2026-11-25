using System.Runtime.InteropServices;
using Avalonia.Controls;
using Avalonia.Platform;

namespace IPMaster.Desktop.Platform;

/// <summary>One tray menu entry; <see cref="Separator"/> draws a line.</summary>
internal sealed record TrayMenuItem(string Text, Action? Invoke, bool Checked = false, bool Enabled = true)
{
    public static readonly TrayMenuItem Separator = new("-", null);
}

/// <summary>
/// Notification-area icon (UI-19, D-065). Windows uses Shell_NotifyIcon directly because Avalonia's TrayIcon has no
/// notification API; other platforms use Avalonia's TrayIcon and report <see cref="SupportsNotifications"/> = false.
/// </summary>
internal interface ITray : IDisposable
{
    bool SupportsNotifications { get; }

    bool IsVisible { get; set; }

    /// <summary>Left click on the icon or a click on one of its notifications.</summary>
    event EventHandler? Activated;

    void Notify(string title, string text);

    /// <summary>Rebuilds the menu text/check state (Windows builds the menu on each right click).</summary>
    void Refresh();

    static ITray Create(string tooltip, Func<IReadOnlyList<TrayMenuItem>> menu) =>
        OperatingSystem.IsWindows() ? new WindowsTray(tooltip, menu) : new AvaloniaTray(tooltip, menu);
}

internal sealed class AvaloniaTray : ITray
{
    private readonly TrayIcon _icon;
    private readonly Func<IReadOnlyList<TrayMenuItem>> _menu;

    public AvaloniaTray(string tooltip, Func<IReadOnlyList<TrayMenuItem>> menu)
    {
        _menu = menu;
        _icon = new TrayIcon
        {
            ToolTipText = tooltip,
            Icon = new WindowIcon(AssetLoader.Open(new Uri("avares://IPMaster/Assets/ipmaster.png"))),
            IsVisible = false,
        };
        _icon.Clicked += (_, _) => Activated?.Invoke(this, EventArgs.Empty);
        Refresh();
        if (Avalonia.Application.Current is { } app)
        {
            var icons = TrayIcon.GetIcons(app) ?? [];
            icons.Add(_icon);
            TrayIcon.SetIcons(app, icons);
        }
    }

    public event EventHandler? Activated;

    public bool SupportsNotifications => false;

    public bool IsVisible
    {
        get => _icon.IsVisible;
        set => _icon.IsVisible = value;
    }

    public void Notify(string title, string text)
    {
        // not supported by Avalonia's TrayIcon: the caller shows the in-window notification
    }

    public void Refresh()
    {
        var m = new NativeMenu();
        foreach (var item in _menu())
        {
            if (ReferenceEquals(item, TrayMenuItem.Separator))
            {
                m.Items.Add(new NativeMenuItemSeparator());
                continue;
            }

            var n = new NativeMenuItem(item.Text) { IsEnabled = item.Enabled };
            if (item.Checked)
            {
                n.ToggleType = MenuItemToggleType.CheckBox;
                n.IsChecked = true;
            }

            var invoke = item.Invoke;
            if (invoke is not null) n.Click += (_, _) => invoke();
            m.Items.Add(n);
        }

        _icon.Menu = m;
    }

    public void Dispose()
    {
        _icon.IsVisible = false;
        _icon.Dispose();
    }
}

/// <summary>Shell_NotifyIcon on a hidden window owned by the UI thread (Avalonia's message loop dispatches to it).</summary>
[System.Runtime.Versioning.SupportedOSPlatform("windows")]
internal sealed unsafe partial class WindowsTray : ITray
{
    private const uint WmApp = 0x8000;
    private const uint CallbackMessage = WmApp + 1;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmRButtonUp = 0x0205;
    private const uint WmNull = 0;
    private const uint NinBalloonUserClick = 0x0405;
    private const uint NimAdd = 0, NimModify = 1, NimDelete = 2;
    private const uint NifMessage = 1, NifIcon = 2, NifTip = 4, NifInfo = 0x10, NifShowTip = 0x80;
    private const uint NiifInfo = 1, NiifNoSound = 0x10;

    private static readonly Dictionary<nint, WindowsTray> Instances = [];
    private static readonly ushort ClassAtom = RegisterClass();
    private static readonly uint TaskbarCreated = RegisterWindowMessageW("TaskbarCreated");

    private readonly Func<IReadOnlyList<TrayMenuItem>> _menu;
    private readonly string _tooltip;
    private readonly nint _hwnd;
    private readonly nint _hicon;
    private bool _visible;

    public WindowsTray(string tooltip, Func<IReadOnlyList<TrayMenuItem>> menu)
    {
        _tooltip = tooltip;
        _menu = menu;
        _hwnd = CreateWindowExW(0, (char*)ClassAtom, null, 0, 0, 0, 0, 0, 0, 0, GetModuleHandleW(null), null);
        if (_hwnd == 0) throw new InvalidOperationException("The notification-area window could not be created.");
        Instances[_hwnd] = this;
        nint small = 0;
        if (Environment.ProcessPath is { } exe) _ = ExtractIconExW(exe, 0, null, &small, 1);
        _hicon = small;
    }

    public event EventHandler? Activated;

    public bool SupportsNotifications => true;

    public bool IsVisible
    {
        get => _visible;
        set
        {
            if (value == _visible) return;
            _visible = value;
            if (value) Add();
            else Delete();
        }
    }

    public void Notify(string title, string text)
    {
        if (!_visible) return;
        var d = Data(NifInfo);
        Copy(title, d.szInfoTitle, 64);
        Copy(text, d.szInfo, 256);
        d.dwInfoFlags = NiifInfo | NiifNoSound;
        _ = Shell_NotifyIconW(NimModify, &d);
    }

    public void Refresh()
    {
        // the menu is built when it opens
    }

    public void Dispose()
    {
        Delete();
        Instances.Remove(_hwnd);
        _ = DestroyWindow(_hwnd);
        if (_hicon != 0) _ = DestroyIcon(_hicon);
    }

    private void Add()
    {
        var d = Data(NifMessage | NifIcon | NifTip | NifShowTip);
        _ = Shell_NotifyIconW(NimAdd, &d);
    }

    private void Delete()
    {
        var d = Data(0);
        _ = Shell_NotifyIconW(NimDelete, &d);
    }

    private NotifyIconData Data(uint flags)
    {
        var d = new NotifyIconData
        {
            cbSize = (uint)sizeof(NotifyIconData),
            hWnd = _hwnd,
            uID = 1,
            uFlags = flags,
            uCallbackMessage = CallbackMessage,
            hIcon = _hicon,
        };
        Copy(_tooltip, d.szTip, 128);
        return d;
    }

    private static void Copy(string s, char* dest, int size)
    {
        var n = Math.Min(s.Length, size - 1);
        for (var i = 0; i < n; i++) dest[i] = s[i];
        dest[n] = '\0';
    }

    private void ShowMenu()
    {
        var items = _menu();
        var menu = CreatePopupMenu();
        try
        {
            for (var i = 0; i < items.Count; i++)
            {
                var it = items[i];
                if (ReferenceEquals(it, TrayMenuItem.Separator))
                {
                    _ = AppendMenuW(menu, 0x800, 0, null);
                    continue;
                }

                var flags = (it.Checked ? 8u : 0u) | (it.Enabled ? 0u : 1u);
                fixed (char* t = it.Text) _ = AppendMenuW(menu, flags, (nuint)(i + 1), t);
            }

            Point p;
            _ = GetCursorPos(&p);
            _ = SetForegroundWindow(_hwnd);
            var chosen = TrackPopupMenu(menu, 0x0100 | 0x0002, p.X, p.Y, 0, _hwnd, null);
            _ = PostMessageW(_hwnd, WmNull, 0, 0);
            if (chosen > 0 && chosen <= items.Count) items[chosen - 1].Invoke?.Invoke();
        }
        finally
        {
            _ = DestroyMenu(menu);
        }
    }

    [UnmanagedCallersOnly]
    private static nint WndProc(nint hwnd, uint msg, nuint wParam, nint lParam)
    {
        if (Instances.TryGetValue(hwnd, out var tray))
        {
            try
            {
                if (msg == CallbackMessage)
                {
                    var ev = (uint)(lParam & 0xFFFF);
                    if (ev is WmLButtonUp or NinBalloonUserClick) tray.Activated?.Invoke(tray, EventArgs.Empty);
                    else if (ev == WmRButtonUp) tray.ShowMenu();
                    return 0;
                }

                if (msg == TaskbarCreated && tray._visible) tray.Add(); // Explorer restarted
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or ArgumentException)
            {
                // never let an exception cross the native boundary
            }
        }

        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }

    private static ushort RegisterClass()
    {
        fixed (char* name = "IPMaster.TrayWindow")
        {
            var wc = new WndClassEx
            {
                cbSize = (uint)sizeof(WndClassEx),
                lpfnWndProc = (nint)(delegate* unmanaged<nint, uint, nuint, nint, nint>)&WndProc,
                hInstance = GetModuleHandleW(null),
                lpszClassName = name,
            };
            return RegisterClassExW(&wc);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Point
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WndClassEx
    {
        public uint cbSize;
        public uint style;
        public nint lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public nint hInstance;
        public nint hIcon;
        public nint hCursor;
        public nint hbrBackground;
        public char* lpszMenuName;
        public char* lpszClassName;
        public nint hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NotifyIconData
    {
        public uint cbSize;
        public nint hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public nint hIcon;
        public fixed char szTip[128];
        public uint dwState;
        public uint dwStateMask;
        public fixed char szInfo[256];
        public uint uTimeoutOrVersion;
        public fixed char szInfoTitle[64];
        public uint dwInfoFlags;
        public Guid guidItem;
        public nint hBalloonIcon;
    }

    [LibraryImport("shell32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool Shell_NotifyIconW(uint message, NotifyIconData* data);

    [LibraryImport("shell32.dll")]
    private static partial uint ExtractIconExW([MarshalAs(UnmanagedType.LPWStr)] string file, int index, nint* large, nint* small, uint count);

    [LibraryImport("user32.dll")]
    private static partial ushort RegisterClassExW(WndClassEx* wc);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint RegisterWindowMessageW(string name);

    [LibraryImport("user32.dll")]
    private static partial nint CreateWindowExW(uint exStyle, char* className, char* windowName, uint style, int x, int y, int w, int h, nint parent, nint menu, nint instance, void* param);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyWindow(nint hwnd);

    [LibraryImport("user32.dll")]
    private static partial nint DefWindowProcW(nint hwnd, uint msg, nuint wParam, nint lParam);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetModuleHandleW(char* name);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyIcon(nint icon);

    [LibraryImport("user32.dll")]
    private static partial nint CreatePopupMenu();

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AppendMenuW(nint menu, uint flags, nuint id, char* text);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool DestroyMenu(nint menu);

    [LibraryImport("user32.dll")]
    private static partial int TrackPopupMenu(nint menu, uint flags, int x, int y, int reserved, nint hwnd, void* rect);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetCursorPos(Point* p);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetForegroundWindow(nint hwnd);

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool PostMessageW(nint hwnd, uint msg, nuint wParam, nint lParam);
}
