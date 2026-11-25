using System.Reflection;
using System.Runtime.InteropServices;
using IPMaster.Core.Network;
using IPMaster.Core.Scanning;

namespace IPMaster.Infrastructure.Discovery;

public sealed record CaptureInterface(string PcapName, string Description, NetworkAdapterInfo Adapter, AdapterAddress Address);

/// <summary>
/// libpcap (Npcap on Windows, libpcap on Linux/macOS), loaded at run time: no package and nothing installed by IPMaster.
/// Without the library <see cref="Capability"/> explains what to install and every user of it reports Unavailable.
/// Shared by duplicate-IP detection and Device IP Discovery (D-090).
/// </summary>
public sealed class PcapLibrary(INetworkAdapterProvider adapters)
{
    private readonly object _gate = new();
    private nint _lib;
    private string? _loadError;

    public CapabilityStatus Capability => EnsureLoaded()
        ? CapabilityStatus.Yes(OperatingSystem.IsWindows() ? "Npcap packet capture driver." : "libpcap packet capture.")
        : CapabilityStatus.No(_loadError!);

    private bool EnsureLoaded()
    {
        lock (_gate)
        {
            if (_lib != 0) return true;
            string[] candidates = OperatingSystem.IsWindows()
                ? [Path.Combine(Environment.SystemDirectory, "Npcap", "wpcap.dll"), "wpcap.dll"]
                : OperatingSystem.IsMacOS() ? ["libpcap.dylib", "libpcap.A.dylib"] : ["libpcap.so.1", "libpcap.so", "libpcap.so.0.8"];
            foreach (var c in candidates)
            {
                if (NativeLibrary.TryLoad(c, Assembly.GetExecutingAssembly(), DllImportSearchPath.System32 | DllImportSearchPath.SafeDirectories, out _lib)) return true;
            }

            _loadError = OperatingSystem.IsWindows()
                ? "Npcap is not installed. Install Npcap from npcap.com (WinPcap API-compatible mode) for packet capture and raw ARP."
                : "libpcap was not found. Install libpcap (e.g. 'libpcap0.8' or 'libpcap') and run with CAP_NET_RAW.";
            return false;
        }
    }

    private T Fn<T>(string name) where T : Delegate => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(_lib, name));

    private unsafe delegate int FindAllDevs(out nint list, byte* err);

    private delegate void FreeAllDevs(nint list);

    private unsafe delegate nint OpenLive(string device, int snaplen, int promisc, int timeoutMs, byte* err);

    internal unsafe delegate int SendPacket(nint p, byte* data, int size);

    internal delegate int NextEx(nint p, out nint header, out nint data);

    internal delegate void Close(nint p);

    private delegate int Compile(nint p, nint program, string filter, int optimize, uint netmask);

    private delegate int SetFilter(nint p, nint program);

    private delegate void FreeCode(nint program);

    /// <summary>IPv4 adapters that libpcap can open (matched by adapter GUID on Windows, by name elsewhere).</summary>
    public unsafe IReadOnlyList<CaptureInterface> Interfaces()
    {
        if (!EnsureLoaded()) return [];
        var err = stackalloc byte[256];
        if (Fn<FindAllDevs>("pcap_findalldevs")(out var list, err) != 0) return [];
        var names = new List<(string Name, string Desc)>();
        try
        {
            for (var p = list; p != 0; p = Marshal.ReadIntPtr(p))
            {
                var name = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(p, IntPtr.Size)) ?? "";
                var desc = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(p, IntPtr.Size * 2)) ?? "";
                names.Add((name, desc));
            }
        }
        finally
        {
            Fn<FreeAllDevs>("pcap_freealldevs")(list);
        }

        var result = new List<CaptureInterface>();
        foreach (var a in adapters.GetAdapters())
        {
            var dev = names.FirstOrDefault(n => n.Name.Contains(a.Id, StringComparison.OrdinalIgnoreCase) || n.Name == a.Name);
            if (dev.Name is null || a.MacAddress is null) continue;
            foreach (var addr in a.IPv4.Where(x => x.PrefixLength is >= 16 and <= 30)) result.Add(new CaptureInterface(dev.Name, dev.Desc, a, addr));
        }

        return result;
    }

    /// <summary>Opens a live capture (non-promiscuous unless asked) with a BPF filter; read with a 50 ms timeout.</summary>
    public unsafe PcapHandle Open(string device, string filter, int snapLength = 128, bool promiscuous = false)
    {
        if (!EnsureLoaded()) throw new InvalidOperationException(_loadError);
        var err = stackalloc byte[256];
        var handle = Fn<OpenLive>("pcap_open_live")(device, snapLength, promiscuous ? 1 : 0, 50, err);
        if (handle == 0)
        {
            throw new InvalidOperationException("Cannot open the capture device: " + Marshal.PtrToStringAnsi((nint)err)
                                                + (OperatingSystem.IsWindows() ? "" : " (CAP_NET_RAW or root is required)"));
        }

        var program = Marshal.AllocHGlobal(16);
        try
        {
            if (Fn<Compile>("pcap_compile")(handle, program, filter, 1, 0) == 0)
            {
                Fn<SetFilter>("pcap_setfilter")(handle, program);
                Fn<FreeCode>("pcap_freecode")(program);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(program);
        }

        return new PcapHandle(handle, Fn<SendPacket>("pcap_sendpacket"), Fn<NextEx>("pcap_next_ex"), Fn<Close>("pcap_close"), snapLength);
    }
}

/// <summary>An open capture. Not thread-safe: one user at a time; Dispose closes it.</summary>
public sealed class PcapHandle : IFrameLink, IDisposable
{
    private readonly PcapLibrary.SendPacket _send;
    private readonly PcapLibrary.NextEx _next;
    private readonly PcapLibrary.Close _close;
    private readonly int _snap;
    private nint _handle;

    internal PcapHandle(nint handle, PcapLibrary.SendPacket send, PcapLibrary.NextEx next, PcapLibrary.Close close, int snap)
        => (_handle, _send, _next, _close, _snap) = (handle, send, next, close, snap);

    /// <summary>
    /// <c>caplen</c> follows <c>struct timeval</c> in <c>pcap_pkthdr</c>: two 32-bit longs on Windows (8 bytes, also on x64),
    /// two native longs elsewhere. D-090: the old code used 2 × pointer size, which is wrong on 64-bit Windows.
    /// </summary>
    internal static int CaplenOffset => OperatingSystem.IsWindows() ? 8 : IntPtr.Size * 2;

    public unsafe void Send(ReadOnlySpan<byte> frame)
    {
        ObjectDisposedException.ThrowIf(_handle == 0, this);
        fixed (byte* f = frame) _send(_handle, f, frame.Length);
    }

    /// <summary>Hands every frame waiting now to <paramref name="onFrame"/>; returns after the 50 ms read timeout.</summary>
    public unsafe int Drain(ReadOnlySpanAction<byte> onFrame)
    {
        ArgumentNullException.ThrowIfNull(onFrame);
        ObjectDisposedException.ThrowIf(_handle == 0, this);
        var n = 0;
        while (_next(_handle, out var hdr, out var data) == 1)
        {
            var caplen = Marshal.ReadInt32(hdr, CaplenOffset);
            onFrame(new ReadOnlySpan<byte>((void*)data, Math.Min(caplen, _snap)));
            n++;
        }

        return n;
    }

    public void Dispose()
    {
        if (_handle == 0) return;
        _close(_handle);
        _handle = 0;
    }
}

public delegate void ReadOnlySpanAction<T>(ReadOnlySpan<T> span);
