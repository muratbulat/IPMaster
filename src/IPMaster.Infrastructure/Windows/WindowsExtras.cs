using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using IPMaster.Core.Security;
using IPMaster.Infrastructure.Queries;
using Microsoft.Win32;

namespace IPMaster.Infrastructure.Windows;

/// <summary>Phase 4 Windows lookups: credential sessions (WKS-07), monitors (BAN-03), terminal sessions (BAN-05), WMI MAC (MAC-03).</summary>
public sealed partial class WindowsExtras : IWindowsExtras
{
    public CapabilityStatus Capability { get; } = OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes("Windows management APIs.")
        : CapabilityStatus.No("Needs a Windows scanner (D-010).");

    public IDisposable? OpenSession(string host, ResolvedCredential credential)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException(Capability.Description);
        return WindowsSession.Connect(host, credential);
    }

    public Observation<IReadOnlyList<MonitorInfo>> GetMonitors(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Observation<IReadOnlyList<MonitorInfo>>.Of(ObservationState.Unsupported, now, Capability.Description);
        try
        {
            using var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host);
            using var display = hklm.OpenSubKey(@"SYSTEM\CurrentControlSet\Enum\DISPLAY");
            if (display is null) return Observation<IReadOnlyList<MonitorInfo>>.Of(ObservationState.Empty, now, "No display devices recorded.");
            var list = new List<MonitorInfo>();
            foreach (var model in display.GetSubKeyNames())
            {
                using var modelKey = display.OpenSubKey(model);
                if (modelKey is null) continue;
                foreach (var instance in modelKey.GetSubKeyNames())
                {
                    using var inst = modelKey.OpenSubKey(instance);
                    // The "Control" subkey exists only for devices that are currently present.
                    if (inst is null || !inst.GetSubKeyNames().Contains("Control", StringComparer.OrdinalIgnoreCase)) continue;
                    using var p = inst.OpenSubKey("Device Parameters");
                    if (p?.GetValue("EDID") is byte[] edid && Edid.Parse(edid) is { } m && !list.Contains(m)) list.Add(m);
                }
            }

            return list.Count == 0
                ? Observation<IReadOnlyList<MonitorInfo>>.Of(ObservationState.Empty, now, "No attached monitor reported an EDID.")
                : Observation<IReadOnlyList<MonitorInfo>>.Ok(list, now);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            var state = ex is IOException ? ObservationState.NoResponse : ObservationState.AccessDenied;
            return Observation<IReadOnlyList<MonitorInfo>>.Of(state, now, "Remote Registry: " + ex.Message);
        }
    }

    public Observation<IReadOnlyList<TerminalSession>> GetTerminalSessions(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Observation<IReadOnlyList<TerminalSession>>.Of(ObservationState.Unsupported, now, Capability.Description);
        var server = WTSOpenServer(host);
        if (server == IntPtr.Zero) return Observation<IReadOnlyList<TerminalSession>>.Of(ObservationState.Failed, now, "WTSOpenServer failed.");
        try
        {
            if (!WTSEnumerateSessions(server, 0, 1, out var buffer, out var count))
            {
                var err = Marshal.GetLastPInvokeError();
                return Observation<IReadOnlyList<TerminalSession>>.Of(err == 5 ? ObservationState.AccessDenied : err is 1722 or 53 ? ObservationState.NoResponse : ObservationState.Failed,
                    now, new System.ComponentModel.Win32Exception(err).Message);
            }

            var list = new List<TerminalSession>();
            try
            {
                var size = Marshal.SizeOf<SessionInfo>();
                for (var i = 0; i < count; i++)
                {
                    var s = Marshal.PtrToStructure<SessionInfo>(buffer + (i * size));
                    var state = (SessionState)s.State;
                    if (state is SessionState.Listen or SessionState.Down or SessionState.Init) continue;
                    var user = QueryString(server, s.SessionId, 5);
                    var domain = QueryString(server, s.SessionId, 7);
                    if (user.Length == 0 && s.SessionId == 0) continue; // services session
                    list.Add(new TerminalSession(s.SessionId, domain.Length > 0 && user.Length > 0 ? $@"{domain}\{user}" : user, state.ToString(),
                        QueryString(server, s.SessionId, 10), ClientAddress(server, s.SessionId)));
                }
            }
            finally
            {
                WTSFreeMemory(buffer);
            }

            return list.Count == 0 ? Observation<IReadOnlyList<TerminalSession>>.Of(ObservationState.Empty, now) : Observation<IReadOnlyList<TerminalSession>>.Ok(list, now);
        }
        finally
        {
            WTSCloseServer(server);
        }
    }

    public Observation<PhysicalAddress> GetMacViaWmi(IPAddress address, ResolvedCredential? credential, TimeSpan timeout, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Observation<PhysicalAddress>.Of(ObservationState.Unsupported, now, Capability.Description);
        var local = IPAddress.IsLoopback(address);
        var options = new ConnectionOptions { Impersonation = ImpersonationLevel.Impersonate, Authentication = AuthenticationLevel.PacketPrivacy, Timeout = timeout };
        if (credential is not null && !local)
        {
            options.Username = credential.UserName;
            options.Password = credential.Password;
        }

        try
        {
            var scope = new ManagementScope(local ? @"\\.\root\cimv2" : $@"\\{WindowsSession.UncHost(address)}\root\cimv2", options);
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE"),
                new System.Management.EnumerationOptions { Timeout = timeout, ReturnImmediately = true, Rewindable = false });
            var target = address.ToString();
            foreach (var o in searcher.Get().Cast<ManagementBaseObject>())
            {
                using (o)
                {
                    if (o["IPAddress"] is string[] ips && (local || ips.Contains(target)) && o["MACAddress"] is string mac && Core.Results.Formats.ParseMac(mac) is { } pa)
                    {
                        return Observation<PhysicalAddress>.Ok(pa, now);
                    }
                }
            }

            return Observation<PhysicalAddress>.Of(ObservationState.Empty, now, "No adapter with this address.");
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            var mapped = WindowsQuery.Map(ex);
            return Observation<PhysicalAddress>.Of(mapped.State, now, mapped.Detail);
        }
    }

    private enum SessionState
    {
        Active,
        Connected,
        ConnectQuery,
        Shadow,
        Disconnected,
        Idle,
        Listen,
        Reset,
        Down,
        Init,
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    [SupportedOSPlatform("windows")]
    private static string QueryString(IntPtr server, int session, int infoClass)
    {
        if (!WTSQuerySessionInformation(server, session, infoClass, out var buf, out _)) return "";
        try
        {
            return Marshal.PtrToStringUni(buf) ?? "";
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }

    /// <summary>WTS_CLIENT_ADDRESS: AddressFamily (int) + 20 bytes; IPv4 bytes start at offset 2 of the address array.</summary>
    [SupportedOSPlatform("windows")]
    private static string ClientAddress(IntPtr server, int session)
    {
        if (!WTSQuerySessionInformation(server, session, 14, out var buf, out var bytes)) return "";
        try
        {
            if (bytes < 24) return "";
            var family = Marshal.ReadInt32(buf);
            var raw = new byte[20];
            Marshal.Copy(buf + 4, raw, 0, 20);
            return family switch
            {
                2 when raw[2..6].Any(b => b != 0) => new IPAddress(raw[2..6]).ToString(),
                23 => new IPAddress(raw[..16]).ToString(),
                _ => "",
            };
        }
        finally
        {
            WTSFreeMemory(buf);
        }
    }

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSOpenServerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr WTSOpenServer(string server);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSCloseServer(IntPtr server);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSEnumerateSessionsW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);

    [LibraryImport("wtsapi32.dll", EntryPoint = "WTSQuerySessionInformationW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);

    [LibraryImport("wtsapi32.dll")]
    private static partial void WTSFreeMemory(IntPtr memory);
}

/// <summary>Router MIB MAC method (MAC-04): walks ipNetToMediaPhysAddress (index = ifIndex.a.b.c.d).</summary>
public sealed class RouterArpSource : IRouterArpSource
{
    public const string IpNetToMediaPhysAddress = "1.3.6.1.2.1.4.22.1.2";

    public async Task<IReadOnlyDictionary<IPAddress, PhysicalAddress>> ArpTableAsync(IPAddress router, string community, CancellationToken cancellationToken)
    {
        var target = new SnmpTarget(new IPEndPoint(router, 161), SnmpVersion.V2c, [community], "", SnmpSecurity.NoAuthNoPriv, SnmpAuth.Sha256, "", SnmpPriv.Aes128, "");
        return Parse(await SnmpClient.WalkAsync(target, IpNetToMediaPhysAddress, cancellationToken, 20_000).ConfigureAwait(false));
    }

    public static IReadOnlyDictionary<IPAddress, PhysicalAddress> Parse(IEnumerable<SnmpValue> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var map = new Dictionary<IPAddress, PhysicalAddress>();
        foreach (var v in values)
        {
            var parts = v.Oid.Split('.');
            if (parts.Length < 4 || v.Octets is not { Length: 6 } mac || mac.All(b => b == 0)) continue;
            if (!parts[^4..].All(p => byte.TryParse(p, System.Globalization.CultureInfo.InvariantCulture, out _))) continue;
            map[new IPAddress(parts[^4..].Select(p => byte.Parse(p, System.Globalization.CultureInfo.InvariantCulture)).ToArray())] = new PhysicalAddress(mac);
        }

        return map;
    }
}
