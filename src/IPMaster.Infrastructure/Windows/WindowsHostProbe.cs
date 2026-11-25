using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using IPMaster.Core.Scanning;
using Microsoft.Win32;

namespace IPMaster.Infrastructure.Windows;

/// <summary>
/// Remote Windows management through NetApi32, remote registry and SMB, using the current account's credentials
/// (specific accounts arrive with the credential vault, Phase 4). Windows scanner only; every method is blocking
/// and is bounded by the scan engine (timeouts, concurrency, abandoned-call cap).
/// </summary>
public sealed partial class WindowsHostProbe : IWindowsHostProbe
{
    private const int NerrSuccess = 0;
    private const int ErrorAccessDenied = 5;
    private const int ErrorMoreData = 234;
    private const int ErrorBadNetPath = 53;
    private const int RpcServerUnavailable = 1722;
    private const int MaxPreferredLength = -1;

    public CapabilityStatus Capability { get; } = OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes("Windows NetApi, remote registry and SMB with the current account.")
        : CapabilityStatus.No("Windows workstation and share lookups need a Windows scanner in this build (portable SMB adapter not yet available, D-035).");

    private static Observation<T> Error<T>(int code, DateTimeOffset now, string what) => code switch
    {
        ErrorAccessDenied => Observation<T>.Of(ObservationState.AccessDenied, now, $"{what}: access denied."),
        ErrorBadNetPath or RpcServerUnavailable or 1231 or 1219 => Observation<T>.Of(ObservationState.NoResponse, now, $"{what}: host not reachable (error {code})."),
        _ => Observation<T>.Of(ObservationState.Failed, now, $"{what}: error {code}."),
    };

    private static Observation<T> Unsupported<T>(DateTimeOffset now) => Observation<T>.Of(ObservationState.Unsupported, now, "Requires a Windows scanner.");

    private static string Unc(string host) => @"\\" + host;

    // ---------------- workstation ----------------
    public Observation<string> GetWorkgroup(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<string>(now);
        var rc = NetWkstaGetInfo(Unc(host), 100, out var buf);
        if (rc != NerrSuccess) return Error<string>(rc, now, "Workstation info");
        try
        {
            var info = Marshal.PtrToStructure<WkstaInfo100>(buf);
            var group = Marshal.PtrToStringUni(info.LanGroup);
            return string.IsNullOrEmpty(group) ? Observation<string>.Of(ObservationState.Empty, now) : Observation<string>.Ok(group, now);
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
    }

    public Observation<string> GetWindowsVersion(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<string>(now);
        // Prefer the registry (edition, feature update and build); fall back to the NetApi major/minor version.
        try
        {
            using var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key?.GetValue("ProductName") is string product)
            {
                var build = key.GetValue("CurrentBuild") as string;
                var ubr = key.GetValue("UBR");
                var display = key.GetValue("DisplayVersion") as string ?? key.GetValue("ReleaseId") as string;
                if (int.TryParse(build, out var b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11", StringComparison.Ordinal);
                var text = product + (display is null ? "" : " " + display) + (build is null ? "" : $" (build {build}{(ubr is null ? "" : "." + ubr)})");
                return Observation<string>.Ok(text, now);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SecurityException)
        {
            // Remote Registry service stopped or denied: use NetApi below.
        }

        var rc = NetServerGetInfo(Unc(host), 101, out var buf);
        if (rc != NerrSuccess) return Error<string>(rc, now, "Server info");
        try
        {
            var info = Marshal.PtrToStructure<ServerInfo101>(buf);
            var role = (info.Type & 0x8000) != 0 ? "Server" : "Workstation";
            if ((info.Type & 0x18) != 0) role = "Domain controller";
            return Observation<string>.Ok($"Windows NT {info.VersionMajor & 0x0F}.{info.VersionMinor} ({role})", now) with
            {
                Detail = "Remote Registry unavailable; version from NetServerGetInfo.",
            };
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
    }

    public Observation<IReadOnlyList<string>> GetAccounts(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<IReadOnlyList<string>>(now);
        var list = new List<string>();
        var resume = 0;
        int rc;
        do
        {
            rc = NetUserEnum(Unc(host), 0, 2, out var buf, MaxPreferredLength, out var read, out _, ref resume);
            if (rc is not (NerrSuccess or ErrorMoreData)) return Error<IReadOnlyList<string>>(rc, now, "User accounts");
            try
            {
                for (var i = 0; i < read; i++) list.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, i * IntPtr.Size)) ?? "");
            }
            finally
            {
                _ = NetApiBufferFree(buf);
            }
        }
        while (rc == ErrorMoreData);

        return Observation<IReadOnlyList<string>>.Ok(list.Where(n => n.Length > 0).Order(StringComparer.OrdinalIgnoreCase).ToList(), now);
    }

    public Observation<IReadOnlyList<string>> GetLoggedOnUsers(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<IReadOnlyList<string>>(now);
        var list = new List<string>();
        var resume = 0;
        int rc;
        do
        {
            rc = NetWkstaUserEnum(Unc(host), 1, out var buf, MaxPreferredLength, out var read, out _, ref resume);
            if (rc is not (NerrSuccess or ErrorMoreData)) return Error<IReadOnlyList<string>>(rc, now, "Logged-on users");
            try
            {
                var size = Marshal.SizeOf<WkstaUserInfo1>();
                for (var i = 0; i < read; i++)
                {
                    var u = Marshal.PtrToStructure<WkstaUserInfo1>(buf + (i * size));
                    var user = Marshal.PtrToStringUni(u.UserName) ?? "";
                    var domain = Marshal.PtrToStringUni(u.LogonDomain) ?? "";
                    if (user.Length == 0 || user.EndsWith('$')) continue; // computer accounts
                    list.Add(domain.Length > 0 ? $"{domain}\\{user}" : user);
                }
            }
            finally
            {
                _ = NetApiBufferFree(buf);
            }
        }
        while (rc == ErrorMoreData);

        return list.Count == 0 ? Observation<IReadOnlyList<string>>.Of(ObservationState.Empty, now) : Observation<IReadOnlyList<string>>.Ok(list.Distinct().ToList(), now);
    }

    public Observation<IReadOnlyList<string>> GetLoggedOnSids(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<IReadOnlyList<string>>(now);
        try
        {
            using var users = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, host);
            var sids = users.GetSubKeyNames().Where(n => UserSid().IsMatch(n)).ToList();
            return sids.Count == 0 ? Observation<IReadOnlyList<string>>.Of(ObservationState.Empty, now) : Observation<IReadOnlyList<string>>.Ok(sids, now);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            return Observation<IReadOnlyList<string>>.Of(ObservationState.AccessDenied, now, "Remote registry: access denied.");
        }
        catch (IOException ex)
        {
            return Observation<IReadOnlyList<string>>.Of(ObservationState.NoResponse, now, "Remote registry unavailable: " + ex.Message);
        }
    }

    public Observation<DateTimeOffset> GetRemoteTime(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<DateTimeOffset>(now);
        var rc = NetRemoteTOD(Unc(host), out var buf);
        if (rc != NerrSuccess) return Error<DateTimeOffset>(rc, now, "Remote time");
        try
        {
            var tod = Marshal.PtrToStructure<TimeOfDayInfo>(buf);
            var utc = DateTimeOffset.FromUnixTimeSeconds(tod.ElapsedSeconds).AddMilliseconds(tod.Hundredths * 10);
            var offset = tod.Timezone == -1 ? TimeSpan.Zero : TimeSpan.FromMinutes(-tod.Timezone);
            return Observation<DateTimeOffset>.Ok(utc.ToOffset(offset), now);
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
    }

    public Observation<IReadOnlyList<InstalledApplication>> GetInstalledApplications(string host, DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<IReadOnlyList<InstalledApplication>>(now);
        var apps = new Dictionary<string, InstalledApplication>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                using var hklm = RegistryKey.OpenRemoteBaseKey(RegistryHive.LocalMachine, host, view);
                using var root = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (root is null) continue;
                foreach (var name in root.GetSubKeyNames())
                {
                    using var k = root.OpenSubKey(name);
                    if (k?.GetValue("DisplayName") is not string display || string.IsNullOrWhiteSpace(display)) continue;
                    if (k.GetValue("SystemComponent") is int sc && sc == 1) continue;
                    if (k.GetValue("ParentKeyName") is not null) continue; // updates/patches
                    var version = k.GetValue("DisplayVersion") as string;
                    apps.TryAdd(display + "|" + version, new InstalledApplication(display.Trim(), version?.Trim(), (k.GetValue("Publisher") as string)?.Trim()));
                }
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            return Observation<IReadOnlyList<InstalledApplication>>.Of(ObservationState.AccessDenied, now, "Remote registry: access denied.");
        }
        catch (IOException ex)
        {
            return Observation<IReadOnlyList<InstalledApplication>>.Of(ObservationState.NoResponse, now, "Remote registry unavailable: " + ex.Message);
        }

        return Observation<IReadOnlyList<InstalledApplication>>.Ok(apps.Values.OrderBy(a => a.Name, StringComparer.OrdinalIgnoreCase).ToList(), now);
    }

    // ---------------- shares ----------------
    public Observation<IReadOnlyList<ShareInfo>> GetShares(string host, ShareTypeSelection types, bool diskSpace, bool security, bool writeCheck,
        DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows()) return Unsupported<IReadOnlyList<ShareInfo>>(now);
        var raw = new List<(string Name, uint Type, string Remark)>();
        var resume = 0;
        int rc;
        do
        {
            rc = NetShareEnum(Unc(host), 1, out var buf, MaxPreferredLength, out var read, out _, ref resume);
            if (rc is not (NerrSuccess or ErrorMoreData)) return Error<IReadOnlyList<ShareInfo>>(rc, now, "Share enumeration");
            try
            {
                var size = Marshal.SizeOf<ShareInfo1>();
                for (var i = 0; i < read; i++)
                {
                    var s = Marshal.PtrToStructure<ShareInfo1>(buf + (i * size));
                    raw.Add((Marshal.PtrToStringUni(s.NetName) ?? "", s.Type, Marshal.PtrToStringUni(s.Remark) ?? ""));
                }
            }
            finally
            {
                _ = NetApiBufferFree(buf);
            }
        }
        while (rc == ErrorMoreData);

        var shares = new List<ShareInfo>();
        foreach (var (name, type, remark) in raw)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var baseType = type & 0xFF;
            var special = (type & 0x80000000) != 0 || name.EndsWith('$');
            var kind = baseType switch
            {
                0 => ShareKind.Folder,
                1 => ShareKind.Printer,
                2 => ShareKind.Device,
                3 => ShareKind.Ipc,
                _ => ShareKind.Other,
            };
            var include = kind switch
            {
                ShareKind.Folder => special ? types.HasFlag(ShareTypeSelection.Administrative) : types.HasFlag(ShareTypeSelection.Folders),
                ShareKind.Printer => types.HasFlag(ShareTypeSelection.Printers),
                ShareKind.Device => types.HasFlag(ShareTypeSelection.Devices),
                ShareKind.Ipc => types.HasFlag(ShareTypeSelection.Ipc),
                _ => types == ShareTypeSelection.All,
            };
            if (!include) continue;

            var share = new ShareInfo { Name = name, Kind = kind, IsAdministrative = special, Remark = remark };
            var path = $@"\\{host}\{name}\";
            if (kind == ShareKind.Folder)
            {
                share = share with { Access = CheckAccess(path, writeCheck, now) };
                if (diskSpace) share = share with { Disk = GetDisk(path, now) };
            }

            if (security) share = share with { Permissions = GetPermissions(host, name, now) };
            shares.Add(share);
        }

        return Observation<IReadOnlyList<ShareInfo>>.Ok(shares.OrderBy(s => s.Name, StringComparer.OrdinalIgnoreCase).ToList(), now);
    }

    /// <summary>Readability = listing the root. Write check (only when enabled) creates a uniquely named temporary file
    /// with DeleteOnClose, so the OS removes it when the handle closes, even if IPMaster crashes (SHR-05).</summary>
    [SupportedOSPlatform("windows")]
    internal static Observation<ShareAccess> CheckAccess(string path, bool writeCheck, DateTimeOffset now)
    {
        bool readable;
        try
        {
            using var e = Directory.EnumerateFileSystemEntries(path).GetEnumerator();
            e.MoveNext();
            readable = true;
        }
        catch (UnauthorizedAccessException)
        {
            readable = false;
        }
        catch (IOException ex)
        {
            return Observation<ShareAccess>.Of(ObservationState.Failed, now, ex.Message);
        }

        bool? writable = null;
        if (writeCheck)
        {
            var probe = Path.Combine(path, $".ipmaster-write-test-{Guid.NewGuid():N}.tmp");
            try
            {
                using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose))
                {
                }

                writable = true;
            }
            catch (UnauthorizedAccessException)
            {
                writable = false;
            }
            catch (IOException ex) when ((ex.HResult & 0xFFFF) is 5 or 19 or 32) // denied, write-protected, sharing violation
            {
                writable = false;
            }
            catch (IOException)
            {
                writable = null;
            }
        }

        return Observation<ShareAccess>.Ok(new ShareAccess(readable, writable), now);
    }

    [SupportedOSPlatform("windows")]
    private static Observation<DiskSpace> GetDisk(string path, DateTimeOffset now)
    {
        if (GetDiskFreeSpaceEx(path, out var free, out var total, out _)) return Observation<DiskSpace>.Ok(new DiskSpace((long)total, (long)free), now);
        var err = Marshal.GetLastPInvokeError();
        return Error<DiskSpace>(err, now, "Disk space");
    }

    [SupportedOSPlatform("windows")]
    private static Observation<IReadOnlyList<ShareAccessEntry>> GetPermissions(string host, string share, DateTimeOffset now)
    {
        var rc = NetShareGetInfo(Unc(host), share, 502, out var buf);
        if (rc != NerrSuccess) return Error<IReadOnlyList<ShareAccessEntry>>(rc, now, "Share security (administrator rights are usually required)");
        try
        {
            var info = Marshal.PtrToStructure<ShareInfo502>(buf);
            if (info.SecurityDescriptor == IntPtr.Zero)
            {
                return Observation<IReadOnlyList<ShareAccessEntry>>.Ok([new ShareAccessEntry("Everyone", "Full Control (no security descriptor)", true)], now);
            }

            var length = (int)GetSecurityDescriptorLength(info.SecurityDescriptor);
            var bytes = new byte[length];
            Marshal.Copy(info.SecurityDescriptor, bytes, 0, length);
            var sd = new RawSecurityDescriptor(bytes, 0);
            var list = new List<ShareAccessEntry>();
            if (sd.DiscretionaryAcl is { } dacl)
            {
                foreach (var ace in dacl.OfType<CommonAce>())
                {
                    string account;
                    try
                    {
                        account = ace.SecurityIdentifier.Translate(typeof(NTAccount)).Value;
                    }
                    catch (IdentityNotMappedException)
                    {
                        account = ace.SecurityIdentifier.Value;
                    }

                    list.Add(new ShareAccessEntry(account, ShareRights(ace.AccessMask), ace.AceQualifier == AceQualifier.AccessAllowed));
                }
            }

            return Observation<IReadOnlyList<ShareAccessEntry>>.Ok(list, now);
        }
        finally
        {
            _ = NetApiBufferFree(buf);
        }
    }

    internal static string ShareRights(int mask) => mask switch
    {
        0x1F01FF => "Full Control",
        0x1301BF => "Change",
        0x1200A9 => "Read",
        _ => "0x" + mask.ToString("X", System.Globalization.CultureInfo.InvariantCulture),
    };

    [GeneratedRegex(@"^S-1-5-21-\d+-\d+-\d+-\d+$")]
    private static partial Regex UserSid();

    // ---------------- interop ----------------
    [StructLayout(LayoutKind.Sequential)]
    private struct WkstaInfo100
    {
        public int PlatformId;
        public IntPtr ComputerName;
        public IntPtr LanGroup;
        public int VersionMajor;
        public int VersionMinor;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServerInfo101
    {
        public int PlatformId;
        public IntPtr Name;
        public int VersionMajor;
        public int VersionMinor;
        public int Type;
        public IntPtr Comment;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WkstaUserInfo1
    {
        public IntPtr UserName;
        public IntPtr LogonDomain;
        public IntPtr OtherDomains;
        public IntPtr LogonServer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TimeOfDayInfo
    {
        public int ElapsedSeconds;
        public int Milliseconds;
        public int Hours;
        public int Minutes;
        public int Seconds;
        public int Hundredths;
        public int Timezone;
        public int Interval;
        public int Day;
        public int Month;
        public int Year;
        public int Weekday;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ShareInfo1
    {
        public IntPtr NetName;
        public uint Type;
        public IntPtr Remark;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ShareInfo502
    {
        public IntPtr NetName;
        public uint Type;
        public IntPtr Remark;
        public int Permissions;
        public int MaxUses;
        public int CurrentUses;
        public IntPtr Path;
        public IntPtr Password;
        public int Reserved;
        public IntPtr SecurityDescriptor;
    }

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetWkstaGetInfo(string server, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetServerGetInfo(string server, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetUserEnum(string server, int level, int filter, out IntPtr buffer, int prefMaxLen, out int entriesRead,
        out int totalEntries, ref int resumeHandle);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetWkstaUserEnum(string server, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead,
        out int totalEntries, ref int resumeHandle);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetRemoteTOD(string server, out IntPtr buffer);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetShareEnum(string server, int level, out IntPtr buffer, int prefMaxLen, out int entriesRead,
        out int totalEntries, ref int resumeHandle);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    private static partial int NetShareGetInfo(string server, string share, int level, out IntPtr buffer);

    [LibraryImport("netapi32.dll")]
    [SupportedOSPlatform("windows")]
    private static partial int NetApiBufferFree(IntPtr buffer);

    [LibraryImport("advapi32.dll")]
    [SupportedOSPlatform("windows")]
    private static partial uint GetSecurityDescriptorLength(IntPtr descriptor);

    [LibraryImport("kernel32.dll", EntryPoint = "GetDiskFreeSpaceExW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [SupportedOSPlatform("windows")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetDiskFreeSpaceEx(string directory, out ulong freeBytesAvailable, out ulong totalBytes, out ulong totalFreeBytes);
}
