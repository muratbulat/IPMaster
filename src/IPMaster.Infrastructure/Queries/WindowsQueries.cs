using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.ServiceProcess;
using System.Text.RegularExpressions;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using IPMaster.Core.Security;
using Microsoft.Win32;
using FileOptions = IPMaster.Core.Queries.FileOptions;
using RegistryOptions = IPMaster.Core.Queries.RegistryOptions;

namespace IPMaster.Infrastructure.Queries;

/// <summary>
/// Authenticated SMB session to <c>\\host\IPC$</c> for queries that use a stored credential (D-055). Registry, SCM,
/// NetApi, performance counters and admin shares then run over that session; without a credential the current
/// Windows account is used. Sessions are reference counted per host.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class WindowsSession
{
    private static readonly Dictionary<string, int> Counts = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object Lock = new();

    public static string UncHost(IPAddress address) => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
        ? address.ToString().Replace(':', '-').Replace('%', 's') + ".ipv6-literal.net"
        : address.ToString();

    public static IDisposable? Connect(string host, ResolvedCredential? credential)
    {
        if (credential is null) return null;
        var remote = $@"\\{host}\IPC$";
        lock (Lock)
        {
            if (Counts.TryGetValue(remote, out var n))
            {
                Counts[remote] = n + 1;
                return new Release(remote);
            }

            var nr = new NetResource { Type = 0, RemoteName = remote };
            var rc = WNetAddConnection2(ref nr, credential.Password, credential.UserName, 0);
            switch (rc)
            {
                case 0:
                    Counts[remote] = 1;
                    return new Release(remote);
                case 1219:
                    throw new UnauthorizedAccessException($"Windows already has a connection to {host} with different credentials (disconnect it first).");
                case 5 or 86 or 1326 or 1327 or 1330 or 1331 or 1909:
                    throw new UnauthorizedAccessException(new System.ComponentModel.Win32Exception(rc).Message);
                case 53 or 67 or 1203 or 1231:
                    throw new IOException(new System.ComponentModel.Win32Exception(rc).Message);
                default:
                    throw new System.ComponentModel.Win32Exception(rc);
            }
        }
    }

    private sealed class Release(string remote) : IDisposable
    {
        private int _done;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 1) return;
            lock (Lock)
            {
                if (!Counts.TryGetValue(remote, out var n)) return;
                if (n > 1)
                {
                    Counts[remote] = n - 1;
                    return;
                }

                Counts.Remove(remote);
                _ = WNetCancelConnection2(remote, 0, true);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NetResource
    {
        public int Scope;
        public int Type;
        public int DisplayType;
        public int Usage;
        public string? LocalName;
        public string? RemoteName;
        public string? Comment;
        public string? Provider;
    }

    [DllImport("mpr.dll", EntryPoint = "WNetAddConnection2W", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WNetAddConnection2(ref NetResource resource, string? password, string? user, uint flags);

    [LibraryImport("mpr.dll", EntryPoint = "WNetCancelConnection2W", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int WNetCancelConnection2(string name, uint flags, [MarshalAs(UnmanagedType.Bool)] bool force);
}

/// <summary>Shared plumbing: Windows-only guard, blocking calls off the thread pool's async path, error mapping.</summary>
internal static class WindowsQuery
{
    public static CapabilityStatus Capability(string what) => OperatingSystem.IsWindows()
        ? CapabilityStatus.Yes(what + " (Windows, current account or stored credential).")
        : CapabilityStatus.No(what + " needs a Windows scanner (D-010).");

    public static async Task<Observation<string>> RunAsync(Func<Observation<string>> work, CancellationToken ct)
    {
        try
        {
            // Windows management APIs block; the query timeout abandons a hung call instead of holding the scan.
            return await Task.Run(work, CancellationToken.None).WaitAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Map(ex);
        }
    }

    public static Observation<string> Map(Exception ex)
    {
        var now = DateTimeOffset.UtcNow;
        return ex switch
        {
            UnauthorizedAccessException or SecurityException => Observation<string>.Of(ObservationState.AccessDenied, now, ex.Message),
            IOException io when io.Message.Contains("network path", StringComparison.OrdinalIgnoreCase) => Observation<string>.Of(ObservationState.NoResponse, now, io.Message),
            COMException com when (uint)com.HResult == 0x800706BA => Observation<string>.Of(ObservationState.NoResponse, now, "RPC server unavailable."),
            COMException com when (uint)com.HResult == 0x80070005 => Observation<string>.Of(ObservationState.AccessDenied, now, com.Message),
            System.ComponentModel.Win32Exception w when w.NativeErrorCode == 5 => Observation<string>.Of(ObservationState.AccessDenied, now, w.Message),
            System.ComponentModel.Win32Exception w when w.NativeErrorCode is 53 or 1722 => Observation<string>.Of(ObservationState.NoResponse, now, w.Message),
            _ => Observation<string>.Of(ObservationState.Failed, now, ex.Message),
        };
    }

    public static Observation<string> Lines(IReadOnlyList<string> lines, string? emptyDetail = null) => lines.Count == 0
        ? Observation<string>.Of(ObservationState.Empty, DateTimeOffset.UtcNow, emptyDetail)
        : Observation<string>.Ok(string.Join('\n', lines), DateTimeOffset.UtcNow);

    public static bool IsLocal(QueryCall call) => call.Device.Address.Equals(IPAddress.Loopback) || call.Device.Address.Equals(IPAddress.IPv6Loopback);
}

/// <summary>Remote Registry (REG-01..04).</summary>
public sealed class RegistryQueryProvider : IRemoteQueryProvider
{
    public QueryKind Kind => QueryKind.Registry;

    public CapabilityStatus Capability { get; } = WindowsQuery.Capability("Remote Registry");

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description));
        var o = call.Query.Registry ?? new RegistryOptions();
        var host = WindowsSession.UncHost(call.Device.Address);
        return WindowsQuery.RunAsync(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var session = WindowsSession.Connect(host, call.Credential);
            return Read(o, host, cancellationToken);
        }, cancellationToken);
    }

    /// <summary>Local Value column of the manager.</summary>
    public static Observation<string> ReadLocal(RegistryOptions o)
    {
        if (!OperatingSystem.IsWindows()) return Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, "Windows only.");
        try
        {
            return Read(o, null, CancellationToken.None);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException or ArgumentException)
        {
            return WindowsQuery.Map(ex);
        }
    }

    [SupportedOSPlatform("windows")]
    private static Observation<string> Read(RegistryOptions o, string? host, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(o);
        var lines = new List<string>();
        if (o.Root == RegistryRoot.CurrentUser && host is not null)
        {
            // Remote HKEY_CURRENT_USER does not exist: read every loaded user hive under HKEY_USERS (D-055).
            using var users = RegistryKey.OpenRemoteBaseKey(RegistryHive.Users, host);
            var sids = users.GetSubKeyNames().Where(s => s.StartsWith("S-1-5-21-", StringComparison.Ordinal) && !s.EndsWith("_Classes", StringComparison.Ordinal)).ToList();
            foreach (var sid in sids)
            {
                using var hive = users.OpenSubKey(sid);
                if (hive is null) continue;
                var r = ReadIn(hive, o, ct);
                if (r.State == ObservationState.Success) lines.AddRange(r.Value!.Split('\n').Select(l => sids.Count > 1 ? $"{sid}: {l}" : l));
            }

            return WindowsQuery.Lines(lines, sids.Count == 0 ? "No user is logged on (no loaded user hive)." : null);
        }

        var hiveId = o.Root switch { RegistryRoot.Users => RegistryHive.Users, RegistryRoot.CurrentUser => RegistryHive.CurrentUser, _ => RegistryHive.LocalMachine };
        using var root = host is null ? RegistryKey.OpenBaseKey(hiveId, RegistryView.Default) : RegistryKey.OpenRemoteBaseKey(hiveId, host);
        return ReadIn(root, o, ct);
    }

    [SupportedOSPlatform("windows")]
    private static Observation<string> ReadIn(RegistryKey root, RegistryOptions o, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        var alternatives = PathPattern.Alternatives(o.Key.Trim().Trim('\\'));
        if (o.Action == RegistryAction.KeyExists)
        {
            foreach (var alt in alternatives)
            {
                if (PathPattern.HasWildcards(alt) ? Resolve(root, alt, ct).Matches.Count > 0 : Exists(root, alt)) return Observation<string>.Ok("Yes", now);
            }

            return Observation<string>.Ok("No", now);
        }

        foreach (var alt in alternatives)
        {
            if (o.Action == RegistryAction.ReadWildcard || PathPattern.HasWildcards(alt))
            {
                var res = Resolve(root, alt, ct);
                if (res.Matches.Count == 0) continue;
                var lines = new List<string>();
                foreach (var m in res.Matches)
                {
                    using var k = root.OpenSubKey(m);
                    var v = k?.GetValue(o.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (v is not null) lines.Add($"{m}: {Format(v)}");
                }

                lines.AddRange(res.Errors.Select(e => $"[{e}]"));
                return WindowsQuery.Lines(lines, "The value does not exist in the matching keys.");
            }

            using var key = root.OpenSubKey(alt);
            if (key is null) continue;
            var value = key.GetValue(o.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            return value is null ? Observation<string>.Of(ObservationState.Empty, now, "The key exists but has no such value.") : Observation<string>.Ok(Format(value), now);
        }

        return Observation<string>.Of(ObservationState.Empty, now, "Key not found.");
    }

    [SupportedOSPlatform("windows")]
    private static bool Exists(RegistryKey root, string path)
    {
        using var k = root.OpenSubKey(path);
        return k is not null;
    }

    [SupportedOSPlatform("windows")]
    private static PathResolution Resolve(RegistryKey root, string path, CancellationToken ct) => PathResolver.Resolve("", path, p =>
    {
        try
        {
            using var k = p.Length == 0 ? null : root.OpenSubKey(p);
            return (p.Length == 0 ? root : k)?.GetSubKeyNames() ?? [];
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return null;
        }
    }, p => Exists(root, p), cancellationToken: ct);

    public static string Format(object value) => value switch
    {
        string[] multi => string.Join("; ", multi),
        byte[] bin => Convert.ToHexString(bin),
        int dword => unchecked((uint)dword).ToString(CultureInfo.InvariantCulture),
        long qword => unchecked((ulong)qword).ToString(CultureInfo.InvariantCulture),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
    };
}

/// <summary>Remote Files through administrative shares (FIL-01..03).</summary>
public sealed class FileQueryProvider : IRemoteQueryProvider
{
    public const int MaxFolderEntries = 1_000_000;

    public QueryKind Kind => QueryKind.Files;

    public CapabilityStatus Capability { get; } = WindowsQuery.Capability("Remote Files");

    /// <summary><c>C:\Dir\file</c> → <c>\\host\C$\Dir\file</c> (FIL-01).</summary>
    public static (string Root, string Relative) MapToAdminShare(string path, string? host)
    {
        ArgumentNullException.ThrowIfNull(path);
        var p = path.Trim().Replace('/', '\\');
        if (p.Length < 3 || !char.IsAsciiLetter(p[0]) || p[1] != ':' || p[2] != '\\') throw new FormatException("Paths must start with a drive letter, e.g. C:\\Program Files\\…");
        var drive = char.ToUpperInvariant(p[0]);
        return (host is null ? $@"{drive}:\" : $@"\\{host}\{drive}$", p[3..]);
    }

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description));
        var o = call.Query.Files ?? new FileOptions();
        var host = WindowsSession.UncHost(call.Device.Address);
        return WindowsQuery.RunAsync(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var session = WindowsSession.Connect(host, call.Credential);
            return Query(o, host, cancellationToken);
        }, cancellationToken);
    }

    public static Observation<string> Query(FileOptions o, string? host, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(o);
        var now = DateTimeOffset.UtcNow;
        foreach (var alt in PathPattern.Alternatives(o.Path))
        {
            var (root, rest) = MapToAdminShare(alt, host);
            if (host is not null && !Directory.Exists(root))
            {
                // an unreachable share is not "file not found"
                throw new IOException($"The administrative share {root} is not reachable (network path not found or access denied).");
            }

            var display = alt[..3];
            List<string> matches;
            var errors = new List<string>();
            if (!PathPattern.HasWildcards(rest))
            {
                var full = Path.Combine(root, rest);
                matches = File.Exists(full) || Directory.Exists(full) ? [full] : [];
            }
            else
            {
                var r = PathResolver.Resolve(root.TrimEnd('\\'), rest, Children, p => File.Exists(p) || Directory.Exists(p), cancellationToken: ct);
                matches = r.Matches.ToList();
                errors.AddRange(r.Errors);
            }

            if (matches.Count == 0)
            {
                if (errors.Count > 0) return Observation<string>.Of(ObservationState.AccessDenied, now, string.Join("; ", errors));
                continue;
            }

            var lines = new List<string>();
            foreach (var m in matches)
            {
                ct.ThrowIfCancellationRequested();
                var value = Property(m, o.Property, errors, ct);
                var label = display + m[root.TrimEnd('\\').Length..].TrimStart('\\');
                lines.Add(matches.Count > 1 || PathPattern.HasWildcards(rest) ? $"{label}: {value}" : value);
            }

            if (errors.Count > 0) lines.Add($"[{errors.Count} location(s) could not be read: {string.Join("; ", errors.Take(3))}{(errors.Count > 3 ? " …" : "")}]");
            return Observation<string>.Ok(string.Join('\n', lines), DateTimeOffset.UtcNow);
        }

        return o.Property == FileProperty.Exists ? Observation<string>.Ok("No", now) : Observation<string>.Of(ObservationState.Empty, now, "File not found.");
    }

    private static List<string>? Children(string dir)
    {
        try
        {
            return Directory.EnumerateFileSystemEntries(dir).Select(p => Path.GetFileName(p)).ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            return null;
        }
        catch (Exception ex) when (ex is DirectoryNotFoundException or IOException)
        {
            return [];
        }
    }

    private static string Property(string path, FileProperty p, List<string> errors, CancellationToken ct)
    {
        var isDir = Directory.Exists(path);
        FileSystemInfo info = isDir ? new DirectoryInfo(path) : new FileInfo(path);
        return p switch
        {
            FileProperty.Exists => "Yes",
            FileProperty.FileSize => isDir ? "[folder]" : ((FileInfo)info).Length.ToString(CultureInfo.InvariantCulture),
            FileProperty.FolderSize => FolderSize(isDir ? path : Path.GetDirectoryName(path)!, errors, ct).ToString(CultureInfo.InvariantCulture),
            FileProperty.Created => Time(info.CreationTime),
            FileProperty.Modified => Time(info.LastWriteTime),
            FileProperty.Accessed => Time(info.LastAccessTime),
            FileProperty.FileVersion => isDir ? "[folder]" : FileVersionInfo.GetVersionInfo(path).FileVersion ?? "",
            FileProperty.ProductVersion => isDir ? "[folder]" : FileVersionInfo.GetVersionInfo(path).ProductVersion ?? "",
            _ => isDir ? "[folder]" : Hash(path, p, ct),
        };
    }

    private static string Time(DateTime t) => t.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);

    private static long FolderSize(string dir, List<string> errors, CancellationToken ct)
    {
        long total = 0;
        var entries = 0;
        var stack = new Stack<string>();
        stack.Push(dir);
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var d = stack.Pop();
            try
            {
                foreach (var e in new DirectoryInfo(d).EnumerateFileSystemInfos())
                {
                    if (++entries > MaxFolderEntries) throw new InvalidOperationException($"More than {MaxFolderEntries:N0} entries; folder size not computed.");
                    if (e is FileInfo f) total += f.Length;
                    else if ((e.Attributes & FileAttributes.ReparsePoint) == 0) stack.Push(e.FullName);
                }
            }
            catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException or IOException)
            {
                errors.Add(d + ": " + ex.Message);
            }
        }

        return total;
    }

    public static string Hash(string path, FileProperty p, CancellationToken ct)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, System.IO.FileOptions.SequentialScan);
        if (p == FileProperty.Crc32)
        {
            var crc = new Crc32();
            var buf = new byte[1024 * 1024];
            int n;
            while ((n = fs.Read(buf)) > 0)
            {
                ct.ThrowIfCancellationRequested();
                crc.Append(buf.AsSpan(0, n));
            }

            return crc.Value.ToString("X8", CultureInfo.InvariantCulture);
        }

#pragma warning disable CA5350, CA5351 // MD5/SHA-1 requested by the manual for integrity comparison, not security
        using HashAlgorithm h = p switch { FileProperty.Md5 => MD5.Create(), FileProperty.Sha1 => SHA1.Create(), _ => SHA256.Create() };
#pragma warning restore CA5350, CA5351
        var buffer = new byte[1024 * 1024];
        int read;
        while ((read = fs.Read(buffer)) > 0)
        {
            ct.ThrowIfCancellationRequested();
            h.TransformBlock(buffer, 0, read, null, 0);
        }

        h.TransformFinalBlock([], 0, 0);
        return Convert.ToHexString(h.Hash!);
    }
}

/// <summary>CRC-32 (IEEE 802.3, reflected polynomial 0xEDB88320), as used by ZIP and most checksum tools.</summary>
public sealed class Crc32
{
    private static readonly uint[] Table = Enumerable.Range(0, 256).Select(i =>
    {
        var c = (uint)i;
        for (var k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        return c;
    }).ToArray();

    private uint _crc = 0xFFFFFFFFu;

    public void Append(ReadOnlySpan<byte> data)
    {
        foreach (var b in data) _crc = Table[(_crc ^ b) & 0xFF] ^ (_crc >> 8);
    }

    public uint Value => _crc ^ 0xFFFFFFFFu;
}

/// <summary>Remote Services (SVC-01): status, executable path, startup type.</summary>
public sealed partial class ServiceQueryProvider : IRemoteQueryProvider
{
    public QueryKind Kind => QueryKind.Services;

    public CapabilityStatus Capability { get; } = WindowsQuery.Capability("Remote Services");

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description));
        var o = call.Query.Service ?? new ServiceOptions();
        var host = WindowsSession.UncHost(call.Device.Address);
        return WindowsQuery.RunAsync(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var session = WindowsSession.Connect(host, call.Credential);
            return Query(o, host);
        }, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    public static Observation<string> Query(ServiceOptions o, string machine)
    {
        ArgumentNullException.ThrowIfNull(o);
        using var sc = new ServiceController(o.ServiceName, machine);
        try
        {
            _ = sc.ServiceName; // throws when the service does not exist
            var value = o.Property switch
            {
                ServiceProperty.Status => sc.Status.ToString(),
                ServiceProperty.StartupType => sc.StartType.ToString(),
                _ => ImagePath(machine, sc.ServiceName),
            };
            return Observation<string>.Ok(value, DateTimeOffset.UtcNow);
        }
        catch (InvalidOperationException ex) when (ex.InnerException is System.ComponentModel.Win32Exception { NativeErrorCode: 1060 })
        {
            return Observation<string>.Ok("Not installed", DateTimeOffset.UtcNow);
        }
        catch (InvalidOperationException ex) when (ex.InnerException is System.ComponentModel.Win32Exception w)
        {
            return WindowsQuery.Map(w);
        }
    }

    /// <summary>Opens the service with SERVICE_QUERY_CONFIG only (ServiceController.ServiceHandle asks for full access).</summary>
    [SupportedOSPlatform("windows")]
    private static string ImagePath(string machine, string service)
    {
        var scm = OpenSCManager(machine == "." ? null : machine, null, 0x0001);
        if (scm == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
        try
        {
            var svc = OpenService(scm, service, 0x0001);
            if (svc == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
            try
            {
                _ = QueryServiceConfig(svc, IntPtr.Zero, 0, out var needed);
                var buf = Marshal.AllocHGlobal(Math.Max(needed, 64));
                try
                {
                    if (!QueryServiceConfig(svc, buf, needed, out _)) throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError());
                    var cfg = Marshal.PtrToStructure<QueryServiceConfigInfo>(buf);
                    return Marshal.PtrToStringUni(cfg.BinaryPathName) ?? "";
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            finally
            {
                _ = CloseServiceHandle(svc);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    [LibraryImport("advapi32.dll", EntryPoint = "OpenSCManagerW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenSCManager(string? machine, string? database, uint access);

    [LibraryImport("advapi32.dll", EntryPoint = "OpenServiceW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial IntPtr OpenService(IntPtr scm, string name, uint access);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct QueryServiceConfigInfo
    {
        public uint ServiceType;
        public uint StartType;
        public uint ErrorControl;
        public IntPtr BinaryPathName;
        public IntPtr LoadOrderGroup;
        public uint TagId;
        public IntPtr Dependencies;
        public IntPtr ServiceStartName;
        public IntPtr DisplayName;
    }

    [LibraryImport("advapi32.dll", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool QueryServiceConfig(IntPtr service, IntPtr config, int bufferSize, out int bytesNeeded);
}

/// <summary>Remote Groups (GRP-01/02) through NetApi.</summary>
public sealed partial class GroupQueryProvider : IRemoteQueryProvider
{
    public QueryKind Kind => QueryKind.Groups;

    public CapabilityStatus Capability { get; } = WindowsQuery.Capability("Remote Groups");

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description));
        var o = call.Query.Group ?? new GroupOptions();
        var host = WindowsSession.UncHost(call.Device.Address);
        return WindowsQuery.RunAsync(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var session = WindowsSession.Connect(host, call.Credential);
            return Query(o, host);
        }, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    public static Observation<string> Query(GroupOptions o, string? server)
    {
        ArgumentNullException.ThrowIfNull(o);
        var srv = server is null ? null : @"\\" + server;
        IReadOnlyList<string> raw = o.Type switch
        {
            GroupQueryType.LocalMembers => Enumerate(srv, (string? s, out IntPtr b, out int r, out int t, ref int h) => NetLocalGroupGetMembers(s, o.Name, 3, out b, -1, out r, out t, ref h), IntPtr.Size),
            GroupQueryType.LocalParticipation => Enumerate(srv, (string? s, out IntPtr b, out int r, out int t, ref int h) => NetUserGetLocalGroups(s, o.Name, 0, 1, out b, -1, out r, out t), IntPtr.Size),
            GroupQueryType.GlobalMembers => Enumerate(DomainController(srv), (string? s, out IntPtr b, out int r, out int t, ref int h) => NetGroupGetUsers(s, o.Name, 0, out b, -1, out r, out t, ref h), IntPtr.Size),
            _ => Enumerate(DomainController(srv), (string? s, out IntPtr b, out int r, out int t, ref int h) => NetUserGetGroups(s, o.Name, 0, out b, -1, out r, out t), IntPtr.Size),
        };
        return WindowsQuery.Lines(AccountFilter.Apply(raw, o.StripDomain, o.Exclusions), "No accounts (after exclusions).");
    }

    private delegate int NetEnum(string? server, out IntPtr buffer, out int read, out int total, ref int resume);

    [SupportedOSPlatform("windows")]
    private static List<string> Enumerate(string? server, NetEnum call, int stride)
    {
        var list = new List<string>();
        var resume = 0;
        int rc;
        do
        {
            rc = call(server, out var buf, out var read, out _, ref resume);
            try
            {
                if (rc is not (0 or 234)) throw Error(rc);
                for (var i = 0; i < read; i++) list.Add(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buf, i * stride)) ?? "");
            }
            finally
            {
                if (buf != IntPtr.Zero) _ = NetApiBufferFree(buf);
            }
        }
        while (rc == 234 && list.Count < 100_000);

        return list;
    }

    [SupportedOSPlatform("windows")]
    private static string? DomainController(string? server)
    {
        var rc = NetGetAnyDCName(server, null, out var buf);
        try
        {
            if (rc != 0) throw Error(rc);
            return Marshal.PtrToStringUni(buf);
        }
        finally
        {
            if (buf != IntPtr.Zero) _ = NetApiBufferFree(buf);
        }
    }

    private static Exception Error(int rc) => rc switch
    {
        5 => new UnauthorizedAccessException("Access is denied."),
        2220 => new InvalidOperationException("The group was not found."),
        2221 => new InvalidOperationException("The user was not found."),
        1376 => new InvalidOperationException("The local group was not found."),
        2453 => new InvalidOperationException("No domain controller was found (the device is not in a domain)."),
        53 or 1722 => new IOException("The network path was not found."),
        _ => new System.ComponentModel.Win32Exception(rc),
    };

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetLocalGroupGetMembers(string? server, string group, int level, out IntPtr buffer, int prefMaxLen, out int read, out int total, ref int resume);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetUserGetLocalGroups(string? server, string user, int level, int flags, out IntPtr buffer, int prefMaxLen, out int read, out int total);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetGroupGetUsers(string? server, string group, int level, out IntPtr buffer, int prefMaxLen, out int read, out int total, ref int resume);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetUserGetGroups(string? server, string user, int level, out IntPtr buffer, int prefMaxLen, out int read, out int total);

    [LibraryImport("netapi32.dll", StringMarshalling = StringMarshalling.Utf16)]
    private static partial int NetGetAnyDCName(string? server, string? domain, out IntPtr buffer);

    [LibraryImport("netapi32.dll")]
    private static partial int NetApiBufferFree(IntPtr buffer);
}

/// <summary>Remote Performance counters (PRF-01). Rate counters are sampled twice <see cref="PerformanceOptions.SampleMilliseconds"/> apart.</summary>
public sealed partial class PerformanceQueryProvider : IRemoteQueryProvider
{
    public const int MaxInstances = 500;

    public QueryKind Kind => QueryKind.Performance;

    public CapabilityStatus Capability { get; } = WindowsQuery.Capability("Remote Performance counters");

    [GeneratedRegex(@"^\\([^\\(]+?)(?:\(([^)]*)\))?\\(.+)$", RegexOptions.CultureInvariant)]
    private static partial Regex CounterPath();

    public static (string Category, string? Instance, string Counter) Parse(string path)
    {
        ArgumentNullException.ThrowIfNull(path);
        var p = path.Trim();
        if (p.StartsWith(@"\\", StringComparison.Ordinal)) throw new FormatException(@"Counter paths start with a single backslash, e.g. \Processor(_Total)\% Processor Time.");
        var m = CounterPath().Match(p);
        if (!m.Success) throw new FormatException(@"Expected \Category(Instance)\Counter or \Category\Counter.");
        return (m.Groups[1].Value, m.Groups[2].Success ? m.Groups[2].Value : null, m.Groups[3].Value);
    }

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description));
        var o = call.Query.Performance ?? new PerformanceOptions();
        var host = WindowsSession.UncHost(call.Device.Address);
        return WindowsQuery.RunAsync(() =>
        {
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
            using var session = WindowsSession.Connect(host, call.Credential);
            return Read(o, host, cancellationToken);
        }, cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    public static Observation<string> Read(PerformanceOptions o, string machine, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(o);
        var (category, instance, counter) = Parse(o.CounterPath);
        var instances = instance == "*"
            ? new PerformanceCounterCategory(category, machine).GetInstanceNames().Order(StringComparer.OrdinalIgnoreCase).Take(MaxInstances).ToList()
            : [instance ?? ""];
        var counters = instances.Select(i => new PerformanceCounter(category, counter, i, machine)).ToList();
        try
        {
            var first = counters.Select(c => c.NextSample()).ToList();
            var needsTwo = counters.Any(c => IsRate(c.CounterType));
            if (needsTwo)
            {
                ct.WaitHandle.WaitOne(Math.Clamp(o.SampleMilliseconds, 100, 10_000));
                ct.ThrowIfCancellationRequested();
            }

            var lines = new List<string>();
            for (var i = 0; i < counters.Count; i++)
            {
                var v = needsTwo ? CounterSample.Calculate(first[i], counters[i].NextSample()) : CounterSample.Calculate(first[i]);
                var text = v.ToString("0.##", CultureInfo.InvariantCulture);
                lines.Add(instance == "*" ? $"{instances[i]}: {text}" : text);
            }

            return WindowsQuery.Lines(lines);
        }
        finally
        {
            foreach (var c in counters) c.Dispose();
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool IsRate(PerformanceCounterType t) => t is not (PerformanceCounterType.NumberOfItems32 or PerformanceCounterType.NumberOfItems64
        or PerformanceCounterType.NumberOfItemsHEX32 or PerformanceCounterType.NumberOfItemsHEX64 or PerformanceCounterType.RawFraction
        or PerformanceCounterType.ElapsedTime or PerformanceCounterType.RawBase);

    /// <summary>Local counter browser: categories → counters.</summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<string> LocalCounterPaths(string filter, int max = 2000)
    {
        var result = new List<string>();
        foreach (var cat in PerformanceCounterCategory.GetCategories().OrderBy(c => c.CategoryName, StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var multi = cat.CategoryType == PerformanceCounterCategoryType.MultiInstance;
                var instance = multi ? (cat.GetInstanceNames().Contains("_Total") ? "_Total" : "*") : null;
                var counters = multi ? cat.GetCounters(instance == "*" ? cat.GetInstanceNames().FirstOrDefault() ?? "" : instance) : cat.GetCounters();
                foreach (var c in counters)
                {
                    var path = instance is null ? $@"\{cat.CategoryName}\{c.CounterName}" : $@"\{cat.CategoryName}({instance})\{c.CounterName}";
                    if (filter.Length == 0 || path.Contains(filter, StringComparison.OrdinalIgnoreCase)) result.Add(path);
                    c.Dispose();
                    if (result.Count >= max) return result;
                }
            }
            catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
            {
                // categories that cannot be read locally are skipped
            }
        }

        return result;
    }
}

/// <summary>Remote WMI (WMI-01/02) over DCOM with packet privacy by default.</summary>
public sealed partial class WmiQueryProvider : IRemoteQueryProvider
{
    public const int MaxRows = 1000;

    public QueryKind Kind => QueryKind.Wmi;

    public CapabilityStatus Capability { get; } = WindowsQuery.Capability("WMI");

    public Task<Observation<string>> ExecuteAsync(QueryCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        if (!OperatingSystem.IsWindows()) return Task.FromResult(Observation<string>.Of(ObservationState.Unsupported, DateTimeOffset.UtcNow, Capability.Description));
        var o = call.Query.Wmi ?? new WmiOptions();
        var host = WindowsQuery.IsLocal(call) ? "." : WindowsSession.UncHost(call.Device.Address);
        var timeout = TimeSpan.FromSeconds(Math.Max(1, call.Query.TimeoutSeconds));
        return WindowsQuery.RunAsync(() => OperatingSystem.IsWindows() ? Query(o, host, host == "." ? null : call.Credential, timeout) : throw new PlatformNotSupportedException(),
            cancellationToken);
    }

    [SupportedOSPlatform("windows")]
    public static Observation<string> Query(WmiOptions o, string host, ResolvedCredential? credential, TimeSpan timeout)
    {
        ArgumentNullException.ThrowIfNull(o);
        var ns = string.IsNullOrWhiteSpace(o.Namespace) ? @"root\cimv2" : o.Namespace.Trim().Trim('\\');
        var options = new ConnectionOptions
        {
            Impersonation = ImpersonationLevel.Impersonate,
            Authentication = o.PacketPrivacy ? AuthenticationLevel.PacketPrivacy : AuthenticationLevel.Default,
            Timeout = timeout,
            EnablePrivileges = true,
        };
        if (credential is not null)
        {
            options.Username = credential.UserName;
            options.Password = credential.Password;
        }

        var scope = new ManagementScope($@"\\{host}\{ns}", options);
        try
        {
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(o.Query),
                new System.Management.EnumerationOptions { Timeout = timeout, ReturnImmediately = true, Rewindable = false });
            var lines = new List<string>();
            foreach (var obj in searcher.Get().Cast<ManagementBaseObject>())
            {
                using (obj)
                {
                    var props = obj.Properties.Cast<PropertyData>().Where(p => !p.Name.StartsWith("__", StringComparison.Ordinal) && p.Value is not null).ToList();
                    if (props.Count == 1) lines.Add(Format(props[0].Value));
                    else if (props.Count > 1) lines.Add(string.Join("; ", props.Select(p => $"{p.Name}: {Format(p.Value)}")));
                    if (lines.Count >= MaxRows) break;
                }
            }

            return WindowsQuery.Lines(lines);
        }
        catch (ManagementException ex)
        {
            var state = ex.ErrorCode == ManagementStatus.AccessDenied ? ObservationState.AccessDenied
                : ex.ErrorCode is ManagementStatus.InvalidQuery or ManagementStatus.InvalidClass or ManagementStatus.InvalidNamespace ? ObservationState.Failed
                : ObservationState.Failed;
            return Observation<string>.Of(state, DateTimeOffset.UtcNow, $"{ex.ErrorCode}: {ex.Message.Trim()}");
        }
    }

    [GeneratedRegex(@"^\d{14}\.\d{6}[+-]\d{3}$", RegexOptions.CultureInvariant)]
    private static partial Regex CimDate();

    [SupportedOSPlatform("windows")]
    public static string Format(object? v) => v switch
    {
        null => "",
        string s when CimDate().IsMatch(s) => ManagementDateTimeConverter.ToDateTime(s).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        string s => s,
        Array a => string.Join(", ", a.Cast<object?>().Select(Format)),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "",
    };

    /// <summary>WMI Query Builder: classes of a local namespace (optionally filtered by class or property name).</summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<string> LocalClasses(string ns, string filter, int max = 3000)
    {
        var scope = new ManagementScope($@"\\.\{ns}");
        scope.Connect();
        using var searcher = new ManagementObjectSearcher(scope, new SelectQuery("meta_class"));
        var list = new List<string>();
        foreach (var c in searcher.Get().Cast<ManagementClass>())
        {
            using (c)
            {
                var name = c.ClassPath.ClassName;
                if (name.StartsWith("__", StringComparison.Ordinal)) continue;
                if (filter.Length > 0 && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)
                    && !c.Properties.Cast<PropertyData>().Any(p => p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)))
                {
                    continue;
                }

                list.Add(name);
                if (list.Count >= max) break;
            }
        }

        list.Sort(StringComparer.OrdinalIgnoreCase);
        return list;
    }

    /// <summary>Properties of a class with an example value from the first local instance.</summary>
    [SupportedOSPlatform("windows")]
    public static IReadOnlyList<(string Name, string Example)> LocalProperties(string ns, string className)
    {
        var scope = new ManagementScope($@"\\.\{ns}");
        scope.Connect();
        using var cls = new ManagementClass(scope, new ManagementPath(className), null);
        var names = cls.Properties.Cast<PropertyData>().Select(p => p.Name).Where(n => !n.StartsWith("__", StringComparison.Ordinal)).ToList();
        var examples = new Dictionary<string, string>();
        try
        {
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {className}"), new System.Management.EnumerationOptions { ReturnImmediately = true, Timeout = TimeSpan.FromSeconds(10) });
            using var first = searcher.Get().Cast<ManagementBaseObject>().FirstOrDefault();
            if (first is not null)
            {
                foreach (var n in names) examples[n] = Format(first[n]);
            }
        }
        catch (ManagementException)
        {
            // abstract classes have no instances
        }

        return names.Select(n => (n, examples.GetValueOrDefault(n, ""))).ToList();
    }
}
