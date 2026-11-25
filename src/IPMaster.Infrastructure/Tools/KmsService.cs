using System.ComponentModel;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text.Json;
using IPMaster.Core.Tools;

namespace IPMaster.Infrastructure.Tools;

public sealed record KmsDetectionResult(IReadOnlyList<KmsProduct> Products, string Error);

public sealed record KmsConnectionResult(bool Resolved, bool Connected, string Text);

/// <summary>Tools → KMS Activation Manager (D-104). Detection is read-only; <see cref="ApplyAsync"/> is the only changing call.</summary>
public interface IKmsService
{
    bool IsSupported { get; }

    Task<KmsDetectionResult> DetectAsync(CancellationToken ct);

    /// <summary>Runs validated steps through the licensing service, elevated when needed (one UAC prompt).</summary>
    Task<KmsApplyResult> ApplyAsync(KmsRequest request, CancellationToken ct);
}

/// <summary>
/// Windows licensing through the documented WMI classes SoftwareLicensingProduct / SoftwareLicensingService (the API that
/// slmgr.vbs and, on Windows 10 and later, ospp.vbs call). Reading needs no elevation. Changes run in this process when it is
/// elevated, else in the same executable started with "runas" and <c>--kms-apply</c> (<see cref="KmsHelper"/>).
/// </summary>
public sealed class WindowsKmsService : IKmsService
{
    public static readonly TimeSpan HelperTimeout = TimeSpan.FromMinutes(5);

    public bool IsSupported => OperatingSystem.IsWindows();

    public Task<KmsDetectionResult> DetectAsync(CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return Task.FromResult(new KmsDetectionResult([], "KMS Activation Manager runs on Windows only."));
        return Task.Run(() =>
        {
            try
            {
                return new KmsDetectionResult(OperatingSystem.IsWindows() ? Detect() : [], "");
            }
            catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
            {
                return new KmsDetectionResult([], "The licensing service cannot be read: " + ex.Message);
            }
        }, ct);
    }

    public async Task<KmsApplyResult> ApplyAsync(KmsRequest request, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) return new KmsApplyResult { Error = "Windows only." };
        if (Kms.ValidateRequest(request) is { } invalid) return new KmsApplyResult { Error = invalid };
        if (IsElevated()) return await Task.Run(() => OperatingSystem.IsWindows() ? KmsHelper.Apply(request) : new KmsApplyResult(), CancellationToken.None).ConfigureAwait(false); // licensing calls cannot be cancelled
        return await RunHelperAsync(request, ct).ConfigureAwait(false);
    }

    [SupportedOSPlatform("windows")]
    public static bool IsElevated()
    {
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }

    [SupportedOSPlatform("windows")]
    private static async Task<KmsApplyResult> RunHelperAsync(KmsRequest request, CancellationToken ct)
    {
        if (Environment.ProcessPath is not { } exe || !exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            return new KmsApplyResult { Error = "Administrator access required. Start IPMaster as administrator." };
        }

        var dir = Directory.CreateTempSubdirectory("ipmaster-kms-");
        try
        {
            var req = Path.Combine(dir.FullName, KmsHelper.RequestFile);
            await File.WriteAllTextAsync(req, JsonSerializer.Serialize(request), ct).ConfigureAwait(false);
            var psi = new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            psi.ArgumentList.Add(KmsHelper.Switch);
            psi.ArgumentList.Add(req);
            Process? proc;
            try
            {
                proc = Process.Start(psi);
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                return new KmsApplyResult { Error = "Administrator access declined. Nothing was changed." };
            }

            if (proc is null) return new KmsApplyResult { Error = "The elevated helper did not start." };
            using (proc)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                timeout.CancelAfter(HelperTimeout);
                try
                {
                    await proc.WaitForExitAsync(timeout.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // the elevated helper cannot be stopped from here; its changes are read back on refresh
                    return new KmsApplyResult { Error = "Stopped waiting. The elevated operation may still finish; refresh to see the license state." };
                }
            }

            var res = Path.Combine(dir.FullName, KmsHelper.ResultFile);
            if (!File.Exists(res)) return new KmsApplyResult { Error = "The elevated helper returned no result." };
            return JsonSerializer.Deserialize<KmsApplyResult>(await File.ReadAllTextAsync(res, CancellationToken.None).ConfigureAwait(false)) ?? new KmsApplyResult { Error = "Unreadable helper result." };
        }
        finally
        {
            try
            {
                dir.Delete(true);
            }
            catch (IOException)
            {
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static IReadOnlyList<KmsProduct> Detect()
    {
        var scope = new ManagementScope(@"\\.\root\cimv2");
        var records = new List<LicenseRecord>();
        using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL"),
                   new System.Management.EnumerationOptions { Timeout = TimeSpan.FromSeconds(60), ReturnImmediately = true, Rewindable = false }))
        {
            foreach (var o in searcher.Get().Cast<ManagementObject>())
            {
                using (o) records.Add(Record(o));
            }
        }

        string host = "";
        int? port = null;
        using (var svc = Service(scope))
        {
            if (svc is not null)
            {
                host = Str(svc, "KeyManagementServiceMachine");
                port = host.Length > 0 ? Int(svc, "KeyManagementServicePort") : null;
            }
        }

        return KmsDetection.Build(records, ReadWindows(), ReadClickToRun(), host, port, DateTimeOffset.Now);
    }

    [SupportedOSPlatform("windows")]
    internal static ManagementObject? Service(ManagementScope scope)
    {
        using var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM SoftwareLicensingService"));
        return s.Get().Cast<ManagementObject>().FirstOrDefault();
    }

    [SupportedOSPlatform("windows")]
    internal static LicenseRecord Record(ManagementBaseObject o) => new()
    {
        Id = Str(o, "ID"), ApplicationId = Str(o, "ApplicationID"), Name = Str(o, "Name"), Description = Str(o, "Description"), LicenseFamily = Str(o, "LicenseFamily"),
        ProductKeyChannel = Str(o, "ProductKeyChannel"), LicenseStatus = UInt(o, "LicenseStatus"), StatusReason = UInt(o, "LicenseStatusReason"),
        GraceMinutes = UInt(o, "GracePeriodRemaining"), PartialKey = Str(o, "PartialProductKey"), KmsHost = Str(o, "KeyManagementServiceMachine"),
        KmsPort = NonZero(Int(o, "KeyManagementServicePort")), UsedHost = Str(o, "DiscoveredKeyManagementServiceMachineName"),
        UsedPort = NonZero(Int(o, "DiscoveredKeyManagementServiceMachinePort")), IsAddon = Get(o, "LicenseIsAddon") is true,
    };

    private static int? NonZero(int? v) => v is 0 ? null : v;

    [SupportedOSPlatform("windows")]
    private static object? Get(ManagementBaseObject o, string name)
    {
        try
        {
            return o[name];
        }
        catch (ManagementException)
        {
            return null; // property absent on this Windows version
        }
    }

    [SupportedOSPlatform("windows")]
    private static string Str(ManagementBaseObject o, string name) => Get(o, name)?.ToString()?.Trim() ?? "";

    [SupportedOSPlatform("windows")]
    private static uint? UInt(ManagementBaseObject o, string name) => Get(o, name) is { } v ? Convert.ToUInt32(v, System.Globalization.CultureInfo.InvariantCulture) : null;

    [SupportedOSPlatform("windows")]
    private static int? Int(ManagementBaseObject o, string name) => Get(o, name) is { } v ? (int)Convert.ToUInt32(v, System.Globalization.CultureInfo.InvariantCulture) : null;

    [SupportedOSPlatform("windows")]
    private static WindowsInfo ReadWindows()
    {
        using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        string S(string n) => k?.GetValue(n)?.ToString() ?? "";
        _ = int.TryParse(S("CurrentBuildNumber"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var build);
        return new WindowsInfo(S("EditionID"), S("ProductName"), build, S("DisplayVersion"), S("InstallationType"), RuntimeInformation.OSArchitecture.ToString());
    }

    [SupportedOSPlatform("windows")]
    private static ClickToRunInfo? ReadClickToRun()
    {
        using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Office\ClickToRun\Configuration");
        if (k is null) return null;
        var ids = (k.GetValue("ProductReleaseIds")?.ToString() ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return new ClickToRunInfo(ids, k.GetValue("VersionToReport")?.ToString() ?? "");
    }
}

/// <summary>
/// The elevated side (<c>IPMaster.exe --kms-apply &lt;request.json&gt;</c>). It re-validates the request (catalog keys only, valid
/// hosts, GUID ids), changes only the addressed product, stops at the first failure and never retries.
/// </summary>
public static class KmsHelper
{
    public const string Switch = "--kms-apply";
    public const string RequestFile = "request.json";
    public const string ResultFile = "result.json";

    public static int Run(string requestPath)
    {
        if (!OperatingSystem.IsWindows() || Path.GetFileName(requestPath) != RequestFile || !File.Exists(requestPath)) return 2;
        KmsApplyResult result;
        try
        {
            var request = JsonSerializer.Deserialize<KmsRequest>(File.ReadAllText(requestPath));
            result = request is null ? new KmsApplyResult { Error = "Empty request." }
                : Kms.ValidateRequest(request) is { } e ? new KmsApplyResult { Error = e }
                : !WindowsKmsService.IsElevated() ? new KmsApplyResult { Error = "Administrator access required." }
                : Apply(request);
        }
        catch (JsonException ex)
        {
            result = new KmsApplyResult { Error = "Invalid request: " + ex.Message };
        }

        File.WriteAllText(Path.Combine(Path.GetDirectoryName(requestPath)!, ResultFile), JsonSerializer.Serialize(result)); // written next to the request only
        return result.Error.Length == 0 && result.Steps.All(s => s.Succeeded) ? 0 : 1;
    }

    [SupportedOSPlatform("windows")]
    internal static KmsApplyResult Apply(KmsRequest request)
    {
        var scope = new ManagementScope(@"\\.\root\cimv2");
        var results = new List<KmsStepResult>();
        var productId = request.Steps[0].ProductId;
        foreach (var step in request.Steps)
        {
            var r = new KmsStepResult { Kind = step.Kind };
            try
            {
                switch (step.Kind)
                {
                    case KmsStepKind.InstallKey:
                        using (var svc = WindowsKmsService.Service(scope) ?? throw new InvalidOperationException("SoftwareLicensingService not found."))
                        {
                            svc.InvokeMethod("InstallProductKey", [step.Key]);
                            svc.InvokeMethod("RefreshLicenseStatus", null);
                        }

                        // a new key is a new licensing product: continue with the record that now holds this key
                        productId = FindByPartialKey(scope, request.ApplicationId, step.Key[^5..]) ?? "";
                        if (productId.Length == 0) throw new InvalidOperationException("The installed key was not found in the licensing records.");
                        break;
                    case KmsStepKind.SetHost:
                        using (var p = Product(scope, productId))
                        {
                            p.InvokeMethod("SetKeyManagementServiceMachine", [step.Host]);
                            p.InvokeMethod("SetKeyManagementServicePort", [(uint)step.Port]);
                        }

                        break;
                    case KmsStepKind.Activate:
                        using (var p = Product(scope, productId)) p.InvokeMethod("Activate", null);
                        using (var svc = WindowsKmsService.Service(scope)) svc?.InvokeMethod("RefreshLicenseStatus", null);
                        break;
                }

                r.Succeeded = true;
                r.Code = 0;
            }
            catch (ManagementException ex)
            {
                Fail(r, unchecked((uint)(int)ex.ErrorCode), ex.Message);
            }
            catch (COMException ex)
            {
                Fail(r, unchecked((uint)ex.HResult), ex.Message);
            }
            catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException)
            {
                Fail(r, unchecked((uint)ex.HResult), ex.Message);
            }

            results.Add(r);
            if (!r.Succeeded) break;
        }

        return new KmsApplyResult { Steps = results, ProductId = productId };
    }

    private static void Fail(KmsStepResult r, uint code, string message)
    {
        r.Succeeded = false;
        r.Code = code;
        r.Message = Kms.ErrorText(code) is { Length: > 0 } t ? t : message.Trim();
    }

    [SupportedOSPlatform("windows")]
    private static ManagementObject Product(ManagementScope scope, string id)
    {
        if (!Guid.TryParse(id, out var g)) throw new InvalidOperationException("Invalid product id.");
        var o = new ManagementObject(scope, new ManagementPath($"SoftwareLicensingProduct.ID='{g:D}'"), null);
        o.Get();
        return o;
    }

    [SupportedOSPlatform("windows")]
    private static string? FindByPartialKey(ManagementScope scope, string applicationId, string partial)
    {
        using var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT ID, ApplicationID, PartialProductKey FROM SoftwareLicensingProduct WHERE PartialProductKey IS NOT NULL"));
        foreach (var o in s.Get().Cast<ManagementObject>())
        {
            using (o)
            {
                var r = WindowsKmsService.Record(o);
                if (string.Equals(r.ApplicationId, applicationId, StringComparison.OrdinalIgnoreCase) && string.Equals(r.PartialKey, partial, StringComparison.OrdinalIgnoreCase)) return r.Id;
            }
        }

        return null;
    }
}

/// <summary>Platform-independent network checks of the KMS Activation Manager: DNS SRV discovery and a TCP test.</summary>
public static class KmsNetwork
{
    /// <summary>The primary DNS suffix and the connection-specific suffixes of the up interfaces.</summary>
    public static IReadOnlyList<string> SearchDomains()
    {
        var list = new List<string>();
        try
        {
            list.Add(IPGlobalProperties.GetIPGlobalProperties().DomainName);
            list.AddRange(NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up).Select(n => n.GetIPProperties().DnsSuffix));
        }
        catch (NetworkInformationException)
        {
        }

        return list.Select(d => (d ?? "").Trim().TrimEnd('.')).Where(d => d.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Queries _vlmcs._tcp.&lt;domain&gt; on the given DNS servers. Lists hosts only; never configures one.</summary>
    public static async Task<(IReadOnlyList<KmsHostCandidate> Hosts, string Detail)> DiscoverAsync(IReadOnlyList<string> domains, IReadOnlyList<IPEndPoint> servers, CancellationToken ct)
    {
        if (domains.Count == 0) return ([], "No DNS domain is configured on this computer.");
        if (servers.Count == 0) return ([], "No DNS server is configured.");
        var hosts = new List<KmsHostCandidate>();
        var notes = new List<string>();
        foreach (var domain in domains.Take(8))
        {
            var name = Kms.SrvPrefix + domain;
            DnsQueryResult? last = null;
            foreach (var server in servers.Take(3))
            {
                last = await DnsClient.QueryAsync(server, name, (ushort)DnsType.SRV, new DnsQueryOptions(), ct).ConfigureAwait(false);
                if (last.Outcome == DnsOutcome.Reply) break;
            }

            var found = last is null ? [] : Kms.ParseSrv(last.Records.Select(r => r.Data), domain);
            hosts.AddRange(found);
            notes.Add($"{name}: {(found.Count > 0 ? found.Count + " host(s)" : last?.Status ?? "no answer")}");
        }

        return (hosts, string.Join("; ", notes));
    }

    /// <summary>DNS resolution and a TCP connection. A connection does not prove a working or authorised KMS host.</summary>
    public static async Task<KmsConnectionResult> TestAsync(string host, int port, TimeSpan timeout, CancellationToken ct)
    {
        IPAddress[] addresses;
        var sw = Stopwatch.StartNew();
        if (IPAddress.TryParse(host, out var literal))
        {
            addresses = [literal];
        }
        else
        {
            try
            {
                using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dnsCts.CancelAfter(timeout);
                addresses = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, dnsCts.Token).ConfigureAwait(false);
            }
            catch (SocketException ex)
            {
                return new(false, false, $"DNS lookup failed: {ex.SocketErrorCode}.");
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return new(false, false, "DNS lookup timed out.");
            }

            if (addresses.Length == 0) return new(false, false, "DNS lookup returned no IPv4 address.");
        }

        var resolved = $"DNS resolved: {string.Join(", ", addresses.Take(3).Select(a => a.ToString()))} ({sw.ElapsedMilliseconds} ms).";
        using var client = new TcpClient(AddressFamily.InterNetwork);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);
        sw.Restart();
        try
        {
            await client.ConnectAsync(addresses[0], port, cts.Token).ConfigureAwait(false);
            return new(true, true, $"{resolved} TCP connected to {addresses[0]}:{port} ({sw.ElapsedMilliseconds} ms). This does not prove a working KMS host.");
        }
        catch (SocketException ex)
        {
            return new(true, false, $"{resolved} Connection failed: {ex.SocketErrorCode}.");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return new(true, false, $"{resolved} Connection timed out after {timeout.TotalSeconds:0} s.");
        }
    }
}
