using IPMaster.Core.Network;
using IPMaster.Core.Scanning;
using IPMaster.Infrastructure.Configuration;
using IPMaster.Infrastructure.Network;
using IPMaster.Infrastructure.Probes;
using IPMaster.Infrastructure.Windows;
using IPMaster.Infrastructure.Management;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace IPMaster.Infrastructure;

/// <summary>Composition root shared by the desktop app and the CLI (same application services).</summary>
public static class ServiceRegistration
{
    public static IServiceCollection AddIPMaster(this IServiceCollection services, string? configDirectory = null)
    {
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IIcmpProbe, IcmpProbe>();
        services.AddSingleton<IArpProbe, ArpProbe>();
        services.AddSingleton<IHostNameResolver, DnsHostNameResolver>();
        services.AddSingleton<INetworkAdapterProvider, SystemNetworkAdapterProvider>();
        services.AddSingleton<ITcpPortProbe, TcpPortProbe>();
        services.AddSingleton<IUdpServiceProbe, UdpServiceProbe>();
        services.AddSingleton<INetBiosProbe, NetBiosProbe>();
        services.AddSingleton<INeighborTable, NeighborTable>();
        services.AddSingleton<IServiceProbe, ServiceProbe>();
        services.AddSingleton<IWindowsHostProbe, WindowsHostProbe>();
        services.AddSingleton<HttpGeoLocator>();
        services.AddSingleton<Core.Management.IRemoteControl, Management.WindowsRemoteControl>();
        services.AddSingleton<Management.WakeOnLanSender>();
        services.AddSingleton<Discovery.DhcpDiscovery>();
        services.AddSingleton<Discovery.SsdpDiscovery>();
        services.AddSingleton<Discovery.MdnsDiscovery>();
        services.AddSingleton<Discovery.WsdDiscovery>();
        services.AddSingleton<Discovery.OnvifDiscovery>();
        services.AddSingleton<Discovery.PcapLibrary>();
        services.AddSingleton<Discovery.DuplicateIpScanner>();
        services.AddSingleton<Discovery.PassiveCapture>();
        services.AddSingleton<Discovery.ArpProbeSweep>();
        services.AddSingleton<Core.Network.ITemporaryAddressManager, Network.TemporaryAddressManager>();
        services.AddSingleton<Core.Wifi.IWifiProvider>(_ => OperatingSystem.IsWindows()
            ? new Wifi.WindowsWifiProvider()
            : new Core.Wifi.UnsupportedWifiProvider("Wi-Fi analysis uses the Windows Native Wifi API; Linux (nl80211) and macOS (CoreWLAN) are not implemented yet."));
        services.AddSingleton<Security.CredentialVault>();
        services.AddSingleton(sp => new SettingsStore(configDirectory, sp.GetRequiredService<Security.CredentialVault>()));
        services.AddSingleton<Queries.KnownHostStore>();
        services.AddSingleton(sp => new Queries.QueryServices(sp.GetRequiredService<Security.CredentialVault>(), sp.GetRequiredService<Queries.KnownHostStore>(),
            sp.GetService<ILoggerFactory>()));
        services.AddSingleton(sp => new OuiDatabase(sp.GetRequiredService<SettingsStore>().Directory, AppContext.BaseDirectory));
        services.AddSingleton<IVendorLookup>(sp => sp.GetRequiredService<OuiDatabase>());
        services.AddSingleton(sp => new ScanProbes(sp.GetRequiredService<IIcmpProbe>(), sp.GetRequiredService<IArpProbe>(), sp.GetRequiredService<IHostNameResolver>())
        {
            Tcp = sp.GetRequiredService<ITcpPortProbe>(),
            Udp = sp.GetRequiredService<IUdpServiceProbe>(),
            NetBios = sp.GetRequiredService<INetBiosProbe>(),
            Neighbors = sp.GetRequiredService<INeighborTable>(),
            Vendors = sp.GetRequiredService<IVendorLookup>(),
            Service = sp.GetRequiredService<IServiceProbe>(),
            Windows = sp.GetRequiredService<IWindowsHostProbe>(),
            Geo = sp.GetRequiredService<HttpGeoLocator>(),
            WindowsExtras = new Windows.WindowsExtras(),
            RouterArp = new Windows.RouterArpSource(),
        });
        services.AddSingleton(sp => new ScanEngine(sp.GetRequiredService<ScanProbes>(), sp.GetRequiredService<TimeProvider>(),
            sp.GetService<ILogger<ScanEngine>>()));
        services.AddSingleton<ScanPlanner>();
        services.AddSingleton<Core.Monitoring.IRouteTracer, Monitoring.RouteTracer>();
        services.AddSingleton<Core.Monitoring.IHistoryStore>(sp => new Monitoring.HistoryStore(sp.GetRequiredService<SettingsStore>().Directory));
        services.AddSingleton<Monitoring.NetworkIdentifier>();
        services.AddSingleton(sp => new Monitoring.NotificationDispatcher(sp.GetRequiredService<Security.CredentialVault>()));
        services.AddSingleton<Tools.ISmtpTester, Tools.SmtpClientTester>();
        services.AddSingleton<Tools.IKmsService, Tools.WindowsKmsService>();
        services.AddSingleton<Tools.IWinGetService, Tools.WinGetService>();
        services.AddSingleton<Tools.IGroupPolicyService, Tools.WindowsGroupPolicyService>();
        services.AddSingleton<Monitoring.ContinuousOperations>();
        services.AddSingleton(sp => new Core.Monitoring.LiveMonitor(sp.GetRequiredService<IIcmpProbe>(), sp.GetRequiredService<TimeProvider>()));
        return services;
    }
}
