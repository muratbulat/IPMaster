using System.Net.NetworkInformation;
using System.Net.Sockets;
using IPMaster.Core.Network;

namespace IPMaster.Infrastructure.Network;

public sealed class SystemNetworkAdapterProvider : INetworkAdapterProvider
{
    public IReadOnlyList<NetworkAdapterInfo> GetAdapters()
    {
        var result = new List<NetworkAdapterInfo>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback) continue;

            IPInterfaceProperties props;
            try
            {
                props = nic.GetIPProperties();
            }
            catch (NetworkInformationException)
            {
                continue;
            }

            var addresses = new List<AdapterAddress>();
            foreach (var u in props.UnicastAddresses)
            {
                if (u.Address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)) continue;
                int prefix;
                try
                {
                    prefix = u.PrefixLength;
                }
                catch (PlatformNotSupportedException)
                {
                    continue;
                }

                addresses.Add(new AdapterAddress(u.Address, prefix));
            }

            if (addresses.Count == 0) continue;

            string? mac = null;
            try
            {
                var bytes = nic.GetPhysicalAddress().GetAddressBytes();
                if (bytes.Length == 6) mac = string.Join("-", bytes.Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)));
            }
            catch (NetworkInformationException)
            {
                // not available
            }

            long speed = 0;
            try
            {
                speed = nic.Speed;
            }
            catch (PlatformNotSupportedException)
            {
                // not available
            }

            result.Add(new NetworkAdapterInfo(
                nic.Id,
                nic.Name,
                nic.Description,
                nic.NetworkInterfaceType.ToString(),
                mac,
                addresses,
                props.GatewayAddresses.Select(g => g.Address).Where(a => !a.Equals(System.Net.IPAddress.Any)).ToList(),
                speed));
        }

        return result;
    }
}
