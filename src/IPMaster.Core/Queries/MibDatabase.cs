namespace IPMaster.Core.Queries;

public sealed record MibEntry(string Name, string Oid, string Module, string Description)
{
    /// <summary>True for table columns (the instance index must be appended or the column walked).</summary>
    public bool IsColumn => !Oid.EndsWith(".0", StringComparison.Ordinal) && Module.Length > 0 && Description.StartsWith("Column", StringComparison.Ordinal);
}

/// <summary>
/// Built-in MIB browser data (SNM-05): standard objects from RFC-defined MIBs, typed from the RFCs. Scalars end in
/// <c>.0</c>; table columns need an index (or use Walk). Vendor MIB files are not bundled (D-054).
/// </summary>
public static class MibDatabase
{
    private static readonly (string Oid, string Name)[] Nodes =
    [
        ("1", "iso"), ("1.3", "org"), ("1.3.6", "dod"), ("1.3.6.1", "internet"), ("1.3.6.1.2", "mgmt"), ("1.3.6.1.2.1", "mib-2"),
        ("1.3.6.1.4", "private"), ("1.3.6.1.4.1", "enterprises"), ("1.3.6.1.6", "snmpV2"), ("1.3.6.1.6.3", "snmpModules"),
        ("1.3.6.1.2.1.1", "system"), ("1.3.6.1.2.1.2", "interfaces"), ("1.3.6.1.2.1.2.2", "ifTable"), ("1.3.6.1.2.1.2.2.1", "ifEntry"),
        ("1.3.6.1.2.1.4", "ip"), ("1.3.6.1.2.1.4.20", "ipAddrTable"), ("1.3.6.1.2.1.4.20.1", "ipAddrEntry"), ("1.3.6.1.2.1.4.22", "ipNetToMediaTable"),
        ("1.3.6.1.2.1.4.22.1", "ipNetToMediaEntry"), ("1.3.6.1.2.1.11", "snmp"), ("1.3.6.1.2.1.17", "dot1dBridge"), ("1.3.6.1.2.1.17.4", "dot1dTp"),
        ("1.3.6.1.2.1.17.4.3", "dot1dTpFdbTable"), ("1.3.6.1.2.1.17.4.3.1", "dot1dTpFdbEntry"), ("1.3.6.1.2.1.25", "host"), ("1.3.6.1.2.1.25.1", "hrSystem"),
        ("1.3.6.1.2.1.25.2", "hrStorage"), ("1.3.6.1.2.1.25.2.3", "hrStorageTable"), ("1.3.6.1.2.1.25.2.3.1", "hrStorageEntry"), ("1.3.6.1.2.1.25.3", "hrDevice"),
        ("1.3.6.1.2.1.25.3.2", "hrDeviceTable"), ("1.3.6.1.2.1.25.3.2.1", "hrDeviceEntry"), ("1.3.6.1.2.1.25.3.3", "hrProcessorTable"),
        ("1.3.6.1.2.1.25.3.3.1", "hrProcessorEntry"), ("1.3.6.1.2.1.25.4", "hrSWRun"), ("1.3.6.1.2.1.25.4.2", "hrSWRunTable"),
        ("1.3.6.1.2.1.25.4.2.1", "hrSWRunEntry"), ("1.3.6.1.2.1.25.6", "hrSWInstalled"), ("1.3.6.1.2.1.25.6.3", "hrSWInstalledTable"),
        ("1.3.6.1.2.1.25.6.3.1", "hrSWInstalledEntry"), ("1.3.6.1.2.1.31", "ifMIB"), ("1.3.6.1.2.1.31.1", "ifMIBObjects"), ("1.3.6.1.2.1.31.1.1", "ifXTable"),
        ("1.3.6.1.2.1.31.1.1.1", "ifXEntry"), ("1.3.6.1.2.1.33", "upsMIB"), ("1.3.6.1.2.1.33.1", "upsObjects"), ("1.3.6.1.2.1.33.1.1", "upsIdent"),
        ("1.3.6.1.2.1.33.1.2", "upsBattery"), ("1.3.6.1.2.1.33.1.3", "upsInput"), ("1.3.6.1.2.1.33.1.3.3", "upsInputTable"),
        ("1.3.6.1.2.1.33.1.3.3.1", "upsInputEntry"), ("1.3.6.1.2.1.33.1.4", "upsOutput"), ("1.3.6.1.2.1.43", "printmib"),
        ("1.3.6.1.2.1.43.5", "prtGeneral"), ("1.3.6.1.2.1.43.5.1", "prtGeneralTable"), ("1.3.6.1.2.1.43.5.1.1", "prtGeneralEntry"),
        ("1.3.6.1.2.1.43.10", "prtMarker"), ("1.3.6.1.2.1.43.10.2", "prtMarkerTable"), ("1.3.6.1.2.1.43.10.2.1", "prtMarkerEntry"),
        ("1.3.6.1.2.1.43.11", "prtMarkerSupplies"), ("1.3.6.1.2.1.43.11.1", "prtMarkerSuppliesTable"), ("1.3.6.1.2.1.43.11.1.1", "prtMarkerSuppliesEntry"),
        ("1.3.6.1.2.1.47", "entityMIB"), ("1.3.6.1.2.1.47.1", "entityMIBObjects"), ("1.3.6.1.2.1.47.1.1", "entityPhysical"),
        ("1.3.6.1.2.1.47.1.1.1", "entPhysicalTable"), ("1.3.6.1.2.1.47.1.1.1.1", "entPhysicalEntry"),
    ];

    public static readonly IReadOnlyList<MibEntry> Entries =
    [
        new("sysDescr", "1.3.6.1.2.1.1.1.0", "SNMPv2-MIB", "Textual description of the device (hardware, OS, version)."),
        new("sysObjectID", "1.3.6.1.2.1.1.2.0", "SNMPv2-MIB", "Vendor's authoritative identification of the device."),
        new("sysUpTime", "1.3.6.1.2.1.1.3.0", "SNMPv2-MIB", "Time since the network management part was re-initialised (1/100 s)."),
        new("sysContact", "1.3.6.1.2.1.1.4.0", "SNMPv2-MIB", "Contact person for the device."),
        new("sysName", "1.3.6.1.2.1.1.5.0", "SNMPv2-MIB", "Administratively assigned name."),
        new("sysLocation", "1.3.6.1.2.1.1.6.0", "SNMPv2-MIB", "Physical location."),
        new("sysServices", "1.3.6.1.2.1.1.7.0", "SNMPv2-MIB", "Set of services offered (OSI layers)."),
        new("ifNumber", "1.3.6.1.2.1.2.1.0", "IF-MIB", "Number of network interfaces."),
        new("ifIndex", "1.3.6.1.2.1.2.2.1.1", "IF-MIB", "Column: interface index."),
        new("ifDescr", "1.3.6.1.2.1.2.2.1.2", "IF-MIB", "Column: interface description."),
        new("ifType", "1.3.6.1.2.1.2.2.1.3", "IF-MIB", "Column: interface type (IANAifType)."),
        new("ifMtu", "1.3.6.1.2.1.2.2.1.4", "IF-MIB", "Column: MTU in octets."),
        new("ifSpeed", "1.3.6.1.2.1.2.2.1.5", "IF-MIB", "Column: bandwidth in bits per second (32-bit)."),
        new("ifPhysAddress", "1.3.6.1.2.1.2.2.1.6", "IF-MIB", "Column: MAC address."),
        new("ifAdminStatus", "1.3.6.1.2.1.2.2.1.7", "IF-MIB", "Column: desired state (1 up, 2 down, 3 testing)."),
        new("ifOperStatus", "1.3.6.1.2.1.2.2.1.8", "IF-MIB", "Column: operational state (1 up, 2 down, …)."),
        new("ifLastChange", "1.3.6.1.2.1.2.2.1.9", "IF-MIB", "Column: sysUpTime at the last state change."),
        new("ifInOctets", "1.3.6.1.2.1.2.2.1.10", "IF-MIB", "Column: octets received (32-bit counter)."),
        new("ifInUcastPkts", "1.3.6.1.2.1.2.2.1.11", "IF-MIB", "Column: unicast packets received."),
        new("ifInDiscards", "1.3.6.1.2.1.2.2.1.13", "IF-MIB", "Column: inbound packets discarded."),
        new("ifInErrors", "1.3.6.1.2.1.2.2.1.14", "IF-MIB", "Column: inbound packets with errors."),
        new("ifOutOctets", "1.3.6.1.2.1.2.2.1.16", "IF-MIB", "Column: octets sent (32-bit counter)."),
        new("ifOutUcastPkts", "1.3.6.1.2.1.2.2.1.17", "IF-MIB", "Column: unicast packets sent."),
        new("ifOutDiscards", "1.3.6.1.2.1.2.2.1.19", "IF-MIB", "Column: outbound packets discarded."),
        new("ifOutErrors", "1.3.6.1.2.1.2.2.1.20", "IF-MIB", "Column: outbound packets with errors."),
        new("ifName", "1.3.6.1.2.1.31.1.1.1.1", "IF-MIB", "Column: interface name (e.g. Gi0/1)."),
        new("ifHCInOctets", "1.3.6.1.2.1.31.1.1.1.6", "IF-MIB", "Column: octets received (64-bit counter)."),
        new("ifHCOutOctets", "1.3.6.1.2.1.31.1.1.1.10", "IF-MIB", "Column: octets sent (64-bit counter)."),
        new("ifHighSpeed", "1.3.6.1.2.1.31.1.1.1.15", "IF-MIB", "Column: bandwidth in Mbit/s."),
        new("ifAlias", "1.3.6.1.2.1.31.1.1.1.18", "IF-MIB", "Column: administrator's alias for the interface."),
        new("ipForwarding", "1.3.6.1.2.1.4.1.0", "IP-MIB", "1 = acts as a router, 2 = host."),
        new("ipAdEntAddr", "1.3.6.1.2.1.4.20.1.1", "IP-MIB", "Column: IPv4 address (index = address)."),
        new("ipAdEntIfIndex", "1.3.6.1.2.1.4.20.1.2", "IP-MIB", "Column: interface of the address (index = address)."),
        new("ipAdEntNetMask", "1.3.6.1.2.1.4.20.1.3", "IP-MIB", "Column: subnet mask (index = address, e.g. …1.3.%0)."),
        new("ipNetToMediaIfIndex", "1.3.6.1.2.1.4.22.1.1", "IP-MIB", "Column: ARP entry interface."),
        new("ipNetToMediaPhysAddress", "1.3.6.1.2.1.4.22.1.2", "IP-MIB", "Column: ARP entry MAC (index = ifIndex.address)."),
        new("ipNetToMediaNetAddress", "1.3.6.1.2.1.4.22.1.3", "IP-MIB", "Column: ARP entry IPv4 address."),
        new("ipNetToMediaType", "1.3.6.1.2.1.4.22.1.4", "IP-MIB", "Column: ARP entry type (3 dynamic, 4 static)."),
        new("snmpInPkts", "1.3.6.1.2.1.11.1.0", "SNMPv2-MIB", "SNMP messages received."),
        new("dot1dTpFdbAddress", "1.3.6.1.2.1.17.4.3.1.1", "BRIDGE-MIB", "Column: MAC address in the forwarding table."),
        new("dot1dTpFdbPort", "1.3.6.1.2.1.17.4.3.1.2", "BRIDGE-MIB", "Column: bridge port of the MAC (index = MAC octets, use %1)."),
        new("hrSystemUptime", "1.3.6.1.2.1.25.1.1.0", "HOST-RESOURCES-MIB", "Time since the host was last initialised (1/100 s)."),
        new("hrSystemNumUsers", "1.3.6.1.2.1.25.1.5.0", "HOST-RESOURCES-MIB", "Number of user sessions."),
        new("hrSystemProcesses", "1.3.6.1.2.1.25.1.6.0", "HOST-RESOURCES-MIB", "Number of process contexts."),
        new("hrMemorySize", "1.3.6.1.2.1.25.2.2.0", "HOST-RESOURCES-MIB", "Main memory in KiB."),
        new("hrStorageDescr", "1.3.6.1.2.1.25.2.3.1.3", "HOST-RESOURCES-MIB", "Column: storage description (disk, RAM, …)."),
        new("hrStorageAllocationUnits", "1.3.6.1.2.1.25.2.3.1.4", "HOST-RESOURCES-MIB", "Column: allocation unit size in bytes."),
        new("hrStorageSize", "1.3.6.1.2.1.25.2.3.1.5", "HOST-RESOURCES-MIB", "Column: size in allocation units."),
        new("hrStorageUsed", "1.3.6.1.2.1.25.2.3.1.6", "HOST-RESOURCES-MIB", "Column: used allocation units."),
        new("hrDeviceDescr", "1.3.6.1.2.1.25.3.2.1.3", "HOST-RESOURCES-MIB", "Column: device description."),
        new("hrProcessorLoad", "1.3.6.1.2.1.25.3.3.1.2", "HOST-RESOURCES-MIB", "Column: average load of a processor over the last minute (%)."),
        new("hrSWRunName", "1.3.6.1.2.1.25.4.2.1.2", "HOST-RESOURCES-MIB", "Column: name of a running program."),
        new("hrSWInstalledName", "1.3.6.1.2.1.25.6.3.1.2", "HOST-RESOURCES-MIB", "Column: installed software name."),
        new("upsIdentManufacturer", "1.3.6.1.2.1.33.1.1.1.0", "UPS-MIB", "UPS manufacturer."),
        new("upsIdentModel", "1.3.6.1.2.1.33.1.1.2.0", "UPS-MIB", "UPS model."),
        new("upsBatteryStatus", "1.3.6.1.2.1.33.1.2.1.0", "UPS-MIB", "1 unknown, 2 normal, 3 low, 4 depleted."),
        new("upsSecondsOnBattery", "1.3.6.1.2.1.33.1.2.2.0", "UPS-MIB", "Seconds on battery (0 = on mains)."),
        new("upsEstimatedMinutesRemaining", "1.3.6.1.2.1.33.1.2.3.0", "UPS-MIB", "Estimated runtime in minutes."),
        new("upsEstimatedChargeRemaining", "1.3.6.1.2.1.33.1.2.4.0", "UPS-MIB", "Battery charge in percent."),
        new("upsInputVoltage", "1.3.6.1.2.1.33.1.3.3.1.3", "UPS-MIB", "Column: input voltage (RMS volts)."),
        new("upsOutputSource", "1.3.6.1.2.1.33.1.4.1.0", "UPS-MIB", "Output source (3 normal, 5 battery, …)."),
        new("prtGeneralSerialNumber", "1.3.6.1.2.1.43.5.1.1.17", "Printer-MIB", "Column: printer serial number (index 1)."),
        new("prtMarkerLifeCount", "1.3.6.1.2.1.43.10.2.1.4", "Printer-MIB", "Column: lifetime page/impression count."),
        new("prtMarkerSuppliesDescription", "1.3.6.1.2.1.43.11.1.1.6", "Printer-MIB", "Column: supply description (toner, drum, …)."),
        new("prtMarkerSuppliesMaxCapacity", "1.3.6.1.2.1.43.11.1.1.8", "Printer-MIB", "Column: supply capacity."),
        new("prtMarkerSuppliesLevel", "1.3.6.1.2.1.43.11.1.1.9", "Printer-MIB", "Column: remaining supply (toner level; manual example)."),
        new("entPhysicalDescr", "1.3.6.1.2.1.47.1.1.1.1.2", "ENTITY-MIB", "Column: physical entity description."),
        new("entPhysicalName", "1.3.6.1.2.1.47.1.1.1.1.7", "ENTITY-MIB", "Column: physical entity name."),
        new("entPhysicalHardwareRev", "1.3.6.1.2.1.47.1.1.1.1.8", "ENTITY-MIB", "Column: hardware revision."),
        new("entPhysicalFirmwareRev", "1.3.6.1.2.1.47.1.1.1.1.9", "ENTITY-MIB", "Column: firmware revision."),
        new("entPhysicalSoftwareRev", "1.3.6.1.2.1.47.1.1.1.1.10", "ENTITY-MIB", "Column: software revision."),
        new("entPhysicalSerialNum", "1.3.6.1.2.1.47.1.1.1.1.11", "ENTITY-MIB", "Column: serial number."),
        new("entPhysicalMfgName", "1.3.6.1.2.1.47.1.1.1.1.12", "ENTITY-MIB", "Column: manufacturer."),
        new("entPhysicalModelName", "1.3.6.1.2.1.47.1.1.1.1.13", "ENTITY-MIB", "Column: model name."),
    ];

    /// <summary>Named intermediate nodes (groups, tables, entries) for the MIB tree.</summary>
    public static IReadOnlyList<(string Oid, string Name)> TreeNodes => Nodes;

    public static IReadOnlyList<MibEntry> Search(string text, int max = 200)
    {
        var t = (text ?? "").Trim().TrimStart('.');
        return Entries.Where(e => t.Length == 0 || e.Name.Contains(t, StringComparison.OrdinalIgnoreCase) || e.Oid.StartsWith(t, StringComparison.Ordinal)
                                  || e.Module.Contains(t, StringComparison.OrdinalIgnoreCase) || e.Description.Contains(t, StringComparison.OrdinalIgnoreCase))
            .Take(max).ToList();
    }

    /// <summary>Symbolic path, e.g. iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0.</summary>
    public static string SymbolicPath(string oid)
    {
        ArgumentNullException.ThrowIfNull(oid);
        var parts = oid.Trim('.').Split('.');
        var names = Nodes.ToDictionary(n => n.Oid, n => n.Name);
        foreach (var e in Entries) names.TryAdd(e.Oid.EndsWith(".0", StringComparison.Ordinal) ? e.Oid[..^2] : e.Oid, e.Name);
        var result = new List<string>();
        for (var i = 1; i <= parts.Length; i++)
        {
            var prefix = string.Join('.', parts.Take(i));
            result.Add(names.TryGetValue(prefix, out var n) ? n : parts[i - 1]);
        }

        return string.Join('.', result);
    }
}
