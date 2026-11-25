using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using IPMaster.Core.Results;
using IPMaster.Core.Scanning;
using IPMaster.Core.Targets;
using IPMaster.Desktop.ViewModels;

/// <summary>
/// NFR-04: the results model behind the grid with N SYNTHETIC devices (default 50,000): insert, sort, filter, cell text,
/// and a results XML file for a timed load in the real GUI. Synthetic data only; nothing is sent on the network.
/// </summary>
internal static class ResultsBench
{
    public static async Task<int> RunAsync(string[] args)
    {
        var n = args.Length > 0 ? int.Parse(args[0], CultureInfo.InvariantCulture) : 50_000;
        var xmlPath = args.Length > 1 ? args[1] : null;
        Console.WriteLine($"IPMaster results-model benchmark — {n:N0} SYNTHETIC devices");
        var t = DateTimeOffset.UtcNow;
        var rnd = new Random(42);
        var devices = new List<DeviceResult>(n);
        for (var i = 0; i < n; i++)
        {
            var ip = new IPAddress([10, (byte)(i >> 16), (byte)(i >> 8), (byte)i]);
            var mac = new byte[] { 0x02, 0x00, (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i };
            devices.Add(new DeviceResult
            {
                Key = AddressKey.From(ip),
                Status = DeviceStatus.Online,
                RespondedTo = PingMethod.Icmp,
                RoundTrip = TimeSpan.FromMilliseconds(rnd.Next(1, 400)),
                Ttl = Observation<int>.Ok(rnd.Next(2) == 0 ? 64 : 128, t),
                HostName = Observation<HostNameInfo>.Ok(new HostNameInfo($"host-{rnd.Next(1_000_000):D6}.bench.invalid", null), t),
                Mac = Observation<PhysicalAddress>.Ok(new PhysicalAddress(mac), t),
                LastScanned = t,
                LastSeen = t,
                IsComplete = true,
                Revision = 1,
            });
        }

        var columns = new[] { ColumnCatalog.IpAddress, ColumnCatalog.ResponseTime, ColumnCatalog.HostName, ColumnCatalog.MacAddress, ColumnCatalog.Ttl };
        GC.Collect();
        var before = GC.GetTotalMemory(true);
        var view = new ResultsView { Columns = columns };
        var sw = Stopwatch.StartNew();
        foreach (var d in devices.OrderBy(_ => rnd.Next())) view.Upsert(d, false); // arrival order is not address order
        view.Rebuild();
        Report("insert (random arrival order) + rebuild", sw, view);
        var memory = GC.GetTotalMemory(true) - before;
        Console.WriteLine($"  results model: {memory / 1024.0 / 1024.0:F1} MB managed ({memory / (double)n:F0} B/device)");

        Time("sort by response time", view, v => v.SetSort("rtt", false));
        Time("sort by host name (text, case-insensitive)", view, v => v.SetSort("hostName", true));
        Time("remove sort (address order)", view, v => v.SetSort(null, false));
        var filter = CompiledFilter.Compile(new FilterDefinition { Conditions = [new FilterCondition { ColumnId = "hostName", Operation = FilterOperation.Contains, Value = "-12" }] }, out _, columns);
        Time("filter 'host name contains -12' (show only matching)", view, v => v.SetFilter(filter, FilterMode.ShowOnlyMatching));
        Time("clear filter", view, v => v.SetFilter(null, FilterMode.Highlight));

        sw.Restart();
        long chars = 0;
        foreach (var row in view.Rows)
        {
            foreach (var c in columns) chars += row[view.KeyFor(c.Id)].Length;
        }

        Console.WriteLine($"  format every cell ({view.Rows.Count * columns.Length:N0} cells, {chars:N0} chars): {sw.ElapsedMilliseconds} ms");

        if (xmlPath is not null)
        {
            sw.Restart();
            await ResultsXml.ExportAsync(xmlPath, columns, devices, new ScanMetadata { Targets = ["10.0.0.0/16 (synthetic)"] });
            Console.WriteLine($"  wrote {xmlPath} ({new FileInfo(xmlPath).Length / 1024.0 / 1024.0:F1} MB) in {sw.ElapsedMilliseconds} ms");
        }

        return 0;
    }

    private static void Time(string what, ResultsView view, Action<ResultsView> change)
    {
        var sw = Stopwatch.StartNew();
        change(view);
        view.Rebuild();
        Report(what, sw, view);
    }

    private static void Report(string what, Stopwatch sw, ResultsView view) =>
        Console.WriteLine($"  {what}: {sw.ElapsedMilliseconds} ms ({view.Rows.Count:N0} rows)");
}
