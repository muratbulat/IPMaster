using System.Diagnostics;
using System.Net;
using IPMaster.Infrastructure.Probes;

namespace IPMaster.Tests;

/// <summary>Scan host names: direct PTR query first (D-083), loopback DNS fixture only.</summary>
public class ReverseLookupTests
{
    private const ushort Ptr = 12;

    [Fact]
    public async Task Ptr_answer_gives_the_name_without_the_trailing_dot()
    {
        await using var f = new DnsFixture((id, n, t, _) => t == Ptr && n == "7.2.0.192.in-addr.arpa"
            ? DnsFixture.Reply(id, n, t, 0, false, (Ptr, 300, DnsFixture.Name("printer.example.test.")))
            : DnsFixture.Reply(id, n, t, 3, false));
        var r = new DnsHostNameResolver(() => [f.EndPoint]);
        Assert.Equal("printer.example.test", await r.ReverseLookupAsync(IPAddress.Parse("192.0.2.7"), CancellationToken.None));
    }

    [Theory]
    [InlineData(3)] // NXDOMAIN
    [InlineData(0)] // empty NOERROR
    public async Task Definite_no_name_answer_is_fast_and_skips_the_os_resolver(int rcode)
    {
        await using var f = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, rcode, false));
        var r = new DnsHostNameResolver(() => [f.EndPoint]);
        var sw = Stopwatch.StartNew();
        Assert.Null(await r.ReverseLookupAsync(IPAddress.Parse("192.0.2.8"), CancellationToken.None));
        Assert.True(sw.ElapsedMilliseconds < 500, $"took {sw.ElapsedMilliseconds} ms");
        Assert.Equal(1, f.UdpQueries);
    }

    [Fact]
    public async Task Own_address_without_ptr_record_gets_the_os_name()
    {
        await using var f = new DnsFixture((id, n, t, _) => DnsFixture.Reply(id, n, t, 3, false));
        var r = new DnsHostNameResolver(() => [f.EndPoint]);
        Assert.False(string.IsNullOrEmpty(await r.ReverseLookupAsync(IPAddress.Loopback, CancellationToken.None)));
    }
}
