using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using IPMaster.Core.Results;

namespace IPMaster.Core.Tools;

/// <summary>One row of a subnet table. Text columns are exact; IPv4 /31 and /32 rows have no broadcast.</summary>
public sealed record SubnetRow(BigInteger Index, IpBlock Block, string Subnet, string First, string Last, string Broadcast, string Count)
{
    /// <summary>1-based position, grouped, for display.</summary>
    public string Number => IpText.Grouped(Index + 1);
}

/// <summary>
/// Splitting a parent network into equal subnets. Subnet <c>i</c> is computed directly from its index, so a page of any
/// split (even ::/0 into /128s, 2^128 subnets) costs only its own rows; nothing enumerates the whole set.
/// </summary>
public sealed class SubnetSplit
{
    /// <summary>Largest set exported as "complete"; bigger splits can be exported a page at a time.</summary>
    public const int MaxExportRows = 1_048_576;

    public const int PageSize = 256;

    public SubnetSplit(IpBlock parent, int newPrefix)
    {
        if (newPrefix < parent.Prefix || newPrefix > parent.Bits) throw new ArgumentOutOfRangeException(nameof(newPrefix));
        Parent = parent;
        NewPrefix = newPrefix;
    }

    public IpBlock Parent { get; }

    public int NewPrefix { get; }

    public bool IsV6 => Parent.IsV6;

    public BigInteger SubnetCount => BigInteger.One << (NewPrefix - Parent.Prefix);

    public BigInteger AddressesPerSubnet => BigInteger.One << (Parent.Bits - NewPrefix);

    /// <summary>IPv4 only: usable hosts per subnet by subnet arithmetic (/31 = 2, /32 = 1).</summary>
    public BigInteger UsablePerSubnet => IsV6 ? 0 : NewPrefix switch { 32 => 1, 31 => 2, _ => AddressesPerSubnet - 2 };

    public UInt128 Mask => IpBlock.Containing(0, NewPrefix, IsV6).Mask;

    public BigInteger PageCount => (SubnetCount + PageSize - 1) / PageSize;

    public IpBlock At(BigInteger index)
    {
        if (index < 0 || index >= SubnetCount) throw new ArgumentOutOfRangeException(nameof(index));
        var offset = index << (Parent.Bits - NewPrefix);
        return new IpBlock(Parent.Network + IpMath.ToUInt128(offset), NewPrefix, IsV6);
    }

    /// <summary>Lazily yields at most <paramref name="max"/> rows starting at <paramref name="first"/>.</summary>
    public IEnumerable<SubnetRow> Rows(BigInteger first, int max)
    {
        var count = SubnetCount;
        for (var i = first; i < count && i < first + max; i++) yield return Row(i);
    }

    public IReadOnlyList<SubnetRow> Page(BigInteger page) => Rows(page * PageSize, PageSize).ToList();

    public SubnetRow Row(BigInteger index)
    {
        var b = At(index);
        string F(UInt128 v) => IpText.Format(v, IsV6);
        var count = IpText.Exact(b.Count);
        if (IsV6) return new SubnetRow(index, b, b.ToString(), F(b.Network), F(b.Last), "", count);
        return b.Prefix switch
        {
            32 => new SubnetRow(index, b, b.ToString(), F(b.Network), F(b.Network), "", count),
            31 => new SubnetRow(index, b, b.ToString(), F(b.Network), F(b.Last), "", count),
            _ => new SubnetRow(index, b, b.ToString(), F(b.Network + 1), F(b.Last - 1), F(b.Last), count),
        };
    }

    public string FirstHeader => IsV6 || NewPrefix >= 31 ? "First Address" : "First Usable";

    public string LastHeader => IsV6 || NewPrefix >= 31 ? "Last Address" : "Last Usable";

    public bool HasBroadcast => !IsV6 && NewPrefix <= 30;

    public string Describe() =>
        $"{Parent} split into /{NewPrefix}: {IpText.Readable(SubnetCount)} subnet(s) of {IpText.Readable(AddressesPerSubnet)} address(es)"
        + (IsV6 ? "." : $", {IpText.Readable(UsablePerSubnet)} usable each.");

    // ---------------------------------------------------------------- export

    /// <summary>Writes rows <paramref name="first"/>…+<paramref name="count"/> as CSV (exact values, formula-protected), checking cancellation.</summary>
    public async Task WriteCsvAsync(TextWriter w, BigInteger first, int count, string scope, CancellationToken ct)
    {
        // one CSV cell (quoted when it contains commas) so spreadsheets keep it on one line above the header
        CsvExporter.WriteRow(w, [$"# IPMaster subnet export: {scope}. {Describe()}"], ',', protectFormulas: false);
        var header = new List<string> { "Index", "Subnet", FirstHeader, LastHeader };
        if (HasBroadcast) header.Add("Broadcast Address");
        header.Add("Address Count");
        CsvExporter.WriteRow(w, header, ',', protectFormulas: true);
        var n = 0;
        foreach (var r in Rows(first, count))
        {
            if ((++n & 4095) == 0)
            {
                ct.ThrowIfCancellationRequested();
                await w.FlushAsync(ct).ConfigureAwait(false);
            }

            var cells = new List<string> { IpText.Exact(r.Index + 1), r.Subnet, r.First, r.Last };
            if (HasBroadcast) cells.Add(r.Broadcast);
            cells.Add(r.Count);
            CsvExporter.WriteRow(w, cells, ',', protectFormulas: true);
        }

        ct.ThrowIfCancellationRequested();
    }

    /// <summary>JSON with exact counts as strings (2^128 does not fit a JSON number reliably).</summary>
    public async Task WriteJsonAsync(Stream s, BigInteger first, int count, string scope, bool complete, CancellationToken ct)
    {
        await using var j = new Utf8JsonWriter(s, new JsonWriterOptions { Indented = true });
        j.WriteStartObject();
        j.WriteString("generator", "IPMaster IP Calculator");
        j.WriteString("scope", complete ? "complete" : "page");
        j.WriteString("scopeDescription", scope);
        j.WriteString("parent", Parent.ToString());
        j.WriteNumber("newPrefix", NewPrefix);
        j.WriteString("totalSubnets", IpText.Exact(SubnetCount));
        j.WriteString("addressesPerSubnet", IpText.Exact(AddressesPerSubnet));
        if (!IsV6) j.WriteString("usablePerSubnet", IpText.Exact(UsablePerSubnet));
        j.WriteString("firstIndex", IpText.Exact(first + 1));
        j.WriteStartArray("subnets");
        var n = 0;
        foreach (var r in Rows(first, count))
        {
            if ((++n & 4095) == 0)
            {
                ct.ThrowIfCancellationRequested();
                await j.FlushAsync(ct).ConfigureAwait(false);
            }

            j.WriteStartObject();
            j.WriteString("index", IpText.Exact(r.Index + 1));
            j.WriteString("subnet", r.Subnet);
            j.WriteString(HasBroadcast ? "firstUsable" : "firstAddress", r.First);
            j.WriteString(HasBroadcast ? "lastUsable" : "lastAddress", r.Last);
            if (HasBroadcast) j.WriteString("broadcast", r.Broadcast);
            j.WriteString("addressCount", r.Count);
            j.WriteEndObject();
        }

        j.WriteEndArray();
        j.WriteEndObject();
        ct.ThrowIfCancellationRequested();
        await j.FlushAsync(ct).ConfigureAwait(false);
    }

    public static string ScopeText(bool complete, BigInteger page, BigInteger pageCount, int rows, BigInteger total) => complete
        ? $"complete set, all {IpText.Grouped(total)} subnets"
        : string.Create(CultureInfo.InvariantCulture, $"current page only, page {IpText.Grouped(page + 1)} of {IpText.Grouped(pageCount)} ({rows} of {IpText.Grouped(total)} subnets)");

    public static Encoding Utf8 { get; } = new UTF8Encoding(false);
}
