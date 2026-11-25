using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace IPMaster.Core.Targets;

/// <summary>
/// Allocation-free numeric form of an IPv4 or IPv6 address (with IPv6 scope ID). Used by target
/// enumeration so plans are never materialised as <see cref="IPAddress"/> instances.
/// </summary>
public readonly record struct AddressKey(UInt128 Value, bool IsV6, long ScopeId = 0) : IComparable<AddressKey>, IComparable
{
    public static AddressKey FromIPv4(uint value) => new(value, false);

    public static AddressKey From(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        Span<byte> bytes = stackalloc byte[16];
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            address.TryWriteBytes(bytes, out _);
            return new AddressKey(BinaryPrimitives.ReadUInt32BigEndian(bytes), false);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            address.TryWriteBytes(bytes, out _);
            return new AddressKey(BinaryPrimitives.ReadUInt128BigEndian(bytes), true, address.ScopeId);
        }

        throw new ArgumentException($"Unsupported address family {address.AddressFamily}.", nameof(address));
    }

    public uint V4 => IsV6 ? throw new InvalidOperationException("Not an IPv4 address.") : (uint)Value;

    public IPAddress ToIPAddress()
    {
        if (!IsV6)
        {
            Span<byte> b4 = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(b4, (uint)Value);
            return new IPAddress(b4);
        }

        Span<byte> b = stackalloc byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(b, Value);
        return new IPAddress(b, ScopeId);
    }

    public AddressKey WithValue(UInt128 value) => this with { Value = value };

    public int CompareTo(AddressKey other)
    {
        var c = IsV6.CompareTo(other.IsV6);
        if (c != 0) return c;
        c = Value.CompareTo(other.Value);
        return c != 0 ? c : ScopeId.CompareTo(other.ScopeId);
    }

    public int CompareTo(object? obj) => obj is AddressKey other ? CompareTo(other) : 1;

    public override string ToString() => ToIPAddress().ToString();

    public static UInt128 MaskFor(int prefixLength, bool isV6)
    {
        var bits = isV6 ? 128 : 32;
        if (prefixLength < 0 || prefixLength > bits) throw new ArgumentOutOfRangeException(nameof(prefixLength));
        if (prefixLength == 0) return UInt128.Zero;
        var all = isV6 ? UInt128.MaxValue : uint.MaxValue;
        return (all << (bits - prefixLength)) & all;
    }
}
