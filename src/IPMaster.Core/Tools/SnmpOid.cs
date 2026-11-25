using System.Globalization;
using IPMaster.Core.Queries;

namespace IPMaster.Core.Tools;

public enum SnmpWalkStop
{
    /// <summary>The next OID is outside the requested subtree: the walk is complete.</summary>
    EndOfSubtree,
    EndOfMibView,
    LimitReached,
    TimeLimitReached,

    /// <summary>The agent returned an OID lower than the previous one (a broken agent; continuing could loop forever).</summary>
    NonIncreasingOid,

    /// <summary>The agent returned the same OID again.</summary>
    RepeatedOid,
}

/// <summary>Numeric OID handling and walk termination rules (D-080). Pure.</summary>
public static class SnmpOid
{
    public const int MaxArcs = 128;

    public static bool TryParse(string? text, out uint[] arcs)
    {
        arcs = [];
        var t = (text ?? "").Trim().TrimStart('.');
        if (t.Length == 0) return false;
        var parts = t.Split('.');
        if (parts.Length is < 2 or > MaxArcs) return false;
        var list = new uint[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length == 0 || (parts[i].Length > 1 && parts[i][0] == '0') || !uint.TryParse(parts[i], NumberStyles.None, CultureInfo.InvariantCulture, out list[i])) return false;
        }

        if (list[0] > 2 || (list[0] < 2 && list[1] > 39)) return false; // X.690 first-arc rules
        arcs = list;
        return true;
    }

    public static string Normalize(string text) => TryParse(text, out var a) ? string.Join('.', a) : throw new FormatException($"'{text}' is not a numeric OID (e.g. 1.3.6.1.2.1.1).");

    /// <summary>Lexicographic order of the numeric arcs (the SNMP order: 1.3.6.1.2 &lt; 1.3.6.1.10).</summary>
    public static int Compare(string a, string b)
    {
        if (!TryParse(a, out var x) || !TryParse(b, out var y)) return string.CompareOrdinal(a, b);
        for (var i = 0; i < Math.Min(x.Length, y.Length); i++)
        {
            if (x[i] != y[i]) return x[i].CompareTo(y[i]);
        }

        return x.Length.CompareTo(y.Length);
    }

    public static bool IsUnder(string oid, string root) => (oid ?? "").StartsWith((root ?? "").TrimStart('.') + ".", StringComparison.Ordinal);

    /// <summary>Why a walk must stop at <paramref name="next"/>, or null to continue.</summary>
    public static SnmpWalkStop? Check(string root, string previous, string next)
    {
        if (!IsUnder(next, root)) return SnmpWalkStop.EndOfSubtree;
        var c = Compare(next, previous);
        if (c == 0) return SnmpWalkStop.RepeatedOid;
        return c < 0 ? SnmpWalkStop.NonIncreasingOid : null;
    }

    public static string Describe(SnmpWalkStop stop) => stop switch
    {
        SnmpWalkStop.EndOfSubtree => "Complete: the agent's next object is outside the subtree.",
        SnmpWalkStop.EndOfMibView => "Complete: end of the agent's MIB view.",
        SnmpWalkStop.LimitReached => "Stopped at the item limit; more objects may exist.",
        SnmpWalkStop.TimeLimitReached => "Stopped at the time limit; more objects may exist.",
        SnmpWalkStop.NonIncreasingOid => "Stopped: the agent returned an OID that does not increase (agent bug; continuing could loop).",
        SnmpWalkStop.RepeatedOid => "Stopped: the agent returned the same OID again (agent bug; continuing would loop).",
        _ => stop.ToString(),
    };
}

/// <summary>Node of the built-in MIB tree (standard objects from the RFC MIBs in <see cref="MibDatabase"/>).</summary>
public sealed record MibTreeNode(string Oid, string Name, MibEntry? Entry, IReadOnlyList<MibTreeNode> Children);

public static class MibTree
{
    /// <summary>Builds the tree from the built-in database: every known object appears under its nearest known ancestor.</summary>
    public static MibTreeNode Build()
    {
        var names = new Dictionary<string, (string Name, MibEntry? Entry)>(StringComparer.Ordinal);
        foreach (var (oid, name) in MibDatabase.TreeNodes) names[oid] = (name, null);
        foreach (var e in MibDatabase.Entries) names[e.Oid] = (e.Name, e);
        var children = names.Keys.ToDictionary(k => k, _ => new List<string>(), StringComparer.Ordinal);
        foreach (var oid in names.Keys.Where(k => k != "1"))
        {
            var parent = oid;
            do
            {
                var dot = parent.LastIndexOf('.');
                parent = dot < 0 ? "1" : parent[..dot];
            }
            while (!names.ContainsKey(parent) && parent != "1");

            children[parent].Add(oid);
        }

        MibTreeNode Make(string oid) => new(oid, names[oid].Name, names[oid].Entry,
            children[oid].OrderBy(c => c, Comparer<string>.Create(SnmpOid.Compare)).Select(Make).ToList());
        return Make("1");
    }
}
