using System.Diagnostics;
using System.Globalization;
using System.Text;
using IPMaster.Core.Queries;
using IPMaster.Core.Scanning;
using IPMaster.Core.Tools;
using IPMaster.Infrastructure.Queries;
using Lextm.SharpSnmpLib;
using SnmpException = IPMaster.Infrastructure.Queries.SnmpException;

namespace IPMaster.Infrastructure.Tools;

public enum SnmpTestOperation
{
    Get,
    GetNext,
    GetBulk,
    Walk,
    BulkWalk,
}

public enum SnmpTestOutcome
{
    Success,

    /// <summary>The agent answered, but the requested objects do not exist (noSuchObject/noSuchInstance/endOfMibView, or an empty walk).</summary>
    NoSuchObject,
    Timeout,
    AuthenticationFailed,
    AgentError,
    InvalidInput,
    Cancelled,
}

public sealed record SnmpTestRow(string Oid, string Name, string Type, string Value);

public sealed record SnmpTestRequest
{
    public required SnmpTarget Target { get; init; }

    public SnmpTestOperation Operation { get; init; } = SnmpTestOperation.Get;

    public IReadOnlyList<string> Oids { get; init; } = [];

    public int NonRepeaters { get; init; }

    public int MaxRepetitions { get; init; } = 20;

    public int MaxItems { get; init; } = 5000;

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    /// <summary>Retries after a timeout (reads are idempotent). Wrong v1/v2c communities look like timeouts: agents stay silent.</summary>
    public int Retries { get; init; } = 1;

    public TimeSpan MaxWalkDuration { get; init; } = TimeSpan.FromMinutes(5);
}

public sealed record SnmpTestResult(SnmpTestOutcome Outcome, string Detail, IReadOnlyList<SnmpTestRow> Rows, SnmpWalkStop? WalkStop, int Requests, TimeSpan Duration);

/// <summary>
/// SNMP Tester (D-080): GET, GETNEXT, GETBULK, WALK and BULKWALK on <see cref="SnmpClient"/> with exactly one community
/// (no guessing). There is no SET. Walks are bounded by items and time and stop on repeated or non-increasing OIDs.
/// </summary>
public static class SnmpTester
{
    public const int MaxItemsLimit = 100_000;
    public const int MaxOidsPerRequest = 32;

    public static async Task<SnmpTestResult> RunAsync(SnmpTestRequest r, Action<int>? progress, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(r);
        var sw = Stopwatch.StartNew();
        var requests = 0;
        SnmpTestResult Done(SnmpTestOutcome o, string detail, IReadOnlyList<SnmpTestRow> rows, SnmpWalkStop? stop = null) => new(o, detail, rows, stop, requests, sw.Elapsed);

        var oids = new List<string>();
        foreach (var o in r.Oids.Where(o => o.Trim().Length > 0))
        {
            if (!SnmpOid.TryParse(o, out _)) return Done(SnmpTestOutcome.InvalidInput, $"'{o.Trim()}' is not a numeric OID (e.g. 1.3.6.1.2.1.1.1.0).", []);
            oids.Add(SnmpOid.Normalize(o));
        }

        if (oids.Count == 0) return Done(SnmpTestOutcome.InvalidInput, "Enter an OID.", []);
        if (oids.Count > MaxOidsPerRequest) return Done(SnmpTestOutcome.InvalidInput, $"At most {MaxOidsPerRequest} OIDs per request.", []);
        if (r.Target.Version != Core.Queries.SnmpVersion.V3 && r.Target.Communities.Count != 1) return Done(SnmpTestOutcome.InvalidInput, "Enter exactly one community.", []);
        if (r.MaxRepetitions is < 1 or > 100 || r.NonRepeaters < 0 || r.MaxItems is < 1 or > MaxItemsLimit) return Done(SnmpTestOutcome.InvalidInput, "Check the bulk and limit settings.", []);
        var bulkAsNext = r.Target.Version == Core.Queries.SnmpVersion.V1 && r.Operation is SnmpTestOperation.GetBulk or SnmpTestOperation.BulkWalk;

        async Task<IReadOnlyList<SnmpValue>> Send(IReadOnlyList<string> list, SnmpPduKind kind, int nonRepeaters, int maxRepetitions)
        {
            for (var attempt = 0; ; attempt++)
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(r.Timeout);
                requests++;
                try
                {
                    return await SnmpClient.RequestAsync(r.Target, list, kind, cts.Token, nonRepeaters, maxRepetitions).ConfigureAwait(false);
                }
                catch (Exception ex) when (!ct.IsCancellationRequested && attempt < r.Retries && (ex is OperationCanceledException || ex is SnmpException { State: ObservationState.NoResponse }))
                {
                }
            }
        }

        try
        {
            switch (r.Operation)
            {
                case SnmpTestOperation.Get:
                case SnmpTestOperation.GetNext:
                case SnmpTestOperation.GetBulk when !bulkAsNext:
                {
                    var kind = r.Operation switch { SnmpTestOperation.Get => SnmpPduKind.Get, SnmpTestOperation.GetNext => SnmpPduKind.GetNext, _ => SnmpPduKind.GetBulk };
                    var values = await Send(oids, kind, Math.Min(r.NonRepeaters, oids.Count), r.MaxRepetitions).ConfigureAwait(false);
                    var rows = values.Take(r.MaxItems).Select(Row).ToList();
                    return values.Count > 0 && values.All(v => v.IsMissing)
                        ? Done(SnmpTestOutcome.NoSuchObject, "The agent answered; the object does not exist (" + string.Join(", ", values.Select(v => v.Type).Distinct()) + ").", rows)
                        : Done(SnmpTestOutcome.Success, values.Any(v => v.IsMissing) ? "Some objects do not exist on this agent." : "", rows);
                }

                case SnmpTestOperation.GetBulk:
                {
                    var values = await Send(oids, SnmpPduKind.GetNext, 0, 0).ConfigureAwait(false);
                    return Done(SnmpTestOutcome.Success, "SNMPv1 has no GETBULK: sent as GETNEXT.", values.Select(Row).ToList());
                }

                default:
                {
                    var root = oids[0];
                    var bulk = r.Operation == SnmpTestOperation.BulkWalk && !bulkAsNext;
                    var rows = new List<SnmpTestRow>();
                    var previous = root;
                    SnmpWalkStop? stop = null;
                    while (stop is null)
                    {
                        if (sw.Elapsed > r.MaxWalkDuration)
                        {
                            stop = SnmpWalkStop.TimeLimitReached;
                            break;
                        }

                        IReadOnlyList<SnmpValue> batch;
                        try
                        {
                            batch = await Send([previous], bulk ? SnmpPduKind.GetBulk : SnmpPduKind.GetNext, 0, Math.Min(r.MaxRepetitions, r.MaxItems - rows.Count)).ConfigureAwait(false);
                        }
                        catch (SnmpException ex) when (ex.ErrorStatus == 2 && r.Target.Version == Core.Queries.SnmpVersion.V1)
                        {
                            stop = SnmpWalkStop.EndOfMibView; // v1 agents answer noSuchName past the last object
                            break;
                        }

                        if (batch.Count == 0)
                        {
                            return Done(SnmpTestOutcome.AgentError, "The agent returned an empty response.", rows);
                        }

                        foreach (var v in batch)
                        {
                            if (v.Type == SnmpType.EndOfMibView)
                            {
                                stop = SnmpWalkStop.EndOfMibView;
                                break;
                            }

                            if (v.IsMissing || SnmpOid.Check(root, previous, v.Oid) is { } s)
                            {
                                stop = v.IsMissing ? SnmpWalkStop.EndOfSubtree : SnmpOid.Check(root, previous, v.Oid);
                                break;
                            }

                            rows.Add(Row(v));
                            previous = v.Oid;
                            if (rows.Count >= r.MaxItems)
                            {
                                stop = SnmpWalkStop.LimitReached;
                                break;
                            }
                        }

                        progress?.Invoke(rows.Count);
                    }

                    var outcome = rows.Count == 0 && stop is SnmpWalkStop.EndOfSubtree or SnmpWalkStop.EndOfMibView ? SnmpTestOutcome.NoSuchObject
                        : stop is SnmpWalkStop.NonIncreasingOid or SnmpWalkStop.RepeatedOid ? SnmpTestOutcome.AgentError : SnmpTestOutcome.Success;
                    var detail = SnmpOid.Describe(stop!.Value) + (bulkAsNext && r.Operation == SnmpTestOperation.BulkWalk ? " (SNMPv1: walked with GETNEXT.)" : "");
                    return Done(outcome, rows.Count == 0 && outcome == SnmpTestOutcome.NoSuchObject ? "The agent answered; nothing exists below this OID." : detail, rows, stop);
                }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return Done(SnmpTestOutcome.Cancelled, "Cancelled.", []);
        }
        catch (OperationCanceledException)
        {
            return Done(SnmpTestOutcome.Timeout, NoAnswer(r), []);
        }
        catch (SnmpException ex)
        {
            return ex.State switch
            {
                ObservationState.NoResponse => Done(SnmpTestOutcome.Timeout, NoAnswer(r) + " " + ex.Message, []),
                ObservationState.AccessDenied => Done(SnmpTestOutcome.AuthenticationFailed, ex.Message, []),
                _ => Done(SnmpTestOutcome.AgentError, ex.Message, []),
            };
        }
    }

    private static string NoAnswer(SnmpTestRequest r) => string.Create(CultureInfo.InvariantCulture,
        $"No answer within {r.Timeout.TotalSeconds:0.#} s ({r.Retries + 1} attempt(s)).")
        + (r.Target.Version == Core.Queries.SnmpVersion.V3 ? "" : " SNMPv1/v2c agents stay silent for a wrong community, so this can also mean the community is not accepted.");

    public static SnmpTestRow Row(SnmpValue v)
    {
        ArgumentNullException.ThrowIfNull(v);
        return new SnmpTestRow(v.Oid, ShortName(v.Oid), TypeName(v.Type), Format(v));
    }

    /// <summary>Nearest known name plus the remaining arcs, e.g. "sysDescr.0" or "ifDescr.3"; empty when nothing below mib roots is known.</summary>
    public static string ShortName(string oid)
    {
        var parts = MibDatabase.SymbolicPath(oid).Split('.');
        var last = Array.FindLastIndex(parts, p => p.Length > 0 && !p.All(char.IsAsciiDigit));
        return last < 0 ? "" : string.Join('.', parts[last..]);
    }

    public static string TypeName(SnmpType t) => t switch
    {
        SnmpType.Integer32 => "INTEGER",
        SnmpType.OctetString => "OCTET STRING",
        SnmpType.ObjectIdentifier => "OBJECT IDENTIFIER",
        SnmpType.IPAddress => "IpAddress",
        SnmpType.Counter32 => "Counter32",
        SnmpType.Gauge32 => "Gauge32",
        SnmpType.TimeTicks => "TimeTicks",
        SnmpType.Opaque => "Opaque",
        SnmpType.Counter64 => "Counter64",
        SnmpType.Null => "NULL",
        SnmpType.NoSuchObject => "noSuchObject",
        SnmpType.NoSuchInstance => "noSuchInstance",
        SnmpType.EndOfMibView => "endOfMibView",
        _ => t.ToString(),
    };

    /// <summary>Display value. Integers are exact (Counter64 as UInt64, never through floating point).</summary>
    public static string Format(SnmpValue v)
    {
        ArgumentNullException.ThrowIfNull(v);
        var c = CultureInfo.InvariantCulture;
        return v.Data switch
        {
            Counter64 x => x.ToUInt64().ToString(c),
            Counter32 x => x.ToUInt32().ToString(c),
            Gauge32 x => x.ToUInt32().ToString(c),
            Integer32 x => x.ToInt32().ToString(c),
            TimeTicks x => Ticks(x.ToUInt32()),
            ObjectIdentifier x => x + (ShortName(x.ToString()) is { Length: > 0 } s ? "  (" + s + ")" : ""),
            OctetString x => SnmpText.RenderOctets(x.GetRaw(), SnmpDisplay.Automatic),
            Opaque x => SnmpText.RenderOctets(x.GetRaw(), SnmpDisplay.Hex),
            NoSuchObject or NoSuchInstance or EndOfMibView or Null => "",
            _ => v.Text,
        };
    }

    public static string Ticks(uint hundredths)
    {
        var t = TimeSpan.FromMilliseconds(hundredths * 10.0);
        return string.Create(CultureInfo.InvariantCulture, $"{hundredths} ({(int)t.TotalDays}d {t.Hours:00}:{t.Minutes:00}:{t.Seconds:00}.{t.Milliseconds / 10:00})");
    }

    public static string Report(SnmpTestRequest q, SnmpTestResult r)
    {
        ArgumentNullException.ThrowIfNull(q);
        ArgumentNullException.ThrowIfNull(r);
        var c = CultureInfo.InvariantCulture;
        var sb = new StringBuilder();
        // the target's ToString carries the user name and algorithms, never communities or passwords
        sb.AppendLine(c, $"SNMP {q.Operation} {string.Join(", ", q.Oids)} on {q.Target} — {r.Outcome}{(r.Detail.Length > 0 ? ": " + r.Detail : "")}");
        sb.AppendLine(c, $"{r.Rows.Count:N0} value(s), {r.Requests} request(s), {r.Duration.TotalMilliseconds:0} ms");
        foreach (var row in r.Rows) sb.AppendLine(c, $"{row.Oid}{(row.Name.Length > 0 ? " (" + row.Name + ")" : "")} = {row.Type}: {row.Value}");
        return sb.ToString();
    }
}
