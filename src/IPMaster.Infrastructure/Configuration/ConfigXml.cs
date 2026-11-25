using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml;
using System.Xml.Linq;
using IPMaster.Core.Configuration;
using IPMaster.Core.Results;

namespace IPMaster.Infrastructure.Configuration;

/// <summary>
/// XML configuration export/import (manual: File → Current Config → Save/Load). Schema <c>urn:ipmaster:config</c>
/// mirrors the versioned settings model: objects become elements, arrays contain &lt;item&gt; elements, and scalars
/// carry a <c>type</c> attribute so the round trip is lossless. Loading runs the same migrations as the JSON store.
/// Encryption with a master password is Phase 4 (SEC-02).
/// </summary>
public static class ConfigXml
{
    public static readonly XNamespace Ns = "urn:ipmaster:config";

    public static XDocument ToXml(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var node = JsonSerializer.SerializeToNode(settings, SettingsJsonContext.Default.AppSettings)!;
        var root = new XElement(Ns + "ipmasterConfig");
        Fill(root, node);
        return new XDocument(root);
    }

    public static async Task SaveAsync(string path, AppSettings settings, CancellationToken cancellationToken = default)
    {
        var doc = ToXml(settings);
        await AtomicFile.WriteAsync(path, async s =>
        {
            await using var xw = XmlWriter.Create(s, new XmlWriterSettings { Indent = true, Encoding = new UTF8Encoding(false), Async = true });
            await doc.SaveAsync(xw, cancellationToken).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    public static SettingsLoadResult Load(string path, SettingsStore parser)
    {
        ArgumentNullException.ThrowIfNull(parser);
        using var fs = File.OpenRead(path);
        using var reader = XmlReader.Create(fs, ResultsXml.SafeReaderSettings(16L * 1024 * 1024));
        var doc = XDocument.Load(reader);
        if (doc.Root is null || doc.Root.Name != Ns + "ipmasterConfig") throw new FormatException("Not an IPMaster configuration file.");
        var json = ToNode(doc.Root)!.ToJsonString();
        return parser.Parse(json);
    }

    private static void Fill(XElement e, JsonNode? node)
    {
        switch (node)
        {
            case null:
                e.SetAttributeValue("type", "null");
                break;
            case JsonObject o:
                foreach (var (k, v) in o)
                {
                    var child = new XElement(Ns + k);
                    Fill(child, v);
                    e.Add(child);
                }

                break;
            case JsonArray a:
                e.SetAttributeValue("type", "array");
                foreach (var v in a)
                {
                    var item = new XElement(Ns + "item");
                    Fill(item, v);
                    e.Add(item);
                }

                break;
            case JsonValue v:
                var kind = v.GetValueKind();
                e.SetAttributeValue("type", kind switch
                {
                    JsonValueKind.Number => "number",
                    JsonValueKind.True or JsonValueKind.False => "bool",
                    _ => "string",
                });
                e.Value = kind switch
                {
                    JsonValueKind.String => v.GetValue<string>(),
                    JsonValueKind.True => "true",
                    JsonValueKind.False => "false",
                    _ => v.ToJsonString(),
                };
                break;
        }
    }

    private static JsonNode? ToNode(XElement e)
    {
        var type = (string?)e.Attribute("type");
        switch (type)
        {
            case "null": return null;
            case "array":
                var a = new JsonArray();
                foreach (var item in e.Elements(Ns + "item")) a.Add(ToNode(item));
                return a;
            case "number": return JsonNode.Parse(decimal.Parse(e.Value, NumberStyles.Float, CultureInfo.InvariantCulture).ToString(CultureInfo.InvariantCulture));
            case "bool": return JsonValue.Create(e.Value == "true");
            case "string": return JsonValue.Create(e.Value);
            default:
                var o = new JsonObject();
                foreach (var child in e.Elements()) o[child.Name.LocalName] = ToNode(child);
                return o;
        }
    }
}
