using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace Touchque.DeviceRisk.Internal;

/// <summary>JSON settings and small helpers shared by the SDK (the main Touchque SDK's, copied).</summary>
internal static class Json
{
    /// <summary>camelCase, case-insensitive reads, nulls left out, non-ASCII kept as is (like JSON.stringify).</summary>
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Serialize(JsonNode? node) => node is null ? "" : node.ToJsonString(Options);

    public static JsonNode? Parse(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try
        {
            return JsonNode.Parse(text);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Whether JSON text is I-JSON (RFC 7493) in the two ways System.Text.Json only notices when a value
    /// is first read: no object repeats a member name (ArgumentException) and no string holds a lone
    /// surrogate (InvalidOperationException). Untrusted JWS parts and token endpoint answers are checked
    /// with it before any read. <paramref name="checkValues"/> false checks the member names only (a
    /// webhook may carry a lone surrogate in a value, as JSON.stringify writes one).
    /// </summary>
    public static bool IsIJson(string text, bool checkValues = true)
    {
        var reader = new Utf8JsonReader(Encoding.UTF8.GetBytes(text));
        var names = new Stack<HashSet<string>>();
        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        names.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;
                    case JsonTokenType.EndObject:
                        names.Pop();
                        break;
                    case JsonTokenType.PropertyName:
                        if (!names.Peek().Add(reader.GetString()!)) return false;
                        break;
                    case JsonTokenType.String when checkValues:
                        _ = reader.GetString();
                        break;
                }
            }
            return true;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            return false;
        }
    }

    /// <summary>A string field, or null when missing or not a string.</summary>
    public static string? Str(JsonNode? node, string key)
    {
        if (node is not JsonObject o || !o.TryGetPropertyValue(key, out var v) || v is not JsonValue jv) return null;
        return jv.TryGetValue<string>(out var s) ? s : null;
    }

    public static long? Long(JsonNode? node, string key)
    {
        if (node is not JsonObject o || !o.TryGetPropertyValue(key, out var v) || v is not JsonValue jv) return null;
        if (jv.TryGetValue<long>(out var l)) return l;
        if (jv.TryGetValue<int>(out var i)) return i;
        if (jv.TryGetValue<double>(out var d)) return (long)d;
        if (jv.TryGetValue<string>(out var s)) return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) ? p : null;
        // A number of another CLR type (decimal, short…): read its JSON text.
        return jv.GetValueKind() == JsonValueKind.Number && double.TryParse(jv.ToJsonString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var x) ? (long)x : null;
    }

    public static int? Int(JsonNode? node, string key)
    {
        var l = Long(node, key);
        return l is null ? null : (int)l.Value;
    }

    /// <summary>Adds key = value when value is not null (and, for strings, not empty).</summary>
    public static JsonObject Put(this JsonObject o, string key, string? value)
    {
        if (!string.IsNullOrEmpty(value)) o[key] = value;
        return o;
    }

    public static JsonObject Put(this JsonObject o, string key, int? value)
    {
        if (value is not null) o[key] = value.Value;
        return o;
    }

    public static JsonObject Put(this JsonObject o, string key, bool? value)
    {
        if (value is not null) o[key] = value.Value;
        return o;
    }

    /// <summary>The bytes JSON.stringify would write for a string (quotes included).</summary>
    public static string JsString(string s)
    {
        var sb = new StringBuilder(s.Length + 2);
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20)
                    {
                        sb.Append("\\u").Append(((int)c).ToString("x4"));
                    }
                    else if (char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1]))
                    {
                        sb.Append(c).Append(s[i + 1]);
                        i++;
                    }
                    else if (char.IsSurrogate(c))
                    {
                        // A lone surrogate: well-formed JSON.stringify escapes it.
                        sb.Append("\\u").Append(((int)c).ToString("x4"));
                    }
                    else
                    {
                        sb.Append(c);
                    }
                    break;
            }
        }
        sb.Append('"');
        return sb.ToString();
    }

    /// <summary>
    /// JSON text without insignificant whitespace; strings and numbers are kept
    /// byte for byte (a pretty-printed body from a proxy still canonicalizes).
    /// </summary>
    public static string Compact(string json)
    {
        var sb = new StringBuilder(json.Length);
        var inString = false;
        for (var i = 0; i < json.Length; i++)
        {
            var c = json[i];
            if (inString)
            {
                sb.Append(c);
                if (c == '\\' && i + 1 < json.Length)
                {
                    sb.Append(json[++i]);
                }
                else if (c == '"')
                {
                    inString = false;
                }
                continue;
            }
            if (c == '"')
            {
                inString = true;
                sb.Append(c);
            }
            else if (c is not (' ' or '\t' or '\n' or '\r'))
            {
                sb.Append(c);
            }
        }
        return sb.ToString();
    }
}
