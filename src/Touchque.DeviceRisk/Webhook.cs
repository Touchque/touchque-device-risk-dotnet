using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Touchque.DeviceRisk.Internal;

namespace Touchque.DeviceRisk;

/// <summary>
/// Storage for webhook <c>jti</c>s already accepted. <see cref="CheckAndSetAsync"/> must
/// atomically record the jti for the TTL and return true when it was NOT seen
/// before. Use <see cref="MemoryReplayCache"/> for one process, or implement it over
/// Redis (<c>SET key 1 NX EX ttl</c>) or your database when you run several instances.
/// </summary>
public interface IWebhookReplayCache
{
    ValueTask<bool> CheckAndSetAsync(string jti, TimeSpan ttl, CancellationToken ct = default);
}

/// <summary>An in-process <see cref="IWebhookReplayCache"/>: entries expire after their TTL; the map is capped.</summary>
public sealed class MemoryReplayCache : IWebhookReplayCache
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new();
    private readonly int _maxEntries;
    private readonly object _gate = new();

    public MemoryReplayCache(int maxEntries = 100_000) => _maxEntries = Math.Max(2, maxEntries);

    public ValueTask<bool> CheckAndSetAsync(string jti, TimeSpan ttl, CancellationToken ct = default)
    {
        lock (_gate)
        {
            var now = DateTimeOffset.UtcNow;
            if (_seen.TryGetValue(jti, out var exp) && exp > now) return ValueTask.FromResult(false);
            if (_seen.Count >= _maxEntries)
            {
                foreach (var (k, v) in _seen)
                {
                    if (v <= now) _seen.TryRemove(k, out _);
                }
                foreach (var k in _seen.Keys.Take(Math.Max(0, _seen.Count - _maxEntries * 9 / 10)).ToList()) _seen.TryRemove(k, out _);
            }
            _seen[jti] = now + ttl;
            return ValueTask.FromResult(true);
        }
    }
}

/// <summary>
/// Device risk webhooks (<c>DEVICE_RISK_SIGNAL</c>, <c>DEVICE_RISK_ALERT</c>): signature verification with
/// your API secret, the same scheme as every Touchque webhook. Use <c>client.Webhook</c>.
/// </summary>
public sealed class DeviceRiskWebhook
{
    /// <summary>Default replay window: a callback whose signed timestamp is further than this from now is rejected.</summary>
    public const int DefaultToleranceSeconds = 300;

    /// <summary>An identification or a <see cref="DeviceRiskClient.CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/> raised a signal that asks for more. Never a trait.</summary>
    public const string EventDeviceRiskSignal = "DEVICE_RISK_SIGNAL";
    /// <summary>An alert rule of the workspace went off (<c>alert.rule</c>: signup_burst, many_accounts, tamper_spike).</summary>
    public const string EventDeviceRiskAlert = "DEVICE_RISK_ALERT";

    /// <summary>The Device risk event names. Ignore event types you do not know.</summary>
    public static readonly IReadOnlyList<string> Events = [EventDeviceRiskSignal, EventDeviceRiskAlert];

    private readonly string _secret;

    internal DeviceRiskWebhook(string apiSecret) => _secret = apiSecret;

    /// <summary>
    /// Verifies an incoming webhook and returns its payload.
    /// </summary>
    /// <param name="rawBody">The raw request body, exactly as received.</param>
    /// <param name="signature">The <c>x-signature</c> header; null uses the <c>signature</c> field inside the body.</param>
    /// <param name="toleranceSeconds">Reject a callback whose signed timestamp is missing, invalid or further than this from now; 0 disables the check.</param>
    /// <param name="replayCache">When set, a second delivery of the same jti throws <see cref="TouchqueWebhookReplayException"/>.</param>
    /// <exception cref="TouchqueWebhookSignatureException">Not from Touchque, changed, or too old.</exception>
    public async Task<JsonObject> VerifyAsync(string rawBody, string? signature = null, int toleranceSeconds = DefaultToleranceSeconds, IWebhookReplayCache? replayCache = null, CancellationToken ct = default)
    {
        var payload = Verify(rawBody, signature, toleranceSeconds);
        if (replayCache is not null)
        {
            var jti = Json.Str(payload, "jti");
            if (string.IsNullOrEmpty(jti)) throw new TouchqueWebhookSignatureException("jti is missing");
            // Remember it for twice the window so it outlives any timestamp that could still pass the freshness check.
            var ttl = TimeSpan.FromSeconds(Math.Max(toleranceSeconds * 2, 600));
            if (!await replayCache.CheckAndSetAsync(jti, ttl, ct).ConfigureAwait(false)) throw new TouchqueWebhookReplayException(jti);
        }
        return payload;
    }

    /// <summary>Verifies the signature and the freshness of a webhook (no replay cache) and returns its payload.</summary>
    public JsonObject Verify(string rawBody, string? signature = null, int toleranceSeconds = DefaultToleranceSeconds)
    {
        JsonObject payload;
        try
        {
            payload = JsonNode.Parse(rawBody) as JsonObject ?? throw new TouchqueWebhookSignatureException("invalid JSON payload");
        }
        catch (JsonException)
        {
            throw new TouchqueWebhookSignatureException("invalid JSON payload");
        }
        // A member name twice (or one with a lone surrogate) makes System.Text.Json throw on the first read
        // of that object; Touchque never sends one. Values may hold a lone surrogate, as JSON.stringify writes it.
        if (!Json.IsIJson(rawBody, checkValues: false)) throw new TouchqueWebhookSignatureException("invalid JSON payload");
        string? provided;
        try
        {
            provided = string.IsNullOrEmpty(signature) ? Json.Str(payload, "signature") : signature;
        }
        catch (InvalidOperationException)
        {
            throw new TouchqueWebhookSignatureException("invalid signature"); // a lone surrogate in the body's signature
        }
        if (string.IsNullOrEmpty(provided)) throw new TouchqueWebhookSignatureException("no signature provided");

        string canonical;
        try
        {
            canonical = Canonicalize(rawBody);
        }
        catch (JsonException)
        {
            throw new TouchqueWebhookSignatureException("could not canonicalize the payload");
        }
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_secret));
        var expected = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        // Never put the expected signature in the exception: it would be a signing oracle.
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(provided)))
        {
            throw new TouchqueWebhookSignatureException("invalid signature");
        }
        // Touchque always signs a timestamp: a missing or unparseable one fails closed.
        if (toleranceSeconds > 0)
        {
            var ts = Json.Str(payload, "timestamp");
            if (ts is null || !DateTimeOffset.TryParse(ts, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var at))
            {
                throw new TouchqueWebhookSignatureException("timestamp is missing or invalid");
            }
            if (Math.Abs((DateTimeOffset.UtcNow - at).TotalSeconds) > toleranceSeconds)
            {
                throw new TouchqueWebhookSignatureException("timestamp is outside the allowed window");
            }
        }
        return payload;
    }

    /// <summary>
    /// The server's stableStringify: drop <c>signature</c>, sort the TOP-LEVEL keys only (by
    /// UTF-16 code units, like JavaScript), and keep each value's bytes (nested key order,
    /// number spelling); insignificant whitespace is removed.
    /// </summary>
    internal static string Canonicalize(string rawBody)
    {
        using var doc = JsonDocument.Parse(rawBody);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("not an object");
        var members = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            if (p.Name == "signature") continue;
            members[p.Name] = Json.Compact(p.Value.GetRawText());
        }
        var sb = new StringBuilder("{");
        var first = true;
        foreach (var key in members.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (!first) sb.Append(',');
            first = false;
            sb.Append(Json.JsString(key)).Append(':').Append(members[key]);
        }
        return sb.Append('}').ToString();
    }
}
