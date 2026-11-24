using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Touchque.DeviceRisk.Internal;

namespace Touchque.DeviceRisk;

/// <summary>
/// Touchque Device Risk, server side (a paid add-on, off until your workspace turns it on): a visitor ID for
/// every browser on your sign-up, password-reset, sign-in or approval page. The page identifies with the
/// Device Risk browser SDK (<c>@touchque/device-risk</c>, or its script tag) and sends you the requestId.
/// Never trust the page's copy: read the identification here (<see cref="GetEventAsync"/>) or check it for an
/// account (<see cref="CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/>). Touchque keeps keyed hashes
/// only, with a key of your workspace alone, and its risk engine decides. Every signal only ever asks for more:
/// <c>StepUp</c> means an extra check on this page (an emailed code, a passkey, a number-matched approval),
/// never a refusal. Collect it only on these pages and name it in your privacy notice.
/// <code>
/// // TQ_API_KEY=tq_…  TQ_API_SECRET=…
/// var dr = new DeviceRiskClient();
/// var r = await dr.CheckAsync(Request.Form["touchque_request_id"], new() { ExternalUsername = email });
/// if (r.StepUp) { /* ask for more on this page */ }
/// </code>
/// With the script tag (device.js), the form arrives with <c>touchque_request_id</c>. Pass it as it came.
/// Missing, empty, made up or expired, it is still a verdict (<c>Report</c> missing, unknown, expired; the
/// signal <c>device_identification_missing</c>), never an exception: a page without the tag, or with it
/// blocked, only gets the visitor a step-up. Every call is signed with your API secret, so it belongs on your
/// server. Thread-safe; create one and reuse it.
/// </summary>
public sealed partial class DeviceRiskClient
{
    public const string DefaultBaseUrl = DeviceRiskOptions.DefaultBaseUrl;

    /// <summary>The pages a device report may come from.</summary>
    public static readonly IReadOnlyList<string> Events = ["sign_in", "sign_up", "password_reset", "approval"];

    /// <summary>What the page had sent: <c>ok</c>, <c>replayed</c>, or no usable identification.</summary>
    public static readonly IReadOnlyList<string> Reports = ["ok", "replayed", "missing", "unknown", "expired", "invalid"];

    /// <summary>How a visitor was recognised (<c>matchedBy</c> in <c>Visitor</c>, an event and a search row).</summary>
    public static readonly IReadOnlyList<string> MatchedByValues = ["key", "fpc", "sid", "traits", "new"];

    /// <summary>What <see cref="ActivityAsync"/> reports.</summary>
    public static readonly IReadOnlyList<string> ActivityTypes = ["payment_attempt", "login_failed", "not_found", "forbidden", "otp_sent", "code_failed"];

    /// <summary>A payment attempt's outcome: what the payment provider answered.</summary>
    public static readonly IReadOnlyList<string> ActivityOutcomes = ["approved", "declined", "error"];

    /// <summary>The class of a <c>not_found</c> or <c>forbidden</c> path (only the class is counted).</summary>
    public static readonly IReadOnlyList<string> PathClasses = ["admin", "wordpress", "secrets", "source", "db_admin", "debug", "shell", "other"];

    /// <summary>The abuse codes an activity may raise (new codes are added in minor versions).</summary>
    public static readonly IReadOnlyList<string> AbuseSignals =
        ["abuse_card_testing", "abuse_card_shared", "abuse_login_failures", "abuse_probing", "abuse_otp_pumping", "abuse_code_guessing"];

    private readonly TouchqueHttp _http;

    /// <summary>A client from the environment (<c>TQ_API_KEY</c>, <c>TQ_API_SECRET</c>, <c>TQ_API_URL</c>).</summary>
    public DeviceRiskClient() : this(new DeviceRiskOptions()) { }

    /// <param name="options">Anything left null falls back to the environment.</param>
    /// <param name="httpClient">
    /// Your own HttpClient (e.g. from IHttpClientFactory). Configure it NOT to follow
    /// redirects: a redirect could replay the signed headers to another host.
    /// </param>
    public DeviceRiskClient(DeviceRiskOptions options, HttpClient? httpClient = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var resolved = options.Resolve();
        _http = new TouchqueHttp(resolved, httpClient);
        Webhook = new DeviceRiskWebhook(resolved.ApiSecret);
    }

    /// <summary>Device risk webhooks (<c>DEVICE_RISK_SIGNAL</c>, <c>DEVICE_RISK_ALERT</c>): signature verification.</summary>
    public DeviceRiskWebhook Webhook { get; }

    [GeneratedRegex("^dre_[A-Za-z0-9_-]{22}$")]
    private static partial Regex RequestIdPattern();

    [GeneratedRegex("^[0-9]{6,8}$")]
    private static partial Regex BinPattern();

    [GeneratedRegex("^[0-9]{4}$")]
    private static partial Regex Last4Pattern();

    [GeneratedRegex("^[0-9]{12,19}$")]
    private static partial Regex CardNumberPattern();

    [GeneratedRegex(@"^\+?[0-9]{6,15}$")]
    private static partial Regex PhonePattern();

    /// <summary>
    /// Checks the page's identification for an account (the <c>touchque_request_id</c> form field, as it came):
    /// null, empty or made up is still a verdict, never an exception. See
    /// <see cref="CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/>.
    /// </summary>
    public Task<DeviceRiskCheckResult> CheckAsync(string? requestId, DeviceRiskCheckOptions? options = null, CancellationToken ct = default)
        => CheckAsync((options ?? new DeviceRiskCheckOptions()) with { RequestId = requestId }, ct);

    /// <summary>
    /// Checks the page's identification for an account: binds it (one account per identification, 15 minutes) and
    /// asks the risk engine (<c>POST /device-risk/check</c>). Pass the form field as it came: null, empty or made up
    /// is still a verdict (<c>Report</c> missing, unknown), never an exception. 409 <c>device_risk_off</c> until your
    /// workspace turns Device risk on.
    /// </summary>
    public async Task<DeviceRiskCheckResult> CheckAsync(DeviceRiskCheckOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var ev = string.IsNullOrEmpty(options.Event) ? "sign_in" : options.Event;
        if (!Events.Contains(ev))
            throw new TouchqueConfigException($"DeviceRisk.CheckAsync(): Event must be one of {string.Join(", ", Events)}");
        var body = new JsonObject();
        if (!string.IsNullOrEmpty(options.RequestId))
            body["requestId"] = options.RequestId.Length > 64 ? options.RequestId[..64] : options.RequestId;
        else if (!string.IsNullOrEmpty(options.DeviceRisk))
            body["deviceRisk"] = options.DeviceRisk;
        body["event"] = ev;
        body.Put("externalUsername", string.IsNullOrEmpty(options.ExternalUsername) ? null : options.ExternalUsername)
            .Put("clientIp", string.IsNullOrEmpty(options.ClientIp) ? null : options.ClientIp);
        return ParseCheck(await _http.PostAsync("/device-risk/check", body, ct).ConfigureAwait(false));
    }

    /// <summary>
    /// Your workspace's identifications, newest first, one page at a time (<c>GET /device-risk/events</c>): a date
    /// range (<c>From</c>/<c>To</c>: YYYY-MM-DD or ISO times; 7 days by default, at most 90, within your retention)
    /// and any of the filters. <c>Ip</c> is an address or a CIDR range and is never returned. Pass
    /// <c>NextCursor</c> back as <c>Cursor</c> until it is null; do not page by moving the dates. A search that would
    /// read too much is a 422 <c>search_too_broad</c>: narrow the range or add a filter. Each row may carry
    /// <c>suspect</c> (read it with <see cref="ParseSuspect"/>).
    /// </summary>
    public async Task<DeviceRiskSearchResult> SearchEventsAsync(DeviceRiskSearchOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new DeviceRiskSearchOptions();
        if (o.Limit is { } l && (l < 1 || l > 100)) throw new TouchqueConfigException("DeviceRisk.SearchEventsAsync() Limit must be 1 to 100");
        var query = new Dictionary<string, string?>();
        void Put(string k, string? v) { if (!string.IsNullOrEmpty(v)) query[k] = v; }
        Put("from", o.From); Put("to", o.To); Put("signal", o.Signal); Put("kind", o.Kind); Put("origin", o.Origin);
        Put("ip", o.Ip); Put("account", o.Account); Put("visitorId", o.VisitorId); Put("requestId", o.RequestId); Put("cursor", o.Cursor);
        if (o.StepUp is { } up) query["stepUp"] = up ? "true" : "false";
        if (o.Limit is { } n) query["limit"] = n.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var res = await _http.GetAsync("/device-risk/events", query, ct).ConfigureAwait(false) as JsonObject ?? new JsonObject();
        var events = new List<JsonObject>();
        if (res["events"] is JsonArray list) foreach (var e in list) if (e is JsonObject obj) events.Add((JsonObject)obj.DeepClone());
        var next = res["nextCursor"] is JsonValue c && c.TryGetValue<string>(out var cs) && cs.Length > 0 ? cs : null;
        return new DeviceRiskSearchResult
        {
            Events = events,
            NextCursor = next,
            From = res["from"] is JsonValue f && f.TryGetValue<string>(out var fs) ? fs : "",
            To = res["to"] is JsonValue t && t.TryGetValue<string>(out var ts) ? ts : "",
        };
    }

    /// <summary>
    /// The trusted identification behind a requestId (<c>GET /device-risk/events/{requestId}</c>): the visitor
    /// (visitorId, confidence, matchedBy), what the page showed (facts), the risk engine's verdict, and on newer
    /// servers <c>accountDevice</c> and <c>suspect</c> (read them with <see cref="ParseAccountDevice"/> and
    /// <see cref="ParseSuspect"/>). Read-only.
    /// </summary>
    public async Task<JsonObject> GetEventAsync(string requestId, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(requestId) || !RequestIdPattern().IsMatch(requestId))
            throw new TouchqueConfigException("DeviceRisk.GetEventAsync() needs a requestId (dre_…)");
        return await _http.GetAsync($"/device-risk/events/{Uri.EscapeDataString(requestId)}", null, ct).ConfigureAwait(false) as JsonObject ?? new JsonObject();
    }

    /// <summary>
    /// Reports what a visitor did that your server saw (<c>POST /device-risk/activity</c>): a payment attempt, a
    /// failed sign-in, a path that was not found or forbidden, an SMS code sent, a wrong coupon or gift-card code.
    /// Touchque counts it per visitor and per network and answers the abuse codes it raised (shadow: they decide
    /// nothing on their own; act on <c>Signals</c> yourself if you want, e.g. stop taking cards). Name the visitor by
    /// <c>RequestId</c>, <c>VisitorId</c> or <c>ClientIp</c>. Never send a card number: a card is its BIN (6 to 8
    /// digits) and last 4 digits; anything that looks like a card number is refused here, before any request.
    /// </summary>
    public async Task<DeviceRiskActivityResult> ActivityAsync(DeviceRiskActivityOptions options, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (string.IsNullOrEmpty(options.Type) || !ActivityTypes.Contains(options.Type))
            throw new TouchqueConfigException($"DeviceRisk.ActivityAsync(): Type must be one of {string.Join(", ", ActivityTypes)}");
        if (!string.IsNullOrEmpty(options.Outcome) && !ActivityOutcomes.Contains(options.Outcome))
            throw new TouchqueConfigException($"DeviceRisk.ActivityAsync(): Outcome must be one of {string.Join(", ", ActivityOutcomes)}");
        if (string.IsNullOrEmpty(options.RequestId) && string.IsNullOrEmpty(options.VisitorId) && string.IsNullOrEmpty(options.ClientIp))
            throw new TouchqueConfigException("DeviceRisk.ActivityAsync(): name the visitor: RequestId, VisitorId or ClientIp");
        if (options.ExternalUsername is { Length: > 255 })
            throw new TouchqueConfigException("DeviceRisk.ActivityAsync(): ExternalUsername is at most 255 characters");
        if (options.Path is { Length: > 2048 })
            throw new TouchqueConfigException("DeviceRisk.ActivityAsync(): Path is at most 2048 characters");
        if (!string.IsNullOrEmpty(options.Phone) && !PhonePattern().IsMatch(options.Phone))
            throw new TouchqueConfigException("DeviceRisk.ActivityAsync(): Phone must be 6 to 15 digits, with an optional leading +");
        if (options.Card is { } card) CheckCard(card);

        var body = new JsonObject { ["type"] = options.Type };
        if (!string.IsNullOrEmpty(options.RequestId))
            body["requestId"] = options.RequestId.Length > 64 ? options.RequestId[..64] : options.RequestId;
        body.Put("visitorId", options.VisitorId)
            .Put("clientIp", options.ClientIp)
            .Put("externalUsername", options.ExternalUsername)
            .Put("outcome", options.Outcome);
        if (options.Card is { } c) body["card"] = new JsonObject { ["bin"] = c.Bin, ["last4"] = c.Last4 };
        body.Put("phone", options.Phone).Put("path", options.Path);
        return ParseActivity(await _http.PostAsync("/device-risk/activity", body, ct).ConfigureAwait(false));
    }

    /// <summary>A card is its BIN and last 4 digits only: a full card number never leaves your server.</summary>
    private static void CheckCard(DeviceRiskCard card)
    {
        static string Digits(string? s) => new string((s ?? "").Where(ch => ch is not (' ' or '-')).ToArray());
        if (CardNumberPattern().IsMatch(Digits(card.Bin)) || CardNumberPattern().IsMatch(Digits(card.Last4)))
            throw new TouchqueConfigException("DeviceRisk.ActivityAsync(): never send the card number. A card is its BIN (first 6 to 8 digits) and its last 4 digits only.");
        if (card.Bin is null || !BinPattern().IsMatch(card.Bin) || card.Last4 is null || !Last4Pattern().IsMatch(card.Last4))
            throw new TouchqueConfigException("DeviceRisk.ActivityAsync(): Card must be { Bin: 6 to 8 digits, Last4: 4 digits }");
    }

    /// <summary>
    /// Reads a <c>POST /device-risk/check</c> answer, failing toward asking: <c>StepUp</c> is true unless it
    /// says exactly <c>stepUp: false</c>; junk signals are dropped.
    /// </summary>
    public static DeviceRiskCheckResult ParseCheck(JsonNode? raw)
    {
        var body = raw as JsonObject ?? new JsonObject();
        bool IsFalse(string key) => body.TryGetPropertyValue(key, out var v) && v is JsonValue jv && jv.TryGetValue<bool>(out var b) && !b;
        bool IsTrue(string key) => body.TryGetPropertyValue(key, out var v) && v is JsonValue jv && jv.TryGetValue<bool>(out var b) && b;
        var signals = new List<DeviceRiskSignal>();
        if (body["signals"] is JsonArray arr)
        {
            foreach (var s in arr)
            {
                var code = Json.Str(s, "code");
                if (code is null) continue;
                var strength = Json.Str(s, "strength");
                signals.Add(new DeviceRiskSignal
                {
                    Code = code,
                    Text = Json.Str(s, "text") ?? "",
                    Strength = strength is "passkey" or "none" ? strength : "number_match",
                    Enforced = s?["enforced"] is JsonValue ev && ev.TryGetValue<bool>(out var e) && e,
                    Evidence = s?["evidence"] as JsonObject,
                });
            }
        }
        var report = Json.Str(body, "report");
        var requires = Json.Str(body, "requires");
        return new DeviceRiskCheckResult
        {
            Report = report is not null && Reports.Contains(report) ? report : "invalid",
            RequestId = Json.Str(body, "requestId"),
            VisitorId = Json.Str(body, "visitorId"),
            Confidence = body["confidence"] is JsonValue cv && cv.TryGetValue<double>(out var c) ? c : null,
            Visitor = body["visitor"] as JsonObject,
            CaseCode = Json.Str(body, "caseCode"),
            Counts = body["counts"] as JsonObject,
            Network = body["network"] as JsonObject,
            Velocity = body["velocity"] as JsonObject,
            Bot = body["bot"] as JsonObject,
            AccountDevice = ParseAccountDevice(body["accountDevice"]),
            Suspect = ParseSuspect(body["suspect"]),
            Signals = signals,
            StepUp = !IsFalse("stepUp"),
            WouldStepUp = IsTrue("wouldStepUp"),
            Requires = requires is "number_match" or "passkey" ? requires : "none",
            Mode = Json.Str(body, "mode") == "enforce" ? "enforce" : "shadow",
            Engine = Json.Str(body, "engine"),
        };
    }

    /// <summary>
    /// Reads a <c>suspect</c> object (a check, an event or a search row): null when it is missing or not an
    /// object. The score is clamped to 0-100; an unknown band or wouldDo is null; reasons without a code are dropped.
    /// </summary>
    public static DeviceRiskSuspect? ParseSuspect(JsonNode? raw)
    {
        if (raw is not JsonObject o) return null;
        var score = Json.Long(o, "score") ?? 0;
        var band = Json.Str(o, "band");
        var wouldDo = Json.Str(o, "wouldDo");
        var reasons = new List<DeviceRiskSuspectReason>();
        if (o["reasons"] is JsonArray arr)
        {
            foreach (var r in arr)
            {
                var code = Json.Str(r, "code");
                if (code is null) continue;
                var by = Json.Str(r, "by");
                reasons.Add(new DeviceRiskSuspectReason
                {
                    Code = code,
                    Points = (int)Math.Clamp(Json.Long(r, "points") ?? 0, -1000, 1000),
                    By = by is "server" or "site" or "page" or "brand" ? by : null,
                    Text = Json.Str(r, "text") ?? "",
                });
            }
        }
        return new DeviceRiskSuspect
        {
            Score = (int)Math.Clamp(score, 0, 100),
            Band = band is "low" or "medium" or "high" or "critical" ? band : null,
            WouldDo = wouldDo is "allow" or "number_match" or "passkey" or "block" ? wouldDo : null,
            Mode = "shadow",
            Reasons = reasons,
        };
    }

    /// <summary>
    /// Reads an <c>accountDevice</c> object (a check or an event): null before an account is named, or when the
    /// status is not one this SDK knows.
    /// </summary>
    public static DeviceRiskAccountDevice? ParseAccountDevice(JsonNode? raw)
    {
        if (raw is not JsonObject o) return null;
        var status = Json.Str(o, "status");
        if (status is not ("known" or "likely" or "new" or "first")) return null;
        return new DeviceRiskAccountDevice { Status = status, VisitorId = Json.Str(o, "visitorId"), Since = Json.Str(o, "since") };
    }

    /// <summary>Reads a <c>POST /device-risk/activity</c> answer: <c>Recorded</c> only when it says exactly true.</summary>
    public static DeviceRiskActivityResult ParseActivity(JsonNode? raw)
    {
        var body = raw as JsonObject ?? new JsonObject();
        var signals = new List<string>();
        if (body["signals"] is JsonArray arr)
        {
            foreach (var s in arr)
            {
                if (s is JsonValue v && v.TryGetValue<string>(out var code) && code.Length > 0) signals.Add(code);
            }
        }
        return new DeviceRiskActivityResult
        {
            Recorded = body["recorded"] is JsonValue rv && rv.TryGetValue<bool>(out var rec) && rec,
            VisitorId = Json.Str(body, "visitorId"),
            PathClass = Json.Str(body, "pathClass"),
            Signals = signals,
        };
    }
}
