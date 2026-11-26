using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
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

    /// <summary>
    /// The kinds of network today (<c>network.kind</c>, and <see cref="DeviceRiskSearchOptions.NetworkKind"/>). An open
    /// list: new kinds may be added in minor versions, and an answer keeps them as they came.
    /// </summary>
    public static readonly IReadOnlyList<string> NetworkKinds =
        ["residential", "mobile_carrier", "education", "business", "public_wifi", "hosting", "proxy", "vpn", "tor", "relay", "unknown"];

    /// <summary>What <see cref="ActivityAsync"/> reports.</summary>
    public static readonly IReadOnlyList<string> ActivityTypes = ["payment_attempt", "login_failed", "not_found", "forbidden", "otp_sent", "code_failed"];

    /// <summary>A payment attempt's outcome: what the payment provider answered.</summary>
    public static readonly IReadOnlyList<string> ActivityOutcomes = ["approved", "declined", "error"];

    /// <summary>The class of a <c>not_found</c> or <c>forbidden</c> path (only the class is counted).</summary>
    public static readonly IReadOnlyList<string> PathClasses = ["admin", "wordpress", "secrets", "source", "db_admin", "debug", "shell", "other"];

    /// <summary>The abuse codes an activity may raise (new codes are added in minor versions).</summary>
    public static readonly IReadOnlyList<string> AbuseSignals =
        ["abuse_card_testing", "abuse_card_shared", "abuse_login_failures", "abuse_probing", "abuse_otp_pumping", "abuse_code_guessing"];

    /// <summary>A bot check's <c>Result</c> (a newer server may add values; an answer keeps them as they came).</summary>
    public static readonly IReadOnlyList<string> BotResults = ["detected", "suspected", "not_detected"];

    /// <summary>A bot check's <c>Category</c> today (new ones come in minor versions; an answer keeps them as they came).</summary>
    public static readonly IReadOnlyList<string> BotCategories =
    [
        "ai_agent", "ai_assistant", "ai_crawler", "ai_search", "search_crawler", "link_preview", "seo", "monitoring",
        "archiver", "feed_reader", "security_scanner", "http_client", "headless_browser", "automation",
    ];

    /// <summary>A bot check's <c>Identity</c>: <c>verified</c>, <c>unverified</c> (a spoofed name) or <c>claimed</c>.</summary>
    public static readonly IReadOnlyList<string> BotIdentities = ["verified", "unverified", "claimed"];

    /// <summary>A bot check's <c>VerifiedBy</c>: what proved a verified name.</summary>
    public static readonly IReadOnlyList<string> BotVerifiedBy = ["signature", "ip_list", "reverse_dns", "asn"];

    /// <summary>A bot check's <c>Confidence</c>.</summary>
    public static readonly IReadOnlyList<string> BotConfidences = ["high", "medium", "low"];

    /// <summary>A bot check's <c>Suggestion</c>: advice in shadow, never enforced by Touchque.</summary>
    public static readonly IReadOnlyList<string> BotSuggestions = ["allow", "block", "challenge"];

    /// <summary>The headers a bot check sends with an empty value (compared ignoring case); their names stay, for the order.</summary>
    public static readonly IReadOnlyList<string> BotBlankedHeaders = ["authorization", "cookie", "proxy-authorization", "x-api-key", "set-cookie"];

    /// <summary>A bot check's <c>HttpVersion</c>, as sent.</summary>
    public static readonly IReadOnlyList<string> BotHttpVersions = ["1.0", "1.1", "2", "3"];

    // The bot check's limits, the server's own: kept here so what a visitor sent never gets the check refused.
    private const int BotMaxHeaders = 100;
    private const int BotMaxNameLength = 128;
    private const int BotMaxValueLength = 4096;
    // 32 KB, kept a little under 32 KiB so either reading of the API's limit holds.
    private const int BotMaxBodyBytes = 32_000;
    // A longer URL is left out, never cut: a signature may cover its path.
    private const int BotMaxUrlLength = 4096;
    private const int BotMaxJa4Length = 128;

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

    // The bot check's: \z, never $ (which also takes a final line break).
    [GeneratedRegex(@"^[A-Za-z]{1,16}\z")]
    private static partial Regex BotMethodPattern();

    [GeneratedRegex(@"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z")]
    private static partial Regex BotTokenPattern();

    [GeneratedRegex(@"^([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\.?)(?::([0-9]{0,5}))?\z")]
    private static partial Regex BotAuthorityPattern();

    [GeneratedRegex(@"^(?:[0-9]+|0[xX][0-9A-Fa-f]*)\z")]
    private static partial Regex BotNumericPattern();

    [GeneratedRegex(@"^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\z")]
    private static partial Regex BotDottedQuadPattern();

    [GeneratedRegex(@"^::[fF]{4}:((?:[0-9]{1,3}\.){3}[0-9]{1,3})\z")]
    private static partial Regex BotMappedPattern();

    [GeneratedRegex(@"^[0-9A-Fa-f:.]+\z")]
    private static partial Regex BotIPv6CharsPattern();

    [GeneratedRegex(@"^(https?|wss?)://([^/]*)(/.*)?\z", RegexOptions.IgnoreCase | RegexOptions.Singleline)]
    private static partial Regex BotUrlPattern();

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
    /// read too much is a 422 <c>search_too_broad</c>: narrow the range or add a filter. <c>NetworkKind</c> matches
    /// only identifications classified since the field exists, and <c>Shared</c> only ones that were counted. Each row
    /// may carry <c>suspect</c> (read it with <see cref="ParseSuspect"/>).
    /// </summary>
    public async Task<DeviceRiskSearchResult> SearchEventsAsync(DeviceRiskSearchOptions? options = null, CancellationToken ct = default)
    {
        var o = options ?? new DeviceRiskSearchOptions();
        if (o.Limit is { } l && (l < 1 || l > 100)) throw new TouchqueConfigException("DeviceRisk.SearchEventsAsync() Limit must be 1 to 100");
        var query = new Dictionary<string, string?>();
        void Put(string k, string? v) { if (!string.IsNullOrEmpty(v)) query[k] = v; }
        Put("from", o.From); Put("to", o.To); Put("signal", o.Signal); Put("kind", o.Kind); Put("origin", o.Origin);
        Put("ip", o.Ip); Put("account", o.Account); Put("visitorId", o.VisitorId); Put("requestId", o.RequestId); Put("cursor", o.Cursor);
        // An open list: a kind newer than this SDK goes as it is, and the server answers one it does not know.
        Put("networkKind", o.NetworkKind);
        if (o.StepUp is { } up) query["stepUp"] = up ? "true" : "false";
        if (o.Shared is { } shared) query["shared"] = shared ? "true" : "false";
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
    /// (visitorId, confidence, matchedBy, mark: the mark actually applied, see <see cref="DeviceRiskCheckResult.Visitor"/>),
    /// what the page showed (facts), the risk engine's verdict, its <c>network</c> (the fields of
    /// <see cref="DeviceRiskCheckResult.Network"/>), and on newer
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
    /// Checks one visitor request for bots from its address and headers alone (<c>POST /device-risk/bot-check</c>). It
    /// is for bots that never run JavaScript, so never reach the page tag: an AI assistant fetching a page
    /// (ChatGPT-User), crawlers (GPTBot, Meta's, Grok's), curl and scripts. The answer says which bot it is, whether
    /// that is proven (<c>Identity</c> <c>unverified</c> is a spoofed name) and a <c>Suggestion</c> that is advice only,
    /// in shadow. Touchque decides on its own servers with its own data; when it cannot check, the answer says so and
    /// never suggests a block. Here, before any request: the sensitive header values are blanked and the query string
    /// is removed from <c>Url</c>. What the visitor sent never makes it throw: the first 100 headers go, a name is cut
    /// to 128 characters and a value to 4096, the body is kept under 32 KB, and <c>truncated</c> tells Touchque so. Only
    /// no <c>Ip</c> (or one that is not an address), null <c>Headers</c> or a header without a name is a
    /// <see cref="TouchqueConfigException"/>.
    /// </summary>
    public async Task<BotCheckResult> BotCheckAsync(BotCheckRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var ip = BotIp(request.Ip);
        if (request.Headers is null)
            throw new TouchqueConfigException("DeviceRisk.BotCheckAsync(): Headers is required (the visitor request's headers; empty for a request that had none)");
        var (headers, truncated) = BotHeaders(request.Headers, request.HeaderOrderKnown);
        var method = request.Method?.Trim() is { } m && BotMethodPattern().IsMatch(m) ? m : null;
        var ciphers = request.Tls?.Ciphers?.Trim() is { Length: > 0 } c ? BotCut(c, BotMaxValueLength) : null;
        var ja4 = request.Tls?.Ja4?.Trim() is { Length: > 0 and <= BotMaxJa4Length } j ? j : null;
        var body = BotFit(new BotParts(ip, headers, request.HeaderOrderKnown, method, BotUrl(request.Url), BotHttpVersion(request.HttpVersion), ciphers, ja4, truncated));
        return ParseBotCheck(await _http.PostAsync("/device-risk/bot-check", body, ct).ConfigureAwait(false));
    }

    /// <summary>What a bot check sends, before it is fitted to 32 KB.</summary>
    private sealed record BotParts(string Ip, List<(string Name, string Value)> Headers, bool Ordered, string? Method, string? Url,
        string? HttpVersion, string? Ciphers, string? Ja4, bool Truncated);

    /// <summary>
    /// The visitor's address: one IPv4 or IPv6 address, read here (never a lookup). A zone is dropped, and an IPv4
    /// address written as IPv6 (<c>::ffff:a.b.c.d</c>) goes as IPv4, so it matches published lists.
    /// </summary>
    private static string BotIp(string? ip)
    {
        var s = ip?.Trim() ?? "";
        var zone = s.IndexOf('%');
        if (zone >= 0) s = s[..zone];
        var mapped = BotMappedPattern().Match(s);
        if (mapped.Success && BotDottedQuadPattern().IsMatch(mapped.Groups[1].Value)) s = mapped.Groups[1].Value;
        var ok = BotDottedQuadPattern().IsMatch(s)
            || (s.Contains(':') && BotIPv6CharsPattern().IsMatch(s) && IPAddress.TryParse(s, out var address) && address.AddressFamily == AddressFamily.InterNetworkV6);
        if (!ok)
            throw new TouchqueConfigException("DeviceRisk.BotCheckAsync(): Ip is required: one IPv4 or IPv6 address (the visitor's, as your server saw it)");
        return s;
    }

    /// <summary>
    /// The headers as they go, and whether any was left out or cut. An HTTP/2 pseudo-header (Method and Url carry it,
    /// and <c>:path</c> has the query) or a null value is no header; neither is one HTTP does not allow (a name that is
    /// not a token, a line break or NUL in the value), on which the API would refuse the whole check. When the order is
    /// not known, one value per name (repeats joined with ", "), so Touchque reads no sign from an order the platform
    /// made up. The first 100 stay; names are cut to 128 characters and values to 4096; the secrets go blank.
    /// </summary>
    private static (List<(string Name, string Value)> Headers, bool Truncated) BotHeaders(IEnumerable<KeyValuePair<string, string>> headers, bool orderKnown)
    {
        var sent = new List<(string Name, string Value)>();
        var byName = orderKnown ? null : new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var truncated = false;
        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrEmpty(name))
                throw new TouchqueConfigException("DeviceRisk.BotCheckAsync(): a header has no name");
            if (name.StartsWith(':') || value is null) continue;
            if (!BotTokenPattern().IsMatch(name) || value.AsSpan().IndexOfAny('\r', '\n', '\0') >= 0)
            {
                truncated = true;
                continue;
            }
            if (byName is not null && byName.TryGetValue(name, out var at))
            {
                sent[at] = (sent[at].Name, sent[at].Value + ", " + value);
                continue;
            }
            byName?.Add(name, sent.Count);
            sent.Add((name, value));
        }
        if (sent.Count > BotMaxHeaders)
        {
            sent.RemoveRange(BotMaxHeaders, sent.Count - BotMaxHeaders); // more is not a browser: the rest is left out, never an error
            truncated = true;
        }
        for (var i = 0; i < sent.Count; i++)
        {
            var (name, value) = sent[i];
            // Credentials and sessions never leave your server; the name stays, for the order.
            var blank = BotBlankedHeaders.Contains(name, StringComparer.OrdinalIgnoreCase);
            var v = blank ? "" : BotCut(value, BotMaxValueLength);
            truncated |= name.Length > BotMaxNameLength || (!blank && v.Length < value.Length);
            sent[i] = (BotCut(name, BotMaxNameLength), v);
        }
        return (sent, truncated);
    }

    /// <summary>
    /// The body within 32 KB: the longest values are cut to one length, the longest that fits. Names always fit (100 of
    /// 128 characters); only a url or cipher list made long by escaping can crowd them out, so tls goes first, then the
    /// url, and the last headers only after that.
    /// </summary>
    private static JsonObject BotFit(BotParts p)
    {
        static int Size(JsonObject b) => Encoding.UTF8.GetByteCount(Json.Serialize(b));
        var whole = BotBody(p, p.Headers.Count, BotMaxValueLength, 0);
        if (Size(whole) <= BotMaxBodyBytes) return whole;
        var drop = 0; // 1: without tls, 2: without tls and the url
        while (drop < 2 && Size(BotBody(p, p.Headers.Count, 0, drop)) > BotMaxBodyBytes) drop++;
        int low = 0, high = BotMaxValueLength - 1;
        while (low < high)
        {
            var mid = (low + high + 1) / 2;
            if (Size(BotBody(p, p.Headers.Count, mid, drop)) <= BotMaxBodyBytes) low = mid;
            else high = mid - 1;
        }
        var count = p.Headers.Count;
        var body = BotBody(p, count, low, drop);
        while (count > 0 && Size(body) > BotMaxBodyBytes) body = BotBody(p, --count, 0, drop);
        return body;
    }

    /// <summary>The body with the first <paramref name="count"/> headers, values cut to <paramref name="limit"/>.</summary>
    private static JsonObject BotBody(BotParts p, int count, int limit, int drop)
    {
        var cut = p.Truncated || count < p.Headers.Count;
        var kept = new List<(string Name, string Value)>(count);
        foreach (var (name, value) in p.Headers.Take(count))
        {
            var v = BotCut(value, limit);
            cut |= v.Length < value.Length;
            kept.Add((name, v));
        }
        JsonNode headers;
        if (p.Ordered)
        {
            headers = new JsonArray(kept.Select(h => (JsonNode?)new JsonArray(h.Name, h.Value)).ToArray());
        }
        else
        {
            var set = new JsonObject();
            foreach (var (name, value) in kept) set[name] = value; // a name cut to 128 characters may meet another: the last wins
            headers = set;
        }
        var body = new JsonObject { ["ip"] = p.Ip, ["headers"] = headers };
        body.Put("method", p.Method).Put("url", drop < 2 ? p.Url : null).Put("httpVersion", p.HttpVersion);
        if (drop < 1)
        {
            var tls = new JsonObject().Put("ciphers", p.Ciphers).Put("ja4", p.Ja4);
            if (tls.Count > 0) body["tls"] = tls;
        }
        if (cut) body["truncated"] = true;
        return body;
    }

    /// <summary>At most <paramref name="max"/> characters (UTF-16 units, as the server counts them), never between the two halves of a surrogate pair.</summary>
    private static string BotCut(string value, int max)
    {
        if (value.Length <= max) return value;
        if (max == 0) return "";
        return value[..(char.IsHighSurrogate(value[max - 1]) ? max - 1 : max)];
    }

    /// <summary>
    /// The address without its query string, fragment or <c>user:password@</c>: Touchque reads the host and path only.
    /// A path, or an http(s) URL (ws and wss read as http and https); a host Touchque could not read goes as the path
    /// alone; anything else, or one over 4096 characters, is null.
    /// </summary>
    internal static string? BotUrl(string? url)
    {
        if (string.IsNullOrWhiteSpace(url)) return null;
        var s = url.Trim();
        var end = s.IndexOfAny(['?', '#']);
        var head = end >= 0 ? s[..end] : s;
        string result;
        if (head.StartsWith('/'))
        {
            result = head;
        }
        else
        {
            var m = BotUrlPattern().Match(head);
            if (!m.Success) return null;
            var scheme = m.Groups[1].Value.ToLowerInvariant() switch { "ws" => "http", "wss" => "https", var other => other };
            var authority = m.Groups[2].Value[(m.Groups[2].Value.LastIndexOf('@') + 1)..];
            var path = m.Groups[3].Value;
            result = BotPlainHost(authority) ? $"{scheme}://{authority}{path}" : path.Length > 0 ? path : "/";
        }
        return result.Length <= BotMaxUrlLength ? result : null;
    }

    /// <summary>
    /// A host Touchque reads as it is: letters, digits, dots, hyphens and underscores, an IPv4 address, a port up to
    /// 65535. Anything else (the Host header is the visitor's) goes as the path alone, so an odd Host never makes the API
    /// refuse the check.
    /// </summary>
    private static bool BotPlainHost(string authority)
    {
        var m = BotAuthorityPattern().Match(authority);
        if (!m.Success) return false;
        var port = m.Groups[2].Value;
        if (port.Length > 0 && int.Parse(port, CultureInfo.InvariantCulture) > 65535) return false;
        var host = m.Groups[1].Value.TrimEnd('.');
        var labels = host.Split('.');
        if (labels.Any(l => l.StartsWith("xn--", StringComparison.OrdinalIgnoreCase))) return false;
        // A name that ends in a number is read as an IPv4 address: it must be one.
        return !BotNumericPattern().IsMatch(labels[^1]) || BotDottedQuadPattern().IsMatch(host);
    }

    /// <summary><c>1.0</c>, <c>1.1</c>, <c>2</c> or <c>3</c>, from the forms platforms write (<c>HTTP/2</c>, <c>2.0</c>, <c>h2</c>); null (left out) for anything else.</summary>
    private static string? BotHttpVersion(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return null;
        var v = version.Trim();
        if (v.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) v = v[5..];
        return v.ToLowerInvariant() switch
        {
            "1.0" => "1.0",
            "1.1" => "1.1",
            "2" or "2.0" or "h2" or "h2c" => "2",
            "3" or "3.0" or "h3" => "3",
            _ => null,
        };
    }

    /// <summary>The visitor as it came; a <c>mark</c> other than trusted or step_up reads as null (no mark applied).</summary>
    private static JsonObject? VisitorOf(JsonObject? visitor)
    {
        if (visitor is null || !visitor.TryGetPropertyValue("mark", out var mark) || mark is null) return visitor;
        if (mark is JsonValue mv && mv.TryGetValue<string>(out var m) && m is "trusted" or "step_up") return visitor;
        var copy = (JsonObject)visitor.DeepClone();
        copy["mark"] = null;
        return copy;
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
            Visitor = VisitorOf(body["visitor"] as JsonObject),
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

    /// <summary>
    /// Reads a <c>POST /device-risk/bot-check</c> answer without failing: a value this version does not know (a new
    /// category, suggestion or rule) is kept as it came, and <c>Raw</c> holds the whole answer, new fields included.
    /// What it cannot read is "cannot tell": a missing <c>result</c> reads as <c>not_detected</c> and a missing
    /// <c>suggestion</c> as <c>allow</c>, never a block. A reason without a code is dropped, and a field of the wrong
    /// type reads as null.
    /// </summary>
    public static BotCheckResult ParseBotCheck(JsonNode? raw)
    {
        var body = raw as JsonObject ?? new JsonObject();
        static string? Text(JsonNode? node, string key) => Json.Str(node, key) is { Length: > 0 } s ? s : null;
        var bot = body["bot"] as JsonObject;
        var reasons = new List<BotCheckReason>();
        if (bot?["reasons"] is JsonArray arr)
        {
            foreach (var r in arr)
            {
                var code = Text(r, "code");
                if (code is null) continue;
                reasons.Add(new BotCheckReason { Code = code, Text = Json.Str(r, "text") ?? "" });
            }
        }
        var network = body["network"] as JsonObject;
        return new BotCheckResult
        {
            Bot = new BotCheckBot
            {
                Result = Text(bot, "result") ?? "not_detected",
                Category = Text(bot, "category"),
                Provider = Text(bot, "provider"),
                Name = Text(bot, "name"),
                Identity = Text(bot, "identity"),
                VerifiedBy = Text(bot, "verifiedBy"),
                Confidence = Text(bot, "confidence"),
                Rule = Text(bot, "rule"),
                Reasons = reasons,
            },
            Network = network is null ? null : new BotCheckNetwork
            {
                Asn = Json.Long(network, "asn"),
                AsnOrg = Text(network, "asnOrg"),
                CountryCode = Text(network, "countryCode"),
                Hosting = network["hosting"] is JsonValue hv && hv.TryGetValue<bool>(out var hosting) ? hosting : null,
            },
            Suggestion = Text(body, "suggestion") ?? "allow",
            RulesVersion = Text(body, "rulesVersion"),
            Raw = body,
        };
    }
}
