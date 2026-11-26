using System.Text.Json.Nodes;

namespace Touchque.DeviceRisk;

/// <summary>One page's identification, for an account.</summary>
public sealed record DeviceRiskCheckOptions
{
    /// <summary>
    /// The <c>touchque_request_id</c> form field (the script tag) or the browser SDK's identify() requestId, as it
    /// came: null or empty is answered <c>Report</c> missing.
    /// </summary>
    public string? RequestId { get; init; }
    /// <summary>Instead: the page's report (the browser SDK's collect()), relayed untouched.</summary>
    public string? DeviceRisk { get; init; }
    /// <summary><c>sign_in</c> (default), <c>sign_up</c>, <c>password_reset</c> or <c>approval</c>.</summary>
    public string? Event { get; init; }
    /// <summary>The account the page is for, when there is one. One account per identification.</summary>
    public string? ExternalUsername { get; init; }
    /// <summary>The end user's address; default: where the browser identified from.</summary>
    public string? ClientIp { get; init; }
}

/// <summary>A device signal. Each one only ever asks for more; none blocks.</summary>
public sealed record DeviceRiskSignal
{
    /// <summary>
    /// <c>device_tampered</c>, <c>device_virtual</c>, <c>device_geo_mismatch</c>, <c>device_many_accounts</c>,
    /// <c>device_signup_burst</c>, <c>device_id_resets</c>, <c>device_many_countries</c>, <c>device_wrong_site</c>,
    /// <c>device_report_replayed</c>, <c>device_private_window</c> (context only), <c>device_step_up_by_admin</c>,
    /// <c>device_identification_missing</c> (no identification, or one that does not verify),
    /// <c>device_pointer_synthetic</c> (the pointer or a finger moved like software), <c>device_new_storage_burst</c>
    /// and <c>device_network_signup_burst</c> (many new browsers, or sign-ups, in a day on this network from devices
    /// like this one: phones, or identical computers where look-alikes are not joined), <c>device_input_synthetic</c>
    /// (typed or clicked like software) and <c>device_ai_agent</c> (an AI agent or bot by its own signature or user
    /// agent, or an AI agent's marks on the page it drives); these two ask for a number-matched step-up only, never a
    /// block. An activity you reported may add <c>abuse_*</c> codes for 24 hours (see
    /// <see cref="DeviceRiskClient.AbuseSignals"/>). New codes are added in minor versions.
    /// </summary>
    public string Code { get; init; } = "";
    /// <summary>English text.</summary>
    public string Text { get; init; } = "";
    /// <summary><c>number_match</c>, <c>passkey</c> or <c>none</c> (context only).</summary>
    public string Strength { get; init; } = "number_match";
    /// <summary>Scored now; false: reported only (shadow) until Touchque enforces it.</summary>
    public bool Enforced { get; init; }
    /// <summary>Counts and finding names behind it (never a raw trait).</summary>
    public JsonObject? Evidence { get; init; }
}

/// <summary>
/// The suspect score, in shadow: 0-100 with every reason, its points and who proves it. It decides nothing yet;
/// <see cref="WouldDo"/> is what it would ask for: allow (0-29), number_match (30-59), passkey (60+). A sign-up or
/// password reset at 80+ would block only with a reason the server proved; an existing account's sign-in is never
/// blocked.
/// </summary>
public sealed record DeviceRiskSuspect
{
    /// <summary>0 to 100.</summary>
    public int Score { get; init; }
    /// <summary><c>low</c>, <c>medium</c>, <c>high</c> or <c>critical</c>; null when the server sent another value.</summary>
    public string? Band { get; init; }
    /// <summary><c>allow</c>, <c>number_match</c>, <c>passkey</c> or <c>block</c>; null when the server sent another value.</summary>
    public string? WouldDo { get; init; }
    /// <summary>Always <c>shadow</c> for now.</summary>
    public string Mode { get; init; } = "shadow";
    /// <summary>Every reason behind the score.</summary>
    public IReadOnlyList<DeviceRiskSuspectReason> Reasons { get; init; } = [];
}

/// <summary>One reason of a <see cref="DeviceRiskSuspect"/> score.</summary>
public sealed record DeviceRiskSuspectReason
{
    public string Code { get; init; } = "";
    /// <summary>Negative for a known browser or a trusted mark.</summary>
    public int Points { get; init; }
    /// <summary>
    /// Who proves it: <c>server</c> (Touchque saw it), <c>site</c> (your server reported it with an activity),
    /// <c>page</c> (the browser reported it) or <c>brand</c> (your admin's mark); null when unknown.
    /// </summary>
    public string? By { get; init; }
    /// <summary>English text.</summary>
    public string Text { get; init; } = "";
}

/// <summary>
/// Once a check names the account: did this account use the device before? <c>known</c> this visitor served it;
/// <c>likely</c> another of its visitors has the same trait profile on the same network (never trusted on it);
/// <c>new</c> the account has other devices here, not this one; <c>first</c> the account has none here yet.
/// </summary>
public sealed record DeviceRiskAccountDevice
{
    /// <summary><c>known</c>, <c>likely</c>, <c>new</c> or <c>first</c>.</summary>
    public string Status { get; init; } = "first";
    /// <summary><c>likely</c>: the account's visitor it looks like.</summary>
    public string? VisitorId { get; init; }
    /// <summary><c>known</c>: the account's first identification on it (ISO time, in the retention).</summary>
    public string? Since { get; init; }
}

/// <summary>The answer of <see cref="DeviceRiskClient.CheckAsync(DeviceRiskCheckOptions, CancellationToken)"/>.</summary>
public sealed record DeviceRiskCheckResult
{
    /// <summary>
    /// What the page had sent: <c>ok</c>; <c>replayed</c> (another account, or sent twice); or no usable
    /// identification, which raises <c>device_identification_missing</c>: <c>missing</c> (none or empty),
    /// <c>unknown</c> (made up, or another workspace's), <c>expired</c> (over 15 minutes old), <c>invalid</c>.
    /// </summary>
    public string Report { get; init; } = "invalid";
    /// <summary>This identification (<c>dre_…</c>).</summary>
    public string? RequestId { get; init; }
    /// <summary>This browser in your workspace only (<c>tqv_…</c>).</summary>
    public string? VisitorId { get; init; }
    /// <summary>How sure the visitorId is (0 to 1).</summary>
    public double? Confidence { get; init; }
    /// <summary>
    /// firstSeenAt, lastSeenAt, seenCount, matchedBy (<c>key</c>, <c>fpc</c>, <c>sid</c>, <c>traits</c>, <c>new</c>),
    /// sealed, status (your admin's mark), labels and mark: the mark actually applied to this identification,
    /// <c>step_up</c> always, <c>trusted</c> only when the browser matched by its stored key or id (never by
    /// traits), else null (any other value reads as null). Older servers send no mark.
    /// </summary>
    public JsonObject? Visitor { get; init; }
    /// <summary>"Why?": the decision record, opened by this code in the dashboard.</summary>
    public string? CaseCode { get; init; }
    /// <summary>Accounts, sign-ups and countries per device, and stored-id resets.</summary>
    public JsonObject? Counts { get; init; }
    /// <summary>
    /// The address as the risk engine saw it (never coordinates): countryCode, region, city, accuracyKm,
    /// timeZone, asn, asnOrg, type (<c>isp</c>, <c>hosting</c>, <c>tor</c>, <c>relay</c> for Apple's iCloud Private
    /// Relay, <c>unknown</c>), tor, hosting, hostingProvider, proxy (reported as a proxy in the last 30 days: context,
    /// often a home or school line resold to a proxy network; the proxy list includes IP2Proxy LITE data available from
    /// https://lite.ip2location.com), timezoneMismatch, and the kind of network below. Null without an address.
    /// <para>
    /// <c>kind</c>: <c>residential</c>, <c>mobile_carrier</c>, <c>education</c>, <c>business</c>,
    /// <c>public_wifi</c>, <c>hosting</c>, <c>proxy</c>, <c>vpn</c>, <c>tor</c>, <c>relay</c> or <c>unknown</c>
    /// (<see cref="DeviceRiskClient.NetworkKinds"/>). An open list: new values may be added in minor versions, so read
    /// one you do not know as <c>unknown</c>. Null: not classified (identified before the field existed).
    /// <c>kindSource</c>: <c>address</c>, <c>network</c>, <c>mixed</c>, <c>network_open</c> or <c>name</c> (the
    /// operator's name only: shown, never used for a decision); null with no kind. <c>vpn</c>: a VPN company's own
    /// address.
    /// </para>
    /// <para>
    /// <c>shared</c>: many browsers used this address on your pages in the last 24 hours (context only);
    /// <c>sharedVisitors24h</c> and <c>sharedAccounts24h</c>: at least 1, 2, 5, 10, 100 or 1000.
    /// <c>lookAlikeMatching</c>: false when this computer was recognised only by its own key, cookie or stored id,
    /// never because it looks like another one (identical computers in use on the address, or a school, company or
    /// public Wi-Fi network on Touchque's list); true when look-alike matching was allowed; null when not decided (a
    /// phone, a tablet or Safari). These describe the identification's own address: null when it was not counted or
    /// the answer is about another address.
    /// </para>
    /// <para>proxy, kind, kindSource, vpn and the shared fields are absent on older servers.</para>
    /// </summary>
    public JsonObject? Network { get; init; }
    /// <summary>
    /// The visitor's counts: accounts24h, accounts30d, signUps24h, countries24h, idResets7d,
    /// identifications1h, identifications24h. Null without a usable identification.
    /// </summary>
    public JsonObject? Velocity { get; init; }
    /// <summary>
    /// One answer to "a bot?": result (<c>detected</c>, <c>suspected</c>, <c>not_detected</c>); reasons, detected
    /// ones first (<c>webdriver</c>, <c>headless</c>, <c>tool_&lt;name&gt;</c> for each of the tools,
    /// <c>agent_verified</c>), then suspected (<c>pointer_synthetic</c>, <c>input_synthetic</c>, <c>agent_pace</c>,
    /// <c>zero_window</c>, <c>headless_window</c>, <c>emulator</c>, <c>cdp</c> (the DevTools protocol attached),
    /// <c>cdp_input</c> (a press with no pressure, which only that protocol sends), <c>input_no_focus</c> (a click or
    /// key into a page that was not in front), <c>insert_text_bulk</c> (text that arrived whole, no key pressed),
    /// <c>scripted_click</c> (a form sent with no click or key), <c>agent_unverified</c>, <c>agent_claimed</c>), and
    /// <c>soft_gpu</c> next to another sign; <c>type</c> (<c>ai_agent</c>, <c>automation</c>, <c>script</c> or null);
    /// <c>tools</c>: the automation tools (<c>selenium</c>, <c>playwright</c>, <c>puppeteer</c>, <c>phantomjs</c>,
    /// <c>nightmare</c>, <c>headless_chrome</c>) and AI agents (<c>claude_agent</c> for the Claude app's browser or
    /// Claude in Chrome, <c>comet_agent</c> for Perplexity Comet, <c>genspark_agent</c>, <c>browser_use</c>,
    /// <c>stagehand</c>, <c>skyvern</c>) whose marks were on the page; <c>agent</c> (null, or <c>provider</c>,
    /// <c>name</c>, <c>category</c> <c>ai_agent</c> | <c>ai_crawler</c> | <c>search_crawler</c>, <c>identity</c>
    /// <c>verified</c> | <c>unverified</c> | <c>claimed</c>); and <c>input</c> (<c>insert_no_keys</c>,
    /// <c>uniform_keys</c>, <c>instant_keys</c>, <c>center_press</c>, <c>agent_pace</c>). New reasons and tools may be
    /// added in minor versions; older servers send no AI agent tools and none of <c>cdp_input</c>,
    /// <c>input_no_focus</c>, <c>insert_text_bulk</c> or <c>scripted_click</c>. Null without a usable identification.
    /// </summary>
    public JsonObject? Bot { get; init; }
    /// <summary>Whether this account used this device before; null before an account is named (or on older servers).</summary>
    public DeviceRiskAccountDevice? AccountDevice { get; init; }
    /// <summary>The suspect score, in shadow; null on older servers.</summary>
    public DeviceRiskSuspect? Suspect { get; init; }
    /// <summary>The signals raised.</summary>
    public IReadOnlyList<DeviceRiskSignal> Signals { get; init; } = [];
    /// <summary>Ask for more on this page. Never a reason to refuse.</summary>
    public bool StepUp { get; init; } = true;
    /// <summary>A signal that asks was raised, enforced or not.</summary>
    public bool WouldStepUp { get; init; }
    /// <summary><c>none</c>, <c>number_match</c> or <c>passkey</c>.</summary>
    public string Requires { get; init; } = "none";
    /// <summary><c>enforce</c> when at least one raised signal is enforced, else <c>shadow</c>.</summary>
    public string Mode { get; init; } = "shadow";
    /// <summary>The engine's state for this check; <c>unavailable</c> when the risk engine could not be reached and the verdict is a safe default.</summary>
    public string? Engine { get; init; }
}

/// <summary><see cref="DeviceRiskClient.SearchEventsAsync"/>'s filters; each one only when set.</summary>
public sealed record DeviceRiskSearchOptions
{
    public string? From { get; init; }
    public string? To { get; init; }
    public string? Signal { get; init; }
    public bool? StepUp { get; init; }
    public string? Kind { get; init; }
    public string? Origin { get; init; }
    /// <summary>An address or a CIDR range; never returned.</summary>
    public string? Ip { get; init; }
    public string? Account { get; init; }
    public string? VisitorId { get; init; }
    public string? RequestId { get; init; }
    /// <summary>
    /// The kind of network (<c>network.kind</c>, one of <see cref="DeviceRiskClient.NetworkKinds"/>), sent as
    /// <c>networkKind</c>. Only identifications classified since the field exists match: older ones have none. A kind
    /// the server does not know is a 400 <c>invalid_network_kind</c>. An older server ignores it and does not narrow
    /// the search.
    /// </summary>
    public string? NetworkKind { get; init; }
    /// <summary>
    /// True: only identifications whose own address was shared (many browsers on your pages in 24 hours, by the count
    /// kept with each identification); false: only the ones counted and not shared. An identification that was not
    /// counted matches neither. Sent as <c>shared=true</c> or <c>shared=false</c>. An older server ignores it and
    /// does not narrow the search.
    /// </summary>
    public bool? Shared { get; init; }
    /// <summary>The previous page's <c>NextCursor</c>, as it came.</summary>
    public string? Cursor { get; init; }
    /// <summary>1 to 100 (default 25).</summary>
    public int? Limit { get; init; }
}

/// <summary>
/// One page: pass <c>NextCursor</c> back as <c>Cursor</c> until it is null. No event carries an address. A row's
/// <c>matchedBy</c> is <c>key</c>, <c>fpc</c>, <c>sid</c>, <c>traits</c> or <c>new</c>; its <c>network</c> has the
/// fields of <see cref="DeviceRiskCheckResult.Network"/>; its <c>suspect</c> reads with
/// <see cref="DeviceRiskClient.ParseSuspect"/>.
/// </summary>
public sealed record DeviceRiskSearchResult
{
    public IReadOnlyList<JsonObject> Events { get; init; } = new List<JsonObject>();
    public string? NextCursor { get; init; }
    public string From { get; init; } = "";
    public string To { get; init; } = "";
}

/// <summary>A payment card as Touchque may see it: its BIN and last 4 digits, never its number.</summary>
public sealed record DeviceRiskCard
{
    /// <summary>The first 6 to 8 digits.</summary>
    public string Bin { get; init; } = "";
    /// <summary>The last 4 digits.</summary>
    public string Last4 { get; init; } = "";
}

/// <summary>What a visitor did that your server saw (<see cref="DeviceRiskClient.ActivityAsync"/>).</summary>
public sealed record DeviceRiskActivityOptions
{
    /// <summary>
    /// <c>payment_attempt</c>, <c>login_failed</c>, <c>not_found</c>, <c>forbidden</c>, <c>otp_sent</c> or
    /// <c>code_failed</c> (a wrong coupon or gift-card code).
    /// </summary>
    public string Type { get; init; } = "";
    /// <summary>The page's identification (the <c>touchque_request_id</c> field as it came).</summary>
    public string? RequestId { get; init; }
    /// <summary>Or the visitor (<c>tqv_…</c>).</summary>
    public string? VisitorId { get; init; }
    /// <summary>The visitor's address (its network is counted); required when neither id is known.</summary>
    public string? ClientIp { get; init; }
    /// <summary>The account it was for (failed sign-ins on several accounts; a card on several accounts). At most 255 characters.</summary>
    public string? ExternalUsername { get; init; }
    /// <summary><c>payment_attempt</c>: <c>approved</c>, <c>declined</c> or <c>error</c>.</summary>
    public string? Outcome { get; init; }
    /// <summary><c>payment_attempt</c>: the card's BIN and last 4 digits, never its number.</summary>
    public DeviceRiskCard? Card { get; init; }
    /// <summary><c>otp_sent</c>: the number the code went to (6 to 15 digits, an optional leading +).</summary>
    public string? Phone { get; init; }
    /// <summary><c>not_found</c> / <c>forbidden</c>: the path asked for (only its class is counted). At most 2048 characters.</summary>
    public string? Path { get; init; }
}

/// <summary>The answer of <see cref="DeviceRiskClient.ActivityAsync"/>.</summary>
public sealed record DeviceRiskActivityResult
{
    /// <summary>False when Touchque's counters were not reachable (nothing failed).</summary>
    public bool Recorded { get; init; }
    /// <summary>The visitor it was counted for, when the request named one.</summary>
    public string? VisitorId { get; init; }
    /// <summary>
    /// <c>not_found</c> / <c>forbidden</c>: the path's class (<c>admin</c>, <c>wordpress</c>, <c>secrets</c>,
    /// <c>source</c>, <c>db_admin</c>, <c>debug</c>, <c>shell</c>, <c>other</c>).
    /// </summary>
    public string? PathClass { get; init; }
    /// <summary>
    /// The abuse codes raised (<c>abuse_card_testing</c>, <c>abuse_card_shared</c>, <c>abuse_login_failures</c>,
    /// <c>abuse_probing</c>, <c>abuse_otp_pumping</c>, <c>abuse_code_guessing</c>). Shadow: they decide nothing on
    /// their own.
    /// </summary>
    public IReadOnlyList<string> Signals { get; init; } = [];
}

/// <summary>
/// One visitor request as your server received it (<see cref="DeviceRiskClient.BotCheckAsync"/>). It is for bots that
/// never run JavaScript, so the page tag never sees them: an AI assistant fetching a page, a crawler, curl, a script.
/// Touchque never logs or stores the header values, and keeps nothing from a bot check beyond short-lived counters.
/// </summary>
public sealed record BotCheckRequest
{
    /// <summary>
    /// Required: the visitor's IPv4 or IPv6 address, as your server saw it (behind a load balancer, the visitor's, not
    /// the balancer's). An IPv4 address written as IPv6 (<c>::ffff:203.0.113.7</c>, as ASP.NET Core gives it on a
    /// dual-stack socket) is sent as IPv4, and a zone is dropped. Anything else is a
    /// <see cref="TouchqueConfigException"/>, before any request.
    /// </summary>
    public string Ip { get; init; } = "";

    /// <summary>
    /// Required: the visitor request's headers, each name with its value (empty for a request that had none).
    /// <c>Authorization</c>, <c>Cookie</c>, <c>Proxy-Authorization</c>, <c>X-Api-Key</c> and <c>Set-Cookie</c> are
    /// sent with an empty value; their names stay, for the order. What the visitor sent never makes the check throw:
    /// the first 100 headers go, a name is cut to 128 characters and a value to 4096, the body is kept under 32 KB, and
    /// the request tells Touchque it was cut. A null value, an HTTP/2 pseudo-header or a header HTTP does not allow is
    /// left out.
    /// </summary>
    public IEnumerable<KeyValuePair<string, string>>? Headers { get; init; }

    /// <summary>
    /// True when <see cref="Headers"/> are in the order the visitor sent them, repeats included: they go as pairs and
    /// Touchque reads their order too. False (the default) when your platform does not keep that order, and ASP.NET
    /// Core's <c>Request.Headers</c> does not: they go as one value per name (repeats joined with ", "), and Touchque
    /// reads no sign from their order.
    /// </summary>
    public bool HeaderOrderKnown { get; init; }

    /// <summary>The request's method (<c>GET</c>, <c>POST</c>…), when you have it; one that is not 1 to 16 letters is left out.</summary>
    public string? Method { get; init; }

    /// <summary>
    /// The address asked for (or its path), when you have it. Touchque reads its host and path only: the query string,
    /// the fragment and any <c>user:password@</c> are removed here, so they never leave your server. A host Touchque
    /// could not read goes as the path alone; one over 4096 characters is left out.
    /// </summary>
    public string? Url { get; init; }

    /// <summary>
    /// The HTTP version the visitor spoke to your edge, only when your edge (a load balancer, a CDN) tells you:
    /// <c>1.0</c>, <c>1.1</c>, <c>2</c> or <c>3</c> (<c>HTTP/2</c>, <c>2.0</c> and <c>h2</c> read as <c>2</c>); anything
    /// else is left out. Never ASP.NET Core's own <c>Request.Protocol</c>: behind a proxy that is the proxy's
    /// connection, not the visitor's.
    /// </summary>
    public string? HttpVersion { get; init; }

    /// <summary>What your edge (a load balancer or a CDN) saw of the visitor's TLS handshake, when it tells you.</summary>
    public BotCheckTls? Tls { get; init; }
}

/// <summary>The visitor's TLS handshake as your edge saw it. Each part only when you have it.</summary>
public sealed record BotCheckTls
{
    /// <summary>The cipher suites the visitor offered, as your edge writes them (a longer list is cut to 4096 characters).</summary>
    public string? Ciphers { get; init; }

    /// <summary>The JA4 fingerprint of the visitor's TLS hello (one over 128 characters is not a JA4 and is left out).</summary>
    public string? Ja4 { get; init; }
}

/// <summary>
/// The answer of <see cref="DeviceRiskClient.BotCheckAsync"/>. A value this version of the SDK does not know yet (a new
/// category, a new rule) is kept as it came, and <see cref="Raw"/> holds the whole answer, new fields included.
/// </summary>
public sealed record BotCheckResult
{
    /// <summary>Which bot sent the request, if any, and whether that is proven.</summary>
    public BotCheckBot Bot { get; init; } = new();

    /// <summary>The address's network, from Touchque's own data; null when Touchque cannot tell right now.</summary>
    public BotCheckNetwork? Network { get; init; }

    /// <summary>
    /// Advice, in shadow: Touchque never enforces it, and you decide what to do with it. <c>allow</c>: a verified bot,
    /// a declared crawler, assistant or other bot Touchque cannot check, or no bot. <c>block</c>: a spoofed name
    /// (<see cref="BotCheckBot.Identity"/> <c>unverified</c>, or a signature that failed). <c>challenge</c>: an AI agent
    /// that only names itself (it acts for a person: ask that person), automation that does not say what it is (an
    /// HTTP client, a headless browser, a browser whose claims contradict each other) or a suspected bot. <c>allow</c>
    /// when the answer had none: "cannot tell" never blocks.
    /// </summary>
    public string Suggestion { get; init; } = "allow";

    /// <summary>The version of Touchque's rules that answered (e.g. <c>2026.11.25-1</c>).</summary>
    public string? RulesVersion { get; init; }

    /// <summary>The whole answer as it came, with any field this version does not know yet (e.g. <c>Raw["bot"]?["…"]</c>).</summary>
    public JsonObject Raw { get; init; } = new();
}

/// <summary>Which bot sent the request, if any, and how Touchque knows.</summary>
public sealed record BotCheckBot
{
    /// <summary>
    /// <c>detected</c> (a bot, by its name, its signature or its software), <c>suspected</c> (signs of one, not proof)
    /// or <c>not_detected</c> (also when the answer had none).
    /// </summary>
    public string Result { get; init; } = "not_detected";

    /// <summary>
    /// What kind of bot: <c>ai_agent</c> (an AI acting for a person), <c>ai_assistant</c> (a page fetched because a
    /// person asked an AI about it), <c>ai_crawler</c> (pages collected for AI training), <c>ai_search</c> (pages
    /// indexed for an AI search), <c>search_crawler</c>, <c>link_preview</c>, <c>seo</c>, <c>monitoring</c>,
    /// <c>archiver</c>, <c>feed_reader</c>, <c>security_scanner</c>, <c>http_client</c> (curl, a script's HTTP library),
    /// <c>headless_browser</c> or <c>automation</c>; or null. New categories come in minor versions and are kept as
    /// they came (<see cref="DeviceRiskClient.BotCategories"/> lists today's).
    /// </summary>
    public string? Category { get; init; }

    /// <summary>Who runs it (e.g. <c>OpenAI</c>), or null.</summary>
    public string? Provider { get; init; }

    /// <summary>Its name (e.g. <c>ChatGPT-User</c>), or null.</summary>
    public string? Name { get; init; }

    /// <summary>
    /// Whether that name is proven. <c>verified</c>: its operator's signature, published addresses or reverse DNS
    /// proved it. <c>unverified</c>: a spoofed name; it claims a name whose operator publishes a way to check, and
    /// that check failed. <c>claimed</c>: a name its operator gives no way to check, or one Touchque cannot check right
    /// now. Null when no name was claimed.
    /// </summary>
    public string? Identity { get; init; }

    /// <summary>What proved the name: <c>signature</c>, <c>ip_list</c>, <c>reverse_dns</c> or <c>asn</c>; null when nothing did.</summary>
    public string? VerifiedBy { get; init; }

    /// <summary>How sure the answer is: <c>high</c>, <c>medium</c> or <c>low</c>; or null.</summary>
    public string? Confidence { get; init; }

    /// <summary>The rule that decided, a stable id (e.g. <c>directory.chatgpt_user</c>, <c>http_client.curl</c>); or null.</summary>
    public string? Rule { get; init; }

    /// <summary>Every sign Touchque saw, each with an English sentence your fraud team can read.</summary>
    public IReadOnlyList<BotCheckReason> Reasons { get; init; } = [];
}

/// <summary>One sign behind a <see cref="BotCheckBot"/> answer.</summary>
public sealed record BotCheckReason
{
    /// <summary>A stable code.</summary>
    public string Code { get; init; } = "";

    /// <summary>English text.</summary>
    public string Text { get; init; } = "";
}

/// <summary>The visitor address's network, from Touchque's own data (never a location finer than the country).</summary>
public sealed record BotCheckNetwork
{
    /// <summary>The network's number (ASN, e.g. 15169), or null.</summary>
    public long? Asn { get; init; }

    /// <summary>Who runs the network, or null.</summary>
    public string? AsnOrg { get; init; }

    /// <summary>The country, two letters (e.g. <c>US</c>), or null.</summary>
    public string? CountryCode { get; init; }

    /// <summary>True for a hosting or cloud network, false for another kind; null when Touchque cannot tell.</summary>
    public bool? Hosting { get; init; }
}
