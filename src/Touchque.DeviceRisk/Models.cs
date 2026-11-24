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
    /// and <c>device_network_signup_burst</c> (many new browsers, or sign-ups, in a day from phones like this one on
    /// this network), <c>device_input_synthetic</c> (typed or clicked like software) and <c>device_ai_agent</c> (an AI
    /// agent or bot by its own signature or user agent); these two ask for a number-matched step-up only, never a
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
    /// sealed, status (your admin's mark), labels.
    /// </summary>
    public JsonObject? Visitor { get; init; }
    /// <summary>"Why?": the decision record, opened by this code in the dashboard.</summary>
    public string? CaseCode { get; init; }
    /// <summary>Accounts, sign-ups and countries per device, and stored-id resets.</summary>
    public JsonObject? Counts { get; init; }
    /// <summary>
    /// The address as the risk engine saw it (never coordinates): countryCode, region, city, accuracyKm,
    /// timeZone, asn, asnOrg, type (<c>isp</c>, <c>hosting</c>, <c>tor</c>, <c>unknown</c>), tor, hosting,
    /// hostingProvider, timezoneMismatch. Null without an address.
    /// </summary>
    public JsonObject? Network { get; init; }
    /// <summary>
    /// The visitor's counts: accounts24h, accounts30d, signUps24h, countries24h, idResets7d,
    /// identifications1h, identifications24h. Null without a usable identification.
    /// </summary>
    public JsonObject? Velocity { get; init; }
    /// <summary>
    /// One answer to "a bot?": result (<c>detected</c>, <c>suspected</c>, <c>not_detected</c>) and reasons (detected
    /// ones first, then suspected: <c>webdriver</c>, <c>headless</c>, <c>pointer_synthetic</c>, <c>zero_window</c>,
    /// <c>soft_gpu</c>, <c>tool_&lt;name&gt;</c>, <c>agent_verified</c>, <c>input_synthetic</c>, <c>agent_pace</c>,
    /// <c>cdp</c>, <c>agent_unverified</c>, <c>agent_claimed</c>), <c>type</c> (<c>ai_agent</c>, <c>automation</c>,
    /// <c>script</c> or null), <c>tools</c> (<c>selenium</c>, <c>playwright</c>, <c>puppeteer</c>, <c>phantomjs</c>,
    /// <c>nightmare</c>, <c>headless_chrome</c>), <c>agent</c> (null, or <c>provider</c>, <c>name</c>, <c>category</c>
    /// <c>ai_agent</c> | <c>ai_crawler</c> | <c>search_crawler</c>, <c>identity</c> <c>verified</c> |
    /// <c>unverified</c> | <c>claimed</c>) and <c>input</c> (<c>insert_no_keys</c>, <c>uniform_keys</c>,
    /// <c>instant_keys</c>, <c>center_press</c>, <c>agent_pace</c>). Null without a usable identification.
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
    /// <summary>The previous page's <c>NextCursor</c>, as it came.</summary>
    public string? Cursor { get; init; }
    /// <summary>1 to 100 (default 25).</summary>
    public int? Limit { get; init; }
}

/// <summary>
/// One page: pass <c>NextCursor</c> back as <c>Cursor</c> until it is null. No event carries an address. A row's
/// <c>matchedBy</c> is <c>key</c>, <c>fpc</c>, <c>sid</c>, <c>traits</c> or <c>new</c>; its <c>suspect</c> reads with
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
