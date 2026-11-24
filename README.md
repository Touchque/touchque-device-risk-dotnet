# Touchque Device Risk for .NET

The official .NET server SDK for **Touchque Device Risk**: a visitor ID for every browser on your sign-up,
password-reset, sign-in or approval page, the risk engine's verdict for an account, and the abuse your own
server sees (card testing, failed sign-ins, probing, SMS pumping, code guessing).

- NuGet: `Touchque.DeviceRisk`, namespace `Touchque.DeviceRisk`
- .NET 8+
- Device risk is a paid add-on, off until your workspace turns it on (409 `device_risk_off` until then).

The browser half is the Device Risk browser SDK (npm `@touchque/device-risk`, or its script tag `device.js`):
it identifies the browser and gives your form a `touchque_request_id` field. This package is the server half.
It does not need the main `Touchque` package. If you also use Touchque sign-in approvals, pass the same
requestId as `DeviceRiskRequestId` to the main SDK's `Login.RequestAsync` / `Risk.CheckAsync`.

## Install

```sh
dotnet add package Touchque.DeviceRisk
```

## Set up

```csharp
using Touchque.DeviceRisk;

// TQ_API_KEY=tq_…  TQ_API_SECRET=…  (TQ_API_URL defaults to https://api.touchque.com)
var dr = new DeviceRiskClient();
// or: new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_…", ApiSecret = "…", Timeout = TimeSpan.FromSeconds(5) });
```

Every call is signed with your API secret (HMAC-SHA256, the same scheme as every Touchque SDK), so the client
belongs on your server. It is thread-safe: create one and reuse it. Redirects are never followed; plain
`http://` is accepted only for localhost.

## Check a page's identification for an account

```csharp
var r = await dr.CheckAsync(Request.Form["touchque_request_id"], new() { Event = "sign_up", ExternalUsername = email });
if (r.StepUp)
{
    // Ask for more on this page: an emailed code, a passkey, a number-matched approval. Never refuse on it.
}
```

Pass the field as it came. Missing, empty, made up or expired, it is still a verdict (`Report` missing,
unknown, expired; the signal `device_identification_missing`), never an exception: a page without the tag, or
with it blocked, only gets the visitor a step-up.

`DeviceRiskCheckResult`: `Report`, `RequestId`, `VisitorId` (`tqv_…`), `Confidence`, `Visitor` (with
`matchedBy`: `key`, `fpc`, `sid`, `traits`, `new`), `Counts`, `Network`, `Velocity`, `Bot`, `Signals`,
`StepUp`, `WouldStepUp`, `Requires`, `Mode`, `CaseCode`, `Engine`, and:

- `AccountDevice`: did this account use this device before? `Status` `known`, `likely`, `new` or `first`
  (null before an account is named).
- `Suspect`: the suspect score, in shadow: `Score` 0-100, `Band` (`low`, `medium`, `high`, `critical`),
  `WouldDo` (`allow`, `number_match`, `passkey`, `block`) and every reason with its points and who proves it
  (`server`, `site`, `page`, `brand`). It decides nothing yet.

## Read and search identifications

```csharp
JsonObject ev = await dr.GetEventAsync(requestId);          // the trusted identification behind a requestId
var suspect = DeviceRiskClient.ParseSuspect(ev["suspect"]);  // typed, when the server sends it

string? cursor = null;
do
{
    var page = await dr.SearchEventsAsync(new() { Account = "ada@example.com", StepUp = true, Limit = 50, Cursor = cursor });
    foreach (var row in page.Events) Console.WriteLine(row["requestId"]);
    cursor = page.NextCursor;
} while (cursor != null);
```

`From`/`To` take YYYY-MM-DD or ISO times (7 days by default, at most 90). `Ip` is an address or a CIDR range
and is never returned. A search that would read too much is a 422 `search_too_broad`.

## Report what a visitor did

```csharp
var a = await dr.ActivityAsync(new DeviceRiskActivityOptions
{
    Type = "payment_attempt",                 // login_failed, not_found, forbidden, otp_sent, code_failed
    RequestId = Request.Form["touchque_request_id"],
    Outcome = "declined",                     // approved, declined, error
    Card = new DeviceRiskCard { Bin = "411111", Last4 = "1111" },
});
if (a.Signals.Contains("abuse_card_testing")) { /* e.g. stop taking cards from this visitor */ }
```

Name the visitor by `RequestId`, `VisitorId` or `ClientIp` (a bot that never runs your page still counts on its
network). For 24 hours the visitor's next checks carry the abuse codes and the suspect score weighs them.
**Never send a card number**: a card is its BIN (6 to 8 digits) and last 4 digits only. Anything that looks like
a card number is refused with `TouchqueConfigException` before a request is made. `Phone` (for `otp_sent`) and
`Path` (for `not_found` / `forbidden`; only its class is counted) are optional.

## Webhooks

```csharp
var payload = await dr.Webhook.VerifyAsync(rawBody, Request.Headers["x-signature"], replayCache: cache);
switch ((string?)payload["event"])
{
    case DeviceRiskWebhook.EventDeviceRiskSignal: /* a signal that asks for more */ break;
    case DeviceRiskWebhook.EventDeviceRiskAlert: /* an alert rule went off */ break;
}
```

Use `MemoryReplayCache` for one process, or implement `IWebhookReplayCache` over Redis or your database.

## Errors

| Exception | When |
|---|---|
| `TouchqueConfigException` | Missing keys, a swapped key and secret, plain http to a remote host, a bad argument, a card number |
| `TouchqueApiException` | Touchque answered with an error: `Status`, `Code` (`device_risk_off`, `invalid_request`…), `CaseCode`, `RetryAfter`, `Body` |
| `TouchqueFeatureException` | 403: Device risk is not in the organization's plan, is being turned off, or is off on this deployment (`Feature` is `device_risk`) |
| `TouchqueNetworkException` | The request never reached Touchque (generally safe to retry) |
| `TouchqueWebhookSignatureException` / `TouchqueWebhookReplayException` | A webhook that is not from Touchque, was changed, is too old, or was already accepted |

These are this package's own types in `Touchque.DeviceRisk`, named like the main SDK's. If a file imports both
namespaces, qualify them (`Touchque.DeviceRisk.TouchqueApiException`).

## Privacy

Collect device data only on sign-up, password-reset, sign-in and approval pages, and name it in your privacy
notice. Touchque keeps keyed hashes only, with a key of your workspace alone (no device is linked across
Touchque customers), for the retention your workspace sets (30 to 90 days).

## License

MIT
