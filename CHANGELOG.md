# Changelog

All notable changes to this project will be documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] — 2026-11-24

### Added
- **Touchque Device Risk for .NET, its own package** (NuGet `Touchque.DeviceRisk`, namespace `Touchque.DeviceRisk`). Device risk used to live in the main `Touchque` package (`tq.DeviceRisk`); it moves here with the same behaviour. `DeviceRiskClient` signs requests, times out and maps errors exactly like the main SDK (`DeviceRiskOptions`: `ApiKey`, `ApiSecret`, `BaseUrl`, `Timeout`, or `TQ_API_KEY` / `TQ_API_SECRET` / `TQ_API_URL`).
- `CheckAsync(requestId, options)` / `CheckAsync(DeviceRiskCheckOptions)` (`POST /device-risk/check`), `GetEventAsync(requestId)` (`GET /device-risk/events/{requestId}`) and `SearchEventsAsync(DeviceRiskSearchOptions)` (`GET /device-risk/events`), as in the main SDK 5.x.
- **`ActivityAsync(DeviceRiskActivityOptions)`** (`POST /device-risk/activity`): report what a visitor did that your server saw (`payment_attempt`, `login_failed`, `not_found`, `forbidden`, `otp_sent`, `code_failed`), named by `RequestId`, `VisitorId` or `ClientIp`. The answer (`DeviceRiskActivityResult`) carries `Recorded`, `VisitorId`, `PathClass` and the abuse codes raised (`abuse_card_testing`, `abuse_card_shared`, `abuse_login_failures`, `abuse_probing`, `abuse_otp_pumping`, `abuse_code_guessing`). A card is `DeviceRiskCard { Bin, Last4 }`; a full card number is refused with `TouchqueConfigException` before any request.
- `DeviceRiskCheckResult.Suspect` (`DeviceRiskSuspect`: `Score` 0-100, `Band`, `WouldDo`, `Mode` shadow, `Reasons` with `Code`, `Points`, `By`, `Text`) and `DeviceRiskCheckResult.AccountDevice` (`DeviceRiskAccountDevice`: `Status` known, likely, new or first, `VisitorId`, `Since`). `DeviceRiskClient.ParseSuspect` and `ParseAccountDevice` read them from an event or a search row. `matchedBy` may be `fpc` (`DeviceRiskClient.MatchedByValues`).
- `client.Webhook` (`DeviceRiskWebhook`): `Verify` / `VerifyAsync` with a replay cache, and the event names `EventDeviceRiskSignal` (`DEVICE_RISK_SIGNAL`) and `EventDeviceRiskAlert` (`DEVICE_RISK_ALERT`).
