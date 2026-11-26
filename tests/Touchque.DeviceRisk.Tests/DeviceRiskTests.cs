using System.Text.Json.Nodes;
using Xunit;

namespace Touchque.DeviceRisk.Tests;

/// <summary>
/// Check, read and search against the shared fake API: the report goes through untouched and the answer fails
/// toward asking. Same scenarios as the main Touchque SDK's former DeviceRisk tests.
/// </summary>
[Collection("fake-api")]
public class DeviceRiskTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public DeviceRiskTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task CheckSendsTheReportAndReadsTheAnswer()
    {
        var dr = _api.Client();
        var r = await dr.CheckAsync(new DeviceRiskCheckOptions { RequestId = "dre_flaggedaaaaaaaaaaaaaaa", Event = "sign_up", ExternalUsername = "ayse@acme.com", ClientIp = "203.0.113.7" });
        Assert.Equal("ok", r.Report);
        Assert.Equal(("tqv_fakeVisitor00000001", "DRK-2QX"), (r.VisitorId, r.CaseCode));
        Assert.False(r.Signals[0].Enforced);
        JsonAssert.Equal(new { requestId = "dre_flaggedaaaaaaaaaaaaaaa", @event = "sign_up", externalUsername = "ayse@acme.com", clientIp = "203.0.113.7" }, (await _api.CallsAsync())[^1]!["body"]);
        var ev = await dr.GetEventAsync("dre_aaaaaaaaaaaaaaaaaaaaaa");
        Assert.Equal("tqv_fakeVisitor00000001", (string)ev["visitorId"]!);
        Assert.Equal(["device_many_accounts"], r.Signals.Select((s) => s.Code));
        Assert.False(r.StepUp);
        Assert.True(r.WouldStepUp);
        Assert.Equal("shadow", r.Mode);
        Assert.Empty((await dr.CheckAsync(new DeviceRiskCheckOptions { DeviceRisk = "REPORT" })).Signals);
    }

    [Fact]
    public async Task TheFormFieldAsItCameIsAnsweredNeverThrown()
    {
        var dr = _api.Client();
        foreach (var value in new string?[] { null, "" })
        {
            var r = await dr.CheckAsync(value, new DeviceRiskCheckOptions { ExternalUsername = "ayse@acme.com" });
            Assert.Equal(("missing", (string?)null, false, true), (r.Report, r.VisitorId, r.StepUp, r.WouldStepUp));
            Assert.Equal(["device_identification_missing"], r.Signals.Select(x => x.Code));
        }
        Assert.Equal("missing", (await dr.CheckAsync(new DeviceRiskCheckOptions())).Report);
        Assert.Equal("unknown", (await dr.CheckAsync("nope")).Report);
        Assert.Equal("expired", DeviceRiskClient.ParseCheck(new JsonObject { ["report"] = "expired" }).Report);
    }

    [Fact]
    public async Task BadInputFailsBeforeAnyRequest()
    {
        var dr = _api.Client();
        await Assert.ThrowsAsync<TouchqueConfigException>(() => dr.CheckAsync(new DeviceRiskCheckOptions { DeviceRisk = "r", Event = "tracking" }));
        await Assert.ThrowsAsync<TouchqueConfigException>(() => dr.GetEventAsync("../users"));
        Assert.Empty(await _api.CallsAsync());
    }

    [Fact]
    public void TheAnswerFailsTowardAsking()
    {
        Assert.True(DeviceRiskClient.ParseCheck(new JsonObject()).StepUp);
        Assert.False(DeviceRiskClient.ParseCheck(new JsonObject { ["stepUp"] = false }).StepUp);
        var r = DeviceRiskClient.ParseCheck(JsonNode.Parse("""{"signals":[{"code":"device_tampered","text":"t"},null,{"text":"x"}],"requires":"passkey"}"""));
        Assert.Single(r.Signals);
        Assert.Equal(("device_tampered", "number_match"), (r.Signals[0].Code, r.Signals[0].Strength));
        Assert.Equal(("passkey", "invalid"), (r.Requires, r.Report));
    }

    [Fact]
    public void EngineUnavailableComesThroughAndANormalAnswerHasNull()
    {
        var down = DeviceRiskClient.ParseCheck(JsonNode.Parse("{\"report\":\"ok\",\"signals\":[],\"stepUp\":true,\"wouldStepUp\":true,\"requires\":\"number_match\",\"mode\":\"enforce\",\"engine\":\"unavailable\"}"));
        Assert.Equal(("unavailable", true, "number_match"), (down.Engine, down.StepUp, down.Requires));
        var normal = DeviceRiskClient.ParseCheck(JsonNode.Parse("{\"report\":\"ok\",\"signals\":[],\"stepUp\":false,\"requires\":\"none\",\"mode\":\"shadow\"}"));
        Assert.Null(normal.Engine);
        Assert.False(normal.StepUp);
        Assert.Null(DeviceRiskClient.ParseCheck(new JsonObject { ["engine"] = 42 }).Engine);
    }

    [Fact]
    public void TheAddressTheCountsAndABotAnswerComeThrough()
    {
        var r = DeviceRiskClient.ParseCheck(JsonNode.Parse("{\"report\":\"ok\",\"network\":{\"type\":\"hosting\"},\"velocity\":{\"identifications1h\":2},\"bot\":{\"result\":\"suspected\"}}")!.AsObject());
        Assert.Equal("hosting", (string?)r.Network!["type"]);
        Assert.Equal(2, (int?)r.Velocity!["identifications1h"]);
        Assert.Equal("suspected", (string?)r.Bot!["result"]);
        Assert.Null(DeviceRiskClient.ParseCheck(new JsonObject { ["network"] = "x" }).Network);
    }

    [Fact]
    public void TheKindOfNetworkAndTheSharedCountsComeThrough()
    {
        var r = DeviceRiskClient.ParseCheck(JsonNode.Parse("""
            {"report":"ok","network":{"countryCode":"TR","asn":64500,"asnOrg":"Example University","type":"isp","tor":false,"hosting":false,
              "hostingProvider":null,"proxy":true,"timezoneMismatch":false,"kind":"education","kindSource":"network","vpn":false,
              "shared":true,"sharedVisitors24h":100,"sharedAccounts24h":null,"lookAlikeMatching":false}}
            """));
        var n = r.Network ?? throw new InvalidOperationException("no network");
        Assert.Equal(("education", "network", (bool?)false, (bool?)true), ((string?)n["kind"], (string?)n["kindSource"], (bool?)n["vpn"], (bool?)n["proxy"]));
        Assert.Equal(((bool?)true, (int?)100, (bool?)false), ((bool?)n["shared"], (int?)n["sharedVisitors24h"], (bool?)n["lookAlikeMatching"]));
        Assert.True(n.ContainsKey("sharedAccounts24h") && n["sharedAccounts24h"] is null);

        // Apple's relay, a VPN company and a kind newer than this SDK: kept as they came (an open list).
        var relay = DeviceRiskClient.ParseCheck(JsonNode.Parse("""{"network":{"type":"relay","kind":"relay","kindSource":"address","vpn":false}}""")).Network!;
        Assert.Equal(("relay", "relay", "address"), ((string?)relay["type"], (string?)relay["kind"], (string?)relay["kindSource"]));
        var vpn = DeviceRiskClient.ParseCheck(JsonNode.Parse("""{"network":{"type":"hosting","kind":"vpn","kindSource":"network","vpn":true}}""")).Network!;
        Assert.Equal(("vpn", (bool?)true), ((string?)vpn["kind"], (bool?)vpn["vpn"]));
        Assert.Equal("satellite", (string?)DeviceRiskClient.ParseCheck(JsonNode.Parse("""{"network":{"kind":"satellite"}}""")).Network!["kind"]);
        Assert.Equal(["residential", "mobile_carrier", "education", "business", "public_wifi", "hosting", "proxy", "vpn", "tor", "relay", "unknown"], DeviceRiskClient.NetworkKinds);

        // An older server sends none of them: absent, never made up from type.
        var old = DeviceRiskClient.ParseCheck(JsonNode.Parse("""{"network":{"type":"hosting","tor":false,"hosting":true}}""")).Network!;
        Assert.Equal(["type", "tor", "hosting"], old.Select(p => p.Key));
    }

    [Fact]
    public void AiAgentsOnThePageAndTheNewBotReasonsComeThrough()
    {
        var r = DeviceRiskClient.ParseCheck(JsonNode.Parse("""
            {"report":"ok","bot":{"result":"detected","type":"ai_agent",
              "reasons":["tool_claude_agent","tool_comet_agent","tool_genspark_agent","tool_browser_use","tool_stagehand","tool_skyvern",
                "headless_window","emulator","cdp_input","input_no_focus","insert_text_bulk","scripted_click"],
              "tools":["claude_agent","comet_agent","genspark_agent","browser_use","stagehand","skyvern"],"agent":null,"input":[]}}
            """));
        var bot = r.Bot ?? throw new InvalidOperationException("no bot");
        Assert.Equal(("detected", "ai_agent"), ((string?)bot["result"], (string?)bot["type"]));
        Assert.Equal(["claude_agent", "comet_agent", "genspark_agent", "browser_use", "stagehand", "skyvern"], bot["tools"]!.AsArray().Select(t => (string)t!));
        Assert.Equal(["tool_claude_agent", "tool_comet_agent", "tool_genspark_agent", "tool_browser_use", "tool_stagehand", "tool_skyvern",
            "headless_window", "emulator", "cdp_input", "input_no_focus", "insert_text_bulk", "scripted_click"], bot["reasons"]!.AsArray().Select(t => (string)t!));
    }

    [Fact]
    public void TheSuspectScoreAndTheAccountDeviceComeThrough()
    {
        var r = DeviceRiskClient.ParseCheck(JsonNode.Parse("""
            {"report":"ok","visitor":{"matchedBy":"fpc"},
             "accountDevice":{"status":"likely","visitorId":"tqv_aaaaaaaaaaaaaaaaaaaa"},
             "suspect":{"score":64,"band":"high","wouldDo":"passkey","mode":"shadow",
               "reasons":[{"code":"abuse_card_testing","points":40,"by":"site","text":"Cards tested"},{"code":"known_browser","points":-10,"by":"server","text":"Known"},{"points":5}]}}
            """));
        Assert.Equal("fpc", (string?)r.Visitor!["matchedBy"]);
        Assert.Contains("fpc", DeviceRiskClient.MatchedByValues);
        var ad = r.AccountDevice ?? throw new InvalidOperationException("no accountDevice");
        Assert.Equal(("likely", "tqv_aaaaaaaaaaaaaaaaaaaa", (string?)null), (ad.Status, ad.VisitorId, ad.Since));
        var s = r.Suspect ?? throw new InvalidOperationException("no suspect");
        Assert.Equal((64, "high", "passkey", "shadow"), (s.Score, s.Band, s.WouldDo, s.Mode));
        Assert.Equal(new[] { ("abuse_card_testing", 40, "site"), ("known_browser", -10, "server") }, s.Reasons.Select(x => (x.Code, x.Points, x.By!)).ToArray());

        var odd = DeviceRiskClient.ParseCheck(JsonNode.Parse("""{"accountDevice":{"status":"maybe"},"suspect":{"score":250,"band":"extreme","wouldDo":"panic"}}"""));
        Assert.Null(odd.AccountDevice);
        var oddSuspect = odd.Suspect ?? throw new InvalidOperationException("no suspect");
        Assert.Equal((100, (string?)null, (string?)null), (oddSuspect.Score, oddSuspect.Band, oddSuspect.WouldDo));
        var old = DeviceRiskClient.ParseCheck(new JsonObject { ["report"] = "ok" });
        Assert.Null(old.AccountDevice);
        Assert.Null(old.Suspect);
        Assert.Null(DeviceRiskClient.ParseSuspect(JsonValue.Create("x")));
    }

    [Fact]
    public async Task SearchEventsPagesWithTheOpaqueCursorAndSendsTheFilters()
    {
        var dr = _api.Client();
        var first = await dr.SearchEventsAsync(new DeviceRiskSearchOptions { Account = "ada@example.com", StepUp = false, Ip = "203.0.113.0/24", Limit = 1 });
        Assert.Equal(new[] { "dre_fakeEvent00000000002" }, first.Events.Select(e => (string)e["requestId"]!).ToArray());
        Assert.Null(first.NextCursor);
        JsonAssert.Equal(new { account = "ada@example.com", stepUp = "false", ip = "203.0.113.0/24", limit = "1" }, await _api.LastDeviceRiskSearchAsync());
        var seen = new List<string>();
        string? cursor = null;
        do
        {
            var page = await dr.SearchEventsAsync(new DeviceRiskSearchOptions { Limit = 1, Cursor = cursor });
            seen.AddRange(page.Events.Select(e => (string)e["requestId"]!));
            cursor = page.NextCursor;
        } while (cursor != null);
        Assert.Equal(new[] { "dre_fakeEvent00000000003", "dre_fakeEvent00000000002", "dre_fakeEvent00000000001" }, seen);
        await Assert.ThrowsAsync<TouchqueConfigException>(() => dr.SearchEventsAsync(new DeviceRiskSearchOptions { Limit = 101 }));
    }

    [Fact]
    public async Task SearchEventsSendsTheNetworkKindAndSharedFilters()
    {
        var dr = _api.Client();
        await dr.SearchEventsAsync(new DeviceRiskSearchOptions { NetworkKind = "education", Shared = false, Limit = 5 });
        JsonAssert.Equal(new { networkKind = "education", shared = "false", limit = "5" }, await _api.LastDeviceRiskSearchAsync());
        await dr.SearchEventsAsync(new DeviceRiskSearchOptions { NetworkKind = "public_wifi", Shared = true });
        JsonAssert.Equal(new { networkKind = "public_wifi", shared = "true" }, await _api.LastDeviceRiskSearchAsync());
    }

    [Fact]
    public async Task TheVisitorMarkIsTheMarkApplied()
    {
        var dr = _api.Client();
        var id = "dre_" + new string('a', 22);
        var flagged = "dre_flagged" + new string('a', 15);
        async Task<JsonObject> VisitorAsync(string requestId) => (await dr.CheckAsync(new DeviceRiskCheckOptions { RequestId = requestId })).Visitor!;

        var v = await VisitorAsync(id);
        Assert.True(v.ContainsKey("mark") && v["mark"] is null);
        Assert.Equal("none", (string?)v["status"]);

        await _api.OptsAsync(new { deviceMark = "trusted" });
        v = await VisitorAsync(id);
        Assert.Equal(("trusted", "trusted", "key"), ((string?)v["status"], (string?)v["mark"], (string?)v["matchedBy"]));
        v = await VisitorAsync(flagged);
        Assert.Equal(("trusted", (string?)null), ((string?)v["status"], (string?)v["mark"]));
        Assert.Equal("trusted", (string?)(await dr.GetEventAsync(id))["visitor"]!["mark"]);

        await _api.OptsAsync(new { deviceMark = "step_up" });
        Assert.Equal("step_up", (string?)(await VisitorAsync(flagged))["mark"]);

        // A mark other than trusted or step_up reads as null; the answer itself is not changed.
        var odd = JsonNode.Parse("""{"report":"ok","visitor":{"status":"none","mark":"allow"}}""")!;
        Assert.Null(DeviceRiskClient.ParseCheck(odd).Visitor!["mark"]);
        Assert.Equal("allow", (string?)odd["visitor"]!["mark"]);
    }
}
