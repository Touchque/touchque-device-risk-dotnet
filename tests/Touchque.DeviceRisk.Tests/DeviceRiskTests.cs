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
}
