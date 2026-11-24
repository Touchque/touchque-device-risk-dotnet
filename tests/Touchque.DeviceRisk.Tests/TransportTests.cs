using System.Text;
using System.Text.Json.Nodes;
using Touchque.DeviceRisk.Internal;
using Xunit;

namespace Touchque.DeviceRisk.Tests;

/// <summary>
/// The transport copied from the main Touchque SDK: it signs like the server and the other SDKs (the shared
/// fixtures), refuses swapped keys and plain http, never follows a redirect, and maps errors the same way.
/// </summary>
public class TransportTests
{
    [Fact]
    public void SignatureVectors()
    {
        var fx = Paths.Fixture("signature-vectors.json");
        var vectors = (JsonArray)fx["vectors"]!;
        Assert.NotEmpty(vectors);
        foreach (var v in vectors)
        {
            var sig = TouchqueHttp.Sign((string)fx["secret"]!, (string)v!["method"]!, (string)v["signed_path"]!, (string)v["body"]!, (string)v["timestamp"]!, (string)v["nonce"]!);
            Assert.Equal((string)v["expected_signature"]!, sig);
        }
    }

    [Fact]
    public void ConfigRefusesSwappedKeysAndPlainHttp()
    {
        Assert.Throws<TouchqueConfigException>(() => new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "secret", ApiSecret = "tq_key" }));
        Assert.Throws<TouchqueConfigException>(() => new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_k", ApiSecret = "s", BaseUrl = "http://api.example.com" }));
        Assert.NotNull(new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_k", ApiSecret = "s", BaseUrl = "http://127.0.0.1:9" }));
        Assert.Equal("https://api.touchque.com", DeviceRiskClient.DefaultBaseUrl);
    }

    [Fact]
    public async Task RequestsAreSignedAndSentToTheBaseUrl()
    {
        HttpRequestMessage? seen = null;
        string? seenBody = null;
        var http = new HttpClient(new StubHandler((req, body) =>
        {
            seen = req;
            seenBody = body;
            return StubHandler.Json(200, new { report = "ok", stepUp = false });
        }));
        var dr = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example/" }, http);
        await dr.CheckAsync("dre_aaaaaaaaaaaaaaaaaaaaaa");
        var req = seen ?? throw new InvalidOperationException("no request");
        Assert.Equal("https://api.example/device-risk/check", req.RequestUri?.ToString());
        Assert.Equal("tq_x", req.Headers.GetValues("x-api-key").Single());
        var ts = req.Headers.GetValues("x-timestamp").Single();
        var nonce = req.Headers.GetValues("x-nonce").Single();
        Assert.Equal(TouchqueHttp.Sign("s", "POST", "/device-risk/check", seenBody ?? "", ts, nonce), req.Headers.GetValues("x-signature").Single());
        Assert.StartsWith("touchque-device-risk-dotnet-sdk/", string.Join(" ", req.Headers.GetValues("User-Agent")));
    }

    [Fact]
    public async Task ErrorsCarryCodeCaseCodeAndRetryAfter()
    {
        var http = new HttpClient(new StubHandler((_, _) =>
        {
            var res = StubHandler.Json(429, new { code = "rate_limited", error = "too_many_requests", caseCode = "REF-USE" });
            res.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(60));
            return res;
        }));
        var dr = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http);
        var e = await Assert.ThrowsAsync<TouchqueApiException>(() => dr.CheckAsync("dre_aaaaaaaaaaaaaaaaaaaaaa"));
        Assert.Equal((429, "rate_limited", "REF-USE", 60), (e.Status, e.Code, e.CaseCode, e.RetryAfter));

        var off = new HttpClient(new StubHandler((_, _) => StubHandler.Json(409, new { code = "device_risk_off", error = "Turn Device risk on in the dashboard." })));
        var dr2 = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, off);
        var offE = await Assert.ThrowsAsync<TouchqueApiException>(() => dr2.CheckAsync("x"));
        Assert.Equal((409, "device_risk_off"), (offE.Status, offE.Code));

        var down = new HttpClient(new StubHandler((_, _) => throw new HttpRequestException("connection refused")));
        var dr3 = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, down);
        await Assert.ThrowsAsync<TouchqueNetworkException>(() => dr3.GetEventAsync("dre_aaaaaaaaaaaaaaaaaaaaaa"));

        var redirect = new HttpClient(new StubHandler((_, _) => new HttpResponseMessage(System.Net.HttpStatusCode.Found) { Headers = { Location = new Uri("https://evil.example/") } }));
        var dr4 = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, redirect);
        Assert.Equal(302, (await Assert.ThrowsAsync<TouchqueApiException>(() => dr4.GetEventAsync("dre_aaaaaaaaaaaaaaaaaaaaaa"))).Status);
    }
}

/// <summary>
/// A feature the workspace's organization cannot use comes back as a typed exception with the feature's id,
/// still a TouchqueApiException, against the shared fake Touchque API.
/// </summary>
[Collection("fake-api")]
public class FeatureErrorTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public FeatureErrorTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => _api.OptsAsync(new { featureRefused = (string?)null });

    [Theory]
    [InlineData("feature_not_in_plan", typeof(TouchqueFeatureNotInPlanException), FeatureRefusal.NotInPlan)]
    [InlineData("feature_read_only", typeof(TouchqueFeatureReadOnlyException), FeatureRefusal.ReadOnly)]
    [InlineData("feature_off", typeof(TouchqueFeatureOffException), FeatureRefusal.Off)]
    public async Task EachFeatureRefusalHasItsOwnException(string code, Type type, FeatureRefusal reason)
    {
        await _api.OptsAsync(new { featureRefused = code, feature = "device_risk" });
        var e = await Assert.ThrowsAnyAsync<TouchqueFeatureException>(() => _api.Client().CheckAsync("dre_aaaaaaaaaaaaaaaaaaaaaa"));
        Assert.IsType(type, e);
        Assert.IsAssignableFrom<TouchqueApiException>(e);
        Assert.Equal((403, "device_risk", reason), (e.Status, e.Feature, e.FeatureReason));
    }
}

/// <summary>Device risk webhooks: the shared vectors, the freshness window and the replay cache, as in the main SDK.</summary>
public class WebhookTests
{
    [Fact]
    public void WebhookVectors()
    {
        var fx = Paths.Fixture("webhook-vectors.json");
        var webhook = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = (string)fx["secret"]! }).Webhook;
        foreach (var v in (JsonArray)fx["vectors"]!)
        {
            var body = (string)v!["delivered_body"]!;
            Assert.Equal((string)v["expected_canonical"]!, DeviceRiskWebhook.Canonicalize(body));
            // The fixtures carry a fixed past timestamp: no freshness check.
            var payload = webhook.Verify(body, null, 0);
            Assert.Equal((string?)v["payload"]!["requestId"], (string?)payload["requestId"]);
        }
    }

    [Fact]
    public async Task ADeviceRiskEventIsVerifiedOnceAndAChangedOneIsRefused()
    {
        const string secret = "whsec_test";
        var webhook = new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = secret }).Webhook;
        string Sign(JsonObject payload)
        {
            using var h = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var sig = Convert.ToHexString(h.ComputeHash(Encoding.UTF8.GetBytes(DeviceRiskWebhook.Canonicalize(payload.ToJsonString())))).ToLowerInvariant();
            payload["signature"] = sig;
            return payload.ToJsonString();
        }
        var now = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'");
        var fresh = Sign(new JsonObject
        {
            ["event"] = DeviceRiskWebhook.EventDeviceRiskSignal, ["integrationId"] = "int_1", ["requestId"] = "dre_aaaaaaaaaaaaaaaaaaaaaa",
            ["visitorId"] = "tqv_aaaaaaaaaaaaaaaaaaaa", ["report"] = "ok", ["timestamp"] = now, ["jti"] = "j1",
            ["signals"] = new JsonArray(new JsonObject { ["code"] = "device_tampered", ["enforced"] = true, ["strength"] = "number_match" }),
        });
        var cache = new MemoryReplayCache();
        var payload = await webhook.VerifyAsync(fresh, null, 300, cache);
        Assert.Equal("DEVICE_RISK_SIGNAL", (string?)payload["event"]);
        Assert.Contains((string?)payload["event"], DeviceRiskWebhook.Events);
        Assert.Equal("DEVICE_RISK_ALERT", DeviceRiskWebhook.EventDeviceRiskAlert);
        var replay = await Assert.ThrowsAsync<TouchqueWebhookReplayException>(() => webhook.VerifyAsync(fresh, null, 300, cache));
        Assert.Equal("j1", replay.Jti);

        var old = Sign(new JsonObject { ["event"] = "DEVICE_RISK_ALERT", ["timestamp"] = "2020-01-01T00:00:00.000Z" });
        Assert.Throws<TouchqueWebhookSignatureException>(() => webhook.Verify(old));
        var tampered = fresh.Replace("\"ok\"", "\"replayed\"");
        var e = Assert.Throws<TouchqueWebhookSignatureException>(() => webhook.Verify(tampered));
        Assert.DoesNotContain("expected", e.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Throws<TouchqueWebhookSignatureException>(() => webhook.Verify("not json"));
        Assert.Throws<TouchqueWebhookSignatureException>(() => webhook.Verify(Sign(new JsonObject { ["event"] = "DEVICE_RISK_ALERT" })));
    }
}
