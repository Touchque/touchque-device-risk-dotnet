using System.Text.Json.Nodes;
using Xunit;

namespace Touchque.DeviceRisk.Tests;

/// <summary>POST /device-risk/activity against the shared fake API: what the visitor did, never a card number.</summary>
[Collection("fake-api")]
public class ActivityTests : IAsyncLifetime
{
    private readonly FakeApi _api;

    public ActivityTests(FakeApi api) => _api = api;

    public Task InitializeAsync() => _api.ResetAsync();

    public Task DisposeAsync() => Task.CompletedTask;

    [Fact]
    public async Task AFailedSignInIsRecordedAndSentAsItCame()
    {
        var r = await _api.Client().ActivityAsync(new DeviceRiskActivityOptions { Type = "login_failed", ClientIp = "203.0.113.7", ExternalUsername = "ayse@acme.com" });
        Assert.True(r.Recorded);
        Assert.Null(r.VisitorId);
        Assert.Null(r.PathClass);
        Assert.Empty(r.Signals);
        JsonAssert.Equal(new { type = "login_failed", clientIp = "203.0.113.7", externalUsername = "ayse@acme.com" }, await _api.LastDeviceRiskActivityAsync());
    }

    [Fact]
    public async Task AFlaggedVisitorTestingCardsRaisesCardTesting()
    {
        var r = await _api.Client().ActivityAsync(new DeviceRiskActivityOptions
        {
            Type = "payment_attempt",
            RequestId = "dre_flaggedaaaaaaaaaaaaaaa",
            Outcome = "declined",
            Card = new DeviceRiskCard { Bin = "411111", Last4 = "1111" },
        });
        Assert.True(r.Recorded);
        Assert.Equal("tqv_fakeVisitor00000001", r.VisitorId);
        Assert.Equal(new[] { "abuse_card_testing" }, r.Signals);
        JsonAssert.Equal(new { type = "payment_attempt", requestId = "dre_flaggedaaaaaaaaaaaaaaa", outcome = "declined", card = new { bin = "411111", last4 = "1111" } },
            await _api.LastDeviceRiskActivityAsync());
    }

    [Fact]
    public async Task AProbedPathAnswersItsClass()
    {
        var r = await _api.Client().ActivityAsync(new DeviceRiskActivityOptions { Type = "not_found", VisitorId = "tqv_aaaaaaaaaaaaaaaaaaaa", Path = "/admin/login.php" });
        Assert.Equal(("admin", "tqv_fakeVisitor00000001"), (r.PathClass, r.VisitorId));
    }

    [Theory]
    [InlineData("4111111111111111", "1111")]
    [InlineData("4111 1111 1111 1111", "1111")]
    [InlineData("411111", "4111-1111-1111-1111")]
    public async Task ACardNumberIsRefusedBeforeAnyRequest(string bin, string last4)
    {
        var e = await Assert.ThrowsAsync<TouchqueConfigException>(() => _api.Client().ActivityAsync(new DeviceRiskActivityOptions
        {
            Type = "payment_attempt",
            ClientIp = "203.0.113.7",
            Card = new DeviceRiskCard { Bin = bin, Last4 = last4 },
        }));
        Assert.Contains("card number", e.Message);
        Assert.Empty(await _api.CallsAsync());
    }

    [Fact]
    public async Task BadInputFailsBeforeAnyRequest()
    {
        var dr = _api.Client();
        DeviceRiskActivityOptions[] bad =
        [
            new() { Type = "tracking", ClientIp = "203.0.113.7" },
            new() { Type = "login_failed" },
            new() { Type = "payment_attempt", ClientIp = "203.0.113.7", Outcome = "maybe" },
            new() { Type = "payment_attempt", ClientIp = "203.0.113.7", Card = new DeviceRiskCard { Bin = "4111", Last4 = "1111" } },
            new() { Type = "payment_attempt", ClientIp = "203.0.113.7", Card = new DeviceRiskCard { Bin = "411111", Last4 = "11" } },
            new() { Type = "otp_sent", ClientIp = "203.0.113.7", Phone = "call me" },
            new() { Type = "not_found", ClientIp = "203.0.113.7", Path = "/" + new string('a', 2048) },
        ];
        foreach (var o in bad) await Assert.ThrowsAsync<TouchqueConfigException>(() => dr.ActivityAsync(o));
        Assert.Empty(await _api.CallsAsync());
    }

    [Fact]
    public void TheAnswerIsReadStrictly()
    {
        var r = DeviceRiskClient.ParseActivity(JsonNode.Parse("""{"recorded":"yes","visitorId":7,"signals":["abuse_probing",3,"",null]}"""));
        Assert.False(r.Recorded);
        Assert.Null(r.VisitorId);
        Assert.Equal(new[] { "abuse_probing" }, r.Signals);
        Assert.False(DeviceRiskClient.ParseActivity(null).Recorded);
    }
}
