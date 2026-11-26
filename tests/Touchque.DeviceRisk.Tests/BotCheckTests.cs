using System.Text;
using System.Text.Json.Nodes;
using Touchque.DeviceRisk.Internal;
using Xunit;

namespace Touchque.DeviceRisk.Tests;

/// <summary>
/// POST /device-risk/bot-check against the in-process fake: the request the contract takes (sensitive values blank,
/// order kept, no query string), the limits checked before any request, and an answer read without failing.
/// </summary>
public class BotCheckTests
{
    private const string Answer = """
        {"bot":{"result":"detected","category":"ai_assistant","provider":"OpenAI","name":"ChatGPT-User","identity":"verified",
                "verifiedBy":"ip_list","confidence":"high","rule":"directory.chatgpt_user",
                "reasons":[{"code":"ip_list_match","text":"The address is on OpenAI's published list for ChatGPT-User."}]},
         "network":{"asn":8075,"asnOrg":"Microsoft Corporation","countryCode":"US","hosting":true},
         "suggestion":"allow","rulesVersion":"2026.11.25-1"}
        """;

    /// <summary>A client whose requests are recorded and answered by <paramref name="answer"/> (by default, <see cref="Answer"/>).</summary>
    private static (DeviceRiskClient Client, List<(HttpRequestMessage Request, string Body)> Seen) Fake(Func<HttpResponseMessage>? answer = null)
    {
        var seen = new List<(HttpRequestMessage, string)>();
        var http = new HttpClient(new StubHandler((req, body) =>
        {
            seen.Add((req, body ?? ""));
            return answer?.Invoke() ?? new HttpResponseMessage(System.Net.HttpStatusCode.OK) { Content = new StringContent(Answer, Encoding.UTF8, "application/json") };
        }));
        return (new DeviceRiskClient(new DeviceRiskOptions { ApiKey = "tq_x", ApiSecret = "s", BaseUrl = "https://api.example" }, http), seen);
    }

    private static KeyValuePair<string, string>[] Many(int count, string value = "v") =>
        Enumerable.Range(0, count).Select(i => KeyValuePair.Create($"X-H{i}", value)).ToArray();

    private static JsonNode SentHeaders(string body) => JsonNode.Parse(body)!["headers"]!;

    [Fact]
    public async Task TheRequestHasTheContractsShapeAndIsSigned()
    {
        var (dr, seen) = Fake();
        var r = await dr.BotCheckAsync(new BotCheckRequest
        {
            Ip = "203.0.113.7",
            Headers =
            [
                new("Host", "shop.example"),
                new("User-Agent", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"),
                new("Accept", "text/html"),
            ],
            HeaderOrderKnown = true,
            Method = "GET",
            Url = "https://shop.example/products/42?utm_source=chatgpt.com#reviews",
            HttpVersion = "HTTP/2",
            Tls = new BotCheckTls { Ja4 = "t13d1516h2_8daaf6152771_02713d6af862" },
        });

        var (req, body) = Assert.Single(seen);
        Assert.Equal(HttpMethod.Post, req.Method);
        Assert.Equal("https://api.example/device-risk/bot-check", req.RequestUri?.ToString());
        var ts = req.Headers.GetValues("x-timestamp").Single();
        var nonce = req.Headers.GetValues("x-nonce").Single();
        Assert.Equal(TouchqueHttp.Sign("s", "POST", "/device-risk/bot-check", body, ts, nonce), req.Headers.GetValues("x-signature").Single());
        JsonAssert.Equal(JsonNode.Parse("""
            {"ip":"203.0.113.7",
             "headers":[["Host","shop.example"],
                        ["User-Agent","Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot"],
                        ["Accept","text/html"]],
             "method":"GET","url":"https://shop.example/products/42","httpVersion":"2",
             "tls":{"ja4":"t13d1516h2_8daaf6152771_02713d6af862"}}
            """), JsonNode.Parse(body));

        Assert.Equal(("detected", "ai_assistant", "OpenAI", "ChatGPT-User"), (r.Bot.Result, r.Bot.Category, r.Bot.Provider, r.Bot.Name));
        Assert.Equal(("verified", "ip_list", "high", "directory.chatgpt_user"), (r.Bot.Identity, r.Bot.VerifiedBy, r.Bot.Confidence, r.Bot.Rule));
        var reason = Assert.Single(r.Bot.Reasons);
        Assert.Equal(("ip_list_match", "The address is on OpenAI's published list for ChatGPT-User."), (reason.Code, reason.Text));
        var net = r.Network ?? throw new InvalidOperationException("no network");
        Assert.Equal((8075L, "Microsoft Corporation", "US", true), (net.Asn, net.AsnOrg, net.CountryCode, net.Hosting));
        Assert.Equal(("allow", "2026.11.25-1"), (r.Suggestion, r.RulesVersion));
    }

    [Fact]
    public async Task OptionalPartsAreLeftOutWhenNotGiven()
    {
        var (dr, seen) = Fake();
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [new("User-Agent", "curl/8.4.0")], Tls = new BotCheckTls() });
        JsonAssert.Equal(JsonNode.Parse("""{"ip":"203.0.113.7","headers":{"User-Agent":"curl/8.4.0"}}"""), JsonNode.Parse(seen.Single().Body));
    }

    [Fact]
    public async Task SensitiveValuesGoEmptyAndTheirNamesStayInPlace()
    {
        var (dr, seen) = Fake();
        KeyValuePair<string, string>[] headers =
        [
            new("Host", "shop.example"),
            new("authorization", "Bearer sk_live_secret"),
            new("Cookie", "session=abc123"),
            new("User-Agent", "curl/8.4.0"),
            new("PROXY-AUTHORIZATION", "Basic dXNlcjpwYXNz"),
            new("X-Api-Key", "key_123"),
            new("Set-Cookie", "id=xyz"),
            new("Accept", "*/*"),
        ];
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "198.51.100.4", Headers = headers, HeaderOrderKnown = true });
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "198.51.100.4", Headers = headers });

        foreach (var (_, body) in seen)
        {
            foreach (var secret in new[] { "sk_live_secret", "session=abc123", "dXNlcjpwYXNz", "key_123", "id=xyz" }) Assert.DoesNotContain(secret, body);
        }
        JsonAssert.Equal(JsonNode.Parse("""
            [["Host","shop.example"],["authorization",""],["Cookie",""],["User-Agent","curl/8.4.0"],
             ["PROXY-AUTHORIZATION",""],["X-Api-Key",""],["Set-Cookie",""],["Accept","*/*"]]
            """), SentHeaders(seen[0].Body));
        var unordered = (JsonObject)SentHeaders(seen[1].Body);
        Assert.Equal(["Host", "authorization", "Cookie", "User-Agent", "PROXY-AUTHORIZATION", "X-Api-Key", "Set-Cookie", "Accept"], unordered.Select(p => p.Key));
        Assert.Equal(["shop.example", "", "", "curl/8.4.0", "", "", "", "*/*"], unordered.Select(p => (string?)p.Value));
    }

    [Fact]
    public async Task TheOrderIsKeptAsItCame()
    {
        var (dr, seen) = Fake();
        KeyValuePair<string, string>[] headers =
        [
            new("User-Agent", "python-requests/2.32.3"),
            new("Accept-Encoding", "gzip, deflate"),
            new("Accept", "*/*"),
            new("Connection", "keep-alive"),
            new("X-Forwarded-For", "10.0.0.1"),
            new("x-forwarded-for", "10.0.0.2"),
            new("Host", "api.shop.example"),
        ];

        // In the order received: pairs, exactly as they came, repeats included.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = headers, HeaderOrderKnown = true });
        JsonAssert.Equal(JsonNode.Parse("""
            [["User-Agent","python-requests/2.32.3"],["Accept-Encoding","gzip, deflate"],["Accept","*/*"],["Connection","keep-alive"],
             ["X-Forwarded-For","10.0.0.1"],["x-forwarded-for","10.0.0.2"],["Host","api.shop.example"]]
            """), SentHeaders(seen[0].Body));

        // Order unknown (the default, as ASP.NET Core's Request.Headers): one value per name, so no order is claimed.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = headers });
        var unordered = Assert.IsType<JsonObject>(SentHeaders(seen[1].Body));
        Assert.Equal(["User-Agent", "Accept-Encoding", "Accept", "Connection", "X-Forwarded-For", "Host"], unordered.Select(p => p.Key));
        Assert.Equal("10.0.0.1, 10.0.0.2", (string?)unordered["X-Forwarded-For"]);
    }

    [Fact]
    public async Task OnlyWhatYourCodePassesWrongThrowsBeforeAnyRequest()
    {
        var (dr, seen) = Fake();
        BotCheckRequest[] bad =
        [
            new() { Headers = Many(1) },
            new() { Ip = "   ", Headers = Many(1) },
            new() { Ip = "not-an-ip", Headers = Many(1) },
            new() { Ip = "203.0.113.7:443", Headers = Many(1) },
            new() { Ip = "1", Headers = Many(1) },
            new() { Ip = "203.0.113.7" },
            new() { Ip = "203.0.113.7", Headers = [new("", "v")] },
        ];
        foreach (var o in bad) await Assert.ThrowsAsync<TouchqueConfigException>(() => dr.BotCheckAsync(o));
        await Assert.ThrowsAsync<ArgumentNullException>(() => dr.BotCheckAsync(null!));
        Assert.Empty(seen);
    }

    [Fact]
    public async Task WhatTheVisitorSentIsKeptToTheLimitsNeverRefused()
    {
        var (dr, seen) = Fake();
        // Past 100 headers: the first 100, and Touchque is told (a sign in itself).
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = Many(150), HeaderOrderKnown = true });
        var last = JsonNode.Parse(seen[^1].Body)!;
        Assert.Equal((100, "X-H99", true), (((JsonArray)last["headers"]!).Count, (string?)last["headers"]![99]![0], (bool?)last["truncated"]));
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = Many(150) });
        Assert.Equal(100, ((JsonObject)SentHeaders(seen[^1].Body)).Count);

        // Exactly 100, and a pseudo-header, which never counts: nothing cut.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [new(":path", "/?q=1"), .. Many(100)], HeaderOrderKnown = true });
        Assert.Equal(100, ((JsonArray)SentHeaders(seen[^1].Body)).Count);
        Assert.Null(JsonNode.Parse(seen[^1].Body)!["truncated"]);

        // A longer value is cut to 4096 characters, never between the two halves of a surrogate pair; a name to 128.
        await dr.BotCheckAsync(new BotCheckRequest
        {
            Ip = "203.0.113.7",
            Headers = [new("Referer", new string('r', 5000)), new("X-Note", new string('a', 4095) + "\U0001F600tail"), new(new string('n', 200), "v")],
            HeaderOrderKnown = true,
        });
        var sent = (JsonArray)SentHeaders(seen[^1].Body);
        Assert.Equal(new string('r', 4096), (string?)sent[0]![1]);
        Assert.Equal(new string('a', 4095), (string?)sent[1]![1]);
        Assert.Equal(new string('n', 128), (string?)sent[2]![0]);
        Assert.True((bool?)JsonNode.Parse(seen[^1].Body)!["truncated"]);
        // A blanked secret is not a cut.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [new("Cookie", new string('c', 5000))] });
        Assert.Null(JsonNode.Parse(seen[^1].Body)!["truncated"]);

        // Over 32 KB: the long values are cut to one length, the longest that fits; a short one stays whole.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [new("User-Agent", "curl/8.4.0"), .. Many(20, new string('a', 5000))], HeaderOrderKnown = true });
        Assert.True(Encoding.UTF8.GetByteCount(seen[^1].Body) <= 32_000);
        sent = (JsonArray)SentHeaders(seen[^1].Body);
        var lengths = sent.Skip(1).Select(h => ((string?)h![1])!.Length).Distinct().ToArray();
        Assert.Equal((21, "curl/8.4.0", 1), (sent.Count, (string?)sent[0]![1], lengths.Length));
        Assert.InRange(lengths[0], 1, 4095);

        // A long url and cipher list leave less room: every name stays, the values shrink, tls goes before any header.
        var url = "https://shop.example/" + new string('\u20AC', 4000);
        var names = Enumerable.Range(0, 100).Select(i => KeyValuePair.Create($"{i:000}" + new string('n', 125), new string('v', 100))).ToArray();
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = names, HeaderOrderKnown = true, Url = url, Tls = new BotCheckTls { Ciphers = new string('\u20AC', 5000) } });
        last = JsonNode.Parse(seen[^1].Body)!;
        Assert.True(Encoding.UTF8.GetByteCount(seen[^1].Body) <= 32_000);
        Assert.Equal((url, (JsonNode?)null, 100), ((string?)last["url"], last["tls"], ((JsonArray)last["headers"]!).Count));
        Assert.InRange(((string?)last["headers"]![0]![1])!.Length, 1, 99);

        // A header HTTP does not allow is left out (the API would refuse the whole check), and so is a null value.
        await dr.BotCheckAsync(new BotCheckRequest
        {
            Ip = "203.0.113.7",
            Headers = [new("X Bad", "1"), new("Caf\u00e9", "2"), new("X-Nul", "a\0b"), new("X-Break", "a\r\nX-Evil: 1"), new("X-None", null!), new("Accept", "*/*")],
            HeaderOrderKnown = true,
        });
        JsonAssert.Equal(JsonNode.Parse("""{"ip":"203.0.113.7","headers":[["Accept","*/*"]],"truncated":true}"""), JsonNode.Parse(seen[^1].Body));
        // None at all (HTTP/1.0 allows it) go as [] or {}.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [], HeaderOrderKnown = true });
        JsonAssert.Equal(JsonNode.Parse("""{"ip":"203.0.113.7","headers":[]}"""), JsonNode.Parse(seen[^1].Body));
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [] });
        JsonAssert.Equal(JsonNode.Parse("""{"ip":"203.0.113.7","headers":{}}"""), JsonNode.Parse(seen[^1].Body));
    }

    [Fact]
    public async Task TheMethodUrlAndTlsGoAsTheApiReadsThem()
    {
        foreach (var (given, sent) in new (string, string?)[]
        {
            ("https://Shop.Example:8443/a/b?c=d#e", "https://Shop.Example:8443/a/b"), ("https://203.0.113.7/login", "https://203.0.113.7/login"),
            ("/sign-in?x=1", "/sign-in"), ("wss://shop.example/socket", "https://shop.example/socket"), ("ws://shop.example/socket", "http://shop.example/socket"),
            // The Host header is the visitor's: one the API could not read goes as the path alone.
            ("https://exa mple.com/login", "/login"), ("https://shop.example.123/login", "/login"), ("https://1.2.3.256/login", "/login"),
            ("https://shop.example:99999/login", "/login"), ("https://[2001:db8::1]/login", "/login"), ("https://xn--zz.example/login", "/login"),
            ("https://a:b:c/login", "/login"), ("https://shop%2eexample/login", "/login"), ("https://shop.example\n/login", "/login"),
            // Anything that is not a path or an http(s) URL is left out, and so is one over 4096 characters (never cut).
            ("*", null), ("ftp://shop.example/x", null), ("shop.example/x", null),
            ("https://shop.example/" + new string('p', 4096), null), ("/" + new string('p', 4095), "/" + new string('p', 4095)),
        })
        {
            Assert.Equal(sent, DeviceRiskClient.BotUrl(given));
        }
        var (dr, seen) = Fake();
        foreach (var (given, sent) in new (string, string?)[] { ("GET", "GET"), (" post ", "post"), ("PROPFIND", "PROPFIND"), ("M-SEARCH", null), (new string('M', 17), null), ("GE\nT", null) })
        {
            await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [], Method = given });
            Assert.Equal(sent, (string?)JsonNode.Parse(seen[^1].Body)!["method"]);
        }
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [], Tls = new BotCheckTls { Ciphers = new string('c', 5000), Ja4 = new string('j', 129) } });
        JsonAssert.Equal(JsonNode.Parse($$"""{"ciphers":"{{new string('c', 4096)}}"}"""), JsonNode.Parse(seen[^1].Body)!["tls"]);
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = [], Tls = new BotCheckTls { Ja4 = new string('j', 129) } });
        Assert.Null(JsonNode.Parse(seen[^1].Body)!["tls"]);
    }

    [Fact]
    public async Task VersionsAndAddressesGoInTheContractsForm()
    {
        var (dr, seen) = Fake();
        foreach (var (given, sent) in new[] { ("HTTP/1.0", "1.0"), ("HTTP/1.1", "1.1"), ("1.1", "1.1"), ("HTTP/2", "2"), ("2.0", "2"), ("h2", "2"), ("HTTP/3", "3"), ("3.0", "3") })
        {
            await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = Many(1), HttpVersion = given });
            Assert.Equal(sent, (string?)JsonNode.Parse(seen[^1].Body)!["httpVersion"]);
        }
        Assert.Equal(DeviceRiskClient.BotHttpVersions, seen.Select(s => (string?)JsonNode.Parse(s.Body)!["httpVersion"]).Distinct());
        // Anything else is left out, never an error.
        await dr.BotCheckAsync(new BotCheckRequest { Ip = "203.0.113.7", Headers = Many(1), HttpVersion = "HTTP/1.2" });
        Assert.Null(JsonNode.Parse(seen[^1].Body)!["httpVersion"]);

        foreach (var (given, sent) in new[] { ("::ffff:203.0.113.7", "203.0.113.7"), (" 198.51.100.4 ", "198.51.100.4"), ("2001:db8::1", "2001:db8::1"), ("fe80::1%en0", "fe80::1") })
        {
            await dr.BotCheckAsync(new BotCheckRequest { Ip = given, Headers = Many(1) });
            Assert.Equal(sent, (string?)JsonNode.Parse(seen[^1].Body)!["ip"]);
        }

        Assert.Equal("https://shop.example/login", DeviceRiskClient.BotUrl("https://ada:pa55@shop.example/login?token=abc#top"));
        Assert.Equal("https://shop.example", DeviceRiskClient.BotUrl("https://ada@shop.example?x=1"));
        Assert.Equal("/login", DeviceRiskClient.BotUrl("/login?next=/admin"));
        Assert.Equal("https://shop.example/@ada", DeviceRiskClient.BotUrl("https://shop.example/@ada"));
        Assert.Null(DeviceRiskClient.BotUrl("?only=query"));
        Assert.Null(DeviceRiskClient.BotUrl(null));
    }

    [Fact]
    public void UnknownValuesAndFieldsAreKept()
    {
        var r = DeviceRiskClient.ParseBotCheck(JsonNode.Parse("""
            {"bot":{"result":"detected","category":"ai_browser","identity":"attested","verifiedBy":"attestation","rule":"browser.new_rule",
                    "signedAgent":"https://agent.example",
                    "reasons":[{"code":"new_sign","text":"A new sign.","weight":3},{"text":"no code"},null,7]},
             "network":null,"suggestion":"observe","rulesVersion":"2027.01.01-1","verdictId":"bcv_123"}
            """));
        Assert.Equal("ai_browser", r.Bot.Category);
        Assert.DoesNotContain("ai_browser", DeviceRiskClient.BotCategories);
        Assert.Equal(("attested", "attestation", "browser.new_rule", "observe"), (r.Bot.Identity, r.Bot.VerifiedBy, r.Bot.Rule, r.Suggestion));
        Assert.Equal(["new_sign"], r.Bot.Reasons.Select(x => x.Code));
        Assert.Null(r.Network);
        Assert.Equal("bcv_123", (string?)r.Raw["verdictId"]);
        Assert.Equal("https://agent.example", (string?)r.Raw["bot"]!["signedAgent"]);
        Assert.Equal(3, (int?)r.Raw["bot"]!["reasons"]![0]!["weight"]);
    }

    [Fact]
    public void AMalformedAnswerReadsAsNothingFoundNeverThrows()
    {
        foreach (var junk in new[] { null, JsonValue.Create("x"), new JsonArray(), JsonNode.Parse("""{"bot":"x","network":"y","suggestion":5}""") })
        {
            var r = DeviceRiskClient.ParseBotCheck(junk);
            Assert.Equal(("not_detected", (string?)null, (string?)null, "allow"), (r.Bot.Result, r.Bot.Category, r.Bot.Identity, r.Suggestion));
            Assert.Empty(r.Bot.Reasons);
            Assert.Null(r.Network);
            Assert.NotNull(r.Raw);
        }
        var odd = DeviceRiskClient.ParseBotCheck(JsonNode.Parse("""{"bot":{"result":"","category":""},"network":{"asn":"15169","asnOrg":7,"hosting":"yes"}}"""));
        Assert.Equal(("not_detected", (string?)null), (odd.Bot.Result, odd.Bot.Category));
        var net = odd.Network ?? throw new InvalidOperationException("no network");
        Assert.Equal((15169L, (string?)null, (string?)null, (bool?)null), (net.Asn, net.AsnOrg, net.CountryCode, net.Hosting));
    }

    [Fact]
    public async Task AnApiErrorIsATypedException()
    {
        var check = new BotCheckRequest { Ip = "203.0.113.7", Headers = [new("User-Agent", "curl/8.4.0")] };

        var (bad, _) = Fake(() => StubHandler.Json(400, new { code = "invalid_ip", error = "ip must be an IPv4 or IPv6 address." }));
        var e = await Assert.ThrowsAsync<TouchqueApiException>(() => bad.BotCheckAsync(check));
        Assert.Equal((400, "invalid_ip", "ip must be an IPv4 or IPv6 address."), (e.Status, e.Code, e.Message));

        var (busy, _) = Fake(() =>
        {
            var res = StubHandler.Json(429, new { error = "integration_quota_exceeded", message = "Too many device_risk_bot_check requests." });
            res.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromSeconds(12));
            return res;
        });
        var q = await Assert.ThrowsAsync<TouchqueApiException>(() => busy.BotCheckAsync(check));
        Assert.Equal((429, "integration_quota_exceeded", 12), (q.Status, q.Error, q.RetryAfter));

        var (off, _) = Fake(() => StubHandler.Json(409, new { code = "device_risk_off", error = "Device risk is off for this workspace." }));
        Assert.Equal("device_risk_off", (await Assert.ThrowsAsync<TouchqueApiException>(() => off.BotCheckAsync(check))).Code);
    }
}
