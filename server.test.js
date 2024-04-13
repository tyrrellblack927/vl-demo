const request = require("supertest");
const {JSDOM} = require("jsdom");

jest.useFakeTimers();

const app = require("./server");
const service = require("./service");

beforeAll(() => service.createClient({
    id: "1",
    secret: "1",
    grants: ["authorization_code", "refresh_token"],
    redirectUris: ["https://fl.vegaslounge.live"],
}));

beforeAll(() => service.createUser({
    namePrefix: "player",
    username: "testplayer1@example.com",
    password: "casino",
    language: "zh-CN",
    currency: "USD",
    balance: 10000,
    avatarUrl: "https://img.example.com/avatar.png"
}));

describe("Authorization Endpoints", () => {

    it("should redirect to default client", () => request(app)
        .get("/vlatest/")
        .expect("Location", "/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live")
        .expect(301));

    it("should authorize by password", async () => {
        const agent = request.agent(app);
        await agent
            .get("/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live/lobby")
            .expect(200)
            .then(res => agent
                .post("/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live/lobby")
                .send({
                    _csrf: new JSDOM(res.text).window.document.querySelector("input[name=_csrf]").value,
                    username: "testplayer1@example.com",
                    password: "casino",
                    guest: false
                })
                .expect("Location", /^https:\/\/fl\.vegaslounge\.live\/lobby\?code=.*$/)
                .expect(302));
    });

    it("should generate token", async () => {
        const agent = request.agent(app);
        await agent
            .get("/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live/lobby")
            .expect(200)
            .then(res => agent
                .post("/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live/lobby")
                .send({
                    _csrf: new JSDOM(res.text).window.document.querySelector("input[name=_csrf]").value,
                    username: "testplayer1@example.com",
                    password: "casino",
                    guest: false
                })
                .expect(302))
            .then(res => request(app)
                .post("/vlatest/oauth2.0/token")
                .send({
                    grant_type: "authorization_code",
                    code: res.headers.location.match(/^https:\/\/fl\.vegaslounge\.live\/lobby\?code=(.*)$/)[1],
                    client_id: "1",
                    client_secret: "1"
                })
                .expect(({body}) => {
                    expect(body.access_token).not.toBeUndefined()
                    expect(body.expires_in).not.toBeUndefined();
                    expect(body.refresh_token).not.toBeUndefined();
                }));

    });
});

describe("Authentication Endpoints", () => {

    let accessToken;
    let refreshToken;

    beforeEach(async () => {
        const agent = request.agent(app);
        [accessToken, refreshToken] = await agent
            .get("/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live/lobby")
            .expect(200)
            .then(res => agent
                .post("/vlatest/oauth2.0/authorize?response_type=code&client_id=1&redirect_uri=https://fl.vegaslounge.live/lobby")
                .send({
                    _csrf: new JSDOM(res.text).window.document.querySelector("input[name=_csrf]").value,
                    username: "testplayer1@example.com",
                    password: "casino",
                    guest: false
                })
                .expect(301))
            .then(res => request(app)
                .post("/vlatest/oauth2.0/token")
                .send({
                    grant_type: "authorization_code",
                    code: res.headers.location.match(/^http:\/\/fl.vegaslounge.live\/lobby\?code=(.*)$/)[1],
                    client_id: "1",
                    client_secret: "1"
                }))
            .then(({body}) => [body.access_token, body.refresh_token]);
    });

    it("should refresh token", () => request(app)
        .post("/vlatest/oauth2.0/token")
        .send({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: "1",
            client_secret: "1"
        })
        .expect(200)
        .expect(({body}) => {
            expect(body.access_token).not.toBeUndefined()
            expect(body.expires_in).not.toBeUndefined();
            expect(body.refresh_token).not.toBeUndefined();
        })
        .then(({body}) => request(app)
            .get("/vlatest/account")
            .set("Authorization", "Bearer " + body.access_token)
            .expect(200)));

    it("should redirect to default client", () => request(app)
        .get("/vlatest/account")
        .set("Authorization", "Bearer " + accessToken)
        .expect(200)
        .expect(({body}) => {
            expect(body.playerId).not.toBeUndefined()
            expect(body.sessionId).not.toBeUndefined();
            expect(body.currency).not.toBeUndefined();
            expect(body.balance).not.toBeUndefined();
            expect(body.language).not.toBeUndefined();
            expect(body.playerName).not.toBeUndefined();
            expect(body.avatarUrl).not.toBeUndefined();
        }));

    it("should be able to place bets", () => request(app)
        .get("/vlatest/balance")
        .set("Authorization", "Bearer " + accessToken)
        .expect(200)
        .then(({body: {balance}}) => request(app)
            .post("/vlatest/bet")
            .send({
                txId: "dc4adb70-e029-460a-8681-be72e720f64f",
                tableId: "sha.s3",
                live: false,
                gameType: "BACCARAT",
                gameId: "sha.d88",
                minBet: 1,
                maxBet: 500,
                bets: [
                    {betType: "RL_SPL7_10", betAmount: 100},
                    {betType: "RL_BLACK", betAmount: 200}
                ]
            })
            .set("Authorization", "Bearer " + accessToken)
            .expect(200)
            .expect(({body}) => {
                expect(body.txId).toEqual("dc4adb70-e029-460a-8681-be72e720f64f");
                expect(body.balance).toEqual(balance - 300);
            }))
    );

    it("should be able to place payoff", () => request(app)
        .get("/vlatest/balance")
        .set("Authorization", "Bearer " + accessToken)
        .expect(200)
        .then(({body: {balance}}) => request(app)
            .post("/vlatest/payoff")
            .send({
                txId: "dc4adb70-e029-460a-8681-be72e720f64f",
                tableId: "sha.s3",
                live: false,
                gameType: "BACCARAT",
                gameId: "sha.d88",
                minBet: 1,
                maxBet: 500,
                payoffs: [
                    {betType: "RL_SPL7_10", payoffAmount: 1000}
                ]
            })
            .set("Authorization", "Bearer " + accessToken)
            .expect(200)
            .expect(({body}) => {
                expect(body.txId).toEqual("dc4adb70-e029-460a-8681-be72e720f64f");
                expect(body.balance).toEqual(balance + 1000);
            }))
    );
});
