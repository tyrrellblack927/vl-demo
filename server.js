const express = require("express");
const csurf = require("csurf");
const hbs = require("hbs");
const helmet = require("helmet");
const session = require("express-session");
const service = require("./service");
const compression = require("compression");
const morgan = require("morgan")

const csrfProtection = csurf();

const BASE_URL = `/v${process.env.RELEASE_VERSION || "latest"}`;

module.exports = express()
    .use((process.env.SECURE_SESSION || "false") === "true" ? helmet() : (req, res, next) => next())
    .use(compression())
    .set("trust proxy", parseInt(process.env.TRUST_PROXY || "0"))
    .set("view engine", "html")
    .set("views", `./public/${process.env.SKIN || "example"}/`)
    .engine("html", hbs.__express)
    .use(BASE_URL + "/", express.static(`./public/${process.env.SKIN || "example"}/`, {
        maxAge: "30d"
    }))
    .use(session({
        secret: process.env.SESSION_SECRET || "test",
        resave: false,
        saveUninitialized: false,
        cookie: {secure: (process.env.SECURE_SESSION || "false") === "true"}
    }))
    .use(express.urlencoded({extended: false}))
    .use(express.json())
    .get(BASE_URL + "/healthcheck", (req, res) => res.status(200).send({state: "healthy"}))
    .post(BASE_URL + "/internal/createUser", (req, res, next) => {
        service.createUser(req.body).then(user => {
            console.log("user created", user);
            res.status(200).send(user);
        }).catch(error => next(error ? error : new service.InvalidRequestError("Invalid user input")));
    })
    .post(BASE_URL + "/internal/updateUser", (req, res, next) => {
        service.updateUser(req.body).then(user => {
            console.log("user updated", user);
            res.status(200).send(user);
        }).catch(error => next(error ? error : new service.InvalidRequestError("Invalid user input")));
    })
    .post(BASE_URL + "/internal/setUserActive", (req, res, next) => {
        service.setUserActive(req.body.username, req.body.active).then(user => {
            res.status(200).send({username: user.username, active: user.active});
        }).catch(error => next(error ? error : new service.InvalidRequestError("Invalid user input")));
    })
    .use(morgan(':remote-addr [:date[clf]] :method ":url" HTTP/:http-version :status :total-time ms ":referrer" ":user-agent"'))
    .get(["/", BASE_URL + "/"], (req, res, next) => service.findDefaultClient()
        .then(client => res.redirect(301, `${BASE_URL}/oauth2.0/authorize?response_type=code&client_id=${client.id}&redirect_uri=${client.redirectUris[0]}`))
        .catch(error => next(error ? error : new service.InvalidRequestError("Can not find default client"))))
    .get(BASE_URL + "/oauth2.0/authorize", csrfProtection, (req, res, next) =>
        req.session.user ? authorizeHandler(req, res, next) : res.render("oauth2.0/login", {
            csrfToken: req.csrfToken(),
            actionUrl: req.url
        }))
    .post(BASE_URL + "/oauth2.0/authorize", csrfProtection, (req, res, next) => {
        (req.body.guest === "true" ? service.createGuestUser(req.acceptsLanguages((process.env.SUPPORTED_LANGUGES || "en-US").split(","))) :
            loginUser(req.body.username, req.body.password))
            .then(user => {
                req.session.user = user;
                return authorizeHandler(req, res, next);
            })
            .catch(error => next(error ? error : new service.InvalidRequestError("Invalid grant: user credentials are invalid")))
    })
    .post(BASE_URL + "/oauth2.0/token", tokenHandler)
    .get(BASE_URL + "/logout", (req, res) => {
        req.session.destroy();
        res.redirect(301, "/");
    })
    .get(BASE_URL + "/account", authenticateHandler, (req, res) => res.status(200).send({
        sessionId: res.locals.oauth.token.sessionId,
        currency: res.locals.oauth.token.user.currency,
        balance: res.locals.oauth.token.user.balance,
        language: res.locals.oauth.token.user.language,
        playerId: res.locals.oauth.token.user.username,
        playerName: res.locals.oauth.token.user.name,
        avatarUrl: res.locals.oauth.token.user.avatarUrl,
    }))
    .get(BASE_URL + "/balance", authenticateHandler, (req, res) => res.status(200).send({
        balance: res.locals.oauth.token.user.balance
    }))
    .post(BASE_URL + "/bet", authenticateHandler, (req, res, next) =>
        service.placeBets(res.locals.oauth.token.user.id, req.body)
            .then(balance => res.status(200).send({balance, txId: req.body.txId}))
            .catch(error => next(error ? error : new service.InvalidRequestError("Invalid token"))))
    .post(BASE_URL + "/payoff", authenticateHandler, (req, res, next) =>
        service.payPayOffs(res.locals.oauth.token.user.id, req.body)
            .then(balance => res.status(200).send({balance, txId: req.body.txId}))
            .catch(error => next(error ? error : new service.InvalidRequestError("Invalid token"))))
    .post(BASE_URL + "/reverse", authenticateHandler, (req, res, next) =>
        service.reverseTransaction(res.locals.oauth.token.user.id, req.body)
            .then(balance => res.status(200).send({balance, txId: req.body.txId}))
            .catch(error => next(error ? error : new service.InvalidRequestError("Invalid token"))))
    .use((err, req, res, next) => {
        if (res.headersSent) {
            return next(err);
        }
        console.error(req.url, JSON.stringify(req.body), err.stack);
        res.status(err.status || 500).send({
            errorCode: err.status,
            error: err.name,
            ...err.props
        });
    })

function loginUser(username, password) {
    if (!username) {
        return Promise.reject(new service.InvalidRequestError("Missing parameter: `username`"));
    }
    if (!password) {
        return Promise.reject(new service.InvalidRequestError("Missing parameter: `password`"));
    }
    return service.loginUser(username, password);
}

async function tokenHandler(req, res, next) {
    try {
        const grantType = req.body.grant_type;
        if (!grantType) {
            throw new service.InvalidRequestError("Missing parameter: `grant_type`");
        }
        const client = await service.getClientBySecret(req.body.client_id, req.body.client_secret);
        if (!client.grants.includes(grantType)) {
            throw new service.InvalidRequestError("Invalid parameter: `grant_type`");
        }
        if (grantType === "authorization_code") {
            const authorizationCode = await service.getAuthorizationCode(req.body.code);
            await service.revokeAuthorizationCode(authorizationCode);
            const token = await service.saveToken(authorizationCode.client, authorizationCode.user);
            res.status(200).send({
                access_token: token.accessToken,
                expires_in: (token.accessTokenExpiresAt - token.created) / 1000,
                refresh_token: token.refreshToken,
            });
        } else if (grantType === "refresh_token") {
            let token = await service.getRefreshToken(req.body.refresh_token);
            await service.revokeToken(token);
            token = await service.saveToken(token.client, token.user);
            res.status(200).send({
                access_token: token.accessToken,
                expires_in: (token.accessTokenExpiresAt - token.created) / 1000,
                refresh_token: token.refreshToken,
            });
        } else {
            throw new service.InvalidRequestError("Invalid parameter: `grant_type`");
        }
    } catch (error) {
        return next(error ? error : new service.InvalidRequestError("Invalid grant: user credentials are invalid"));
    }
}

async function authorizeHandler(req, res, next) {
    try {
        const redirectUri = req.body.redirect_uri || req.query.redirect_uri;
        if (!redirectUri) {
            throw new service.InvalidRequestError("Missing parameter: `redirect_uri`");
        }
        if (!redirectUri) {
            throw new service.InvalidRequestError("Invalid request: `redirect_uri` is not a valid URI");
        }
        const client = await service.getClientById(req.body.client_id || req.query.client_id);
        if (!client.redirectUris.some(prefix => redirectUri.startsWith(prefix))) {
            throw new service.InvalidRequestError(`Invalid client: 'redirect_uri' does not match client value : ${redirectUri}`);
        }
        if (!req.session.user) {
            throw new service.InvalidRequestError("Invalid user: `session` did not return a `user` object");
        }
        const user = await service.getUser(req.session.user.username);
        const token = await service.saveAuthorizationCode(redirectUri, client, user);
        const uri = new URL(redirectUri);
        uri.searchParams = new URLSearchParams();
        uri.searchParams.delete("code");
        uri.searchParams.delete("state");
        uri.searchParams.append("code", token.authorizationCode);
        const state = req.body.state || req.query.state;
        if (state) {
            uri.searchParams.append("state", state);
        }
        res.redirect(302, uri.toString());
    } catch (error) {
        return next(error ? error : new service.InvalidRequestError("Invalid grant: user credentials are invalid"));
    }
}

async function authenticateHandler(req, res, next) {
    try {
        res.locals.oauth = {token: await service.getAccessToken((req.get("Authorization") || "").match(/Bearer\s(\S+)/)[1] || req.query.access_token || req.body.access_token || "")};
        next();
    } catch (error) {
        return next(error ? error : new service.InvalidRequestError("Invalid grant: user credentials are invalid"));
    }
}


