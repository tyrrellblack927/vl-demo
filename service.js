const Big = require('big.js');
const db = require("./db");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const {v4: uuid} = require("uuid");
const util = require("util");
const constants = require("./constants");
const {uniqueNamesGenerator, names} = require("unique-names-generator");

Big.DP = 2;
Big.RM = 1;

class InvalidRequestError extends Error {
    status = 400;
    name = "invalid_parameter"
}

class InvalidGrantError extends Error {
    status = 400;
    name = "invalid_grant"
}

class InvalidStateError extends Error {
    status = 400;
    name = "invalid_state"
}

const PASSWORD_SALT_ROUNDS = parseInt(process.env.PASSWORD_SALT_ROUNDS || 10);

module.exports = {
    InvalidRequestError,
    InvalidGrantError,
    findDefaultClient() {
        return db.findClientById(process.env.OAUTH_DEFAULT_CLIENT_ID || "1");
    },
    createClient(client) {
        return bcrypt.genSalt(PASSWORD_SALT_ROUNDS)
            .then(salt => bcrypt.hash(client.secret, salt))
            .then(secret => {
                client.secret = secret;
                return db.createClient(client)
            });
    },
    createGuestUser(language) {
        return this.createUser({
            namePrefix: uniqueNamesGenerator({dictionaries: [names]}),
            currency: constants.CURRENCIES.USD,
            type: "guest",
            balance: Big(process.env.INITIAL_BALANCE || 100000),
            language: language || constants.LANGUAGES.en_US
        });
    },
    createUser(user) {
        return Promise.all([
            this.verifyUserInput(user),
            bcrypt.genSalt(PASSWORD_SALT_ROUNDS).then(salt => bcrypt.hash(user.password || user.id, salt))
        ])
            .then(([user, password]) => {
                user.password = password;
                user.name = capitalizeFirstLetter(user.name || (user.namePrefix + randomBetween(0, 500)));
                user.expiresAt = user.type === "guest" ? Date.now() + parseInt(process.env.GUEST_USER_TTL || (24 * 60 * 60 * 1000)) : Number.MAX_SAFE_INTEGER;
                delete user.namePrefix;
                return db.createUser(user);
            });
    },
    updateUser(user) {
        if (user.balance) {
            user.balance = new Big(user.balance);
        }
        if (user.language) {
            user.language = constants.LANGUAGES[user.language.replace("-", "_")] || constants.LANGUAGES.en_US;
        }
        if (user.password) {
            return bcrypt.genSalt(PASSWORD_SALT_ROUNDS)
                .then(salt => bcrypt.hash(user.password, salt))
                .then(password => {
                    user.password = password;
                    return Promise.resolve(user);
                })
                .then(user => db.updateUser(user));
        } else {
            return db.updateUser(user);
        }

    },
    setUserActive(username, active) {
        return db.findUserByUserName(username).then(user => {
            user.active = active;
            if (user.active) {
                return Promise.resolve(user);
            } else {
                return db.deleteTokenAndCode(user.id).then(() => Promise.resolve(user));
            }
        });
    },
    verifyUserInput(user) {
        if (user.balance === undefined || user.balance < 0) {
            return Promise.reject(new InvalidRequestError(`invalid balance ${user.balance}`));
        }
        if (user.currency === undefined) {
            return Promise.reject(new InvalidRequestError(`missing user.currency`));
        }
        if (user.language === undefined) {
            return Promise.reject(new InvalidRequestError(`missing user.language`));
        }
        user.id = uuid();
        user.transactions = {};
        user.username = user.username || user.id;
        user.type = user.type || "real";
        user.balance = new Big(user.balance);
        user.language = user.language.replace("-", "_");
        user.active = true;
        return Promise.resolve(user);
    },
    placeBets(userId, transaction) {
        return db.addTransaction(userId, Big(-transaction.bets.reduce((total, payoff) => total + payoff.betAmount, 0)), transaction);
    },
    payPayOffs(userId, transaction) {
        return db.addTransaction(userId, Big(transaction.payoffs.reduce((total, payoff) => total + payoff.payoffAmount, 0)), transaction);
    },
    reverseTransaction(userId, transaction) {
        return db.addTransaction(userId, Big(transaction.reversalAmount), transaction);
    },
    getClientById: function (clientId) {
        if (!clientId) {
            return Promise.reject(new InvalidRequestError('Missing parameter: `client_id`'));
        }
        return db.findClientById(clientId)
            .then(client => {
                if (!client.grants.includes("authorization_code")) {
                    throw new InvalidGrantError('Unauthorized client: `grant_type` is invalid');
                }
                return client;
            })
            .then(client => ({
                id: client.id,
                redirectUris: client.redirectUris,
                grants: client.grants,
                accessTokenLifetime: client.accessTokenLifetime,
                refreshTokenLifetime: client.refreshTokenLifetime
            }));
    },
    getClientBySecret: function (clientId, clientSecret) {
        if (!clientId) {
            return Promise.reject(new InvalidRequestError('Missing parameter: `client_id`'));
        }
        if (!clientSecret) {
            return Promise.reject(new InvalidRequestError('Missing parameter: `client_secret`'));
        }
        return db.findClientById(clientId)
            .then(client => bcrypt.compare(clientSecret, client.secret).then(result => result ? client : Promise.reject(false)))
            .then(client => ({
                id: client.id,
                redirectUris: client.redirectUris,
                grants: client.grants,
                accessTokenLifetime: client.accessTokenLifetime,
                refreshTokenLifetime: client.refreshTokenLifetime
            }));
    },
    getUser(username) {
        return db.findUserByUserName(username)
            .then(user => {
                if (user.active) {
                    return Promise.resolve(user);
                }
                return Promise.reject(new InvalidStateError(`user ${username} is not active`))
            });
    },
    loginUser(username, password) {
        return this.getUser(username).then(user => bcrypt.compare(password, user.password).then(result => result ? user : Promise.reject(false)));
    },
    getAuthorizationCode(authorizationCode) {
        if (!authorizationCode) {
            return Promise.reject(new InvalidRequestError('Missing parameter: `code`'));
        }
        return db.findAuthorizationCode(authorizationCode)
            .then(code => {
                if (code.expiresAt < Date.now()) {
                    throw new InvalidGrantError('Invalid grant: authorization code has expired');
                }
                return code;
            })
            .then(code => Promise.all([
                code,
                db.findClientById(code.clientId),
                db.findUserById(code.userId)
            ]))
            .then(([code, client, user]) => ({
                authorizationCode: code.authorizationCode,
                expiresAt: code.authorizationCodeExpiresAt,
                client: client,
                user: user
            }));
    },
    getAccessToken(accessToken) {
        if (accessToken.length === 0) {
            return Promise.reject(new InvalidRequestError('Invalid request: only one authentication method is allowed'));
        }
        return db.findAccessToken(accessToken)
            .then(token => {
                if (token.accessTokenExpiresAt < Date.now()) {
                    throw new InvalidGrantError('Invalid token: access token has expired');
                }
                return token;
            })
            .then(token => Promise.all([
                token,
                db.findClientById(token.clientId),
                db.findUserById(token.userId)
            ]))
            .then(([token, client, user]) => ({
                sessionId: token.sessionId,
                accessToken: token.accessToken,
                accessTokenExpiresAt: token.accessTokenExpiresAt,
                client: client,
                user: user
            }));
    },
    getRefreshToken(refreshToken) {
        if (!refreshToken) {
            return Promise.reject(new InvalidRequestError('Missing parameter: `refresh_token`'));
        }
        return db.findRefreshToken(refreshToken)
            .then(token => {
                if (token.refreshTokenExpiresAt < Date.now()) {
                    throw new InvalidGrantError('Invalid token: refresh token has expired');
                }
                return token;
            })
            .then(token => Promise.all([
                token,
                db.findClientById(token.clientId),
                db.findUserById(token.userId)
            ]))
            .then(([token, client, user]) => ({
                refreshToken: token.refreshToken,
                refreshTokenExpiresAt: token.refreshTokenExpiresAt,
                client: client,
                user: user
            }));
    },
    saveAuthorizationCode(redirectUri, client, user) {
        return generateRandomToken()
            .then(authorizationCode => db.saveAuthorizationCode({
                authorizationCode,
                authorizationCodeExpiresAt: Date.now() + parseInt(process.env.AUTH_CODE_TTL || (60 * 1000)),
                redirectUri,
                clientId: client.id,
                userId: user.id,
                created: Date.now()
            }))
            .then(authorizationCode => ({
                authorizationCode: authorizationCode.authorizationCode,
                expiresAt: authorizationCode.authorizationCodeExpiresAt,
                redirectUri: authorizationCode.redirectUri,
                created: authorizationCode.created,
                client: client,
                user: user
            }));
    },
    saveToken(client, user) {
        return Promise.all([generateRandomToken(), generateRandomToken()])
            .then(([accessToken, refreshToken]) => db.saveToken({
                sessionId: uuid(),
                accessToken, refreshToken,
                accessTokenExpiresAt: Date.now() + parseInt(process.env.ACCESS_TOKEN_TTL || (60 * 60 * 1000)),
                refreshTokenExpiresAt: Date.now() + parseInt(process.env.REFRESH_TOKEN_TTL || (24 * 60 * 60 * 1000)),
                clientId: client.id,
                userId: user.id,
                created: Date.now()
            }))
            .then(token => ({
                sessionId: token.sessionId,
                accessToken: token.accessToken,
                accessTokenExpiresAt: token.accessTokenExpiresAt,
                refreshToken: token.refreshToken,
                refreshTokenExpiresAt: token.refreshTokenExpiresAt,
                created: token.created,
                client: client,
                user: user
            }));
    },
    revokeToken(token) {
        return db.deleteToken(token.refreshToken).then(refreshToken => {
            if (!refreshToken) {
                throw new InvalidGrantError('Invalid grant: refresh token is invalid');
            }
            return refreshToken;
        });
    },
    revokeAuthorizationCode(code) {
        return db.deleteAuthorizationCode(code.authorizationCode).then(authorizationCode => {
            if (!authorizationCode) {
                throw new InvalidGrantError('Invalid grant: authorization code is invalid');
            }
            return authorizationCode;
        });
    }
};

function randomBetween(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function capitalizeFirstLetter(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function generateRandomToken() {
    return util.promisify(crypto.randomBytes)(256)
        .then(buffer => crypto
            .createHash("sha1")
            .update(buffer)
            .digest("hex"));
}
