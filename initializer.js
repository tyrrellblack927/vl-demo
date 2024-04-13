const service = require("./service");
const constants = require("./constants");

module.exports = {
    initUsers() {
        this.creatUsers();
    },
    creatUsers() {
        ["player1", "player2", "player3", "player4", "player5"]
            .map(username => service.createUser({
                name: username,
                username: `${username}@${constants.DEFAULT_EMAIL}`,
                password: constants.DEFAULT_PASSWORD,
                currency: constants.CURRENCIES.USD,
                balance: constants.DEFAULT_CURRENCY_BALANCE[constants.CURRENCIES.USD],
                language: constants.LANGUAGES.en_US
            }));
    }
}
