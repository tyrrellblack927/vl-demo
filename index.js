const expressServer = require("./server");
const service = require("./service");
const initializer = require("./initializer");

const httpServer = expressServer.listen(process.env.PORT || 3030, () => {
    console.log("OAuth Server listening on port", process.env.PORT || 3030);
    Promise.all([
        ...(process.env.OAUTH_CLIENT_ID || "DEFAULT").split(",").map(name => service.createClient({
            id: process.env[`OAUTH_${name}_CLIENT_ID`] || "1",
            secret: process.env[`OAUTH_${name}_CLIENT_SECRET`] || "1",
            grants: ["authorization_code", "refresh_token"],
            redirectUris: (process.env[`OAUTH_${name}_REDIRECT_URLS`] || "http://localhost,https://localhost").split(","),
        })),
        initializer.initUsers()
    ]).then(() => console.log("Initialized"), error => console.error("Can not initialize", error));
});

process.on("SIGTERM", () => {
    console.log("SIGTERM signal received: closing HTTP server");
    httpServer.close(() => console.log("HTTP server closed"));
});
