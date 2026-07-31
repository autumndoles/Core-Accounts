```javascript
const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================================================
CONFIGURATION
========================================================= */

const SESSION_DURATION_DAYS = 30;

const SESSION_DURATION_MS =
    SESSION_DURATION_DAYS *
    24 *
    60 *
    60 *
    1000;

/*
API TOKENS

API tokens are separate from browser sessions.

They are used by external Core Games services,
such as Bad Apples Multiplayer.

The raw token is only shown once when created.
Only the SHA-256 hash is stored in PostgreSQL.
*/

const API_TOKEN_DURATION_DAYS = 30;

const API_TOKEN_DURATION_MS =
    API_TOKEN_DURATION_DAYS *
    24 *
    60 *
    60 *
    1000;

/* =========================================================
POSTGRESQL DATABASE
========================================================= */

if (!process.env.DATABASE_URL) {

    console.error(
        "ERROR: DATABASE_URL environment variable is not set."
    );

    process.exit(1);

}

const pool = new Pool({

    connectionString:
        process.env.DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    }

});

/* =========================================================
MIDDLEWARE
========================================================= */

app.use(
    express.json()
);

app.use(
    express.urlencoded({
        extended: true
    })
);

app.use(
    cookieParser()
);

/* =========================================================
SERVE WEBSITE
========================================================= */

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);

/* =========================================================
DATABASE SETUP
========================================================= */

async function initializeDatabase() {

    try {

        /*
        ACCOUNTS TABLE
        */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id SERIAL PRIMARY KEY,
                username VARCHAR(20) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        /*
        SESSIONS TABLE
        */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS sessions (
                id SERIAL PRIMARY KEY,
                token_hash TEXT UNIQUE NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id)
                    ON DELETE CASCADE,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        /*
        API TOKENS TABLE

        Used by external Core Games applications.

        The actual API token is NEVER stored.

        Only the SHA-256 hash is stored.
        */

        await pool.query(`
            CREATE TABLE IF NOT EXISTS api_tokens (
                id SERIAL PRIMARY KEY,
                token_hash TEXT UNIQUE NOT NULL,
                account_id INTEGER NOT NULL
                    REFERENCES accounts(id)
                    ON DELETE CASCADE,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);


        /*
        INDEX FOR FAST SESSION LOOKUPS
        */

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            sessions_token_hash_index
            ON sessions(token_hash)
        `);


        /*
        INDEX FOR CLEANING EXPIRED SESSIONS
        */

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            sessions_expires_at_index
            ON sessions(expires_at)
        `);


        /*
        INDEX FOR FAST API TOKEN LOOKUPS
        */

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            api_tokens_token_hash_index
            ON api_tokens(token_hash)
        `);


        /*
        INDEX FOR CLEANING EXPIRED API TOKENS
        */

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            api_tokens_expires_at_index
            ON api_tokens(expires_at)
        `);


        console.log(
            "PostgreSQL database initialized successfully."
        );

    } catch (error) {

        console.error(
            "Database initialization error:",
            error
        );

        process.exit(1);

    }

}

/* =========================================================
SESSION HELPERS
========================================================= */

/*
Create a secure random session token.
*/

function createSessionToken() {

    return crypto
        .randomBytes(32)
        .toString("hex");

}


/*
Hash the session token before storing it.

The raw token stays in the user's browser.
Only the hash is stored in PostgreSQL.
*/

function hashSessionToken(token) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


/*
Create a new session for an account.
*/

async function createSession(
    accountId
) {

    const token =
        createSessionToken();

    const tokenHash =
        hashSessionToken(
            token
        );

    const expiresAt =
        new Date(
            Date.now() +
            SESSION_DURATION_MS
        );

    await pool.query(
        `
        INSERT INTO sessions
        (
            token_hash,
            account_id,
            expires_at
        )
        VALUES
        (
            $1,
            $2,
            $3
        )
        `,
        [
            tokenHash,
            accountId,
            expiresAt
        ]
    );

    return token;

}


/*
Get the currently logged-in account
using the browser session cookie.
*/

async function getAccountFromSession(
    req
) {

    const token =
        req.cookies.core_session;

    if (!token) {

        return null;

    }

    const tokenHash =
        hashSessionToken(
            token
        );

    const result =
        await pool.query(
            `
            SELECT
                accounts.id,
                accounts.username,
                accounts.created_at,
                sessions.expires_at
            FROM sessions
            INNER JOIN accounts
                ON accounts.id =
                   sessions.account_id
            WHERE
                sessions.token_hash = $1
            AND
                sessions.expires_at > NOW()
            `,
            [
                tokenHash
            ]
        );

    if (
        result.rows.length === 0
    ) {

        return null;

    }

    return result.rows[0];

}


/*
Set the session cookie.
*/

function setSessionCookie(
    res,
    token
) {

    res.cookie(
        "core_session",
        token,
        {

            httpOnly: true,

            secure: true,

            sameSite: "lax",

            maxAge:
                SESSION_DURATION_MS,

            path: "/"

        }
    );

}


/*
Remove the session cookie.
*/

function clearSessionCookie(
    res
) {

    res.clearCookie(
        "core_session",
        {

            httpOnly: true,

            secure: true,

            sameSite: "lax",

            path: "/"

        }
    );

}

/* =========================================================
API TOKEN HELPERS
========================================================= */

/*
Create a secure random API token.

The token is returned to the application once.

Only the hash is stored in PostgreSQL.
*/

function createApiToken() {

    return (
        "cga_" +
        crypto
            .randomBytes(48)
            .toString("hex")
    );

}


/*
Hash an API token before storing or looking it up.
*/

function hashApiToken(
    token
) {

    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");

}


/*
Create a new API token for an account.
*/

async function createApiTokenForAccount(
    accountId
) {

    const token =
        createApiToken();

    const tokenHash =
        hashApiToken(
            token
        );

    const expiresAt =
        new Date(
            Date.now() +
            API_TOKEN_DURATION_MS
        );

    await pool.query(
        `
        INSERT INTO api_tokens
        (
            token_hash,
            account_id,
            expires_at
        )
        VALUES
        (
            $1,
            $2,
            $3
        )
        `,
        [
            tokenHash,
            accountId,
            expiresAt
        ]
    );

    return {
        token,
        expiresAt
    };

}


/*
Get the account associated with
an API Bearer token.

Expected header:

Authorization: Bearer cga_...
*/

async function getAccountFromApiToken(
    req
) {

    const authorization =
        req.headers.authorization;

    if (
        !authorization
    ) {

        return null;

    }

    const parts =
        authorization.split(
            " "
        );


    if (
        parts.length !== 2 ||
        parts[0].toLowerCase() !==
            "bearer"
    ) {

        return null;

    }


    const token =
        parts[1];


    if (
        !token
    ) {

        return null;

    }


    const tokenHash =
        hashApiToken(
            token
        );


    const result =
        await pool.query(
            `
            SELECT
                accounts.id,
                accounts.username,
                accounts.created_at,
                api_tokens.expires_at
            FROM api_tokens
            INNER JOIN accounts
                ON accounts.id =
                   api_tokens.account_id
            WHERE
                api_tokens.token_hash = $1
            AND
                api_tokens.expires_at > NOW()
            `,
            [
                tokenHash
            ]
        );


    if (
        result.rows.length === 0
    ) {

        return null;

    }


    return result.rows[0];

}

/* =========================================================
REGISTER
========================================================= */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username ||
                    ""
                ).trim();

            const password =
                String(
                    req.body.password ||
                    ""
                );


            /*
            VALIDATE USERNAME
            */

            if (!username) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please enter a username."

                });

            }


            if (
                username.length < 3 ||
                username.length > 20
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username must be between 3 and 20 characters."

                });

            }


            /*
            VALIDATE USERNAME CHARACTERS
            */

            if (
                !/^[a-zA-Z0-9_]+$/.test(
                    username
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Username can only contain letters, numbers, and underscores."

                });

            }


            /*
            VALIDATE PASSWORD
            */

            if (!password) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please enter a password."

                });

            }


            if (
                password.length < 8
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Password must be at least 8 characters."

                });

            }


            /*
            CHECK EXISTING ACCOUNT
            */

            const existingAccount =
                await pool.query(
                    `
                    SELECT id
                    FROM accounts
                    WHERE LOWER(username)
                        = LOWER($1)
                    `,
                    [
                        username
                    ]
                );


            if (
                existingAccount.rows.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "That username is already taken."

                });

            }


            /*
            HASH PASSWORD
            */

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            /*
            CREATE ACCOUNT
            */

            const result =
                await pool.query(
                    `
                    INSERT INTO accounts
                    (
                        username,
                        password_hash
                    )
                    VALUES
                    (
                        $1,
                        $2
                    )
                    RETURNING
                        id,
                        username,
                        created_at
                    `,
                    [
                        username,
                        passwordHash
                    ]
                );


            const account =
                result.rows[0];


            console.log(
                `New Core Games account created: ${account.username}`
            );


            /*
            AUTOMATICALLY LOG THE USER IN
            */

            const sessionToken =
                await createSession(
                    account.id
                );


            setSessionCookie(
                res,
                sessionToken
            );


            return res.status(201).json({

                success: true,

                message:
                    "Account created successfully.",

                username:
                    account.username

            });

        } catch (error) {

            console.error(
                "Registration error:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "An error occurred while creating your account."

            });

        }

    }
);

/* =========================================================
LOGIN
========================================================= */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const username =
                String(
                    req.body.username ||
                    ""
                ).trim();

            const password =
                String(
                    req.body.password ||
                    ""
                );


            if (
                !username ||
                !password
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please enter your username and password."

                });

            }


            /*
            FIND ACCOUNT
            */

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        password_hash
                    FROM accounts
                    WHERE LOWER(username)
                        = LOWER($1)
                    `,
                    [
                        username
                    ]
                );


            const account =
                result.rows[0];


            /*
            DON'T REVEAL WHETHER ACCOUNT EXISTS
            */

            if (!account) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid username or password."

                });

            }


            /*
            CHECK PASSWORD
            */

            const passwordMatches =
                await bcrypt.compare(
                    password,
                    account.password_hash
                );


            if (!passwordMatches) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid username or password."

                });

            }


            /*
            CREATE SESSION
            */

            const sessionToken =
                await createSession(
                    account.id
                );


            setSessionCookie(
                res,
                sessionToken
            );


            console.log(
                `Account logged in: ${account.username}`
            );


            return res.json({

                success: true,

                message:
                    "Login successful.",

                username:
                    account.username

            });

        } catch (error) {

            console.error(
                "Login error:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "An error occurred while logging in."

            });

        }

    }
);

/* =========================================================
CHECK CURRENT SESSION
========================================================= */

app.get(
    "/api/me",
    async (req, res) => {

        try {

            const account =
                await getAccountFromSession(
                    req
                );


            if (!account) {

                return res.status(401).json({

                    success: false,

                    loggedIn: false

                });

            }


            return res.json({

                success: true,

                loggedIn: true,

                username:
                    account.username,

                createdAt:
                    account.created_at,

                sessionExpiresAt:
                    account.expires_at

            });

        } catch (error) {

            console.error(
                "Session check error:",
                error
            );

            return res.status(500).json({

                success: false,

                message:
                    "Unable to check login status."

            });

        }

    }
);

/* =========================================================
LOGOUT
========================================================= */

app.post(
    "/api/logout",
    async (req, res) => {

        try {

            const token =
                req.cookies.core_session;


            if (token) {

                const tokenHash =
                    hashSessionToken(
                        token
                    );


                await pool.query(
                    `
                    DELETE FROM sessions
                    WHERE token_hash = $1
                    `,
                    [
                        tokenHash
                    ]
                );

            }


            clearSessionCookie(
                res
            );


            return res.json({

                success: true,

                message:
                    "Logged out successfully."

            });

        } catch (error) {

            console.error(
                "Logout error:",
                error
            );


            clearSessionCookie(
                res
            );


            return res.status(500).json({

                success: false,

                message:
                    "An error occurred while logging out."

            });

        }

    }
);

/* =========================================================
CORE GAMES API V1
CREATE API TOKEN
========================================================= */

/*
Create an API token for the currently
logged-in Core Games account.

The user must already be logged in
through the Core Games Accounts website.

The raw token is returned only once.
*/

app.post(
    "/api/v1/tokens",
    async (req, res) => {

        try {

            const account =
                await getAccountFromSession(
                    req
                );


            if (!account) {

                return res.status(401).json({

                    success: false,

                    message:
                        "You must be logged in to create an API token."

                });

            }


            /*
            CREATE TOKEN
            */

            const apiToken =
                await createApiTokenForAccount(
                    account.id
                );


            console.log(
                `API token created for account: ${account.username}`
            );


            return res.status(201).json({

                success: true,

                token:
                    apiToken.token,

                tokenType:
                    "Bearer",

                expiresAt:
                    apiToken.expiresAt,

                username:
                    account.username,

                message:
                    "API token created. Store this token securely. It will not be shown again."

            });

        } catch (error) {

            console.error(
                "API token creation error:",
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to create API token."

            });

        }

    }
);

/* =========================================================
CORE GAMES API V1
VERIFY API TOKEN
========================================================= */

/*
External applications can use this endpoint
to identify the Core Games account associated
with an API token.

Expected header:

Authorization: Bearer cga_...
*/

app.get(
    "/api/v1/me",
    async (req, res) => {

        try {

            const account =
                await getAccountFromApiToken(
                    req
                );


            if (!account) {

                return res.status(401).json({

                    success: false,

                    authenticated: false,

                    message:
                        "Invalid or expired API token."

                });

            }


            return res.json({

                success: true,

                authenticated: true,

                user: {

                    id:
                        account.id,

                    username:
                        account.username,

                    createdAt:
                        account.created_at

                },

                tokenExpiresAt:
                    account.expires_at

            });

        } catch (error) {

            console.error(
                "API authentication error:",
                error
            );


            return res.status(500).json({

                success: false,

                authenticated: false,

                message:
                    "Unable to authenticate API token."

            });

        }

    }
);

/* =========================================================
CORE GAMES API V1
REVOKE CURRENT API TOKEN
========================================================= */

/*
Revokes the API token provided in
the Authorization header.
*/

app.delete(
    "/api/v1/tokens",
    async (req, res) => {

        try {

            const authorization =
                req.headers.authorization;


            if (
                !authorization
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Authorization header is required."

                });

            }


            const parts =
                authorization.split(
                    " "
                );


            if (
                parts.length !== 2 ||
                parts[0].toLowerCase() !==
                    "bearer"
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Invalid Authorization header."

                });

            }


            const token =
                parts[1];


            const tokenHash =
                hashApiToken(
                    token
                );


            const result =
                await pool.query(
                    `
                    DELETE FROM api_tokens
                    WHERE token_hash = $1
                    RETURNING id
                    `,
                    [
                        tokenHash
                    ]
                );


            if (
                result.rowCount === 0
            ) {

                return res.status(404).json({

                    success: false,

                    message:
                        "API token not found."

                });

            }


            console.log(
                "API token revoked."
            );


            return res.json({

                success: true,

                message:
                    "API token revoked successfully."

            });

        } catch (error) {

            console.error(
                "API token revocation error:",
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    "Unable to revoke API token."

            });

        }

    }
);

/* =========================================================
CLEAN EXPIRED SESSIONS AND API TOKENS
========================================================= */

async function cleanExpiredSessions() {

    try {

        /*
        CLEAN EXPIRED SESSIONS
        */

        const sessionResult =
            await pool.query(
                `
                DELETE FROM sessions
                WHERE expires_at <= NOW()
                `
            );


        if (
            sessionResult.rowCount > 0
        ) {

            console.log(
                `Cleaned ${sessionResult.rowCount} expired session(s).`
            );

        }


        /*
        CLEAN EXPIRED API TOKENS
        */

        const apiTokenResult =
            await pool.query(
                `
                DELETE FROM api_tokens
                WHERE expires_at <= NOW()
                `
            );


        if (
            apiTokenResult.rowCount > 0
        ) {

            console.log(
                `Cleaned ${apiTokenResult.rowCount} expired API token(s).`
            );

        }

    } catch (error) {

        console.error(
            "Session and API token cleanup error:",
            error
        );

    }

}


/*
Run cleanup every hour.
*/

setInterval(
    cleanExpiredSessions,
    60 * 60 * 1000
);

/* =========================================================
TEST API
========================================================= */

app.get(
    "/api/status",
    (req, res) => {

        res.json({

            online: true,

            service:
                "Core Games Accounts",

            version:
                "4.0.0",

            database:
                "PostgreSQL",

            sessions:
                "PostgreSQL",

            api:
                "Core Games API v1"

        });

    }
);

/* =========================================================
FALLBACK
========================================================= */

app.use(
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "public",
                "index.html"
            )
        );

    }
);

/* =========================================================
START SERVER
========================================================= */

async function startServer() {

    await initializeDatabase();

    await cleanExpiredSessions();


    app.listen(
        PORT,
        "0.0.0.0",
        () => {

            console.log(
                `Core Games Accounts server running on port ${PORT}`
            );

        }
    );

}


startServer();
```
