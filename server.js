const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { Pool } = require("pg");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

/* =========================================================
CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;

const SESSION_DURATION_DAYS = 30;
const SESSION_DURATION_MS =
SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000;

const API_TOKEN_DURATION_DAYS = 30;
const API_TOKEN_DURATION_MS =
API_TOKEN_DURATION_DAYS * 24 * 60 * 60 * 1000;

/* =========================================================
ALLOWED FRONTEND ORIGINS
========================================================= */

/*
Your launcher currently runs locally at:

```
http://localhost:3000

When you deploy the launcher to Render, add its URL here.

Example:

"https://core-games-launcher.onrender.com"
```

*/

const allowedOrigins = [
"http://localhost:3000"
];

/* =========================================================
SOCKET.IO
========================================================= */

const io = new Server(server, {
cors: {
origin: allowedOrigins,
credentials: true
}
});

/* =========================================================
POSTGRESQL DATABASE
========================================================= */

if (!process.env.DATABASE_URL) {

```
console.error(
    "ERROR: DATABASE_URL environment variable is not set."
);

process.exit(1);
```

}

const pool = new Pool({

```
connectionString:
    process.env.DATABASE_URL,

ssl: {
    rejectUnauthorized: false
}
```

});

/* =========================================================
MIDDLEWARE
========================================================= */

app.use(
cors({
origin: function(origin, callback) {

```
        /*
            Requests without an Origin header can happen
            from tools, server-side requests, or direct API calls.
        */

        if (!origin) {
            return callback(null, true);
        }

        if (
            allowedOrigins.includes(origin)
        ) {

            return callback(null, true);

        }

        return callback(
            new Error(
                "CORS origin not allowed."
            )
        );

    },

    credentials: true
})
```

);

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

```
try {

    /* ACCOUNTS */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            username VARCHAR(20) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);


    /* SESSIONS */

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


    /* API TOKENS */

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


    /* FRIEND REQUESTS */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS friend_requests (
            id SERIAL PRIMARY KEY,

            sender_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            receiver_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            status VARCHAR(20) NOT NULL
                DEFAULT 'pending',

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(sender_id, receiver_id)
        )
    `);


    /* FRIENDSHIPS */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,

            user_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            friend_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            UNIQUE(user_id, friend_id)
        )
    `);


    /* MESSAGES */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,

            sender_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            receiver_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            message TEXT NOT NULL,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    `);


    /* INDEXES */

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        sessions_token_hash_index
        ON sessions(token_hash)
    `);


    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        sessions_expires_at_index
        ON sessions(expires_at)
    `);


    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        api_tokens_token_hash_index
        ON api_tokens(token_hash)
    `);


    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        api_tokens_expires_at_index
        ON api_tokens(expires_at)
    `);


    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        friend_requests_receiver_index
        ON friend_requests(receiver_id)
    `);


    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        friendships_user_index
        ON friendships(user_id)
    `);


    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        messages_conversation_index
        ON messages(
            sender_id,
            receiver_id,
            created_at
        )
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
```

}

/* =========================================================
SESSION HELPERS
========================================================= */

function createSessionToken() {

```
return crypto
    .randomBytes(32)
    .toString("hex");
```

}

function hashSessionToken(token) {

```
return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
```

}

async function createSession(accountId) {

```
const token =
    createSessionToken();

const tokenHash =
    hashSessionToken(token);

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
    ($1, $2, $3)
    `,
    [
        tokenHash,
        accountId,
        expiresAt
    ]
);


return token;
```

}

async function getAccountFromSession(req) {

```
const token =
    req.cookies.core_session;


if (!token) {

    return null;

}


const tokenHash =
    hashSessionToken(token);


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
```

}

function setSessionCookie(
res,
token
) {

```
res.cookie(
    "core_session",
    token,
    {
        httpOnly: true,

        secure: true,

        /*
            Lax works when the launcher and account server
            are same-site. We will test this after deployment.
        */

        sameSite: "lax",

        maxAge:
            SESSION_DURATION_MS,

        path: "/"
    }
);
```

}

function clearSessionCookie(
res
) {

```
res.clearCookie(
    "core_session",
    {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/"
    }
);
```

}

/* =========================================================
API TOKEN HELPERS
========================================================= */

function createApiToken() {

```
return (
    "cga_" +
    crypto
        .randomBytes(48)
        .toString("hex")
);
```

}

function hashApiToken(token) {

```
return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
```

}

async function createApiTokenForAccount(
accountId
) {

```
const token =
    createApiToken();

const tokenHash =
    hashApiToken(token);

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
    ($1, $2, $3)
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
```

}

async function getAccountFromApiToken(
req
) {

```
const authorization =
    req.headers.authorization;


if (!authorization) {

    return null;

}


const parts =
    authorization.split(" ");


if (
    parts.length !== 2 ||
    parts[0].toLowerCase() !==
        "bearer"
) {

    return null;

}


const token =
    parts[1];


if (!token) {

    return null;

}


const tokenHash =
    hashApiToken(token);


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
```

}

/* =========================================================
REGISTER
========================================================= */

app.post(
"/api/register",
async (req, res) => {

```
    try {

        const username =
            String(
                req.body.username || ""
            ).trim();


        const password =
            String(
                req.body.password || ""
            );


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


        const existingAccount =
            await pool.query(
                `
                SELECT id

                FROM accounts

                WHERE
                    LOWER(username) =
                    LOWER($1)
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


        const passwordHash =
            await bcrypt.hash(
                password,
                12
            );


        const result =
            await pool.query(
                `
                INSERT INTO accounts
                (
                    username,
                    password_hash
                )

                VALUES
                ($1, $2)

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


        const sessionToken =
            await createSession(
                account.id
            );


        setSessionCookie(
            res,
            sessionToken
        );


        console.log(
            "New Core Games account created: " +
            account.username
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
```

);

/* =========================================================
LOGIN
========================================================= */

app.post(
"/api/login",
async (req, res) => {

```
    try {

        const username =
            String(
                req.body.username || ""
            ).trim();


        const password =
            String(
                req.body.password || ""
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


        const result =
            await pool.query(
                `
                SELECT
                    id,
                    username,
                    password_hash

                FROM accounts

                WHERE
                    LOWER(username) =
                    LOWER($1)
                `,
                [
                    username
                ]
            );


        const account =
            result.rows[0];


        if (!account) {

            return res.status(401).json({
                success: false,
                message:
                    "Invalid username or password."
            });

        }


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


        const sessionToken =
            await createSession(
                account.id
            );


        setSessionCookie(
            res,
            sessionToken
        );


        console.log(
            "Account logged in: " +
            account.username
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
```

);

/* =========================================================
CHECK CURRENT SESSION
========================================================= */

app.get(
"/api/me",
async (req, res) => {

```
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
```

);

/* =========================================================
LOGOUT
========================================================= */

app.post(
"/api/logout",
async (req, res) => {

```
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

                WHERE
                    token_hash = $1
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
```

);

/* =========================================================
SOCIAL AUTHENTICATION MIDDLEWARE
========================================================= */

async function requireLogin(
req,
res,
next
) {

```
try {

    const account =
        await getAccountFromSession(
            req
        );


    if (!account) {

        return res.status(401).json({
            success: false,
            message:
                "You must be logged in."
        });

    }


    req.account =
        account;


    next();

} catch (error) {

    console.error(
        "Authentication error:",
        error
    );


    return res.status(500).json({
        success: false,
        message:
            "Unable to authenticate account."
    });

}
```

}

/* =========================================================
USER SEARCH
========================================================= */

app.get(
"/api/users/search",
requireLogin,
async (req, res) => {

```
    try {

        const query =
            String(
                req.query.q || ""
            ).trim();


        if (
            query.length < 2
        ) {

            return res.json({
                success: true,
                users: []
            });

        }


        const result =
            await pool.query(
                `
                SELECT
                    id,
                    username

                FROM accounts

                WHERE
                    username ILIKE $1

                AND
                    id != $2

                ORDER BY
                    username

                LIMIT 20
                `,
                [
                    `%${query}%`,
                    req.account.id
                ]
            );


        return res.json({
            success: true,
            users:
                result.rows
        });

    } catch (error) {

        console.error(
            "User search error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to search users."
        });

    }

}
```

);

/* =========================================================
SEND FRIEND REQUEST
========================================================= */

app.post(
"/api/friends/request",
requireLogin,
async (req, res) => {

```
    try {

        const username =
            String(
                req.body.username || ""
            ).trim();


        if (!username) {

            return res.status(400).json({
                success: false,
                message:
                    "Username is required."
            });

        }


        const userResult =
            await pool.query(
                `
                SELECT
                    id,
                    username

                FROM accounts

                WHERE
                    LOWER(username) =
                    LOWER($1)
                `,
                [
                    username
                ]
            );


        if (
            userResult.rows.length === 0
        ) {

            return res.status(404).json({
                success: false,
                message:
                    "User not found."
            });

        }


        const target =
            userResult.rows[0];


        if (
            target.id ===
            req.account.id
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "You cannot add yourself."
            });

        }


        const friendship =
            await pool.query(
                `
                SELECT id

                FROM friendships

                WHERE
                (
                    user_id = $1
                    AND
                    friend_id = $2
                )

                OR

                (
                    user_id = $2
                    AND
                    friend_id = $1
                )

                LIMIT 1
                `,
                [
                    req.account.id,
                    target.id
                ]
            );


        if (
            friendship.rows.length > 0
        ) {

            return res.status(409).json({
                success: false,
                message:
                    "You are already friends."
            });

        }


        const existingRequest =
            await pool.query(
                `
                SELECT
                    id,
                    sender_id,
                    receiver_id,
                    status

                FROM friend_requests

                WHERE
                (
                    (
                        sender_id = $1
                        AND
                        receiver_id = $2
                    )

                    OR

                    (
                        sender_id = $2
                        AND
                        receiver_id = $1
                    )
                )

                AND
                    status = 'pending'

                LIMIT 1
                `,
                [
                    req.account.id,
                    target.id
                ]
            );


        if (
            existingRequest.rows.length > 0
        ) {

            return res.status(409).json({
                success: false,
                message:
                    "A friend request already exists."
            });

        }


        await pool.query(
            `
            INSERT INTO friend_requests
            (
                sender_id,
                receiver_id
            )

            VALUES
            ($1, $2)
            `,
            [
                req.account.id,
                target.id
            ]
        );


        return res.json({
            success: true,
            message:
                "Friend request sent."
        });

    } catch (error) {

        console.error(
            "Friend request error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to send friend request."
        });

    }

}
```

);

/* =========================================================
GET FRIEND REQUESTS
========================================================= */

app.get(
"/api/friends/requests",
requireLogin,
async (req, res) => {

```
    try {

        const result =
            await pool.query(
                `
                SELECT
                    friend_requests.id,
                    accounts.username,
                    friend_requests.created_at

                FROM friend_requests

                INNER JOIN accounts
                    ON accounts.id =
                       friend_requests.sender_id

                WHERE
                    friend_requests.receiver_id = $1

                AND
                    friend_requests.status =
                    'pending'

                ORDER BY
                    friend_requests.created_at DESC
                `,
                [
                    req.account.id
                ]
            );


        return res.json({
            success: true,
            requests:
                result.rows
        });

    } catch (error) {

        console.error(
            "Friend request list error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to load friend requests."
        });

    }

}
```

);

/* =========================================================
ACCEPT FRIEND REQUEST
========================================================= */

app.post(
"/api/friends/requests/:id/accept",
requireLogin,
async (req, res) => {

```
    const client =
        await pool.connect();


    try {

        await client.query(
            "BEGIN"
        );


        const requestResult =
            await client.query(
                `
                SELECT
                    id,
                    sender_id,
                    receiver_id

                FROM friend_requests

                WHERE
                    id = $1

                AND
                    receiver_id = $2

                AND
                    status = 'pending'

                FOR UPDATE
                `,
                [
                    req.params.id,
                    req.account.id
                ]
            );


        if (
            requestResult.rows.length === 0
        ) {

            await client.query(
                "ROLLBACK"
            );


            return res.status(404).json({
                success: false,
                message:
                    "Friend request not found."
            });

        }


        const request =
            requestResult.rows[0];


        await client.query(
            `
            UPDATE friend_requests

            SET
                status = 'accepted'

            WHERE
                id = $1
            `,
            [
                request.id
            ]
        );


        await client.query(
            `
            INSERT INTO friendships
            (
                user_id,
                friend_id
            )

            VALUES
            ($1, $2),
            ($2, $1)

            ON CONFLICT DO NOTHING
            `,
            [
                request.sender_id,
                request.receiver_id
            ]
        );


        await client.query(
            "COMMIT"
        );


        return res.json({
            success: true,
            message:
                "Friend request accepted."
        });

    } catch (error) {

        await client.query(
            "ROLLBACK"
        );


        console.error(
            "Accept friend request error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to accept friend request."
        });

    } finally {

        client.release();

    }

}
```

);

/* =========================================================
DECLINE FRIEND REQUEST
========================================================= */

app.post(
"/api/friends/requests/:id/decline",
requireLogin,
async (req, res) => {

```
    try {

        const result =
            await pool.query(
                `
                DELETE FROM friend_requests

                WHERE
                    id = $1

                AND
                    receiver_id = $2

                RETURNING id
                `,
                [
                    req.params.id,
                    req.account.id
                ]
            );


        if (
            result.rowCount === 0
        ) {

            return res.status(404).json({
                success: false,
                message:
                    "Friend request not found."
            });

        }


        return res.json({
            success: true,
            message:
                "Friend request declined."
        });

    } catch (error) {

        console.error(
            "Decline friend request error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to decline friend request."
        });

    }

}
```

);

/* =========================================================
GET FRIENDS
========================================================= */

app.get(
"/api/friends",
requireLogin,
async (req, res) => {

```
    try {

        const result =
            await pool.query(
                `
                SELECT
                    accounts.id,
                    accounts.username

                FROM friendships

                INNER JOIN accounts
                    ON accounts.id =
                       friendships.friend_id

                WHERE
                    friendships.user_id = $1

                ORDER BY
                    accounts.username
                `,
                [
                    req.account.id
                ]
            );


        return res.json({
            success: true,
            friends:
                result.rows
        });

    } catch (error) {

        console.error(
            "Friends list error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to load friends."
        });

    }

}
```

);

/* =========================================================
REMOVE FRIEND
========================================================= */

app.delete(
"/api/friends/:friendId",
requireLogin,
async (req, res) => {

```
    try {

        await pool.query(
            `
            DELETE FROM friendships

            WHERE
            (
                user_id = $1
                AND
                friend_id = $2
            )

            OR

            (
                user_id = $2
                AND
                friend_id = $1
            )
            `,
            [
                req.account.id,
                req.params.friendId
            ]
        );


        return res.json({
            success: true,
            message:
                "Friend removed."
        });

    } catch (error) {

        console.error(
            "Remove friend error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to remove friend."
        });

    }

}
```

);

/* =========================================================
GET MESSAGE HISTORY
========================================================= */

app.get(
"/api/messages/:friendId",
requireLogin,
async (req, res) => {

```
    try {

        const friendId =
            Number(
                req.params.friendId
            );


        if (
            !Number.isInteger(
                friendId
            )
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid friend ID."
            });

        }


        const friendship =
            await pool.query(
                `
                SELECT id

                FROM friendships

                WHERE
                    user_id = $1

                AND
                    friend_id = $2
                `,
                [
                    req.account.id,
                    friendId
                ]
            );


        if (
            friendship.rows.length === 0
        ) {

            return res.status(403).json({
                success: false,
                message:
                    "You can only message your friends."
            });

        }


        const result =
            await pool.query(
                `
                SELECT
                    messages.id,

                    messages.sender_id,

                    sender.username
                        AS sender_username,

                    messages.receiver_id,

                    receiver.username
                        AS receiver_username,

                    messages.message,

                    messages.created_at

                FROM messages

                INNER JOIN accounts sender
                    ON sender.id =
                       messages.sender_id

                INNER JOIN accounts receiver
                    ON receiver.id =
                       messages.receiver_id

                WHERE
                (
                    messages.sender_id = $1
                    AND
                    messages.receiver_id = $2
                )

                OR

                (
                    messages.sender_id = $2
                    AND
                    messages.receiver_id = $1
                )

                ORDER BY
                    messages.created_at ASC

                LIMIT 100
                `,
                [
                    req.account.id,
                    friendId
                ]
            );


        return res.json({
            success: true,
            messages:
                result.rows
        });

    } catch (error) {

        console.error(
            "Message history error:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Unable to load messages."
        });

    }

}
```

);

/* =========================================================
CREATE API TOKEN
========================================================= */

app.post(
"/api/v1/tokens",
async (req, res) => {

```
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


        const apiToken =
            await createApiTokenForAccount(
                account.id
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
                "API token created. Store this token securely."
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
```

);

/* =========================================================
VERIFY API TOKEN
========================================================= */

app.get(
"/api/v1/me",
async (req, res) => {

```
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
```

);

/* =========================================================
REVOKE API TOKEN
========================================================= */

app.delete(
"/api/v1/tokens",
async (req, res) => {

```
    try {

        const authorization =
            req.headers.authorization;


        if (!authorization) {

            return res.status(400).json({
                success: false,
                message:
                    "Authorization header is required."
            });

        }


        const parts =
            authorization.split(" ");


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

                WHERE
                    token_hash = $1

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
```

);

/* =========================================================
SOCKET.IO AUTHENTICATION
========================================================= */

io.use(
async (socket, next) => {

```
    try {

        const cookieHeader =
            socket.handshake.headers.cookie;


        if (!cookieHeader) {

            return next(
                new Error(
                    "Not authenticated"
                )
            );

        }


        const cookies = {};


        cookieHeader
            .split(";")
            .forEach(
                cookie => {

                    const parts =
                        cookie
                            .trim()
                            .split("=");


                    const key =
                        parts.shift();


                    const value =
                        parts.join("=");


                    if (key) {

                        cookies[key] =
                            decodeURIComponent(
                                value
                            );

                    }

                }
            );


        const token =
            cookies.core_session;


        if (!token) {

            return next(
                new Error(
                    "Not authenticated"
                )
            );

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
                    accounts.username

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

            return next(
                new Error(
                    "Session expired"
                )
            );

        }


        socket.account =
            result.rows[0];


        next();

    } catch (error) {

        console.error(
            "Socket authentication error:",
            error
        );


        next(
            new Error(
                "Authentication failed"
            )
        );

    }

}
```

);

/* =========================================================
ONLINE USERS
========================================================= */

const onlineUsers =
new Map();

function setUserOnline(
accountId,
socketId
) {

```
if (
    !onlineUsers.has(
        accountId
    )
) {

    onlineUsers.set(
        accountId,
        new Set()
    );

}


onlineUsers
    .get(accountId)
    .add(socketId);
```

}

function setUserOffline(
accountId,
socketId
) {

```
if (
    !onlineUsers.has(
        accountId
    )
) {

    return;

}


const sockets =
    onlineUsers.get(
        accountId
    );


sockets.delete(
    socketId
);


if (
    sockets.size === 0
) {

    onlineUsers.delete(
        accountId
    );

}
```

}

function isUserOnline(
accountId
) {

```
return onlineUsers.has(
    accountId
);
```

}

/* =========================================================
SOCKET.IO CONNECTION
========================================================= */

io.on(
"connection",
socket => {

```
    const account =
        socket.account;


    setUserOnline(
        account.id,
        socket.id
    );


    console.log(
        "User connected: " +
        account.username
    );


    socket.emit(
        "presence",
        {
            userId:
                account.id,

            online: true
        }
    );


    socket.on(
        "getPresence",
        userId => {

            const numericUserId =
                Number(
                    userId
                );


            socket.emit(
                "presence",
                {
                    userId:
                        numericUserId,

                    online:
                        isUserOnline(
                            numericUserId
                        )
                }
            );

        }
    );


    socket.on(
        "sendMessage",
        async data => {

            try {

                const receiverId =
                    Number(
                        data.receiverId
                    );


                const message =
                    String(
                        data.message || ""
                    ).trim();


                if (
                    !Number.isInteger(
                        receiverId
                    )
                ) {

                    return socket.emit(
                        "messageError",
                        {
                            message:
                                "Invalid receiver."
                        }
                    );

                }


                if (
                    receiverId ===
                    account.id
                ) {

                    return socket.emit(
                        "messageError",
                        {
                            message:
                                "You cannot message yourself."
                        }
                    );

                }


                if (
                    !message ||
                    message.length > 2000
                ) {

                    return socket.emit(
                        "messageError",
                        {
                            message:
                                "Message must be between 1 and 2000 characters."
                        }
                    );

                }


                const friendship =
                    await pool.query(
                        `
                        SELECT id

                        FROM friendships

                        WHERE
                            user_id = $1

                        AND
                            friend_id = $2
                        `,
                        [
                            account.id,
                            receiverId
                        ]
                    );


                if (
                    friendship.rows.length === 0
                ) {

                    return socket.emit(
                        "messageError",
                        {
                            message:
                                "You can only message your friends."
                        }
                    );

                }


                const result =
                    await pool.query(
                        `
                        INSERT INTO messages

                        (
                            sender_id,
                            receiver_id,
                            message
                        )

                        VALUES
                        ($1, $2, $3)

                        RETURNING
                            id,
                            sender_id,
                            receiver_id,
                            message,
                            created_at
                        `,
                        [
                            account.id,
                            receiverId,
                            message
                        ]
                    );


                const savedMessage =
                    result.rows[0];


                const messageData = {

                    id:
                        savedMessage.id,

                    senderId:
                        savedMessage.sender_id,

                    receiverId:
                        savedMessage.receiver_id,

                    message:
                        savedMessage.message,

                    createdAt:
                        savedMessage.created_at

                };


                socket.emit(
                    "newMessage",
                    messageData
                );


                for (
                    const [
                        socketId,
                        socketSet
                    ]
                    of io.sockets.sockets
                ) {

                    if (
                        socketSet.account &&
                        socketSet.account.id ===
                            receiverId
                    ) {

                        socketSet.emit(
                            "newMessage",
                            messageData
                        );

                    }

                }

            } catch (error) {

                console.error(
                    "Socket message error:",
                    error
                );


                socket.emit(
                    "messageError",
                    {
                        message:
                            "Unable to send message."
                    }
                );

            }

        }
    );


    socket.on(
        "disconnect",
        () => {

            setUserOffline(
                account.id,
                socket.id
            );


            console.log(
                "User disconnected: " +
                account.username
            );

        }
    );

}
```

);

/* =========================================================
CLEAN EXPIRED SESSIONS AND API TOKENS
========================================================= */

async function cleanExpiredSessions() {

```
try {

    const sessionResult =
        await pool.query(
            `
            DELETE FROM sessions

            WHERE
                expires_at <= NOW()
            `
        );


    if (
        sessionResult.rowCount > 0
    ) {

        console.log(
            "Cleaned " +
            sessionResult.rowCount +
            " expired session(s)."
        );

    }


    const apiTokenResult =
        await pool.query(
            `
            DELETE FROM api_tokens

            WHERE
                expires_at <= NOW()
            `
        );


    if (
        apiTokenResult.rowCount > 0
    ) {

        console.log(
            "Cleaned " +
            apiTokenResult.rowCount +
            " expired API token(s)."
        );

    }

} catch (error) {

    console.error(
        "Session and API token cleanup error:",
        error
    );

}
```

}

setInterval(
cleanExpiredSessions,
60 * 60 * 1000
);

/* =========================================================
STATUS API
========================================================= */

app.get(
"/api/status",
(req, res) => {

```
    res.json({

        online:
            true,

        service:
            "Core Games Accounts",

        version:
            "5.0.0",

        database:
            "PostgreSQL",

        sessions:
            "PostgreSQL",

        api:
            "Core Games API v1",

        social:
            true,

        socketIO:
            true

    });

}
```

);

/* =========================================================
FALLBACK
========================================================= */

app.use(
(req, res) => {

```
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );

}
```

);

/* =========================================================
START SERVER
========================================================= */

async function startServer() {

```
await initializeDatabase();

await cleanExpiredSessions();


server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            "Core Games Accounts server running on port " +
            PORT
        );

        console.log(
            "Social features enabled."
        );

        console.log(
            "Socket.IO enabled."
        );

        console.log(
            "Allowed frontend origins:"
        );

        allowedOrigins.forEach(
            origin => {
                console.log(
                    " - " + origin
                );
            }
        );

    }
);
```

}

startServer();
