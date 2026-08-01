const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const path = require("path");
const http = require("http");
const { Server } = require("socket.io");

const app = express();

const server = http.createServer(app);

const io = new Server(server, {
cors: {
origin: true,
credentials: true
}
});

const PORT = process.env.PORT || 3000;

const SESSION_DURATION_DAYS = 30;
const SESSION_DURATION_MS =
SESSION_DURATION_DAYS * 24 * 60 * 60 * 1000;

const API_TOKEN_DURATION_DAYS = 30;
const API_TOKEN_DURATION_MS =
API_TOKEN_DURATION_DAYS * 24 * 60 * 60 * 1000;

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

    /* =====================================================
    ACCOUNTS
    ===================================================== */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS accounts (
            id SERIAL PRIMARY KEY,
            username VARCHAR(20) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);


    /* =====================================================
    SESSIONS
    ===================================================== */

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


    /* =====================================================
    API TOKENS
    ===================================================== */

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


    /* =====================================================
    FRIENDSHIPS
    ===================================================== */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS friendships (
            id SERIAL PRIMARY KEY,

            requester_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            addressee_id INTEGER NOT NULL
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            status VARCHAR(20) NOT NULL
                DEFAULT 'pending',

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            updated_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

            CONSTRAINT friendships_different_users
                CHECK (requester_id <> addressee_id),

            CONSTRAINT friendships_unique_pair
                UNIQUE (requester_id, addressee_id)
        )
    `);


    /* =====================================================
    MESSAGES
    ===================================================== */

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

            is_read BOOLEAN
                DEFAULT FALSE,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    `);


    /* =====================================================
    ONLINE STATUS
    ===================================================== */

    await pool.query(`
        CREATE TABLE IF NOT EXISTS user_presence (
            account_id INTEGER PRIMARY KEY
                REFERENCES accounts(id)
                ON DELETE CASCADE,

            is_online BOOLEAN
                DEFAULT FALSE,

            last_seen TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
        )
    `);


    /* =====================================================
    INDEXES
    ===================================================== */

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
        messages_sender_receiver_index
        ON messages(sender_id, receiver_id, created_at)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        messages_receiver_read_index
        ON messages(receiver_id, is_read)
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS
        friendships_addressee_status_index
        ON friendships(addressee_id, status)
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

function hashSessionToken(
token
) {

```
return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
```

}

async function createSession(
accountId
) {

```
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
    (token_hash, account_id, expires_at)
    VALUES ($1, $2, $3)
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

async function getAccountFromSession(
req
) {

```
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
        WHERE sessions.token_hash = $1
            AND sessions.expires_at > NOW()
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

function hashApiToken(
token
) {

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
    (token_hash, account_id, expires_at)
    VALUES ($1, $2, $3)
    `,
    [
        tokenHash,
        accountId,
        expiresAt
    ]
);

return {

    token:
        token,

    expiresAt:
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
        WHERE api_tokens.token_hash = $1
            AND api_tokens.expires_at > NOW()
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
REQUIRE LOGIN
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
            "Unable to authenticate."

    });

}
```

}

/* =========================================================
REGISTER
========================================================= */

app.post(
"/api/register",
async (
req,
res
) => {

```
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
                WHERE LOWER(username) =
                    LOWER($1)
                `,
                [
                    username
                ]
            );


        if (
            existingAccount.rows.length >
            0
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
                (username, password_hash)
                VALUES ($1, $2)
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


        await pool.query(
            `
            INSERT INTO user_presence
            (account_id, is_online)
            VALUES ($1, TRUE)
            ON CONFLICT (account_id)
            DO UPDATE SET
                is_online = TRUE,
                last_seen = CURRENT_TIMESTAMP
            `,
            [
                account.id
            ]
        );


        console.log(
            "New Core Games account created: " +
            account.username
        );


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
```

);

/* =========================================================
LOGIN
========================================================= */

app.post(
"/api/login",
async (
req,
res
) => {

```
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


        const result =
            await pool.query(
                `
                SELECT
                    id,
                    username,
                    password_hash
                FROM accounts
                WHERE LOWER(username) =
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


        await pool.query(
            `
            INSERT INTO user_presence
            (account_id, is_online)
            VALUES ($1, TRUE)
            ON CONFLICT (account_id)
            DO UPDATE SET
                is_online = TRUE,
                last_seen = CURRENT_TIMESTAMP
            `,
            [
                account.id
            ]
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
async (
req,
res
) => {

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


        await pool.query(
            `
            INSERT INTO user_presence
            (account_id, is_online)
            VALUES ($1, TRUE)
            ON CONFLICT (account_id)
            DO UPDATE SET
                is_online = TRUE,
                last_seen = CURRENT_TIMESTAMP
            `,
            [
                account.id
            ]
        );


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
async (
req,
res
) => {

```
    try {

        const account =
            await getAccountFromSession(
                req
            );


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


        if (account) {

            await pool.query(
                `
                UPDATE user_presence
                SET
                    is_online = FALSE,
                    last_seen =
                        CURRENT_TIMESTAMP
                WHERE account_id = $1
                `,
                [
                    account.id
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
SEARCH USERS
========================================================= */

app.get(
"/api/social/users/search",
requireLogin,
async (
req,
res
) => {

```
    try {

        const query =
            String(
                req.query.q ||
                ""
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
                    accounts.id,
                    accounts.username,

                    COALESCE(
                        user_presence.is_online,
                        FALSE
                    ) AS is_online,

                    user_presence.last_seen

                FROM accounts

                LEFT JOIN user_presence
                    ON user_presence.account_id =
                        accounts.id

                WHERE accounts.id <> $1

                AND accounts.username ILIKE $2

                ORDER BY accounts.username

                LIMIT 20
                `,
                [
                    req.account.id,
                    "%" +
                    query +
                    "%"
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
"/api/social/friends/request",
requireLogin,
async (
req,
res
) => {

```
    try {

        const username =
            String(
                req.body.username ||
                ""
            ).trim();


        if (!username) {

            return res.status(400).json({

                success: false,

                message:
                    "Username is required."

            });

        }


        const targetResult =
            await pool.query(
                `
                SELECT id, username
                FROM accounts
                WHERE LOWER(username) =
                    LOWER($1)
                `,
                [
                    username
                ]
            );


        if (
            targetResult.rows.length ===
            0
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "User not found."

            });

        }


        const target =
            targetResult.rows[0];


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


        const existing =
            await pool.query(
                `
                SELECT *
                FROM friendships
                WHERE
                (
                    requester_id = $1
                    AND addressee_id = $2
                )
                OR
                (
                    requester_id = $2
                    AND addressee_id = $1
                )
                `,
                [
                    req.account.id,
                    target.id
                ]
            );


        if (
            existing.rows.length > 0
        ) {

            const friendship =
                existing.rows[0];


            if (
                friendship.status ===
                "accepted"
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        "You are already friends."

                });

            }


            if (
                friendship.requester_id ===
                target.id &&
                friendship.addressee_id ===
                req.account.id &&
                friendship.status ===
                "pending"
            ) {

                return res.json({

                    success: true,

                    message:
                        "This user already sent you a friend request. Accept it instead."

                });

            }


            return res.status(409).json({

                success: false,

                message:
                    "A friend request already exists."

            });

        }


        await pool.query(
            `
            INSERT INTO friendships
            (
                requester_id,
                addressee_id,
                status
            )
            VALUES ($1, $2, 'pending')
            `,
            [
                req.account.id,
                target.id
            ]
        );


        return res.status(201).json({

            success: true,

            message:
                "Friend request sent.",

            username:
                target.username

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
"/api/social/friends/requests",
requireLogin,
async (
req,
res
) => {

```
    try {

        const result =
            await pool.query(
                `
                SELECT
                    friendships.id,
                    accounts.id AS user_id,
                    accounts.username,
                    friendships.created_at

                FROM friendships

                INNER JOIN accounts
                    ON accounts.id =
                        friendships.requester_id

                WHERE
                    friendships.addressee_id =
                        $1

                AND friendships.status =
                    'pending'

                ORDER BY
                    friendships.created_at DESC
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
RESPOND TO FRIEND REQUEST
========================================================= */

app.post(
"/api/social/friends/request/:id",
requireLogin,
async (
req,
res
) => {

```
    try {

        const requestId =
            Number(
                req.params.id
            );

        const action =
            String(
                req.body.action ||
                ""
            ).toLowerCase();


        if (
            !Number.isInteger(
                requestId
            )
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Invalid friend request."

            });

        }


        if (
            action !== "accept" &&
            action !== "decline"
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Action must be accept or decline."

            });

        }


        const result =
            await pool.query(
                `
                SELECT *
                FROM friendships
                WHERE id = $1
                AND addressee_id = $2
                AND status = 'pending'
                `,
                [
                    requestId,
                    req.account.id
                ]
            );


        if (
            result.rows.length ===
            0
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "Friend request not found."

            });

        }


        if (
            action === "accept"
        ) {

            await pool.query(
                `
                UPDATE friendships

                SET
                    status = 'accepted',
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id = $1
                `,
                [
                    requestId
                ]
            );

        } else {

            await pool.query(
                `
                DELETE FROM friendships
                WHERE id = $1
                `,
                [
                    requestId
                ]
            );

        }


        return res.json({

            success: true,

            message:
                action ===
                "accept"
                    ? "Friend request accepted."
                    : "Friend request declined."

        });

    } catch (error) {

        console.error(
            "Friend request response error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to respond to friend request."

        });

    }

}
```

);

/* =========================================================
GET FRIENDS
========================================================= */

app.get(
"/api/social/friends",
requireLogin,
async (
req,
res
) => {

```
    try {

        const result =
            await pool.query(
                `
                SELECT

                    accounts.id,

                    accounts.username,

                    COALESCE(
                        user_presence.is_online,
                        FALSE
                    ) AS is_online,

                    user_presence.last_seen

                FROM friendships

                INNER JOIN accounts

                    ON accounts.id =
                        CASE

                            WHEN
                                friendships.requester_id =
                                    $1

                            THEN
                                friendships.addressee_id

                            ELSE
                                friendships.requester_id

                        END

                LEFT JOIN user_presence

                    ON user_presence.account_id =
                        accounts.id

                WHERE

                (
                    friendships.requester_id =
                        $1

                    OR

                    friendships.addressee_id =
                        $1
                )

                AND friendships.status =
                    'accepted'

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
"/api/social/friends/:userId",
requireLogin,
async (
req,
res
) => {

```
    try {

        const userId =
            Number(
                req.params.userId
            );


        if (
            !Number.isInteger(
                userId
            )
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Invalid user."

            });

        }


        const result =
            await pool.query(
                `
                DELETE FROM friendships

                WHERE status =
                    'accepted'

                AND
                (
                    requester_id = $1
                    AND addressee_id = $2
                )

                OR

                (
                    requester_id = $2
                    AND addressee_id = $1
                )

                RETURNING id
                `,
                [
                    req.account.id,
                    userId
                ]
            );


        if (
            result.rowCount ===
            0
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "Friendship not found."

            });

        }


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
SEND MESSAGE
========================================================= */

app.post(
"/api/social/messages",
requireLogin,
async (
req,
res
) => {

```
    try {

        const receiverId =
            Number(
                req.body.receiverId
            );

        const message =
            String(
                req.body.message ||
                ""
            ).trim();


        if (
            !Number.isInteger(
                receiverId
            )
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Invalid recipient."

            });

        }


        if (!message) {

            return res.status(400).json({

                success: false,

                message:
                    "Message cannot be empty."

            });

        }


        if (
            message.length > 2000
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Message is too long."

            });

        }


        if (
            receiverId ===
            req.account.id
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "You cannot message yourself."

            });

        }


        const friendship =
            await pool.query(
                `
                SELECT id
                FROM friendships

                WHERE status =
                    'accepted'

                AND
                (
                    requester_id = $1
                    AND addressee_id = $2
                )

                OR

                (
                    requester_id = $2
                    AND addressee_id = $1
                )
                `,
                [
                    req.account.id,
                    receiverId
                ]
            );


        if (
            friendship.rows.length ===
            0
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "You can only message your friends."

            });

        }


        const receiver =
            await pool.query(
                `
                SELECT id, username
                FROM accounts
                WHERE id = $1
                `,
                [
                    receiverId
                ]
            );


        if (
            receiver.rows.length ===
            0
        ) {

            return res.status(404).json({

                success: false,

                message:
                    "Recipient not found."

            });

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
                    is_read,
                    created_at
                `,
                [
                    req.account.id,
                    receiverId,
                    message
                ]
            );


        const newMessage =
            result.rows[0];


        /* Send live message through Socket.IO */

        io.to(
            "user_" +
            receiverId
        ).emit(
            "new_message",
            {

                id:
                    newMessage.id,

                senderId:
                    req.account.id,

                senderUsername:
                    req.account.username,

                receiverId:
                    receiverId,

                message:
                    newMessage.message,

                createdAt:
                    newMessage.created_at

            }
        );


        return res.status(201).json({

            success: true,

            message:
                newMessage

        });

    } catch (error) {

        console.error(
            "Send message error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to send message."

        });

    }

}
```

);

/* =========================================================
GET MESSAGE HISTORY
========================================================= */

app.get(
"/api/social/messages/:userId",
requireLogin,
async (
req,
res
) => {

```
    try {

        const userId =
            Number(
                req.params.userId
            );


        if (
            !Number.isInteger(
                userId
            )
        ) {

            return res.status(400).json({

                success: false,

                message:
                    "Invalid user."

            });

        }


        const friendship =
            await pool.query(
                `
                SELECT id
                FROM friendships

                WHERE status =
                    'accepted'

                AND
                (
                    requester_id = $1
                    AND addressee_id = $2
                )

                OR

                (
                    requester_id = $2
                    AND addressee_id = $1
                )
                `,
                [
                    req.account.id,
                    userId
                ]
            );


        if (
            friendship.rows.length ===
            0
        ) {

            return res.status(403).json({

                success: false,

                message:
                    "You can only view messages with friends."

            });

        }


        const result =
            await pool.query(
                `
                SELECT
                    id,
                    sender_id,
                    receiver_id,
                    message,
                    is_read,
                    created_at

                FROM messages

                WHERE

                (
                    sender_id = $1
                    AND receiver_id = $2
                )

                OR

                (
                    sender_id = $2
                    AND receiver_id = $1
                )

                ORDER BY
                    created_at ASC

                LIMIT 200
                `,
                [
                    req.account.id,
                    userId
                ]
            );


        await pool.query(
            `
            UPDATE messages

            SET is_read = TRUE

            WHERE
                sender_id = $1

            AND
                receiver_id = $2
            `,
            [
                userId,
                req.account.id
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
UNREAD MESSAGE COUNT
========================================================= */

app.get(
"/api/social/messages/unread/count",
requireLogin,
async (
req,
res
) => {

```
    try {

        const result =
            await pool.query(
                `
                SELECT
                    COUNT(*)::INTEGER
                    AS unread_count

                FROM messages

                WHERE receiver_id =
                    $1

                AND is_read =
                    FALSE
                `,
                [
                    req.account.id
                ]
            );


        return res.json({

            success: true,

            unreadCount:
                result.rows[0]
                    .unread_count

        });

    } catch (error) {

        console.error(
            "Unread count error:",
            error
        );

        return res.status(500).json({

            success: false,

            message:
                "Unable to get unread messages."

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
async (
req,
res
) => {

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


        console.log(
            "API token created for account: " +
            account.username
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
async (
req,
res
) => {

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
async (
req,
res
) => {

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
                WHERE token_hash = $1
                RETURNING id
                `,
                [
                    tokenHash
                ]
            );


        if (
            result.rowCount ===
            0
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
async (
socket,
next
) => {

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
                part => {

                    const index =
                        part.indexOf("=");

                    if (
                        index === -1
                    ) {

                        return;

                    }

                    const key =
                        part
                            .slice(
                                0,
                                index
                            )
                            .trim();

                    const value =
                        part
                            .slice(
                                index + 1
                            )
                            .trim();

                    cookies[key] =
                        decodeURIComponent(
                            value
                        );

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
                    sessions.token_hash =
                        $1

                AND
                    sessions.expires_at >
                        NOW()
                `,
                [
                    tokenHash
                ]
            );


        if (
            result.rows.length ===
            0
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
SOCKET.IO CONNECTIONS
========================================================= */

io.on(
"connection",
async (
socket
) => {

```
    const account =
        socket.account;


    socket.join(
        "user_" +
        account.id
    );


    await pool.query(
        `
        INSERT INTO user_presence
        (
            account_id,
            is_online,
            last_seen
        )

        VALUES
        ($1, TRUE, CURRENT_TIMESTAMP)

        ON CONFLICT (account_id)

        DO UPDATE SET
            is_online = TRUE,
            last_seen =
                CURRENT_TIMESTAMP
        `,
        [
            account.id
        ]
    );


    console.log(
        "User connected to chat: " +
        account.username
    );


    socket.on(
        "disconnect",
        async () => {

            try {

                await pool.query(
                    `
                    UPDATE user_presence

                    SET
                        is_online = FALSE,
                        last_seen =
                            CURRENT_TIMESTAMP

                    WHERE account_id =
                        $1
                    `,
                    [
                        account.id
                    ]
                );


                console.log(
                    "User disconnected from chat: " +
                    account.username
                );

            } catch (error) {

                console.error(
                    "Presence update error:",
                    error
                );

            }

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
            WHERE expires_at <= NOW()
            `
        );


    if (
        sessionResult.rowCount >
        0
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
            WHERE expires_at <= NOW()
            `
        );


    if (
        apiTokenResult.rowCount >
        0
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
(
req,
res
) => {

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

        social:
            true,

        chat:
            true,

        realtime:
            "Socket.IO",

        api:
            "Core Games API v1"

    });

}
```

);

/* =========================================================
FALLBACK
========================================================= */

app.use(
(
req,
res
) => {

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
            "Real-time chat enabled."
        );

    }
);
```

}

startServer();
