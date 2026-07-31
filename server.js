const express = require("express");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

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
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

/* =========================================================
MIDDLEWARE
========================================================= */

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
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

        await pool.query(`
            CREATE TABLE IF NOT EXISTS accounts (
                id SERIAL PRIMARY KEY,
                username VARCHAR(20) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
                    req.body.username || ""
                ).trim();

            const password =
                String(
                    req.body.password || ""
                );

            /* -----------------------------------------
            VALIDATE USERNAME
            ----------------------------------------- */

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

            /* -----------------------------------------
            VALIDATE USERNAME CHARACTERS
            ----------------------------------------- */

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

            /* -----------------------------------------
            VALIDATE PASSWORD
            ----------------------------------------- */

            if (!password) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Please enter a password."
                });

            }

            if (password.length < 8) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 8 characters."
                });

            }

            /* -----------------------------------------
            CHECK IF USERNAME EXISTS
            ----------------------------------------- */

            const existingAccount =
                await pool.query(
                    `
                    SELECT id
                    FROM accounts
                    WHERE LOWER(username) = LOWER($1)
                    `,
                    [username]
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

            /* -----------------------------------------
            HASH PASSWORD
            ----------------------------------------- */

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            /* -----------------------------------------
            CREATE ACCOUNT
            ----------------------------------------- */

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
                    RETURNING id, username, created_at
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

            /* -----------------------------------------
            FIND ACCOUNT
            ----------------------------------------- */

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        username,
                        password_hash
                    FROM accounts
                    WHERE LOWER(username) = LOWER($1)
                    `,
                    [username]
                );

            const account =
                result.rows[0];

            /* -----------------------------------------
            DON'T REVEAL WHETHER USER EXISTS
            ----------------------------------------- */

            if (!account) {

                return res.status(401).json({

                    success: false,

                    message:
                        "Invalid username or password."

                });

            }

            /* -----------------------------------------
            CHECK PASSWORD
            ----------------------------------------- */

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
                "2.0.0",

            database:
                "PostgreSQL"

        });

    }
);

/* =========================================================
FALLBACK
========================================================= */

/*
Express 5 does not accept "*" as a route pattern.

This middleware handles requests that were
not matched by the API or static files.
*/

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
