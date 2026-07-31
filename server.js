const express = require("express");
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

/* =========================================================
TEMPORARY ACCOUNT STORAGE

This is only for testing.

Accounts will disappear when the server restarts.
We will replace this with PostgreSQL later.
========================================================= */

const accounts = new Map();

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
        path.join(__dirname, "public")
    )
);

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

            if (password.length < 8) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be at least 8 characters."
                });

            }

            const usernameKey =
                username.toLowerCase();

            if (
                accounts.has(
                    usernameKey
                )
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

            const account = {

                id:
                    Date.now().toString(),

                username,

                passwordHash,

                createdAt:
                    new Date().toISOString()

            };

            accounts.set(
                usernameKey,
                account
            );

            console.log(
                `New Core Games account created: ${username}`
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

            const usernameKey =
                username.toLowerCase();

            const account =
                accounts.get(
                    usernameKey
                );

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
                    account.passwordHash
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
                "1.0.0"

        });

    }
);

/* =========================================================
FALLBACK
========================================================= */

app.get(
    "*",
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

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Core Games Accounts server running on port ${PORT}`
        );

    }
);
