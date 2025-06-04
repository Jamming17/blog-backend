import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import db from "../db.js"

dotenv.config();
const router = express.Router();

// Register user
router.post("/register", async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const hashed = await bcrypt.hash(password, 10);
        const result = await db.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id, username, email",
            [username, email, hashed]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: "Registration failed" });
    }
});

// Log in user
router.post("/login", async (req, res) => {
    const { usernameOrEmail, password } = req.body;

    try {
        const result = await db.query(
            "SELECT * FROM users WHERE email = $1 OR username = $1",
            [usernameOrEmail]
        );
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: "Invalid credentials "});
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, user: { id: user.id, username: user.username } });
    } catch (err) {
        res.status(500).json({ error: "Login server failed" });
    }
});

export default router;