import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import db from "../db.js"

dotenv.config();
const router = express.Router();

function authenticateJWT(req, res, next) {
    const authHeader = req.headers.authorization;

    if (authHeader) {
        const token = authHeader.split(" ")[1];

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }

            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
}

// Register user
router.post("/register", async (req, res) => {
    const { username, password, admin } = req.body;

    try {
        const hashed = await bcrypt.hash(password, 10);
        const result = await db.query(
            "INSERT INTO users (username, password, admin) VALUES ($1, $2, $3) RETURNING id, username",
            [username, hashed, admin]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: "Registration failed" });
    }
});

// Log in user
router.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await db.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );
        const user = result.rows[0];

        if (!user) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(400).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign({ id: user.id, username: user.username, admin: user.admin }, process.env.JWT_SECRET, { expiresIn: "7d" });
        res.json({ token, user: { id: user.id, username: user.username, admin: user.admin } });
    } catch (err) {
        res.status(500).json({ error: "Login server failed" });
    }
});

// Post a blog post
router.post("/post", authenticateJWT, async (req, res) => {
    if (!req.user.admin) {
        return res.status(403).json({ error: "Not authorised" });
    }
    const { username, title, content, datetime } = req.body;

    try {
        const result = await db.query(
            "INSERT INTO posts (username, title, content, datetime) VALUES ($1, $2, $3, $4)",
            [username, title, content, datetime]
        );
        res.status(201).json({ message: "Post successful" });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: "Post failed" });
    }
});

// Retrieve ten most recent blog posts
router.get("/posts", async (req, res) => {
    const offset = parseInt(req.query.offset || "0")
    const pageSize = 10;

    try {
        const result = await db.query(
            "SELECT * FROM posts ORDER BY datetime DESC LIMIT $1 OFFSET $2",
            [pageSize + 1, offset]
        );

        const posts = result.rows.slice(0, pageSize);
        const areThereMorePosts = result.rows.length > pageSize;
        res.json({ posts, areThereMorePosts });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to retrieve posts" });
    }
});

// Delete a blog post
router.delete("/post/delete", authenticateJWT, async (req, res) => {
    if (!req.user.admin) {
        return res.status(403).json({ error: "Not authorised" });
    }
    const postID = req.query.postID;
    try {
        const result = await db.query(
            "DELETE FROM posts WHERE id = $1",
            [postID]
        )
        const result2 = await db.query(
            "DELETE FROM comments WHERE postID = $1",
            [postID]
        )
        res.status(201).json({ message: `Post with ID ${postID} and comments deleted` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to delete post" })
    }
});

// Edit a blog post
router.put("/post/edit", authenticateJWT, async (req, res) => {
    if (!req.user.admin) {
        return res.status(403).json({ error: "Not authorised" });
    }
    const postID = req.query.postID;
    const { title, content } = req.body;
    try {
        const result = await db.query(
            "UPDATE posts SET title = $1, content = $2 WHERE id = $3",
            [title, content, postID]
        );
        res.status(201).json({ message: `Post with ID ${postID} updated` });
    } catch {
        console.error(err);
        res.status(500).json({ error: "Failed to edit post" });
    }
});

// Post a comment
router.post("/comment", authenticateJWT, async (req, res) => {
    const username = req.user.username;
    const { content, datetime, postID } = req.body;

    try {
        const result = await db.query(
            "INSERT INTO comments (username, content, datetime, postID) VALUES ($1, $2, $3, $4) RETURNING id",
            [username, content, datetime, postID]
        );
        const commentID = result.rows[0].id;
        res.status(201).json({ message: "Comment successful", commentID });
    } catch (err) {
        console.error(err);
        res.status(400).json({ error: "Comment failed" });
    }
});


// Retrieve all comments on a post
router.get("/comments", async (req, res) => {
    const offset = parseInt(req.query.offset || "0");
    const commentAmount = parseInt(req.query.pageSize || "10");
    const postID = parseInt(req.query.postID);

    try {
        const result = await db.query(
            "SELECT * FROM comments WHERE postID = $1 ORDER BY datetime DESC LIMIT $2 OFFSET $3",
            [postID, commentAmount + 1, offset]
        );

        const comments = result.rows.slice(0, commentAmount);
        const areThereMoreComments = result.rows.length > commentAmount;
        res.json({ comments, areThereMoreComments });
    } catch (err) {
        console.error("DB ERROR: ", err);
        res.status(500).json({ error:"Failed to retrieve comments" });
    }
});

// Delete a comment
router.delete("/comment/delete", authenticateJWT, async (req, res) => {
    const commentID = req.query.commentID;
    try {
        const result = await db.query(
            "SELECT username FROM comments WHERE id = $1",
            [commentID]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Comment not found" });
        }
        if (req.user.username !== result.rows[0].username && !req.user.admin) {
            return res.status(403).json({ error: "Not authorised to delete comment" });
        }

        await db.query(
            "DELETE FROM comments WHERE id = $1",
            [commentID]
        )
        res.status(201).json({ message: `Comment with ID ${commentID} deleted` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to delete comment" })
    }
});

// Edit a comment
router.put("/comment/edit", authenticateJWT, async (req, res) => {
    const commentID = req.query.commentID;
    const { content } = req.body;
    try {
        const result = await db.query(
            "SELECT username FROM comments WHERE id = $1",
            [commentID]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Comment not found" });
        }
        if (req.user.username !== result.rows[0].username && !req.user.admin) {
            return res.status(403).json({ error: "Not authorised to edit comment" });
        }
        
        await db.query(
            "UPDATE comments SET content = $1 WHERE id = $2",
            [ content, commentID]
        );
        res.status(201).json({ message: `Comment with ID ${commentID} updated` });
    } catch {
        console.error(err);
        res.status(500).json({ error: "Failed to edit comment" });
    }
});

export default router;