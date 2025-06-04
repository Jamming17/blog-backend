import express from "express";
import cors from "cors";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

app.get("/", (req, res) => {
    res.send("Blog backend is running");
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});