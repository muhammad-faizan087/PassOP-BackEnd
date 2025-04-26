import express from "express";
const router = express.Router();
import { MongoClient } from "mongodb";
import bodyParser from "body-parser";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import "dotenv/config";

const url = process.env.MONGO_URI;
const client = new MongoClient(url, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  ssl: true,
});

const dbName = "PassOP";
await client.connect();

const db = client.db(dbName);
const usersCollection = db.collection("users");

const port = 3000;
router.use(cors());
router.use(bodyParser.json());

router.post("/", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await usersCollection.findOne({ username });

    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compareSync(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userID: user.userID }, process.env.JWT_SECRET);

    res.json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

export default router;
