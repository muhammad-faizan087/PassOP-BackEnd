import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bodyParser from "body-parser";
import cors from "cors";
import users from "./routes/users.js";
import login from "./routes/login.js";
import jwt from "jsonwebtoken";
import "dotenv/config";

// Database setup
const client = new MongoClient(process.env.MONGO_URI, { ssl: true });
await client.connect();
const db = client.db("PassOP");
const passwordsCollection = db.collection("passwords");

// Express app
const app = express();

// ======== MIDDLEWARE =========
app.use(
  cors({
    origin: ["http://localhost:5173", "https://pass-op-front-end.vercel.app"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// Handle preflight (OPTIONS) requests
app.options("*", cors());

app.use(bodyParser.json());

// Routes
app.use("/users", users);
app.use("/login", login);

// ======== AUTH MIDDLEWARE =========
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userID = decoded.userID;
    next();
  } catch {
    res.status(403).json({ error: "Invalid token" });
  }
};

// ======== PROTECTED ROUTES =========
app.get("/passwords", verifyToken, async (req, res) => {
  try {
    const passwords = await passwordsCollection
      .find({ userID: req.userID })
      .toArray();
    res.json(passwords);
  } catch {
    res.status(500).json({ error: "Error fetching passwords" });
  }
});

app.post("/passwords", verifyToken, async (req, res) => {
  try {
    const passwordData = { ...req.body, userID: req.userID };
    const insertResult = await passwordsCollection.insertOne(passwordData);

    const insertedPassword = await passwordsCollection.findOne({
      _id: insertResult.insertedId,
    });

    res.status(201).json(insertedPassword);
  } catch {
    res.status(500).json({ error: "Error saving password" });
  }
});

app.delete("/passwords", verifyToken, async (req, res) => {
  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: "Missing password ID" });

    const deleteResult = await passwordsCollection.deleteOne({
      _id: ObjectId.isValid(id) ? new ObjectId(id) : id,
      userID: req.userID,
    });

    if (deleteResult.deletedCount === 0) {
      return res.status(404).json({ message: "Password not found" });
    }

    res.json({ message: "Password deleted successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ error: "Error deleting password", details: error.message });
  }
});

// ======== EXPORT HANDLER FOR VERCEL =========
export default app;
