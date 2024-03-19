const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
dotenv.config();
const rateLimit = require("express-rate-limit");
const fs = require("fs");
const morgan = require("morgan");
const path = require("path");
const connectDB = require("./config/db.js");
connectDB();
const app = express();
const PORT = 3000;
const secretKey = "Hello123"; // Replace with your own secret key

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Define Todo schema
const todoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  title: { type: String, required: true },
  description: { type: String, required: true },
  status: { type: String, default: "pending", enum: ["pending", "completed"] }, // Add enum for status
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Todo = mongoose.model("Todo", todoSchema);

// Define User schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});

const User = mongoose.model("User", userSchema);

// Temporary array to store invalidated tokens
let invalidatedTokens = [];

// Middleware to verify JWT token and extract user information
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  // Check if the token is blacklisted (invalidated)
  if (invalidatedTokens.includes(token)) {
    return res.status(401).json({ error: "Token has been invalidated" });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Forbidden" });
    }
    req.user = user;
    next();
  });
}
// Rate limiting middleware (100 requests per hour per IP)
const limiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 100, // Max 100 requests per hour per IP
  message: "Too many requests from this IP, please try again later.",
});

// Apply rate limiting to all requests
app.use(limiter);

// Create a write stream (append mode) for logging requests
const accessLogStream = fs.createWriteStream(
  path.join(__dirname, "access.log"),
  { flags: "a" }
);

// Log requests with morgan middleware
app.use(morgan("combined", { stream: accessLogStream }));

// Search and filter todo items endpoint
app.get("/todos", authenticateToken, async (req, res) => {
  try {
    const { title, description, status } = req.query;
    const filter = { userId: req.user.userId };

    if (title) {
      filter.title = { $regex: title, $options: "i" }; // Case-insensitive search
    }
    if (description) {
      filter.description = { $regex: description, $options: "i" }; // Case-insensitive search
    }
    if (status) {
      filter.status = status;
    }

    const todos = await Todo.find(filter);
    res.json(todos);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// User signup endpoint
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;
  try {
    const newUser = await User.create({ username, password });
    res
      .status(201)
      .json({ message: "User created successfully", user: newUser });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// User login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username, password });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ userId: user._id }, secretKey, {
      expiresIn: "1h",
    });
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// User logout endpoint
app.post("/logout", authenticateToken, (req, res) => {
  const token = req.headers["authorization"].split(" ")[1];
  invalidatedTokens.push(token); // Add token to blacklist
  res.json({ message: "Logout successful" });
});

// Todo CRUD endpoints (authenticated users only)
app.post("/todos", authenticateToken, async (req, res) => {
  // Input validation example (validate title and description fields)
  const { title, description, status } = req.body;
  if (!title || !description) {
    return res
      .status(400)
      .json({ error: "Title and description are required" });
  }
  if (status && !["pending", "completed"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  try {
    const todo = await Todo.create({
      userId: req.user.userId,
      title,
      description,
      status,
    });
    res.status(201).json(todo);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

app.get("/todos/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const todo = await Todo.findOne({ _id: id, userId: req.user.userId });
    if (!todo) {
      return res.status(404).json({ error: "Todo not found" });
    }
    res.json(todo);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put("/todos/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, description, status } = req.body;
  try {
    const updatedTodo = await Todo.findOneAndUpdate(
      { _id: id, userId: req.user.userId },
      { title, description, status, updatedAt: Date.now() },
      { new: true }
    );
    if (!updatedTodo) {
      return res.status(404).json({ error: "Todo not found" });
    }
    res.json(updatedTodo);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/todos/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedTodo = await Todo.findOneAndDelete({
      _id: id,
      userId: req.user.userId,
    });
    if (!deletedTodo) {
      return res.status(404).json({ error: "Todo not found" });
    }
    res.json({ message: "Todo deleted successfully" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
