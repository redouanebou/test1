const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET;

app.get("/", (req, res) => {
  res.send("Server is working! Welcome to the homepage.");
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id", [email, hashedPassword]);
    const userId = result.rows[0].id;
    res.status(201).json({ message: "User registered", userId });
  } catch (err) {
    res.status(500).json({ error: "Registration failed", details: err.message });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed", details: err.message });
  }
});

const authenticate = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    return res.status(403).json({ error: "Access denied, no token provided." });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

app.get("/content", authenticate, async (req, res) => {
  try {
    const result = await pool.query("SELECT content FROM user_content WHERE user_id = $1", [req.userId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "No content found for this user" });
    }
    res.json({ content: result.rows[0].content });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch content", details: err.message });
  }
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
