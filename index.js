const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const cors = require("cors");

const app = express();
const PORT = 5000;

// Middlewares
app.use(cors());
app.use(express.json()); // replace bodyParser.json()

// Database setup
const db = new sqlite3.Database("./meetpass.db", (err) => {
  if (err) console.error("DB Error:", err.message);
  else console.log("✅ Connected to SQLite database");
});

// Create tables
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId TEXT UNIQUE,
    password TEXT,
    role TEXT CHECK(role IN ('student','staff'))
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT,
    sender TEXT,
    participantType TEXT,
    purpose TEXT,
    venue TEXT,
    dateTime TEXT,
    isGroup INTEGER,
    participants TEXT,
    status TEXT DEFAULT 'pending',
    approvedBy TEXT DEFAULT ''
  )
`);

// ------------------- Routes -------------------

// Test route
app.get("/", (req, res) => {
  res.send("MeetPass Backend is running 🚀");
});

// Register user (for testing)
app.post("/api/register", (req, res) => {
  const { userId, password, role } = req.body;
  console.log("Register request:", req.body);
  db.run(
    `INSERT INTO users (userId, password, role) VALUES (?, ?, ?)`,
    [userId, password, role],
    function (err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID, userId, role });
    }
  );
});

// Login
app.post("/api/login", (req, res) => {
  const { userId, password } = req.body;
  console.log("Login request:", req.body);
  db.get(
    `SELECT * FROM users WHERE userId=? AND password=?`,
    [userId, password],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(401).json({ error: "Invalid credentials" });
      res.json({ userId: row.userId, role: row.role });
    }
  );
});

// Create meeting
app.post("/api/meetings", (req, res) => {
  const {
    token, sender, participantType, purpose, venue, dateTime,
    isGroup, participants, status = "pending"
  } = req.body;

  console.log("Create meeting request:", req.body);

  db.run(
    `INSERT INTO meetings 
      (token, sender, participantType, purpose, venue, dateTime, isGroup, participants, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [token, sender, participantType, purpose, venue, dateTime, isGroup ? 1 : 0, JSON.stringify(participants || []), status],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, token, status });
    }
  );
});

// Get all meetings
app.get("/api/meetings", (req, res) => {
  console.log("Fetching all meetings");
  db.all(`SELECT * FROM meetings`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    rows.forEach(r => { r.participants = JSON.parse(r.participants || "[]"); });
    res.json(rows);
  });
});

// Approve/Reject meeting
app.patch("/api/meetings/:id", (req, res) => {
  const { id } = req.params;
  const { status, approvedBy } = req.body;

  console.log(`Update meeting ${id} request:`, req.body);

  db.run(
    `UPDATE meetings SET status=?, approvedBy=? WHERE id=?`,
    [status, approvedBy || "", id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    }
  );
});

// Start server
app.listen(PORT, () => console.log(`✅ Backend running on http://localhost:${PORT}`));
