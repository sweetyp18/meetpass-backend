const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5000;


// Middlewares
app.use(cors());
app.use(bodyParser.json());

// Database setup
const db = new sqlite3.Database("./meetpass.db", (err) => {
  if (err) console.error("DB connection error:", err.message);
  else console.log("Connected to SQLite DB");
});

// Create tables if not exist
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      userId TEXT PRIMARY KEY,
      password TEXT,
      role TEXT
    )`
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token TEXT,
      sender TEXT,
      meetingWith TEXT,
      purpose TEXT,
      venue TEXT,
      dateTime TEXT,
      isGroup INTEGER,
      participants TEXT,
      status TEXT,
      approvedBy TEXT
    )`
  );
});

// ------------------- Routes -------------------

// Login
app.post("/api/login", (req, res) => {
  const { userId, password } = req.body;
  if (!userId || !password)
    return res.status(400).json({ error: "Missing credentials" });

  db.get(
    "SELECT * FROM users WHERE userId = ? AND password = ?",
    [userId, password],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(401).json({ error: "Invalid Credentials" });
      res.json({ userId: row.userId, role: row.role });
    }
  );
});

// Create meeting
app.post("/api/meetings", (req, res) => {
  const {
    token,
    sender,
    meetingWith,
    purpose,
    venue,
    dateTime,
    isGroup,
    participants,
    status,
  } = req.body;

  db.run(
    `INSERT INTO meetings
    (token, sender, meetingWith, purpose, venue, dateTime, isGroup, participants, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      token,
      sender,
      meetingWith,
      purpose,
      venue,
      dateTime,
      isGroup ? 1 : 0,
      JSON.stringify(participants || []),
      status,
    ],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// Get all meetings
app.get("/api/meetings", (req, res) => {
  db.all("SELECT * FROM meetings", [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    // Parse participants JSON
    const meetings = rows.map((m) => ({ ...m, participants: JSON.parse(m.participants) }));
    res.json(meetings);
  });
});

// Approve / Reject meeting
app.patch("/api/meetings/:id", (req, res) => {
  const { status, approvedBy } = req.body;
  const { id } = req.params;
  db.run(
    "UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?",
    [status, approvedBy, id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    }
  );
});
app.get("/", (req, res) => {
  res.send("MeetPass Backend is running 🚀");
});

app.get("/api/setup", (req, res) => {
  db.run(
    `INSERT OR IGNORE INTO users (userId, password, role) VALUES
    ('staff1', '123456', 'staff'),
    ('staff2', '100000', 'staff'),
    ('SJU-03', '110000', 'student'),
    ('SJU-04', '111111', 'student'),
    ('staff4', '111111', 'staff')`,
    (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Test users added" });
    }
  );
});



// ------------------- Start Server -------------------
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
