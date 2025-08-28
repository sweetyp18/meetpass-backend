const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 10000;

// Middlewares
app.use(cors());
app.use(bodyParser.json());

// Database setup
const db = new sqlite3.Database("./meetpass.db", (err) => {
  if (err) console.error("DB Error: ", err.message);
  else console.log("Connected to meetpass.db");
});

// Create tables if not exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      createdBy INTEGER,
      participantType TEXT,
      participantEmail TEXT,
      purpose TEXT,
      venue TEXT,
      startTime TEXT,
      endTime TEXT,
      isGroup INTEGER DEFAULT 0,
      participants TEXT,
      token TEXT UNIQUE,
      status TEXT DEFAULT 'Pending',
      approvedBy TEXT,
      FOREIGN KEY (createdBy) REFERENCES users(id)
    )
  `);
});

// Root route for health check
app.get("/", (req, res) => {
  res.send("MeetPass Backend is running!");
});

// Signup API
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ message: "All fields are required" });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
      [name, email, hashedPassword],
      function (err) {
        if (err) return res.status(400).json({ message: "User already exists" });
        res.json({ message: "Signup successful", userId: this.lastID });
      }
    );
  } catch (err) {
    res.status(500).json({ message: "Signup failed" });
  }
});

// Login API
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "Invalid email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

    res.json({ message: "Login successful", userId: user.id });
  });
});

// Schedule Meeting API
app.post("/meetings", (req, res) => {
  const {
    createdBy,
    participantType,
    participantEmail,
    purpose,
    venue,
    startTime,
    endTime,
    isGroup,
    participants,
    token,
    status,
  } = req.body;

  if (!createdBy || !purpose || !startTime || !endTime)
    return res.status(400).json({ message: "All fields required" });

  db.run(
    `INSERT INTO meetings 
    (createdBy, participantType, participantEmail, purpose, venue, startTime, endTime, isGroup, participants, token, status) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      createdBy,
      participantType,
      participantEmail,
      purpose,
      venue,
      startTime,
      endTime,
      isGroup ? 1 : 0,
      participants ? JSON.stringify(participants) : "",
      token,
      status || "Pending",
    ],
    function (err) {
      if (err) return res.status(500).json({ message: "Error scheduling meeting" });
      res.json({ message: "Meeting scheduled", meetingId: this.lastID });
    }
  );
});

// Get all meetings (staff)
app.get("/meetings", (req, res) => {
  db.all(`SELECT * FROM meetings`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: "Error fetching meetings" });
    res.json(rows);
  });
});

// Get meetings by user
app.get("/meetings/:userId", (req, res) => {
  const { userId } = req.params;
  db.all(`SELECT * FROM meetings WHERE createdBy = ?`, [userId], (err, rows) => {
    if (err) return res.status(500).json({ message: "Error fetching meetings" });
    res.json(rows);
  });
});

// Approve/Reject meeting (staff)
app.patch("/meetings/:meetingId", (req, res) => {
  const { meetingId } = req.params;
  const { status, approvedBy } = req.body;
  db.run(
    `UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?`,
    [status, approvedBy, meetingId],
    function (err) {
      if (err) return res.status(500).json({ message: "Error updating meeting" });
      res.json({ message: "Meeting updated" });
    }
  );
});

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
