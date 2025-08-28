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
    password TEXT,
    role TEXT DEFAULT 'student'
  )
`);


  db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'student'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scheduler TEXT,
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
      approvedBy TEXT
    )
  `);
});


// Root route for health check
app.get("/", (req, res) => {
  res.send("MeetPass Backend is running!");
});
// Login API
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "Invalid email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

    // Return name, email, and role
    res.json({
      message: "Login successful",
      name: user.name,
      email: user.email,
      role: user.role || "student"
    });
  });
});

//schedule meeting
app.post("/meetings", (req, res) => {
  const {
    scheduler, participantType, participantEmail,
    purpose, venue, startTime, endTime, isGroup,
    participants, token, status
  } = req.body;

  const participantsJSON = JSON.stringify(participants || []);

  db.run(
    `INSERT INTO meetings 
      (scheduler, participantType, participantEmail, purpose, venue, startTime, endTime, isGroup, participants, token, status) 
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [scheduler, participantType, participantEmail, purpose, venue, startTime, endTime, isGroup ? 1 : 0, participantsJSON, token, status],
    function (err) {
      if (err) return res.status(500).json({ message: "Failed to schedule meeting" });
      res.json({ message: "Meeting scheduled", id: this.lastID });
    }
  );
});

app.get("/meetings/:email", (req, res) => {
  const email = req.params.email;

  db.all(
    `SELECT * FROM meetings WHERE scheduler = ? OR participantEmail = ?`,
    [email, email],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Failed to fetch meetings" });
      // Parse participants JSON
      const meetings = rows.map((m) => ({ ...m, participants: JSON.parse(m.participants || "[]") }));
      res.json(meetings);
    }
  );
});
app.patch("/meetings/:id", (req, res) => {
  const { status, approvedBy } = req.body;
  const id = req.params.id;

  db.run(
    `UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?`,
    [status, approvedBy, id],
    function (err) {
      if (err) return res.status(500).json({ message: "Failed to update status" });
      res.json({ message: "Status updated" });
    }
  );
});


// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
