const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 5000;

// Use absolute path for SQLite in Render (optional, can use relative too)
const path = require("path");
const dbPath = path.join(__dirname, "meetpass.db");

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("DB Error: ", err.message);
  else console.log("Connected to meetpass.db");
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
    scheduler,
    participantType,
    participantEmail,
    purpose,
    venue,
    startTime,
    endTime,
    isGroup,
    participants,
    token,
    status
  } = req.body;

  db.run(
    `INSERT INTO meetings (createdBy, participantType, participantEmail, purpose, venue, startTime, endTime, isGroup, participants, token, status)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      scheduler,
      participantType,
      participantEmail,
      purpose,
      venue,
      startTime,
      endTime,
      isGroup ? 1 : 0,
      JSON.stringify(participants || []),
      token,
      status
    ],
    function (err) {
      if (err) return res.status(500).json({ message: "Error scheduling meeting" });
      res.json({ message: "Meeting scheduled", meetingId: this.lastID });
    }
  );
});

// Get all meetings (for staff)
app.get("/meetings", (req, res) => {
  db.all(`SELECT * FROM meetings`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: "Error fetching meetings" });
    const meetings = rows.map(m => ({ ...m, participants: JSON.parse(m.participants || '[]') }));
    res.json(meetings);
  });
});

// Get meetings for a specific user
app.get("/meetings/:userId", (req, res) => {
  const { userId } = req.params;
  db.all(
    `SELECT * FROM meetings WHERE createdBy = ?`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Error fetching meetings" });
      const meetings = rows.map(m => ({ ...m, participants: JSON.parse(m.participants || '[]') }));
      res.json(meetings);
    }
  );
});

// Approve/Reject Meeting
app.patch("/meetings/:id", (req, res) => {
  const { status, approvedBy } = req.body;
  const { id } = req.params;

  db.run(
    `UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?`,
    [status, approvedBy, id],
    function(err) {
      if (err) return res.status(500).json({ message: "Failed to update meeting" });
      res.json({ message: "Meeting updated" });
    }
  );
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
