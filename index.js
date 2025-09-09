const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
require("dotenv").config();

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

  db.run(`
    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scheduler TEXT,
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

// ------------------- SIGNUP ENDPOINT -------------------
app.post("/signup", async (req, res) => {
  const { name, email, password, role } = req.body;

  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "Please fill in all fields" });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`,
      [name, email, hashedPassword, role],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE constraint failed")) {
            return res.status(409).json({ message: "Email already exists" });
          }
          console.error("Database error during signup:", err);
          return res.status(500).json({ message: "Registration failed" });
        }
        res.status(201).json({ message: "User registered successfully" });
      }
    );
  } catch (err) {
    console.error("Hashing error:", err);
    res.status(500).json({ message: "Server error during registration" });
  }
});
// ------------------- END SIGNUP -------------------

// ------------------- LOGIN ENDPOINT -------------------
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user)
      return res.status(400).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid email or password" });

    res.json({
      message: "Login successful",
      name: user.name,
      email: user.email,
      role: user.role || "student",
    });
  });
});
// ------------------- END LOGIN -------------------

// ------------------- EMAIL TRANSPORTER -------------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER, // your Gmail
    pass: process.env.EMAIL_PASS, // your App Password
  },
});

// ------------------- SCHEDULE MEETING -------------------
app.post("/meetings", (req, res) => {
  const {
    scheduler,
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

  const participantsJSON = JSON.stringify(participants || []);

  db.run(
    `INSERT INTO meetings
      (scheduler, participantEmail, purpose, venue, startTime, endTime, isGroup, participants, token, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      scheduler,
      participantEmail,
      purpose,
      venue,
      startTime,
      endTime,
      isGroup ? 1 : 0,
      participantsJSON,
      token,
      status,
    ],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Failed to schedule meeting" });
      }

      // -------- Send Email Notification --------
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: participantEmail,
        subject: "New Meeting Scheduled - MeetPass",
        text: `Hello,

You have a new meeting scheduled.

📌 Purpose: ${purpose}
📍 Venue: ${venue}
🕒 Time: ${startTime} - ${endTime}
👤 Scheduled By: ${scheduler}

Please check MeetPass for more details.`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Email error:", error);
        } else {
          console.log("Email sent:", info.response);
        }
      });
      // ----------------------------------------

      res.json({ message: "Meeting scheduled & email sent", id: this.lastID });
    }
  );
});
// ------------------- END SCHEDULE MEETING -------------------

// ------------------- GET MEETINGS -------------------
app.get("/meetings/:email", (req, res) => {
  const email = req.params.email;

  db.all(
    `SELECT * FROM meetings WHERE scheduler = ? OR participantEmail = ?`,
    [email, email],
    (err, rows) => {
      if (err)
        return res.status(500).json({ message: "Failed to fetch meetings" });

      const meetings = rows.map((m) => ({
        ...m,
        participants: JSON.parse(m.participants || "[]"),
      }));
      res.json(meetings);
    }
  );
});
// ------------------- END GET MEETINGS -------------------

// ------------------- UPDATE MEETING STATUS -------------------
app.patch("/meetings/:id", (req, res) => {
  const { status, approvedBy } = req.body;
  const id = req.params.id;

  db.run(
    `UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?`,
    [status, approvedBy, id],
    function (err) {
      if (err)
        return res.status(500).json({ message: "Failed to update status" });
      res.json({ message: "Status updated" });
    }
  );
});
// ------------------- END UPDATE STATUS -------------------

// Start server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
