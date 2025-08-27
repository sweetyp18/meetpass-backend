const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");

const app = express();
const PORT = process.env.PORT || 5000;

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
      title TEXT,
      purpose TEXT,
      date TEXT,
      time TEXT,
      createdBy INTEGER,
      FOREIGN KEY (createdBy) REFERENCES users(id)
    )
  `);
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
  const { title, purpose, date, time, createdBy } = req.body;
  if (!purpose || !date || !time)
    return res.status(400).json({ message: "All fields required" });

  db.run(
    `INSERT INTO meetings (title, purpose, date, time, createdBy) VALUES (?, ?, ?, ?, ?)`,
    [title || "", purpose, date, time, createdBy],
    function (err) {
      if (err) return res.status(500).json({ message: "Error scheduling meeting" });
      res.json({ message: "Meeting scheduled", meetingId: this.lastID });
    }
  );
});

// Get Meetings API
app.get("/meetings/:userId", (req, res) => {
  const { userId } = req.params;
  db.all(
    `SELECT * FROM meetings WHERE createdBy = ?`,
    [userId],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Error fetching meetings" });
      res.json(rows);
    }
  );
});

app.listen(PORT, () => console.log(`Server running on https://meetpass-backend.onrender.com:${PORT}`));
