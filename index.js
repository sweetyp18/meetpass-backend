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
  if (err) console.error("DB Error:", err.message);
  else console.log("Connected to meetpass.db");
});

// Create tables if not exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS meetings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      participantType TEXT,
      participantEmail TEXT,
      purpose TEXT NOT NULL,
      venue TEXT,
      startTime TEXT NOT NULL,
      endTime TEXT NOT NULL,
      isGroup INTEGER,
      participants TEXT,
      token TEXT,
      status TEXT,
      createdBy TEXT
    )
  `);
});

// Remove or comment out Signup route -- no signup here

// Keep Login route only

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ message: "Email and password required" });

  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err) return res.status(500).json({ message: "Database error" });
    if (!user) return res.status(400).json({ message: "Invalid email" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Incorrect password" });

    res.json({ message: "Login successful", userId: user.id, role: user.email.toLowerCase().includes("staff") ? "staff" : "user" });
  });
});

// Other APIs (meetings) remain unchanged...

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
