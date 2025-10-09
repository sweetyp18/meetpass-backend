require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors()); // Allow requests from front-end. Configure origin in production.

// ---------- Config ----------
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "please_change_this_secret";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "30d"; // token lifetime

// ---------- DB ----------
const db = new sqlite3.Database("./meetpass.db", (err) => {
  if (err) console.error("DB Error:", err.message);
  else console.log("✅ Connected to SQLite database");
});

// Create tables if not exist
db.run(
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    regno TEXT UNIQUE,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'student',
    resetToken TEXT,
    resetTokenExpiry INTEGER
  )`
);

db.run(
  `CREATE TABLE IF NOT EXISTS meetings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scheduler TEXT,
    participantEmail TEXT,
    purpose TEXT,
    venue TEXT,
    startTime TEXT,
    endTime TEXT,
    isGroup INTEGER,
    participants TEXT,
    token TEXT,
    status TEXT DEFAULT 'Pending',
    approvedBy TEXT
  )`
);

// ---------- Email (nodemailer) ----------
const transporter = nodemailer.createTransport({
  service: "SendGrid",
  auth: {
    user: process.env.EMAIL_USER, // should be "apikey"
    pass: process.env.EMAIL_PASS, // your SendGrid API key
  },
});


// ---------- Helpers ----------
function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Middleware to protect endpoints
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"] || req.headers["Authorization"];
  if (!authHeader) return res.status(401).json({ message: "Missing authorization header" });
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") return res.status(401).json({ message: "Invalid authorization format" });
  const token = parts[1];
  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = payload; // payload includes regno, email, name, role
    next();
  });
}

// ---------- Routes ----------

// Health
app.get("/", (req, res) => res.send("MeetPass running successfully"));

// -------------- SIGNUP --------------
app.post("/signup", async (req, res) => {
  const { regno, name, email, password, role } = req.body;
  if (!regno || !name || !email || !password || !role) {
    return res.status(400).json({ message: "Please fill in all fields" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (regno, name, email, password, role) VALUES (?, ?, ?, ?, ?)`,
      [regno, name, email, hashedPassword, role],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE constraint failed")) {
            return res.status(409).json({ message: "User already exists (regno or email)" });
          }
          console.error("DB error during signup:", err);
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

// -------------- LOGIN (returns JWT) --------------
app.post("/login-regno", (req, res) => {
  const { regno, password } = req.body;
  if (!regno || !password) {
    return res.status(400).json({ message: "Please enter RegNo and password" });
  }
  db.get(`SELECT * FROM users WHERE regno = ?`, [regno], async (err, user) => {
    if (err) {
      console.error("DB error /login-regno:", err);
      return res.status(500).json({ message: "Server error" });
    }
    if (!user) return res.status(400).json({ message: "Invalid RegNo or password" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid RegNo or password" });

    const token = signJwt({
      id: user.id,
      regno: user.regno,
      name: user.name,
      email: user.email,
      role: user.role,
    });

    res.json({
      message: "Login successful",
      token,
      user: {
        regno: user.regno,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  });
});

// ----------------- FORGOT PASSWORD -----------------
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  console.log("Forgot password requested for:", email);  // ✅ log email

  if (!email) return res.status(400).json({ message: "Email is required" });

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      console.error("DB error:", err);  // ✅ log DB errors
      return res.status(500).json({ message: "Server error" });
    }
    console.log("User found:", user); // ✅ log user

    if (!user) {
      return res.json({ message: "If an account exists with that email, a reset link will be sent" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiry = Date.now() + 3600_000;

    db.run(
      `UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE email = ?`,
      [resetToken, resetTokenExpiry, email],
      (updateErr) => {
        if (updateErr) {
          console.error("Error saving reset token:", updateErr); // ✅ log
          return res.status(500).json({ message: "Error saving reset token" });
        }

        const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        const mailOptions = {
          from: process.env.EMAIL_FROM,
          to: email,
          subject: "MeetPass - Password Reset",
          html: `<p>Click here to reset your password:</p><a href="${resetLink}">${resetLink}</a>`
        };

        console.log("Sending email to:", email); // ✅ log before sending
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error("Failed to send email:", error); // ✅ log email errors
            return res.status(500).json({ message: "Failed to send email" });
          }
          console.log("Email sent:", info.response); // ✅ success log
          res.json({ message: "If an account exists with that email, a reset link will be sent" });
        });
      }
    );
  });
});


// Reset Password
app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ message: "New password is required" });

  const now = Date.now();
  db.get(
    `SELECT * FROM users WHERE resetToken = ? AND resetTokenExpiry > ?`,
    [token, now],
    async (err, user) => {
      if (err) return res.status(500).json({ message: "Server error" });
      if (!user) return res.status(400).json({ message: "Invalid or expired reset link" });

      try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        db.run(
          `UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?`,
          [hashedPassword, user.id],
          (updateErr) => {
            if (updateErr) return res.status(500).json({ message: "Error resetting password" });
            res.json({ message: "Password reset successfully" });
          }
        );
      } catch (hashErr) {
        res.status(500).json({ message: "Error hashing password" });
      }
    }
  );
});

// -------------- SCHEDULE MEETING (protected, improved) --------------
app.post("/meetings", authenticateToken, (req, res) => {
  console.log("Meeting request body:", req.body); // ✅ log incoming request
  console.log("Authenticated user:", req.user);   // ✅ log user from JWT

  const {
    scheduler, participantEmail, purpose, venue,
    startTime, endTime, isGroup, participants, token
  } = req.body;

  const schedulerEmail = scheduler || req.user.email;

  if (!schedulerEmail || !participantEmail || !purpose || !venue || !startTime || !endTime || !token) {
    console.log("Missing required fields"); // ✅ log missing fields
    return res.status(400).json({ message: "Missing required meeting fields" });
  }

  if (new Date(startTime) >= new Date(endTime)) {
    console.log("Invalid time range"); // ✅ log invalid times
    return res.status(400).json({ message: "Start time must be before end time" });
  }

  db.get(`SELECT * FROM meetings WHERE token = ?`, [token], (err, existing) => {
    if (err) {
      console.error("DB error checking token:", err); // ✅ log DB error
      return res.status(500).json({ message: "Server error" });
    }
    if (existing) {
      console.log("Token already exists:", token); // ✅ log token conflict
      return res.status(409).json({ message: "Meeting token already exists." });
    }

    console.log("Scheduling meeting for:", schedulerEmail, participantEmail); // ✅ log scheduling

    let finalParticipants = Array.isArray(participants) ? [...new Set(participants)] : [];
    let recipients = [schedulerEmail, participantEmail, ...finalParticipants];
    recipients = [...new Set(recipients)];

    db.run(
      `INSERT INTO meetings (scheduler, participantEmail, purpose, venue, startTime, endTime, isGroup, participants, token, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        schedulerEmail,
        participantEmail,
        purpose,
        venue,
        startTime,
        endTime,
        isGroup ? 1 : 0,
        JSON.stringify(finalParticipants),
        token,
        req.user.role === "staff" ? "Approved" : "Pending",
      ],
      function (err) {
        if (err) {
          console.error("DB error inserting meeting:", err); // ✅ log insert error
          return res.status(500).json({ message: "Failed to schedule meeting" });
        }

        console.log("Meeting inserted with ID:", this.lastID); // ✅ log success
        res.json({ message: "Meeting scheduled successfully", meetingId: this.lastID });
      }
    );
  });
});



// -------------- GET MEETINGS (protected) --------------
app.get("/meetings/:email", authenticateToken, (req, res) => {
  const userEmail = req.params.email;

  // Only allow user to fetch their own meetings unless staff (staff can fetch others)
  if (req.user.email !== userEmail && req.user.role !== "staff") {
    return res.status(403).json({ message: "Forbidden: cannot fetch other user's meetings" });
  }

  // participants is stored as JSON string; use LIKE to match email in that JSON string
  db.all(
    `SELECT * FROM meetings WHERE scheduler = ? OR participantEmail = ? OR participants LIKE ? ORDER BY startTime ASC`,
    [userEmail, userEmail, `%${userEmail}%`],
    (err, rows) => {
      if (err) {
        console.error("DB error fetching meetings:", err);
        return res.status(500).json({ message: "Failed to fetch meetings" });
      }
      // Parse participants JSON for each row for convenience
      const parsed = rows.map((r) => {
        try {
          return { ...r, participants: JSON.parse(r.participants || "[]") };
        } catch {
          return { ...r, participants: [] };
        }
      });
      res.json(parsed);
    }
  );
});

// -------------- UPDATE MEETING STATUS (protected) --------------
app.patch("/meetings/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status, approvedBy } = req.body;

  // Only staff or the approver can change status — here we allow staff to approve/reject
  if (req.user.role !== "staff") {
    return res.status(403).json({ message: "Only staff can update meeting status" });
  }

  db.run(
    `UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?`,
    [status, approvedBy || req.user.email, id],
    function (err) {
      if (err) {
        console.error("DB error updating meeting:", err);
        return res.status(500).json({ message: "Failed to update meeting" });
      }
      if (this.changes === 0) return res.status(404).json({ message: "Meeting not found" });
      res.json({ message: "Meeting status updated" });
    }
  );
});

// -------------- DELETE USER (protected) --------------
app.delete("/users/:regno", authenticateToken, (req, res) => {
  const { regno } = req.params;

  // Only staff can delete users; or allow user to delete own account
  if (req.user.role !== "staff" && req.user.regno !== regno) {
    return res.status(403).json({ message: "Forbidden: cannot delete this user" });
  }

  db.run(`DELETE FROM users WHERE regno = ?`, [regno], function (err) {
    if (err) {
      console.error("DB error deleting user:", err);
      return res.status(500).json({ message: "Failed to delete user" });
    }
    if (this.changes === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User deleted successfully" });
  });
});

// -------------- GET ALL USERS (protected) --------------
app.get("/users", authenticateToken, (req, res) => {
  // Only staff allowed to list all users
  if (req.user.role !== "staff") return res.status(403).json({ message: "Forbidden" });

  db.all("SELECT regno, name, email, role FROM users", [], (err, rows) => {
    if (err) {
      console.error("DB error fetching users:", err);
      return res.status(500).json({ message: "Failed to fetch users" });
    }
    res.json(rows);
  });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`🚀 MeetPass backend running on http://localhost:${PORT} (PORT=${PORT})`);
});
