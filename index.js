const express = require("express");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());

// ------------------- DATABASE -------------------
const db = new sqlite3.Database("meetpass.db");

// Create tables
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

// ------------------- SIGNUP -------------------
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
            return res.status(409).json({ message: "User already exists" });
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

// ------------------- LOGIN -------------------
app.post("/login-regno", (req, res) => {
  const { regno, password } = req.body;
  if (!regno || !password) {
    return res.status(400).json({ message: "Please enter RegNo and password" });
  }
  db.get(`SELECT * FROM users WHERE regno = ?`, [regno], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "Invalid RegNo or password" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid RegNo or password" });
    res.json({
      message: "Login successful",
      user: {
        regno: user.regno,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  });
});

// ------------------- DASHBOARD -------------------
app.get("/dashboard/:regno", (req, res) => {
  const { regno } = req.params;
  db.get(
    `SELECT regno, name, email, role FROM users WHERE regno = ?`,
    [regno],
    (err, user) => {
      if (err || !user) return res.status(404).json({ message: "User not found" });
      res.json({ user });
    }
  );
});

// ------------------- EMAIL TRANSPORTER -------------------
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ------------------- FORGOT PASSWORD -------------------
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  console.log("Received forgot-password request for email:", email);

  if (!email) {
    console.log("Email not provided");
    return res.status(400).json({ message: "Email is required" });
  }

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (err) {
      console.error("DB error while fetching user:", err);
      return res.status(500).json({ message: "Internal server error" });
    }
    if (!user) {
      console.log("User not found for email:", email);
      return res.status(400).json({ message: "User not found" });
    }

    try {
      const resetToken = crypto.randomBytes(20).toString("hex");
      const resetTokenExpiry = Date.now() + 3600_000; // 1 hour
      const resetLink = `http://localhost:3000/reset-password/${resetToken}`;

      console.log("Generated reset token:", resetToken);

      db.run(
        `UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE email = ?`,
        [resetToken, resetTokenExpiry, email],
        (updateErr) => {
          if (updateErr) {
            console.error("Error updating reset token in DB:", updateErr);
            return res.status(500).json({ message: "Error generating reset token" });
          }
          console.log("Reset token updated in DB, sending email...");

          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: "MeetPass - Password Reset",
            text: `Hello ${user.name},\n\nClick to reset your password:\n${resetLink}\n\nIgnore if not requested.`,
          };

          transporter.sendMail(mailOptions, (error) => {
            if (error) {
              console.error("Failed to send email:", error);
              return res.status(500).json({ message: "Failed to send email" });
            }
            console.log("Password reset email sent successfully to:", user.email);
            res.json({ message: "Password reset link sent to registered email" });
          });
        }
      );
    } catch (ex) {
      console.error("Exception in forgot-password:", ex);
      return res.status(500).json({ message: "Internal server error" });
    }
  });
});

// ------------------- RESET PASSWORD -------------------
app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ message: "New password required" });

  db.get(`SELECT * FROM users WHERE resetToken = ?`, [token], async (err, user) => {
    if (err || !user) return res.status(400).json({ message: "Invalid or expired token" });
    if (Date.now() > user.resetTokenExpiry) return res.status(400).json({ message: "Token expired" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    db.run(
      `UPDATE users SET password = ?, resetToken = NULL, resetTokenExpiry = NULL WHERE id = ?`,
      [hashedPassword, user.id],
      (updateErr) => {
        if (updateErr) return res.status(500).json({ message: "Failed to reset password" });
        res.json({ message: "Password reset successful" });
      }
    );
  });
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
      JSON.stringify(participants || []),
      token,
      status || "Pending",
    ],
    function (err) {
      if (err) {
        console.error("Error saving meeting:", err);
        return res.status(500).json({ message: "Failed to schedule meeting" });
      }

      // ----------------- FIXED EMAIL RECIPIENTS -----------------
      let recipients = [scheduler, participantEmail];
      if (isGroup && participants && participants.length > 0) {
        recipients = recipients.concat(participants);
      }

      // Remove duplicates
      recipients = [...new Set(recipients)];

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: recipients,   // ✅ scheduler + participant(s)
        subject: `Meeting Scheduled: ${token}`,
        text: `
Hello,

A meeting has been scheduled.

Scheduler: ${scheduler}
Participant(s): ${isGroup && participants.length > 0 ? participants.join(", ") : participantEmail}
Purpose: ${purpose}
Venue: ${venue}
Start Time: ${startTime}
End Time: ${endTime}
Token: ${token}

Thank you,
MeetPass
        `,
      };

      transporter.sendMail(mailOptions, (emailErr) => {
        if (emailErr) console.error("Failed to send meeting email:", emailErr);
        else console.log("✅ Meeting email sent to:", recipients.join(", "));
      });

      res.json({ message: "Meeting scheduled successfully", meetingId: this.lastID });
    }
  );
});


// ------------------- GET MEETINGS -------------------
app.get("/meetings/:email", (req, res) => {
  const userEmail = req.params.email;
  db.all(
    `SELECT * FROM meetings WHERE scheduler = ? OR participantEmail = ?`,
    [userEmail, userEmail],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "Failed to fetch meetings" });
      res.json(rows);
    }
  );
});

// ------------------- UPDATE MEETING STATUS -------------------
app.patch("/meetings/:id", (req, res) => {
  const { id } = req.params;
  const { status, approvedBy } = req.body;

  db.run(
    `UPDATE meetings SET status = ?, approvedBy = ? WHERE id = ?`,
    [status, approvedBy, id],
    function (err) {
      if (err) return res.status(500).json({ message: "Failed to update meeting" });
      res.json({ message: "Meeting status updated" });
    }
  );
});
app.get("/", (req, res) => {
  res.send("meetpass running successfully");
});
// Delete user by regno
app.delete("/users/:regno", (req, res) => {
  const { regno } = req.params;
  db.run(`DELETE FROM users WHERE regno = ?`, [regno], function(err) {
    if (err) {
      console.error("Error deleting user:", err);
      return res.status(500).json({ message: "Failed to delete user" });
    }
    if (this.changes === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  });
});


// ------------------- SERVER -------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
// Route to get all users (for debugging/viewing data)
app.get("/users", (req, res) => {
  db.all("SELECT regno, name, email, role FROM users", [], (err, rows) => {
    if (err) {
      console.error("Error fetching users", err);
      return res.status(500).json({ message: "Failed to fetch users" });
    }
    res.json(rows);
  });
});
