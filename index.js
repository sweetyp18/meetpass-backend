const express = require("express");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg"); // changed to pg
const nodemailer = require("nodemailer");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());

// ------------------- DATABASE -------------------
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
async function runMigrations() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      regno TEXT UNIQUE,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT,
      role TEXT DEFAULT 'student',
      resetToken TEXT,
      resetTokenExpiry BIGINT
    );
    CREATE TABLE IF NOT EXISTS meetings (
      id SERIAL PRIMARY KEY,
      scheduler TEXT,
      participantEmail TEXT,
      purpose TEXT,
      venue TEXT,
      startTime TEXT,
      endTime TEXT,
      isGroup BOOLEAN,
      participants TEXT,
      token TEXT,
      status TEXT DEFAULT 'Pending',
      approvedBy TEXT
    );
  `);
}

runMigrations().catch(err => {
  console.error("DB migration error:", err);
});


// ------------------- SIGNUP -------------------
app.post("/signup", async (req, res) => {
  const { regno, name, email, password, role } = req.body;
  if (!regno || !name || !email || !password || !role) {
    return res.status(400).json({ message: "Please fill in all fields" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
      await pool.query(
        `INSERT INTO users (regno, name, email, password, role) VALUES ($1, $2, $3, $4, $5)`,
        [regno, name, email, hashedPassword, role]
      );
      res.status(201).json({ message: "User registered successfully" });
    } catch (err) {
      if (err.code === '23505') { // unique violation
        return res.status(409).json({ message: "User already exists" });
      }
      console.error("DB error during signup:", err);
      return res.status(500).json({ message: "Registration failed" });
    }
  } catch (err) {
    console.error("Hashing error:", err);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// ------------------- LOGIN -------------------
app.post("/login-regno", async (req, res) => {
  const { regno, password } = req.body;
  if (!regno || !password) {
    return res.status(400).json({ message: "Please enter RegNo and password" });
  }
  try {
    const result = await pool.query(`SELECT * FROM users WHERE regno = $1`, [regno]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: "Invalid RegNo or password" });

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
  } catch (err) {
    res.status(500).json({ message: "Server error during login" });
  }
});

// ------------------- DASHBOARD -------------------
app.get("/dashboard/:regno", async (req, res) => {
  const { regno } = req.params;
  try {
    const result = await pool.query(
      `SELECT regno, name, email, role FROM users WHERE regno = $1`,
      [regno]
    );
    const user = result.rows[0];
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
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
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  console.log("Received forgot-password request for email:", email);

  if (!email) {
    console.log("Email not provided");
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    const user = result.rows[0];
    if (!user) {
      console.log("User not found for email:", email);
      return res.status(400).json({ message: "User not found" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiry = Date.now() + 3600_000; // 1 hour
    const resetLink = `http://localhost:3000/reset-password/${resetToken}`;

    console.log("Generated reset token:", resetToken);

    await pool.query(
      `UPDATE users SET resetToken = $1, resetTokenExpiry = $2 WHERE email = $3`,
      [resetToken, resetTokenExpiry, email]
    );

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
  } catch (ex) {
    console.error("Exception in forgot-password:", ex);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// ------------------- RESET PASSWORD -------------------
app.post("/reset-password/:token", async (req, res) => {
  const { token } = req.params;
  const { newPassword } = req.body;
  if (!newPassword) return res.status(400).json({ message: "New password required" });

  try {
    const result = await pool.query(`SELECT * FROM users WHERE resetToken = $1`, [token]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ message: "Invalid or expired token" });
    if (Date.now() > user.resetTokenExpiry) return res.status(400).json({ message: "Token expired" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await pool.query(
      `UPDATE users SET password = $1, resetToken = NULL, resetTokenExpiry = NULL WHERE id = $2`,
      [hashedPassword, user.id]
    );
    res.json({ message: "Password reset successful" });
  } catch (err) {
    res.status(500).json({ message: "Failed to reset password" });
  }
});

// ------------------- SCHEDULE MEETING -------------------
app.post("/meetings", async (req, res) => {
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

  try {
    await pool.query(
      `INSERT INTO meetings 
      (scheduler, participantEmail, purpose, venue, startTime, endTime, isGroup, participants, token, status)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        scheduler,
        participantEmail,
        purpose,
        venue,
        startTime,
        endTime,
        isGroup,
        JSON.stringify(participants || []),
        token,
        status || "Pending",
      ]
    );

    let recipients = [scheduler, participantEmail];
    if (isGroup && participants && participants.length > 0) {
      recipients = recipients.concat(participants);
    }
    recipients = [...new Set(recipients)];

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: recipients,
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

    res.json({ message: "Meeting scheduled successfully" });
  } catch (err) {
    console.error("Error saving meeting:", err);
    return res.status(500).json({ message: "Failed to schedule meeting" });
  }
});

// ------------------- GET MEETINGS -------------------
app.get("/meetings/:email", async (req, res) => {
  const userEmail = req.params.email;
  try {
    const result = await pool.query(
      `SELECT * FROM meetings WHERE scheduler = $1 OR participantEmail = $2`,
      [userEmail, userEmail]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ message: "Failed to fetch meetings" });
  }
});

// ------------------- UPDATE MEETING STATUS -------------------
app.patch("/meetings/:id", async (req, res) => {
  const { id } = req.params;
  const { status, approvedBy } = req.body;

  try {
    await pool.query(
      `UPDATE meetings SET status = $1, approvedBy = $2 WHERE id = $3`,
      [status, approvedBy, id]
    );
    res.json({ message: "Meeting status updated" });
  } catch (err) {
    res.status(500).json({ message: "Failed to update meeting" });
  }
});

// ------------------- DELETE USER -------------------
app.delete("/users/:regno", async (req, res) => {
  const { regno } = req.params;
  try {
    const result = await pool.query(`DELETE FROM users WHERE regno = $1`, [regno]);
    if (result.rowCount === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "Failed to delete user" });
  }
});

// ------------------- ROUTE TO GET ALL USERS -------------------
app.get("/users", async (req, res) => {
  try {
    const result = await pool.query("SELECT regno, name, email, role FROM users");
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching users", err);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});
