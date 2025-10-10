require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path"); 
const app = express();

// ---------- Middleware ----------
app.use(express.json());
app.use(cors({
  origin: "http://localhost:3000",
  methods: ["GET", "POST", "PATCH", "DELETE"],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ---------- Config ----------
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "sweetysumanthdisneyigneshiya!";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "30d";

// ---------- DB ----------
const dbPath = path.join(__dirname, "meetpass.db");
console.log("📂 Using database at:", dbPath);

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) console.error("DB Error:", err.message);
  else console.log("✅ Connected to SQLite database");
});


// Create tables (if not exists)
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  regno TEXT UNIQUE,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'student',
  resetToken TEXT,
  resetTokenExpiry INTEGER,
  profileImage TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS meetings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scheduler TEXT,
  participantEmail TEXT,
  purpose TEXT,
  venue TEXT,
  date TEXT,
  startTime TEXT,
  endTime TEXT,
  isGroup INTEGER,
  participants TEXT,
  token TEXT UNIQUE,
  status TEXT DEFAULT 'Pending',
  approvedBy TEXT
)`);

// ---------- Helpers ----------
function signJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// ---------- JWT Middleware ----------
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ message: "Missing authorization header" });

  const [type, token] = authHeader.split(" ");
  if (type !== "Bearer" || !token) return res.status(401).json({ message: "Invalid authorization format" });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = payload;
    next();
  });
}

// Health check
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

const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY); // your SendGrid API key

// ---------- TEST EMAIL (improved for debugging) ----------
app.get("/test-email", async (req, res) => {
  const msg = {
    to: "sweetyparaman123@gmail.com",
    from: process.env.EMAIL_FROM, // must be verified in SendGrid
    subject: "Test Email from MeetPass",
    html: "<p>Hello! This is a test email from MeetPass using SendGrid.</p>",
  };

  try {
    await sgMail.send(msg);
    console.log("✅ Test email sent successfully");
    res.json({ success: true, message: "Test email sent" });
  } catch (err) {
    console.error("❌ SendGrid error:", err);

    // Detailed error info
    if (err.response && err.response.body) {
      console.error("SendGrid response body:", err.response.body);
    }

    res.status(500).json({ 
      message: "Failed to send email", 
      error: err.message || err.toString(),
      responseBody: err.response?.body || null
    });
  }
});

// ----------------- FORGOT PASSWORD -----------------
app.post("/forgot-password", (req, res) => {
  let { email } = req.body;
  if (!email) return res.status(400).json({ message: "Email is required" });

  email = email.trim();

  db.get(`SELECT * FROM users WHERE LOWER(email) = LOWER(?)`, [email], (err, user) => {
    if (err) {
      console.error("DB error:", err);
      return res.status(500).json({ message: "Server error" });
    }

    console.log("User found:", user);

    if (!user) {
      return res.json({ message: "If an account exists with that email, a reset link will be sent" });
    }

    const resetToken = crypto.randomBytes(20).toString("hex");
    const resetTokenExpiry = Date.now() + 3600_000; // 1 hour

    db.run(
      `UPDATE users SET resetToken = ?, resetTokenExpiry = ? WHERE email = ?`,
      [resetToken, resetTokenExpiry, email],
      async (updateErr) => {
        if (updateErr) {
          console.error("Error saving reset token:", updateErr);
          return res.status(500).json({ message: "Error saving reset token" });
        }

        const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
        const msg = {
          to: email,
          from: process.env.EMAIL_FROM,
          subject: "MeetPass - Password Reset",
          html: `<p>Click the link below to reset your password:</p><a href="${resetLink}">${resetLink}</a>`,
        };

        try {
          await sgMail.send(msg);
          console.log("Password reset email sent to:", email);
          res.json({ message: "If an account exists with that email, a reset link will be sent" });
        } catch (sendErr) {
          console.error("SendGrid API error:", sendErr);
          res.status(500).json({ message: "Failed to send email" });
        }
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

// -------------- SCHEDULE MEETING (protected) --------------
app.post("/meetings", authenticateToken, (req, res) => {
  try {
    if (!req.user || !req.user.email) {
      return res.status(401).json({ message: "Unauthorized: invalid token" });
    }

    const { scheduler, participantEmail, purpose, venue, date, startTime, endTime, isGroup, participants, token } = req.body;
    const schedulerEmail = scheduler || req.user.email;

    // Validate required fields including date
    if (!schedulerEmail || !participantEmail || !purpose || !venue || !date || !startTime || !endTime || !token) {
      return res.status(400).json({ message: "Missing required meeting fields" });
    }

    // Validate start time is before end time using date + time
    const startDateTime = new Date(`${date}T${startTime}`);
    const endDateTime = new Date(`${date}T${endTime}`);

    if (startDateTime >= endDateTime) {
      return res.status(400).json({ message: "Start time must be before end time" });
    }

    db.get(`SELECT * FROM meetings WHERE token = ?`, [token], (err, existing) => {
      if (err) return res.status(500).json({ message: "Server error" });
      if (existing) return res.status(409).json({ message: "Meeting token already exists." });

      const finalParticipants = Array.isArray(participants) ? [...new Set(participants)] : [];

     db.run(
  `INSERT INTO meetings (
    scheduler, participantEmail, purpose, venue, date, startTime, endTime, isGroup, participants, token, status, approvedBy
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  [
    schedulerEmail,
    participantEmail,
    purpose,
    venue,
    date,
    startTime,
    endTime,
    isGroup ? 1 : 0,
    JSON.stringify(finalParticipants),
    token,
    req.user.role === "staff" ? "Approved" : "Pending",
    null // or staff email if staff is scheduling
  ],

        function (err) {
          if (err) return res.status(500).json({ message: "Failed to schedule meeting" });
          return res.status(201).json({ message: "Meeting scheduled successfully", meetingId: this.lastID });
        }
      );
    });
  } catch (err) {
    return res.status(500).json({ message: "Server error" });
  }
});


// -------------- GET MEETINGS (protected) --------------
app.get("/meetings", authenticateToken, (req, res) => {
  const userEmail = req.user.email;
  const isStaff = req.user.role === "staff";

  db.all(`SELECT * FROM meetings ORDER BY startTime ASC`, [], (err, rows) => {
    if (err) return res.status(500).json({ message: "Failed to fetch meetings" });

    const parsed = rows.map(r => {
      try { r.participants = JSON.parse(r.participants || "[]"); } 
      catch { r.participants = []; }
      return r;
    });

    const filtered = parsed.filter(m =>
      isStaff || 
      m.scheduler === userEmail || 
      m.participantEmail === userEmail || 
      (m.isGroup && m.participants.includes(userEmail))
    );

    res.json(filtered);
  });
});

// -------------- UPDATE MEETING STATUS (protected) --------------
app.patch("/meetings/:id", authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status, approvedBy } = req.body;

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
app.get("/debug-users", (req, res) => {
  db.all("SELECT * FROM users", [], (err, rows) => {
    if(err) return res.status(500).json({ message: err.message });
    res.json(rows);
  });
});

// -------------- GET ALL USERS (protected) --------------
app.get("/users", authenticateToken, (req, res) => {
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
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
