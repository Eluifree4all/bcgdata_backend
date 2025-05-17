process.on('uncaughtException', (error) => {
  console.error('--- UNCAUGHT EXCEPTION ---');
  console.error(error.stack || error);
  // process.exit(1); // Optionally exit, but for debugging, just log
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('--- UNHANDLED REJECTION ---');
  console.error('Unhandled Rejection at:', promise, 'reason:', reason.stack || reason);
  // process.exit(1); // Optionally exit
});

// ... rest of your server.js (const express = require("express"); etc.)


// server.js
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const sharp = require("sharp");
const jwt = require("jsonwebtoken");
const axios = require("axios");

// Load .env file only if not in production
if (process.env.NODE_ENV !== 'production') {
  console.log("Loading .env file for development/local environment...");
  require('dotenv').config();
}

// Early logging for critical environment variables
console.log("--- START OF SCRIPT ---");
console.log(`Initial process.env.PORT value: ${process.env.PORT}`);
console.log(`Initial process.env.NODE_ENV value: ${process.env.NODE_ENV}`);
console.log(`Initial process.env.JWT_SECRET available: ${!!process.env.JWT_SECRET}`);
console.log(`Initial process.env.DB_HOST available: ${!!process.env.DB_HOST}`);
console.log(`Initial process.env.CALLMEBOT_APIKEY available: ${!!process.env.CALLMEBOT_APIKEY}`);
console.log(`Initial process.env.ADMIN_PHONE_CALLMEBOT available: ${!!process.env.ADMIN_PHONE_CALLMEBOT}`);


const JWT_SECRET = process.env.JWT_SECRET;
const app = express();

const PORT = process.env.PORT || 3000; // Use Alwaysdata's PORT or 3000 for local
const HOST = '::'; // Listen on all available network interfaces

const saltRounds = 10;

// Image Processing Configuration
const IMAGE_QUALITY = 80;
const MAX_IMAGE_WIDTH = 800;
const MAX_IMAGE_HEIGHT = 800;
const TARGET_FILE_SIZE_KB = 300;

// Ensure 'assets' directory exists
const UPLOAD_DIR = path.join(__dirname, "assets");
if (!fs.existsSync(UPLOAD_DIR)) {
  console.log(`Creating upload directory: ${UPLOAD_DIR}`);
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// JWT Verification Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    console.log("Auth Middleware: No token provided");
    return res.status(401).json({ message: "No token provided. Access denied." });
  }

  if (!JWT_SECRET) {
    console.error("CRITICAL: JWT_SECRET is not defined. Cannot verify tokens.");
    return res.status(500).json({ message: "Server configuration error: JWT secret missing." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("Auth Middleware: Token verification failed:", err.message);
      if (err.name === "TokenExpiredError") {
        return res.status(403).json({ message: "Token expired. Please log in again." });
      }
      return res.status(403).json({ message: "Invalid token. Access denied." });
    }
    // console.log("Auth Middleware: Token verified, user:", user); // Can be verbose
    req.user = user;
    next();
  });
};

const getUserIdFromAuthenticatedRequest = (req) => {
  if (req.user && req.user.id) {
    return req.user.id;
  }
  console.warn("getUserIdFromAuthenticatedRequest: req.user or req.user.id is missing.");
  return null;
};

// Super Admin Authorization Middleware
const authorizeSuperAdmin = (req, res, next) => {
  if (req.user && req.user.role === "SuperAdmin") {
    next();
  } else {
    console.warn(`Unauthorized super admin access attempt by user: ${req.user?.username} (Role: ${req.user?.role})`);
    return res.status(403).json({ message: "Forbidden: You do not have super admin privileges." });
  }
};

// Database Configuration
const dbPool = mysql.createPool({
  host: process.env.DB_HOST || "mysql-bccg.alwaysdata.net",
  user: process.env.DB_USER || "bccg_bcg",
  password: process.env.DB_PASSWORD || "S0m1b@b3", // Ensure this is secure or only for local fallback
  database: process.env.DB_DATABASE || "bccg_bcg",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  dateStrings: true,
  typeCast: function (field, next) {
    if (field.type === "JSON") {
      try {
        return JSON.parse(field.string());
      } catch (e) {
        return field.string();
      }
    }
    return next();
  },
});

// Multer Configuration
const memoryStorage = multer.memoryStorage();
const imageFileFilter = (req, file, cb) => {
  const allowedMimes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    console.log(`Rejected file type: ${file.mimetype}`);
    cb(new Error("Invalid file type. Only JPEG, PNG, GIF, or WEBP images are allowed."), false);
  }
};
const upload = multer({
  storage: memoryStorage,
  fileFilter: imageFileFilter,
  limits: { fileSize: 10 * 1024 * 1024 },
}).single("passportPhoto");

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use("/assets", express.static(UPLOAD_DIR));

// CallMeBot Configuration
const CALLMEBOT_API_KEY = process.env.CALLMEBOT_APIKEY;
const ADMIN_WHATSAPP_NUMBER_FOR_CALLMEBOT = process.env.ADMIN_PHONE_CALLMEBOT;

// Helper Function to Send CallMeBot WhatsApp Notification
async function sendCallMeBotAdminNotification(newUserName, newUserFullName) {
  if (!CALLMEBOT_API_KEY || !ADMIN_WHATSAPP_NUMBER_FOR_CALLMEBOT) {
    console.warn("CallMeBot API Key or Admin WhatsApp number not configured. Skipping notification.");
    return;
  }
  const messageText = `BCG Pastors DB Alert: New admin registration for ${newUserFullName} (Username: ${newUserName}). Account requires activation.`;
  const encodedMessage = encodeURIComponent(messageText);
  const phoneNumber = encodeURIComponent(ADMIN_WHATSAPP_NUMBER_FOR_CALLMEBOT);
  const callMeBotUrl = `https://api.callmebot.com/whatsapp.php?phone=${phoneNumber}&text=${encodedMessage}&apikey=${CALLMEBOT_API_KEY}`;
  try {
    // console.log(`Sending CallMeBot notification to ${ADMIN_WHATSAPP_NUMBER_FOR_CALLMEBOT}...`);
    // console.log(`CallMeBot URL: ${callMeBotUrl}`);
    const response = await axios.get(callMeBotUrl);
    // console.log("CallMeBot API Response Status:", response.status);
    if (response.status === 200) {
      console.log("CallMeBot WhatsApp notification request successful.");
    } else {
      console.warn(`CallMeBot API request may have failed. Status: ${response.status}`);
    }
  } catch (error) {
    console.error("Error sending CallMeBot WhatsApp notification:", error.message);
  }
}

// Helper Function for Age Calculation
function calculateAge(dobString) {
  if (!dobString) return null;
  try {
    const birthDate = new Date(dobString);
    if (isNaN(birthDate.getTime())) return null;
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const m = today.getMonth() - birthDate.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
      age--;
    }
    return age >= 0 ? age : null;
  } catch (e) {
    console.error("Error calculating age for DOB:", dobString, e);
    return null;
  }
}

// Helper function to calculate birth date range for a given age
function getBirthDateRangeForAge(age) {
  const today = new Date();
  const currentYear = today.getFullYear();
  const currentMonth = today.getMonth();
  const currentDate = today.getDate();
  const latestBirthDate = new Date(currentYear - age, currentMonth, currentDate + 1);
  const earliestBirthDate = new Date(currentYear - age - 1, currentMonth, currentDate + 1);
  return {
    earliest: `${earliestBirthDate.getFullYear()}-${String(earliestBirthDate.getMonth() + 1).padStart(2, "0")}-${String(earliestBirthDate.getDate()).padStart(2, "0")}`,
    latest: `${latestBirthDate.getFullYear()}-${String(latestBirthDate.getMonth() + 1).padStart(2, "0")}-${String(latestBirthDate.getDate()).padStart(2, "0")}`,
  };
}

// Helper function to calculate birth date for min/max age for an age range
function getBirthDateForAgeLimit(age, limitType) {
  const today = new Date();
  const currentYear = today.getFullYear();
  const currentMonth = today.getMonth();
  const currentDate = today.getDate();
  let birthDateObj;
  if (limitType === "min") {
    birthDateObj = new Date(currentYear - age, currentMonth, currentDate);
  } else { // max age
    birthDateObj = new Date(currentYear - age - 1, currentMonth, currentDate + 1);
  }
  return `${birthDateObj.getFullYear()}-${String(birthDateObj.getMonth() + 1).padStart(2, "0")}-${String(birthDateObj.getDate()).padStart(2, "0")}`;
}


// --- API Routes ---

app.post("/pastors/multi-search", authenticateToken, async (req, res) => {
  const criteria = req.body;
  // console.log("Received multi-search criteria:", criteria);
  if (Object.keys(criteria).length === 0) {
    return res.status(400).json({ message: "At least one search criterion is required." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    let sql = `
            SELECT id, pastor_id, surname, first_name, gender, dob, 
                   church_status, native_state, church_groups, 
                   passport_photo_url, mobile_phone, outpost, 
                   is_draft, is_archived, sub_groups
            FROM pastors
            WHERE 1=1 `;
    const sqlParams = [];

    if (criteria.name) {
      sql += ` AND (LOWER(surname) LIKE ? OR LOWER(first_name) LIKE ? OR LOWER(other_names) LIKE ?)`;
      const nameTerm = `%${criteria.name.toLowerCase()}%`;
      sqlParams.push(nameTerm, nameTerm, nameTerm);
    }
    if (criteria.gender) {
      sql += ` AND LOWER(gender) = ?`;
      sqlParams.push(criteria.gender.toLowerCase());
    }
    if (criteria.nativeState) {
      sql += ` AND LOWER(native_state) LIKE ?`;
      sqlParams.push(`%${criteria.nativeState.toLowerCase()}%`);
    }
    if (criteria.outpost) {
      sql += ` AND outpost = ?`;
      sqlParams.push(criteria.outpost);
    }
    if (criteria.status) {
      sql += ` AND LOWER(church_status) = ?`;
      sqlParams.push(criteria.status.toLowerCase());
    }
    if (criteria.group) {
      sql += ` AND LOWER(church_groups) = ?`;
      sqlParams.push(criteria.group.toLowerCase());
    }
    if (criteria.age) {
      const targetAge = parseInt(criteria.age, 10);
      if (!isNaN(targetAge) && targetAge >= 0) {
        const { earliest, latest } = getBirthDateRangeForAge(targetAge);
        sql += ` AND dob > ? AND dob <= ?`;
        sqlParams.push(earliest, latest);
      }
    } else if (criteria.ageMin || criteria.ageMax) {
      const ageMin = criteria.ageMin ? parseInt(criteria.ageMin, 10) : null;
      const ageMax = criteria.ageMax ? parseInt(criteria.ageMax, 10) : null;
      if (ageMin !== null && !isNaN(ageMin) && ageMin >= 0) {
        const latestBirthDateForMinAge = getBirthDateForAgeLimit(ageMin, "min");
        sql += ` AND dob <= ?`;
        sqlParams.push(latestBirthDateForMinAge);
      }
      if (ageMax !== null && !isNaN(ageMax) && ageMax >= 0) {
        const earliestBirthDateForMaxAge = getBirthDateForAgeLimit(ageMax, "max");
        sql += ` AND dob >= ?`;
        sqlParams.push(earliestBirthDateForMaxAge);
      }
    }
    if (criteria.subGroups && criteria.subGroups.length > 0) {
      const subGroupConditions = criteria.subGroups.map(() => `JSON_CONTAINS(sub_groups, JSON_QUOTE(?))`).join(" OR ");
      sql += ` AND (${subGroupConditions})`;
      criteria.subGroups.forEach((sg) => sqlParams.push(sg));
    }
    if (criteria.includeArchived === false || criteria.includeArchived === 'false' || criteria.includeArchived === undefined) {
      sql += ` AND is_archived = 0`;
    }
    if (criteria.includeDrafts === false || criteria.includeDrafts === 'false' || criteria.includeDrafts === undefined) {
      sql += ` AND is_draft = 0`;
    }
    sql += ` ORDER BY surname ASC, first_name ASC`;
    // console.log("Executing Multi-Search SQL:", sql.substring(0, 200) + "...", "Params:", sqlParams.length);
    const [rows] = await connection.query(sql, sqlParams);
    const processedRows = rows.map((p) => ({
      ...p, // Keep original snake_case from DB
      age: calculateAge(p.dob),
      subGroups: Array.isArray(p.sub_groups) ? p.sub_groups : (typeof p.sub_groups === 'string' ? JSON.parse(p.sub_groups || "[]") : []),
      isDraft: !!p.is_draft,
      isArchived: !!p.is_archived,
      // For frontend convenience if it expects these specific camelCase names:
      churchStatus: p.church_status,
      churchGroup: p.church_groups,
      // All other fields will be snake_case as selected
    }));
    res.json(processedRows);
  } catch (error) {
    console.error("Error during multi-search:", error);
    res.status(500).json({ message: "An error occurred during search." });
  } finally {
    if (connection) connection.release();
  }
});

const userManagementRouter = express.Router();
userManagementRouter.use(authenticateToken);
userManagementRouter.use(authorizeSuperAdmin);

userManagementRouter.get("/", async (req, res) => {
  // console.log("API: SuperAdmin - GET /api/users (manage users)");
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [users] = await connection.query("SELECT UserID, Name, Username, Email, Status, Usergroup FROM users ORDER BY Name ASC");
    res.json(users);
  } catch (error) {
    console.error("Error fetching users for management:", error);
    res.status(500).json({ message: "Failed to fetch users." });
  } finally {
    if (connection) connection.release();
  }
});

userManagementRouter.put("/:userId/status", async (req, res) => {
  const { userId } = req.params;
  const { status } = req.body;
  const targetUserId = parseInt(userId, 10);
  const superAdminId = getUserIdFromAuthenticatedRequest(req);
  // console.log(`API: SuperAdmin - PUT /api/users/${targetUserId}/status to ${status}`);
  if (targetUserId === superAdminId) {
    return res.status(400).json({ message: "Super admins cannot change their own status." });
  }
  if (!["Active", "Inactive"].includes(status)) {
    return res.status(400).json({ message: "Invalid status value." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [result] = await connection.query("UPDATE users SET Status = ? WHERE UserID = ? AND UserID != ?", [status, targetUserId, superAdminId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found or cannot be modified." });
    }
    res.json({ message: `User status updated successfully.` });
  } catch (error) {
    console.error(`Error updating user ${targetUserId} status:`, error);
    res.status(500).json({ message: "Failed to update user status." });
  } finally {
    if (connection) connection.release();
  }
});

userManagementRouter.put("/:userId/role", async (req, res) => {
  const { userId } = req.params;
  const { role } = req.body;
  const targetUserId = parseInt(userId, 10);
  const superAdminId = getUserIdFromAuthenticatedRequest(req);
  // console.log(`API: SuperAdmin - PUT /api/users/${targetUserId}/role to ${role}`);
  if (targetUserId === superAdminId && role !== "SuperAdmin") {
    return res.status(400).json({ message: "Super admins cannot demote themselves." });
  }
  const allowedRoles = ["Admin", "SuperAdmin"];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ message: "Invalid role specified." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    const preventSelfDemoteCondition = (targetUserId === superAdminId && role !== 'SuperAdmin') ? `AND UserID != ${superAdminId}` : '';
    const sql = `UPDATE users SET Usergroup = ? WHERE UserID = ? ${preventSelfDemoteCondition}`;
    const [result] = await connection.query(sql, [role, targetUserId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found or role change not permitted." });
    }
    res.json({ message: `User role updated successfully.` });
  } catch (error) {
    console.error(`Error updating user ${targetUserId} role:`, error);
    res.status(500).json({ message: "Failed to update user role." });
  } finally {
    if (connection) connection.release();
  }
});

userManagementRouter.post("/:userId/change-password", async (req, res) => {
  const { userId } = req.params;
  const { newPassword } = req.body;
  const targetUserId = parseInt(userId, 10);
  // console.log(`API: SuperAdmin - POST /api/users/${targetUserId}/change-password`);
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ message: "New password must be at least 6 characters long." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    const [result] = await connection.query("UPDATE users SET Password = ? WHERE UserID = ?", [hashedNewPassword, targetUserId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User not found." });
    }
    res.json({ message: `Password for user updated successfully.` });
  } catch (error) {
    console.error(`Error changing password for user ${targetUserId}:`, error);
    res.status(500).json({ message: "Failed to change password." });
  } finally {
    if (connection) connection.release();
  }
});

userManagementRouter.delete("/:userId", async (req, res) => {
  const { userId } = req.params;
  const targetUserId = parseInt(userId, 10);
  const requestingAdminId = getUserIdFromAuthenticatedRequest(req);
  // console.log(`API: SuperAdmin - DELETE /api/users/${targetUserId} requested by Admin ID: ${requestingAdminId}`);
  if (isNaN(targetUserId)) {
    return res.status(400).json({ message: "Invalid User ID provided." });
  }
  if (targetUserId === requestingAdminId) {
    return res.status(403).json({ message: "Super admins cannot delete their own account." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    await connection.beginTransaction();
    const [notesDeleteResult] = await connection.query("DELETE FROM admin_notes WHERE user_id = ?", [targetUserId]);
    // console.log(`Deleted ${notesDeleteResult.affectedRows} notes for user ${targetUserId}.`);
    const [result] = await connection.query("DELETE FROM users WHERE UserID = ?", [targetUserId]);
    if (result.affectedRows === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "User not found or already deleted." });
    }
    await connection.commit();
    // console.log(`User ${targetUserId} deleted successfully by Admin ID: ${requestingAdminId}.`);
    res.json({ message: `User deleted successfully.` });
  } catch (error) {
    if (connection) await connection.rollback();
    console.error(`Error deleting user ${targetUserId}:`, error);
    res.status(500).json({ message: "Failed to delete user due to a server error." });
  } finally {
    if (connection) connection.release();
  }
});
app.use("/api/users", userManagementRouter);

app.get("/", (req, res) => {
  res.send("BCG Pastor API is running!");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }
  if (!JWT_SECRET) {
    console.error("CRITICAL: JWT_SECRET is not defined. Cannot issue tokens.");
    return res.status(500).json({ message: "Server configuration error: JWT secret missing." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    const sql = "SELECT UserID, Username, Password, Name, Status, Email, Usergroup FROM users WHERE Username = ?";
    const [users] = await connection.query(sql, [username]);
    if (users.length === 0) {
      return res.status(401).json({ message: "Invalid username or password." });
    }
    const user = users[0];
    const passwordMatch = await bcrypt.compare(password, user.Password);
    if (passwordMatch) {
      if (user.Status && user.Status.toLowerCase() === "active") {
        const userForToken = { id: user.UserID, username: user.Username, name: user.Name, role: user.Usergroup, email: user.Email };
        const accessToken = jwt.sign(userForToken, JWT_SECRET, { expiresIn: "1h" });
        // console.log(`User ${user.Username} logged in. Token issued.`);
        res.status(200).json({ message: "Login successful", token: accessToken, user: userForToken });
      } else {
        return res.status(403).json({ message: "Account not active. Please contact support." });
      }
    } else {
      return res.status(401).json({ message: "Invalid username or password." });
    }
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "An error occurred during login." });
  } finally {
    if (connection) connection.release();
  }
});

const profileRouter = express.Router();
profileRouter.use(authenticateToken);

app.post("/register", async (req, res) => {
  const { name, username, email, password } = req.body;
  if (!name || !username || !email || !password) {
    return res.status(400).json({ message: "Name, username, email, and password are required." });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: "Password must be at least 6 characters long." });
  }
  let connection;
  try {
    connection = await dbPool.getConnection();
    const checkUserSql = "SELECT Username, Email FROM users WHERE Username = ? OR Email = ?";
    const [existingUsers] = await connection.query(checkUserSql, [username, email]);
    if (existingUsers.length > 0) {
      if (existingUsers[0].Username === username) {
        return res.status(409).json({ message: "Username already taken." });
      } else if (existingUsers[0].Email === email) {
        return res.status(409).json({ message: "Email address already registered." });
      }
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const insertUserSql = "INSERT INTO users (Name, Username, Email, Password, Status, Usergroup) VALUES (?, ?, ?, ?, ?, ?)";
    const [result] = await connection.query(insertUserSql, [name, username, email, hashedPassword, "Inactive", "Admin"]);
    console.log(`User "${username}" registered with ID: ${result.insertId}. Status: Inactive.`);
    await sendCallMeBotAdminNotification(username, name);
    res.status(201).json({ message: "Registration successful. Your account is pending admin approval." });
  } catch (error) {
    console.error("Registration database error:", error);
    if (error.code === 'ER_DUP_ENTRY') {
      if (error.message.includes('Username')) return res.status(409).json({ message: 'Username already taken.' });
      if (error.message.includes('Email')) return res.status(409).json({ message: 'Email address already registered.' });
      return res.status(409).json({ message: 'Duplicate entry. Please check username or email.' });
    }
    res.status(500).json({ message: "Registration failed due to a server error." });
  } finally {
    if (connection) connection.release();
  }
});

profileRouter.get("/stats", async (req, res) => {
  const adminUserId = getUserIdFromAuthenticatedRequest(req);
  if (!adminUserId) return res.status(401).json({ message: "Unauthorized" });
  // console.log(`API: GET /api/profile/stats for user ID: ${adminUserId}`);
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [totalResult] = await connection.query("SELECT COUNT(*) as totalPastorsManaged FROM pastors WHERE is_archived = 0 AND is_draft = 0");
    const [draftResult] = await connection.query("SELECT COUNT(*) as draftRecords FROM pastors WHERE is_draft = 1 AND is_archived = 0");
    const [userRecord] = await connection.query("SELECT Name FROM users WHERE UserID = ?", [adminUserId]);
    const lastLoginPlaceholder = new Date().toLocaleString("en-US", { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    res.json({
      totalPastorsManaged: totalResult[0]?.totalPastorsManaged || 0,
      draftRecords: draftResult[0]?.draftRecords || 0,
      lastLogin: lastLoginPlaceholder,
      adminName: userRecord[0]?.Name || "Admin"
    });
  } catch (error) {
    console.error("Error fetching profile stats:", error);
    res.status(500).json({ message: "Failed to fetch profile statistics." });
  } finally {
    if (connection) connection.release();
  }
});

profileRouter.get("/notes", async (req, res) => {
  const adminUserId = getUserIdFromAuthenticatedRequest(req);
  if (!adminUserId) return res.status(401).json({ message: "Unauthorized" });
  // console.log(`API: GET /api/profile/notes for user ID: ${adminUserId}`);
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [notes] = await connection.query("SELECT id, title, content, DATE_FORMAT(updated_at, '%M %d, %Y %h:%i %p') as date FROM admin_notes WHERE user_id = ? ORDER BY updated_at DESC", [adminUserId]);
    res.json(notes.map((note) => ({ ...note, snippet: (note.content || "").substring(0, 100) + ((note.content || "").length > 100 ? "..." : "") })));
  } catch (error) {
    console.error("Error fetching admin notes:", error);
    res.status(500).json({ message: "Failed to fetch notes." });
  } finally {
    if (connection) connection.release();
  }
});

profileRouter.post("/notes", async (req, res) => {
  const adminUserId = getUserIdFromAuthenticatedRequest(req);
  if (!adminUserId) return res.status(401).json({ message: "Unauthorized" });
  const { title, content } = req.body;
  // console.log(`API: POST /api/profile/notes by user ID: ${adminUserId}`);
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [result] = await connection.query("INSERT INTO admin_notes (user_id, title, content) VALUES (?, ?, ?)", [adminUserId, title || "Untitled Note", content || ""]);
    const [newNotes] = await connection.query("SELECT id, title, content, DATE_FORMAT(updated_at, '%M %d, %Y %h:%i %p') as date FROM admin_notes WHERE id = ?", [result.insertId]);
    if (newNotes.length > 0) res.status(201).json({ ...newNotes[0], snippet: (newNotes[0].content || "").substring(0, 100) + "..." });
    else throw new Error("Failed to retrieve saved note.");
  } catch (error) {
    console.error("Error creating admin note:", error);
    res.status(500).json({ message: "Failed to save note." });
  } finally {
    if (connection) connection.release();
  }
});

profileRouter.put("/notes/:noteId", async (req, res) => {
  const adminUserId = getUserIdFromAuthenticatedRequest(req);
  if (!adminUserId) return res.status(401).json({ message: "Unauthorized" });
  const { noteId } = req.params;
  const { title, content } = req.body;
  // console.log(`API: PUT /api/profile/notes/${noteId} by user ID: ${adminUserId}`);
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [result] = await connection.query("UPDATE admin_notes SET title = ?, content = ?, updated_at = NOW() WHERE id = ? AND user_id = ?", [title || "Untitled Note", content || "", noteId, adminUserId]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "Note not found or not authorized to update." });
    const [updatedNotes] = await connection.query("SELECT id, title, content, DATE_FORMAT(updated_at, '%M %d, %Y %h:%i %p') as date FROM admin_notes WHERE id = ?", [noteId]);
    if (updatedNotes.length > 0) res.json({ ...updatedNotes[0], snippet: (updatedNotes[0].content || "").substring(0, 100) + "..." });
    else res.status(404).json({ message: "Note not found after update." });
  } catch (error) {
    console.error("Error updating admin note:", error);
    res.status(500).json({ message: "Failed to update note." });
  } finally {
    if (connection) connection.release();
  }
});

profileRouter.delete("/notes/:noteId", async (req, res) => {
  const adminUserId = getUserIdFromAuthenticatedRequest(req);
  if (!adminUserId) return res.status(401).json({ message: "Unauthorized" });
  const { noteId } = req.params;
  // console.log(`API: DELETE /api/profile/notes/${noteId} by user ID: ${adminUserId}`);
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [result] = await connection.query("DELETE FROM admin_notes WHERE id = ? AND user_id = ?", [noteId, adminUserId]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "Note not found or not authorized to delete." });
    res.status(200).json({ message: "Note deleted successfully." });
  } catch (error) {
    console.error("Error deleting admin note:", error);
    res.status(500).json({ message: "Failed to delete note." });
  } finally {
    if (connection) connection.release();
  }
});

profileRouter.post("/change-password", async (req, res) => {
  const adminUserId = getUserIdFromAuthenticatedRequest(req);
  if (!adminUserId) return res.status(401).json({ message: "Unauthorized" });
  const { currentPassword, newPassword } = req.body;
  // console.log(`API: POST /api/profile/change-password for user ID: ${adminUserId}`);
  if (!currentPassword || !newPassword) return res.status(400).json({ message: "Current and new passwords are required." });
  if (newPassword.length < 6) return res.status(400).json({ message: "New password must be at least 6 characters." });
  let connection;
  try {
    connection = await dbPool.getConnection();
    const [users] = await connection.query("SELECT UserID, Password FROM users WHERE UserID = ?", [adminUserId]);
    if (users.length === 0) return res.status(404).json({ message: "User not found." });
    const user = users[0];
    const passwordMatch = await bcrypt.compare(currentPassword, user.Password);
    if (!passwordMatch) return res.status(401).json({ message: "Incorrect current password." });
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    await connection.query("UPDATE users SET Password = ? WHERE UserID = ?", [hashedNewPassword, user.UserID]);
    res.json({ success: true, message: "Password updated successfully." });
  } catch (error) {
    console.error("Error changing password:", error);
    res.status(500).json({ message: "Failed to change password." });
  } finally {
    if (connection) connection.release();
  }
});
app.use("/api/profile", profileRouter);

app.get("/pastors/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const pastorDbId = parseInt(id, 10);
  if (isNaN(pastorDbId)) return res.status(400).json({ message: "Invalid Pastor ID provided." });
  // console.log(`API: GET /pastors/${pastorDbId} called`);
  let connection;
  try {
    connection = await dbPool.getConnection();
    const sql = `
            SELECT id, pastor_id, passport_photo_url, surname, first_name, other_names, gender, dob, 
                   nationality, village_town, lga, native_state, marital_status, spouse_name, 
                   children_info, address, city, state, postal_code, country, email, home_phone, 
                   mobile_phone, alt_phone, church_status, church_groups, sub_groups, outpost, 
                   date_joined, emergency_name, emergency_relationship, emergency_phone, kin_name, 
                   kin_mobile, more_details, bank_name, bank_acct_name, bank_acct_number, 
                   bank_branch, is_draft, is_archived 
            FROM pastors WHERE id = ?`;
    const [rows] = await connection.query(sql, [pastorDbId]);
    if (rows.length === 0) return res.status(404).json({ message: "Pastor not found." });
    const pastor = rows[0];
    const processedPastor = {
      ...pastor,
      isDraft: !!pastor.is_draft,
      isArchived: !!pastor.is_archived,
      subGroups: Array.isArray(pastor.sub_groups) ? pastor.sub_groups : (typeof pastor.sub_groups === 'string' ? JSON.parse(pastor.sub_groups || "[]") : []),
    };
    res.json(processedPastor);
  } catch (error) {
    console.error(`Error fetching pastor ${pastorDbId}:`, error);
    res.status(500).json({ message: "Failed to retrieve pastor details." });
  } finally {
    if (connection) connection.release();
  }
});

app.put("/pastors/update/:id", authenticateToken, async (req, res) => {
  upload(req, res, async (uploadError) => {
    if (uploadError) {
      console.error("Multer error in PUT /pastors/update/:id :", uploadError.message);
      return res.status(400).json({ message: uploadError instanceof multer.MulterError ? `File upload error: ${uploadError.message}` : uploadError.message });
    }
    const { id } = req.params;
    const pastorDbId = parseInt(id, 10);
    if (isNaN(pastorDbId)) return res.status(400).json({ message: "Invalid Pastor DB ID." });

    const { /* ... all fields from req.body ... */ } = req.body;
    const dataToUpdate = { ...req.body }; // Shallow copy
    delete dataToUpdate.currentPassportPhotoUrl; // Don't try to save this to DB

    const uploadedFile = req.file;
    let newPassportPhotoUrl = null;
    let savedFilePath = null;

    // console.log(`PUT /pastors/update/${pastorDbId} - Body:`, Object.keys(dataToUpdate).length, "File:", uploadedFile ? uploadedFile.originalname : "No");

    if (!dataToUpdate.surname || !dataToUpdate.firstName || !dataToUpdate.mobilePhone) {
      return res.status(400).json({ message: "Missing required fields: Surname, First Name, Mobile Phone." });
    }

    if (uploadedFile) {
      try {
        const sanitize = (name) => (name || "").replace(/[^a-zA-Z0-9._-]/g, "-").replace(/-+/g, "-").toLowerCase();
        const baseName = `${sanitize(dataToUpdate.firstName)}-${sanitize(dataToUpdate.surname)}` || "pastor-photo";
        const generatedFilename = `${baseName}-${Date.now()}.jpg`;
        savedFilePath = path.join(UPLOAD_DIR, generatedFilename);
        const processedImageBuffer = await sharp(uploadedFile.buffer)
          .resize({ width: MAX_IMAGE_WIDTH, height: MAX_IMAGE_HEIGHT, fit: sharp.fit.inside, withoutEnlargement: true })
          .jpeg({ quality: IMAGE_QUALITY, progressive: true })
          .toBuffer();
        if (processedImageBuffer.length / 1024 > TARGET_FILE_SIZE_KB) {
          if (savedFilePath && fs.existsSync(savedFilePath)) fs.unlinkSync(savedFilePath);
          return res.status(400).json({ message: `Image size exceeds ${TARGET_FILE_SIZE_KB} KB limit.` });
        }
        fs.writeFileSync(savedFilePath, processedImageBuffer);
        newPassportPhotoUrl = `/assets/${generatedFilename}`;
        dataToUpdate.passport_photo_url = newPassportPhotoUrl; // Add to data to be updated
        // console.log(`Image processed for update: ${newPassportPhotoUrl}`);
      } catch (processingError) {
        console.error("Error processing image in PUT /pastors/update/:id :", processingError);
        return res.status(500).json({ message: "Failed to process uploaded image." });
      }
    } else if (req.body.passport_photo_url === null || req.body.passport_photo_url === '') {
        // If explicitly set to null/empty, allow removing photo (if frontend sends this)
        dataToUpdate.passport_photo_url = null;
    } else if (req.body.currentPassportPhotoUrl) {
        // No new file, keep existing photo if currentPassportPhotoUrl is provided and not being nulled
        dataToUpdate.passport_photo_url = req.body.currentPassportPhotoUrl;
    }


    dataToUpdate.sub_groups = JSON.stringify(Array.isArray(JSON.parse(dataToUpdate.subGroups || "[]")) ? JSON.parse(dataToUpdate.subGroups || "[]") : []);
    delete dataToUpdate.subGroups; // remove camelCase if snake_case is used for DB

    dataToUpdate.is_draft = dataToUpdate.isDraft === "true" || dataToUpdate.isDraft === true;
    dataToUpdate.is_archived = dataToUpdate.isArchived === "true" || dataToUpdate.isArchived === true;
    delete dataToUpdate.isDraft;
    delete dataToUpdate.isArchived;

    // Map camelCase from form to snake_case for DB if needed
    const dbReadyData = {};
    const camelToSnakeMap = { // Define your mappings
        pastorId: 'pastor_id', firstName: 'first_name', otherNames: 'other_names', villageTown: 'village_town',
        nativeState: 'native_state', maritalStatus: 'marital_status', spouseName: 'spouse_name',
        childrenInfo: 'children_info', postalCode: 'postal_code', homePhone: 'home_phone',
        mobilePhone: 'mobile_phone', altPhone: 'alt_phone', churchStatus: 'church_status',
        churchGroups: 'church_groups', dateJoined: 'date_joined', emergencyName: 'emergency_name',
        emergencyRelationship: 'emergency_relationship', emergencyPhone: 'emergency_phone',
        kinName: 'kin_name', kinMobile: 'kin_mobile', moreDetails: 'more_details',
        bankName: 'bank_name', bankAcctName: 'bank_acct_name', bankAcctNumber: 'bank_acct_number',
        bankBranch: 'bank_branch'
        // passport_photo_url, is_draft, is_archived, sub_groups are already snake_case
    };
    for (const key in dataToUpdate) {
        dbReadyData[camelToSnakeMap[key] || key] = dataToUpdate[key];
    }


    let connection;
    try {
      connection = await dbPool.getConnection();
      await connection.beginTransaction();

      let oldPhotoPathForDeletion = null;
      if (newPassportPhotoUrl || dataToUpdate.passport_photo_url === null) { // A new photo was uploaded OR photo is being removed
        const [existingRecords] = await connection.query("SELECT passport_photo_url FROM pastors WHERE id = ?", [pastorDbId]);
        if (existingRecords.length > 0 && existingRecords[0].passport_photo_url) {
          oldPhotoPathForDeletion = existingRecords[0].passport_photo_url;
        }
      }
      
      // Construct SET part of SQL query dynamically
      const setClauses = [];
      const values = [];
      for (const key in dbReadyData) {
          if (key !== 'id' && dbReadyData[key] !== undefined) { // Exclude id and undefined values
              setClauses.push(`${key} = ?`);
              values.push(dbReadyData[key]);
          }
      }
      if (setClauses.length === 0) {
          await connection.rollback();
          return res.status(400).json({ message: "No data provided for update." });
      }
      values.push(pastorDbId); // For WHERE id = ?

      const sql = `UPDATE pastors SET ${setClauses.join(', ')} WHERE id = ?`;
      // console.log("Executing SQL to update pastor:", sql.substring(0,150)+"...", values.length);

      const [result] = await connection.query(sql, values);

      if (result.affectedRows === 0) {
        await connection.rollback();
        if (savedFilePath && fs.existsSync(savedFilePath)) fs.unlinkSync(savedFilePath);
        return res.status(404).json({ message: "Pastor not found or no changes." });
      }

      if (oldPhotoPathForDeletion && oldPhotoPathForDeletion !== newPassportPhotoUrl) {
        const oldFilename = path.basename(oldPhotoPathForDeletion);
        const oldFilePath = path.join(UPLOAD_DIR, oldFilename);
        if (fs.existsSync(oldFilePath)) {
          try { fs.unlinkSync(oldFilePath); /* console.log(`Deleted old image: ${oldFilePath}`); */ }
          catch (e) { console.error(`Error deleting old image ${oldFilePath}:`, e); }
        }
      }

      await connection.commit();
      // console.log(`Pastor ID ${pastorDbId} updated.`);
      res.status(200).json({
        message: "Pastor data updated successfully",
        pastorDbId: pastorDbId,
        passportPhotoUrl: dataToUpdate.passport_photo_url // Send back the current photo URL
      });
    } catch (dbError) {
      if (connection) await connection.rollback();
      console.error("Error updating pastor (PUT /pastors/update/:id):", dbError);
      if (savedFilePath && fs.existsSync(savedFilePath)) fs.unlinkSync(savedFilePath);
      if (dbError.code === "ER_DUP_ENTRY" && dbError.message.includes("pastor_id")) {
        return res.status(409).json({ message: "Pastor ID (Application ID) conflicts." });
      }
      res.status(500).json({ message: "Server error updating pastor data." });
    } finally {
      if (connection) connection.release();
    }
  });
});

app.post("/pastors", authenticateToken, async (req, res) => {
  upload(req, res, async (uploadError) => {
    if (uploadError) {
      console.error("Multer error in POST /pastors:", uploadError.message);
      return res.status(400).json({ message: uploadError instanceof multer.MulterError ? `File upload error: ${uploadError.message}` : uploadError.message });
    }

    const data = { ...req.body }; // Use a copy
    const uploadedFile = req.file;
    let passportPhotoUrl = null;
    let savedFilePath = null;

    if (!data.surname || !data.firstName || !data.mobilePhone) {
      return res.status(400).json({ message: "Missing required fields: Surname, First Name, Mobile Phone." });
    }

    if (uploadedFile) {
      try {
        const sanitize = (name) => (name || "").replace(/[^a-zA-Z0-9._-]/g, "-").replace(/-+/g, "-").toLowerCase();
        const baseName = `${sanitize(data.firstName)}-${sanitize(data.surname)}` || "pastor-photo";
        const generatedFilename = `${baseName}-${Date.now()}.jpg`;
        savedFilePath = path.join(UPLOAD_DIR, generatedFilename);
        const processedImageBuffer = await sharp(uploadedFile.buffer)
          .resize({ width: MAX_IMAGE_WIDTH, height: MAX_IMAGE_HEIGHT, fit: sharp.fit.inside, withoutEnlargement: true })
          .jpeg({ quality: IMAGE_QUALITY, progressive: true })
          .toBuffer();
        if (processedImageBuffer.length / 1024 > TARGET_FILE_SIZE_KB) {
          if (savedFilePath && fs.existsSync(savedFilePath)) fs.unlinkSync(savedFilePath);
          return res.status(400).json({ message: `Image size exceeds ${TARGET_FILE_SIZE_KB} KB limit.` });
        }
        fs.writeFileSync(savedFilePath, processedImageBuffer);
        passportPhotoUrl = `/assets/${generatedFilename}`;
        // console.log(`Image processed for new pastor: ${passportPhotoUrl}`);
      } catch (processingError) {
        console.error("Error processing image for new pastor:", processingError);
        return res.status(500).json({ message: "Failed to process uploaded image." });
      }
    }
    
    const subGroups = JSON.stringify(Array.isArray(JSON.parse(data.subGroups || "[]")) ? JSON.parse(data.subGroups || "[]") : []);
    const isDraft = data.isDraft === "true" || data.isDraft === true;
    const isArchived = data.isArchived === "true" || data.isArchived === true;

    let connection;
    try {
      connection = await dbPool.getConnection();
      const sql = `INSERT INTO pastors (
          pastor_id, passport_photo_url, surname, first_name, other_names, gender, dob, nationality, village_town, lga, 
          native_state, marital_status, spouse_name, children_info, address, city, state, postal_code, country, email, 
          home_phone, mobile_phone, alt_phone, church_status, church_groups, sub_groups, outpost, date_joined, 
          emergency_name, emergency_relationship, emergency_phone, kin_name, kin_mobile, more_details, bank_name, 
          bank_acct_name, bank_acct_number, bank_branch, is_draft, is_archived
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const values = [
        data.pastorId || null, passportPhotoUrl, data.surname, data.firstName, data.otherNames || null, data.gender || null, data.dob || null,
        data.nationality || null, data.villageTown || null, data.lga || null, data.nativeState || null, data.maritalStatus || null,
        data.spouseName || null, data.childrenInfo || null, data.address || null, data.city || null, data.state || null,
        data.postalCode || null, data.country || null, data.email || null, data.homePhone || null, data.mobilePhone, data.altPhone || null,
        data.churchStatus || null, data.churchGroups || null, subGroups, data.outpost || null, data.dateJoined || null,
        data.emergencyName || null, data.emergencyRelationship || null, data.emergencyPhone || null, data.kinName || null,
        data.kinMobile || null, data.moreDetails || null, data.bankName || null, data.bankAcctName || null,
        data.bankAcctNumber || null, data.bankBranch || null, isDraft, isArchived
      ];
      const [result] = await connection.query(sql, values);
      // console.log("Pastor added successfully, Insert ID:", result.insertId);
      res.status(201).json({
        message: "Pastor added successfully",
        pastorDbId: result.insertId,
        passportPhotoUrl: passportPhotoUrl,
      });
    } catch (dbError) {
      console.error("Error saving pastor to database:", dbError);
      if (savedFilePath && fs.existsSync(savedFilePath)) {
        try { fs.unlinkSync(savedFilePath); /* console.log(`Cleaned up file: ${savedFilePath}`); */ }
        catch (unlinkErr) { console.error(`Error cleaning file ${savedFilePath}:`, unlinkErr); }
      }
      if (dbError.code === "ER_DUP_ENTRY") {
        if (dbError.message.includes("'pastors.pastor_id'")) return res.status(409).json({ message: "Pastor ID (Application ID) already exists." });
        if (dbError.message.includes("'pastors.email'")) return res.status(409).json({ message: "Email address already used by another pastor." });
        return res.status(409).json({ message: "Duplicate entry detected." });
      }
      res.status(500).json({ message: "Server error saving pastor." });
    } finally {
      if (connection) connection.release();
    }
  });
});

app.post("/archive", authenticateToken, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ message: "Missing or invalid 'ids' array." });
  // console.log("Request to archive pastors IDs:", ids);
  const numericIds = ids.map((id) => parseInt(id, 10)).filter((id) => !isNaN(id));
  if (numericIds.length !== ids.length || numericIds.length === 0) return res.status(400).json({ message: "Invalid or no numeric IDs provided." });

  let connection;
  try {
    connection = await dbPool.getConnection();
    const sql = `UPDATE pastors SET is_archived = 1, is_draft = 0 WHERE id IN (?) AND is_archived = 0`;
    const [result] = await connection.query(sql, [numericIds]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "No records found to archive or already archived." });
    res.status(200).json({ message: `Successfully archived ${result.affectedRows} pastor(s).`, archivedCount: result.affectedRows });
  } catch (dbError) {
    console.error("Error archiving pastors:", dbError);
    res.status(500).json({ message: "Failed to archive pastors." });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/pastors/permanent-delete", authenticateToken, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ message: "Missing or invalid 'ids' array." });
  // console.log("Request to PERMANENTLY DELETE pastors IDs:", ids);
  const numericIds = ids.map((id) => parseInt(id, 10)).filter((id) => !isNaN(id));
   if (numericIds.length !== ids.length || numericIds.length === 0) return res.status(400).json({ message: "Invalid or no numeric IDs provided." });

  let connection;
  try {
    connection = await dbPool.getConnection();
    await connection.beginTransaction();
    const [recordsToDelete] = await connection.query("SELECT id, passport_photo_url FROM pastors WHERE id IN (?) AND is_archived = 1", [numericIds]);
    if (recordsToDelete.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "No matching archived records found to permanently delete." });
    }
    const actualIdsToDelete = recordsToDelete.map(r => r.id);
    for (const record of recordsToDelete) {
      if (record.passport_photo_url) {
        const filePath = path.join(UPLOAD_DIR, path.basename(record.passport_photo_url));
        if (fs.existsSync(filePath)) {
          try { fs.unlinkSync(filePath); /* console.log(`Deleted image: ${filePath}`); */ }
          catch (fileErr) { console.error(`Error deleting image ${filePath}:`, fileErr); }
        }
      }
    }
    const [result] = await connection.query("DELETE FROM pastors WHERE id IN (?) AND is_archived = 1", [actualIdsToDelete]);
    await connection.commit();
    res.status(200).json({ message: `Successfully permanently deleted ${result.affectedRows} pastor(s).`, deletedCount: result.affectedRows });
  } catch (dbError) {
    if (connection) await connection.rollback();
    console.error("Error permanently deleting pastors:", dbError);
    res.status(500).json({ message: "Failed to permanently delete pastors." });
  } finally {
    if (connection) connection.release();
  }
});

app.delete("/pastors/permanent-delete/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const pastorId = parseInt(id, 10);
  if (isNaN(pastorId)) return res.status(400).json({ message: "Invalid Pastor ID." });
  // console.log("Request to PERMANENTLY DELETE single pastor ID:", pastorId);
  let connection;
  try {
    connection = await dbPool.getConnection();
    await connection.beginTransaction();
    const [records] = await connection.query("SELECT passport_photo_url FROM pastors WHERE id = ? AND is_archived = 1", [pastorId]);
    if (records.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: `Pastor with ID ${pastorId} not found or not archived.`});
    }
    if (records[0].passport_photo_url) {
      const filePath = path.join(UPLOAD_DIR, path.basename(records[0].passport_photo_url));
      if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); /* console.log(`Deleted image: ${filePath}`); */ }
        catch (fileErr) { console.error(`Error deleting image ${filePath}:`, fileErr); }
      }
    }
    await connection.query("DELETE FROM pastors WHERE id = ? AND is_archived = 1", [pastorId]);
    await connection.commit();
    res.status(200).json({ message: `Pastor ${pastorId} permanently deleted successfully.` });
  } catch (dbError) {
    if (connection) await connection.rollback();
    console.error(`Error permanently deleting single pastor ${pastorId}:`, dbError);
    res.status(500).json({ message: "Server error during permanent deletion." });
  } finally {
    if (connection) connection.release();
  }
});

app.post("/restore", authenticateToken, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ message: "Missing or invalid 'ids' array." });
  // console.log("Request to RESTORE pastors IDs:", ids);
  const numericIds = ids.map((id) => parseInt(id, 10)).filter((id) => !isNaN(id));
  if (numericIds.length !== ids.length || numericIds.length === 0) return res.status(400).json({ message: "Invalid or no numeric IDs provided." });

  let connection;
  try {
    connection = await dbPool.getConnection();
    const sql = `UPDATE pastors SET is_archived = 0 WHERE id IN (?) AND is_archived = 1`;
    const [result] = await connection.query(sql, [numericIds]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "No matching archived records found to restore." });
    res.status(200).json({ message: `Successfully restored ${result.affectedRows} pastor(s).`, restoredCount: result.affectedRows });
  } catch (dbError) {
    console.error("Error restoring pastors:", dbError);
    res.status(500).json({ message: "Failed to restore pastors." });
  } finally {
    if (connection) connection.release();
  }
});

app.get("/getpastors", authenticateToken, async (req, res) => {
  // console.log("Request to fetch all pastors (drafts/archived included)");
  let connection;
  try {
    connection = await dbPool.getConnection();
    const sql = `
            SELECT id, pastor_id, passport_photo_url, surname, first_name, other_names, gender, dob, 
                   nationality, village_town, lga, native_state, marital_status, spouse_name, 
                   children_info, address, city, state, postal_code, country, email, home_phone, 
                   mobile_phone, alt_phone, church_status, church_groups, sub_groups, outpost, 
                   date_joined, emergency_name, emergency_relationship, emergency_phone, kin_name, 
                   kin_mobile, more_details, bank_name, bank_acct_name, bank_acct_number, 
                   bank_branch, is_draft, is_archived
            FROM pastors
            ORDER BY is_draft DESC, is_archived ASC, surname ASC, first_name ASC`;
    const [rows] = await connection.query(sql);
    // console.log(`Retrieved ${rows.length} pastors.`);
    const processedRows = rows.map((pastor) => ({
      ...pastor,
      age: calculateAge(pastor.dob),
      subGroups: Array.isArray(pastor.sub_groups) ? pastor.sub_groups : (typeof pastor.sub_groups === 'string' ? JSON.parse(pastor.sub_groups || "[]") : []),
      isDraft: !!pastor.is_draft,
      isArchived: !!pastor.is_archived,
      status: pastor.church_status, // Keep consistent for frontend
      churchGroup: pastor.church_groups, // Keep consistent for frontend
    }));
    res.status(200).json(processedRows);
  } catch (dbError) {
    console.error("Error fetching pastors:", dbError);
    res.status(500).json({ message: "Failed to retrieve pastors." });
  } finally {
    if (connection) connection.release();
  }
});

app.delete("/pastors/draft", authenticateToken, async (req, res) => {
  const { ids } = req.body;
  if (!ids || !Array.isArray(ids) || ids.length === 0) return res.status(400).json({ message: "Missing or invalid 'ids' array." });
  // console.log("Request to delete draft pastors IDs:", ids);
  const numericIds = ids.map((id) => parseInt(id, 10)).filter((id) => !isNaN(id));
  if (numericIds.length !== ids.length || numericIds.length === 0) return res.status(400).json({ message: "Invalid or no numeric IDs provided." });

  let connection;
  try {
    connection = await dbPool.getConnection();
    await connection.beginTransaction();
    const [recordsToDelete] = await connection.query("SELECT id, passport_photo_url FROM pastors WHERE id IN (?) AND is_draft = 1 AND is_archived = 0", [numericIds]);
    if (recordsToDelete.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "No matching draft records found to delete." });
    }
    const actualIdsToDelete = recordsToDelete.map(r => r.id);
    for (const record of recordsToDelete) {
      if (record.passport_photo_url) {
        const filePath = path.join(UPLOAD_DIR, path.basename(record.passport_photo_url));
        if (fs.existsSync(filePath)) {
          try { fs.unlinkSync(filePath); /* console.log(`Deleted image for draft: ${filePath}`); */ }
          catch (fileErr) { console.error(`Error deleting image for draft ${filePath}:`, fileErr); }
        }
      }
    }
    const [result] = await connection.query("DELETE FROM pastors WHERE id IN (?) AND is_draft = 1 AND is_archived = 0", [actualIdsToDelete]);
    await connection.commit();
    res.status(200).json({ message: `Successfully deleted ${result.affectedRows} draft pastor(s).`, deletedCount: result.affectedRows });
  } catch (dbError) {
    if (connection) await connection.rollback();
    console.error("Error deleting draft pastors:", dbError);
    res.status(500).json({ message: "Failed to delete drafts." });
  } finally {
    if (connection) connection.release();
  }
});

app.delete("/pastors/draft/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const pastorId = parseInt(id, 10);
  if (isNaN(pastorId)) return res.status(400).json({ message: "Invalid Pastor ID." });
  // console.log("Request to delete single draft pastor ID:", pastorId);
  let connection;
  try {
    connection = await dbPool.getConnection();
    await connection.beginTransaction();
    const [records] = await connection.query("SELECT passport_photo_url FROM pastors WHERE id = ? AND is_draft = 1 AND is_archived = 0", [pastorId]);
    if (records.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: `Draft pastor with ID ${pastorId} not found.`});
    }
    if (records[0].passport_photo_url) {
      const filePath = path.join(UPLOAD_DIR, path.basename(records[0].passport_photo_url));
      if (fs.existsSync(filePath)) {
        try { fs.unlinkSync(filePath); /* console.log(`Deleted image for draft: ${filePath}`); */ }
        catch (fileErr) { console.error(`Error deleting image for draft ${filePath}:`, fileErr); }
      }
    }
    await connection.query("DELETE FROM pastors WHERE id = ? AND is_draft = 1 AND is_archived = 0", [pastorId]);
    await connection.commit();
    res.status(200).json({ message: `Draft pastor ${pastorId} deleted successfully.` });
  } catch (dbError) {
    if (connection) await connection.rollback();
    console.error(`Error deleting single draft pastor ${pastorId}:`, dbError);
    res.status(500).json({ message: "Server error during draft deletion." });
  } finally {
    if (connection) connection.release();
  }
});


// --- Start Server ---
console.log(`Attempting to start server on HOST: ${HOST}, PORT: ${PORT}`);
if (!JWT_SECRET) {
  console.error("CRITICAL ERROR: JWT_SECRET is not set. Application will not function correctly. Please set JWT_SECRET environment variable.");
  // process.exit(1); // Uncomment to prevent startup if JWT_SECRET is missing
}

dbPool.getConnection()
  .then((connection) => {
    console.log("Successfully connected to the database pool.");
    connection.release();
    app.listen(PORT, HOST, () => {
      console.log(`BCG Pastor API server running on http://${HOST}:${PORT}`);
      console.log(`Accessible externally via your Alwaysdata domain, mapped to this internal port.`);
      console.log(`NODE_ENV is currently: ${process.env.NODE_ENV || 'not set (defaulting to development behavior)'}`);
    });
  })
  .catch((err) => {
    console.error("!!! DATABASE CONNECTION FAILED !!!", err.message);
    console.error("Full database connection error object:", err);
    process.exit(1);
  });