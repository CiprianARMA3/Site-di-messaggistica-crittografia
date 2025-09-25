// server.js
require('dotenv').config();
const path = require('path');
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const sharp = require('sharp'); // image processing

const { db } = require('./db'); // SQLite
const {
  getSettings,
  updateSettings,
  deletePfp,
  canChangeUsername,
  ensureSettings
} = require("./userSettings");

const app = express();

// --- Static files ---
app.use(express.static(path.join(__dirname, "public")));
app.use("/user-images", express.static(path.join(__dirname, "database/user-images")));

// --- Environment / Secrets ---
const SECRET_KEY = process.env.SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const PORT = process.env.PORT || 3000;
const IN_PROD = process.env.PRODUCTION === 'true';

if (!SECRET_KEY) {
  console.error('❌ Missing SECRET_KEY in .env');
  process.exit(1);
}

// derive AES key
const AES_KEY = crypto.createHash('sha256').update(SECRET_KEY).digest();
const SALT_ROUNDS = 12;

// --- App setup ---
app.set('view engine', 'ejs');

// parse urlencoded bodies (for forms) and JSON bodies (for fetch)
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(helmet());

// --- Rate limiting ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many attempts, please try again later.'
});

// --- CSRF protection ---
// csurf reads the token from the cookie (we'll expose it in res.locals.csrfToken for forms)
// For fetch/XHR you must include the token in a header (e.g. 'csrf-token') or in the body as _csrf
app.use(csurf({ cookie: true }));
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// Optional: nice CSRF error handler
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    // If it's an AJAX request, return JSON; otherwise render an error page
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
    return res.status(403).render('csrf-error', { csrfToken: res.locals.csrfToken });
  }
  next(err);
});

// --- Helper functions (encrypt/decrypt) ---
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', AES_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(String(text), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

function decrypt(b64) {
  try {
    const buf = Buffer.from(b64, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const ct = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

function emailHmac(email) {
  return crypto.createHmac('sha256', SECRET_KEY)
    .update(String(email).toLowerCase())
    .digest('hex');
}

// --- JWT Helpers ---
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: '2h' }
  );
}

// --- Auth middleware with ban check ---
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    return req.xhr || req.headers.accept?.includes("application/json")
      ? res.status(401).json({ error: "Unauthorized" })
      : res.redirect('/login');
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;

    db.get("SELECT banned FROM database_utenti WHERE id = ?", [decoded.id], (err, row) => {
      if (err || !row) {
        return req.xhr || req.headers.accept?.includes("application/json")
          ? res.status(401).json({ error: "Unauthorized" })
          : res.redirect('/home');
      }

      if (row.banned === 1) {
        res.clearCookie('token');
        return res.redirect('/ban');
      }
      next();
    });

  } catch {
    return req.xhr || req.headers.accept?.includes("application/json")
      ? res.status(401).json({ error: "Unauthorized" })
      : res.redirect('/home');
  }
}

function redirectIfAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return next();

  try {
    jwt.verify(token, JWT_SECRET);
    return res.redirect('/chat');
  } catch {
    next();
  }
}

// --- Routes (simple ones) ---
app.get('/', (req, res) => res.render('home', { csrfToken: res.locals.csrfToken, user: null }));
app.get('/home', (req, res) => res.render('home', { csrfToken: res.locals.csrfToken, user: null }));
app.get('/about-us', (req, res) => res.render('about-us', { csrfToken: res.locals.csrfToken }));
app.get('/contact', (req, res) => res.render('contact', { csrfToken: res.locals.csrfToken }));
app.get('/forgot-password', (req, res) => res.render('forgot-password', { csrfToken: res.locals.csrfToken }));

app.get('/ban', (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    return res.render('ban', { csrfToken: res.locals.csrfToken });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    db.get("SELECT banned FROM database_utenti WHERE id = ?", [decoded.id], (err, row) => {
      if (err || !row) return res.render('ban', { csrfToken: res.locals.csrfToken });

      if (row.banned === 1) {
        return res.render('ban', { csrfToken: res.locals.csrfToken });
      }

      return res.redirect('/home');
    });
  } catch {
    return res.render('ban', { csrfToken: res.locals.csrfToken });
  }
});

// --- Settings page ---
app.get("/settings", requireAuth, (req, res) => {
  const userSettings = getSettings(req.user.id);
  res.render("settings", {
    csrfToken: res.locals.csrfToken,
    user: req.user,
    userSettings,
  });
});

// ---------------- Multer setup ----------------
const userImagesDir = path.join(__dirname, "database/user-images");
if (!fs.existsSync(userImagesDir)) fs.mkdirSync(userImagesDir, { recursive: true });

const upload = multer({
  dest: userImagesDir,
  limits: { fileSize: 1024 * 1024 }, // 1 MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new multer.MulterError('LIMIT_UNEXPECTED_FILE', 'Only images allowed'));
    }
    cb(null, true);
  }
});

// --- Multer error handling middleware ---
function uploadErrorHandler(err, req, res, next) {
  const user = req.user || null;
  if (err instanceof multer.MulterError) {
    let msg = "⚠️ Upload failed.";
    if (err.code === "LIMIT_FILE_SIZE") msg = "❌ File too large. Max 1MB allowed.";
    else if (err.code === "LIMIT_UNEXPECTED_FILE") msg = "❌ Only image uploads are allowed.";
    else msg = `❌ Upload error: ${err.message}`;

    return res.status(400).render("settings", {
      csrfToken: req.csrfToken(),
      user,
      userSettings: user ? getSettings(user.id) : {},
      error: msg
    });
  }
  if (err) {
    return res.status(400).render("settings", {
      csrfToken: req.csrfToken(),
      user,
      userSettings: user ? getSettings(user.id) : {},
      error: "❌ Upload error: " + err.message
    });
  }
  next();
}

// --- Track PFP change attempts (in-memory) ---
const pfpChangeLog = {};
function canChangePfp(userId) {
  const now = Date.now();
  if (!pfpChangeLog[userId]) pfpChangeLog[userId] = [];
  pfpChangeLog[userId] = pfpChangeLog[userId].filter(ts => now - ts < 10 * 60 * 1000);
  if (pfpChangeLog[userId].length >= 5) return false;
  pfpChangeLog[userId].push(now);
  return true;
}

// ---------------- Change PFP route with sharp ----------------
app.post(
  "/settings/pfp",
  requireAuth,
  upload.single("pfp"),
  uploadErrorHandler,
  async (req, res) => {
    const userId = req.user.id;

    try {
      if (!req.file) {
        return res.status(400).render("settings", {
          csrfToken: res.locals.csrfToken,
          user: req.user,
          userSettings: getSettings(userId),
          error: "❌ No file uploaded."
        });
      }

      if (!canChangePfp(userId)) {
        try { fs.unlinkSync(req.file.path); } catch {}
        return res.status(429).render("settings", {
          csrfToken: res.locals.csrfToken,
          user: req.user,
          userSettings: getSettings(userId),
          error: "❌ You can only change PFP 5 times every 10 minutes."
        });
      }

      // Delete old picture
      deletePfp(userId);

      // Generate new filename
      const filename = crypto.randomBytes(12).toString("hex") + ".jpg";
      const filepath = path.join(userImagesDir, filename);

      // Resize + compress
      await sharp(req.file.path)
        .resize(500, 500, { fit: "inside" })
        .jpeg({ quality: 80 })
        .toFile(filepath);

      fs.unlinkSync(req.file.path); // delete temp upload

      updateSettings(userId, { pfp: "/user-images/" + filename });

      res.redirect("/settings");
    } catch (err) {
      console.error(err);
      if (req.file && req.file.path && fs.existsSync(req.file.path)) {
        try { fs.unlinkSync(req.file.path); } catch {}
      }
      res.status(500).render("settings", {
        csrfToken: res.locals.csrfToken,
        user: req.user,
        userSettings: getSettings(userId),
        error: "⚠️ Upload failed."
      });
    }
  }
);

// ---------------- Change username ----------------
app.post("/settings/username", requireAuth, (req, res) => {
  const userId = req.user.id;
  const newUsername = req.body.newUsername;

  if (!newUsername || newUsername.trim().length < 3) {
    return res.status(400).render("settings", {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      userSettings: getSettings(userId),
      error: "❌ Username too short."
    });
  }

  if (!canChangeUsername(userId)) {
    return res.status(429).render("settings", {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      userSettings: getSettings(userId),
      error: "❌ You can only change username once per week."
    });
  }

  updateSettings(userId, { username: newUsername.trim() });
  res.redirect("/settings");
});

// ---------------- Change password ----------------
const passwordChangeLog = {};
function canChangePassword(userId) {
  const now = Date.now();
  const oneWeek = 7 * 24 * 60 * 60 * 1000;
  if (!passwordChangeLog[userId]) return true;
  return now - passwordChangeLog[userId] >= oneWeek;
}
function logPasswordChange(userId) {
  passwordChangeLog[userId] = Date.now();
}

app.post("/settings/password", requireAuth, async (req, res) => {
  const userId = req.user.id;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).render('settings', {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      userSettings: getSettings(userId),
      error: "❌ Please fill in all fields."
    });
  }

  if (!canChangePassword(userId)) {
    return res.status(429).render('settings', {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      userSettings: getSettings(userId),
      error: "❌ You can only change password once per week."
    });
  }

  try {
    db.get("SELECT password FROM database_utenti WHERE id = ?", [userId], async (err, row) => {
      if (err || !row) {
        return res.status(500).render('settings', {
          csrfToken: res.locals.csrfToken,
          user: req.user,
          userSettings: getSettings(userId),
          error: "⚠️ Server error."
        });
      }

      const match = await bcrypt.compare(currentPassword, row.password);
      if (!match) {
        return res.status(400).render('settings', {
          csrfToken: res.locals.csrfToken,
          user: req.user,
          userSettings: getSettings(userId),
          error: "❌ Current password is incorrect."
        });
      }

      const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
      db.run("UPDATE database_utenti SET password = ? WHERE id = ?", [hashed, userId], (err2) => {
        if (err2) {
          return res.status(500).render('settings', {
            csrfToken: res.locals.csrfToken,
            user: req.user,
            userSettings: getSettings(userId),
            error: "⚠️ Could not update password."
          });
        }

        logPasswordChange(userId);
        res.redirect("/settings");
      });
    });
  } catch (e) {
    console.error(e);
    return res.status(500).render('settings', {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      userSettings: getSettings(userId),
      error: "⚠️ Unexpected error."
    });
  }
});

// --- Chat ---
app.get('/chat', requireAuth, (req, res) => {
  const userSettings = getSettings(req.user.id);
  res.render('chat', {
    csrfToken: res.locals.csrfToken,
    user: req.user,
    userSettings
  });
});

// ---------------- FRIENDS API ----------------
// Friends & Requests now only store IDs in LowDB.
// Usernames + PFP are always fetched fresh from database_utenti + userSettings.
// ------------------------------------------------

// Send friend request
app.post("/friends/request", requireAuth, (req, res) => {
  const { friendId } = req.body;
  const senderId = req.user.id;

  if (!friendId || String(friendId) === String(senderId)) {
    return res.status(400).json({ error: "Invalid friend ID" });
  }

  db.get("SELECT id, username FROM database_utenti WHERE id = ?", [friendId], (err, target) => {
    if (err) return res.status(500).json({ error: "Server error" });
    if (!target) return res.status(404).json({ error: "User not found" });

    const senderSettings = ensureSettings(senderId);
    const targetSettings = ensureSettings(target.id);

    if (!Array.isArray(senderSettings.friends)) senderSettings.friends = [];
    if (!Array.isArray(targetSettings.requests)) targetSettings.requests = [];

    // ✅ Block if already friends
    const alreadyFriends = senderSettings.friends.some(f => String(f.id) === String(friendId));
    if (alreadyFriends) {
      return res.status(400).json({ error: "You are already friends with this user" });
    }

    // ✅ Prevent duplicate requests
    if (targetSettings.requests.find(r => String(r.fromId) === String(senderId))) {
      return res.status(400).json({ error: "Request already sent" });
    }

    // ✅ Fetch sender's username + pfp
    db.get("SELECT username FROM database_utenti WHERE id = ?", [senderId], (err2, senderRow) => {
      if (err2 || !senderRow) return res.status(500).json({ error: "Could not fetch sender info" });

      const senderViewedName = decrypt(senderRow.username) || "Unknown";
      const senderPfp = senderSettings.pfp || "/images/icon-user.png";

      targetSettings.requests.push({
        fromId: senderId,
        fromUsername: senderViewedName,
        fromPfp: senderPfp,
        date: Date.now()
      });

      updateSettings(target.id, targetSettings);
      res.json({ success: true, message: "Request sent" });
    });
  });
});

// Get incoming requests (resolve username + pfp)
app.get("/friends/requests", requireAuth, (req, res) => {
  const settings = ensureSettings(req.user.id);
  const requests = settings.requests || [];

  const fromIds = requests.map(r => r.fromId);
  if (fromIds.length === 0) {
    return res.json({ requests: [], count: 0 });
  }

  const placeholders = fromIds.map(() => "?").join(",");
  db.all(`SELECT id, username FROM database_utenti WHERE id IN (${placeholders})`, fromIds, (err, rows) => {
    if (err) return res.status(500).json({ error: "Server error" });

    const requestsWithNames = requests.map(r => {
      const userRow = rows.find(row => String(row.id) === String(r.fromId));
      const userSettings = getSettings(r.fromId); // 🔥 get pfp from LowDB
      return {
        fromId: r.fromId,
        fromUsername: userRow ? decrypt(userRow.username) : "Unknown",
        fromPfp: userSettings?.pfp || "/images/icon-user.png",
        date: r.date
      };
    });

    res.json({ requests: requestsWithNames, count: requestsWithNames.length });
  });
});

// Accept friend request
app.post("/friends/accept", requireAuth, (req, res) => {
  const { fromId } = req.body;
  const receiverId = req.user.id;
  const receiverSettings = ensureSettings(receiverId);

  if (!Array.isArray(receiverSettings.requests)) {
    return res.status(400).json({ error: "No requests" });
  }

  const request = receiverSettings.requests.find(r => String(r.fromId) === String(fromId));
  if (!request) return res.status(404).json({ error: "Request not found" });

  db.all("SELECT id, username FROM database_utenti", [], (err, rows) => {
    if (err) return res.status(500).json({ error: "Server error" });

    const sender = rows.find(r => String(r.id) === String(fromId));
    const receiver = rows.find(r => String(r.id) === String(receiverId));
    if (!sender || !receiver) return res.status(404).json({ error: "User not found" });

    const senderSettings = ensureSettings(sender.id);
    if (!Array.isArray(receiverSettings.friends)) receiverSettings.friends = [];
    if (!Array.isArray(senderSettings.friends)) senderSettings.friends = [];

    // ✅ Check if already friends
    const alreadyFriends =
      receiverSettings.friends.some(f => String(f.id) === String(sender.id)) &&
      senderSettings.friends.some(f => String(f.id) === String(receiver.id));

    if (alreadyFriends) {
      return res.status(400).json({ error: "You are already friends with this user" });
    }

    // Remove request
    receiverSettings.requests = receiverSettings.requests.filter(r => String(r.fromId) !== String(fromId));

    // ✅ Store usernames + pfps
    const senderViewedName = decrypt(sender.username) || "Unknown";
    const receiverViewedName = decrypt(receiver.username) || "Unknown";

    const senderPfp = senderSettings.pfp || "/images/icon-user.png";
    const receiverPfp = receiverSettings.pfp || "/images/icon-user.png";

    receiverSettings.friends.push({ id: sender.id, username: senderViewedName, pfp: senderPfp });
    senderSettings.friends.push({ id: receiver.id, username: receiverViewedName, pfp: receiverPfp });

    updateSettings(receiverId, receiverSettings);
    updateSettings(sender.id, senderSettings);

    return res.json({ success: true, message: "Friend request accepted" });
  });
});

// Decline request
app.post("/friends/decline", requireAuth, (req, res) => {
  const { fromId } = req.body;
  const receiverId = req.user.id;
  const receiverSettings = ensureSettings(receiverId);

  if (!Array.isArray(receiverSettings.requests)) {
    return res.json({ success: true });
  }

  receiverSettings.requests = receiverSettings.requests.filter(r => String(r.fromId) !== String(fromId));
  updateSettings(receiverId, receiverSettings);

  res.json({ success: true });
});

app.get("/friends/list", requireAuth, (req, res) => {
  const settings = ensureSettings(req.user.id);
  const friendsRaw = Array.isArray(settings.friends) ? settings.friends : [];
  const friendIds = friendsRaw.map(f => f.id);

  if (friendIds.length === 0) {
    return res.json({ friends: [] });
  }

  const placeholders = friendIds.map(() => "?").join(",");
  db.all(
    `SELECT id, username FROM database_utenti WHERE id IN (${placeholders})`,
    friendIds,
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Server error" });

      const friends = rows.map(r => {
        const userSettings = getSettings(r.id);

        // ✅ pull viewed username from LowDB if it exists
        const viewedName = userSettings?.username || decrypt(r.username) || "Unknown";

        return {
          id: r.id,
          username: viewedName,
          pfp: userSettings?.pfp || "/images/icon-user.png"
        };
      });

      res.json({ friends });
    }
  );
});




// --- SIGNUP / LOGIN / LOGOUT ---
const lastRegistrationByIP = {};
app.get('/signup', redirectIfAuth, (req, res) =>
  res.render('signup', { csrfToken: res.locals.csrfToken })
);

app.post('/signup', authLimiter, async (req, res) => {
  const ip = req.ip;
  const now = Date.now();

  if (lastRegistrationByIP[ip] && now - lastRegistrationByIP[ip] < 5 * 60 * 1000) {
    return res.status(429).render('signup', {
      csrfToken: res.locals.csrfToken,
      error: 'Please wait 5 minutes before registering again.'
    });
  }

  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).render('signup', {
      csrfToken: res.locals.csrfToken,
      error: 'All fields are required.'
    });
  }

  const email_hash = emailHmac(email);
  db.get("SELECT id FROM database_utenti WHERE email_hash = ?", [email_hash], async (err, row) => {
    if (err) {
      return res.status(500).render('signup', {
        csrfToken: res.locals.csrfToken,
        error: 'Server error.'
      });
    }
    if (row) {
      return res.status(400).render('signup', {
        csrfToken: res.locals.csrfToken,
        error: 'Email already registered.'
      });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      const encUsername = encrypt(username);
      const encEmail = encrypt(email);

      db.run(
        "INSERT INTO database_utenti(username,password,email,email_hash,banned) VALUES (?,?,?,?,0)",
        [encUsername, hashedPassword, encEmail, email_hash],
        function (err2) {
          if (err2) {
            return res.status(500).render('signup', {
              csrfToken: res.locals.csrfToken,
              error: 'Database insert error.'
            });
          }

          updateSettings(this.lastID, {
            username: username,
            pfp: "/images/icon-user.png"
          });

          lastRegistrationByIP[ip] = Date.now();
          res.redirect('/login');
        }
      );
    } catch (e) {
      console.error(e);
      res.status(500).render('signup', {
        csrfToken: res.locals.csrfToken,
        error: 'Unexpected server error.'
      });
    }
  });
});

app.get('/login', redirectIfAuth, (req, res) =>
  res.render('login', { csrfToken: res.locals.csrfToken })
);

app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).render('login', {
      csrfToken: res.locals.csrfToken,
      error: 'Please fill in all fields.'
    });
  }

  const email_hash = emailHmac(email);
  db.get("SELECT * FROM database_utenti WHERE email_hash = ?", [email_hash], async (err, user) => {
    if (err) return res.status(500).render('login', { csrfToken: res.locals.csrfToken, error: 'Server error.' });
    if (!user) return res.status(401).render('login', { csrfToken: res.locals.csrfToken, error: 'Invalid credentials.' });

    if (user.banned === 1) {
      return res.redirect('/ban');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).render('login', { csrfToken: res.locals.csrfToken, error: 'Invalid credentials.' });

    const decodedUser = {
      id: user.id,
      username: decrypt(user.username),
      email: decrypt(user.email)
    };

    const token = generateToken(decodedUser);

    res.cookie('token', token, {
      httpOnly: true,
      secure: IN_PROD,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 2
    });

    res.redirect('/chat');
  });
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.use((req, res) => {
  res.status(404).render('404', { csrfToken: res.locals.csrfToken });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
