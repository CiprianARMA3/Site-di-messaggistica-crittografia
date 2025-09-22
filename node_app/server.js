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
const sharp = require('sharp'); // ✅ for image resizing/compression

const { db } = require('./db'); // SQLite
const { getSettings, updateSettings, deletePfp, canChangeUsername } = require("./userSettings");

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
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(helmet());

// --- Rate limiting ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many attempts, please try again later.'
});

// --- CSRF protection ---
app.use(csurf({ cookie: true }));
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// --- Helper functions (encrypt/decrypt kept for your DB usage) ---
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

function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.redirect('/login');
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
  limits: { fileSize: 1024 * 1024 }, // 1 MB max upload
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

      // ✅ Resize and compress image before saving
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

// --- Chat ---
app.get('/chat', requireAuth, (req, res) =>
  res.render('chat', { csrfToken: res.locals.csrfToken, user: req.user })
);

// --- SIGNUP / LOGIN / LOGOUT (unchanged except updateSettings default) ---
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
        "INSERT INTO database_utenti(username,password,email,email_hash) VALUES (?,?,?,?)",
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

// --- Start server ---
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
