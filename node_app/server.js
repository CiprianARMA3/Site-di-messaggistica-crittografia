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
const { db } = require('./db'); // SQLite
const { getSettings, updateSettings } = require("./userSettings");

const app = express();

// --- Static files ---
app.use(express.static(path.join(__dirname, "public"))); // serves /public/* at /
app.use("/user-images", express.static(path.join(__dirname, "database/user-images"))); // uploaded pfps

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

// --- Helper functions ---
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

// --- Routes ---
app.get('/', (req, res) => res.render('home', { csrfToken: res.locals.csrfToken, user: null }));
app.get('/home', (req, res) => res.render('home', { csrfToken: res.locals.csrfToken, user: null }));
app.get('/about-us', (req, res) => res.render('about-us', { csrfToken: res.locals.csrfToken }));
app.get('/contact', (req, res) => res.render('contact', { csrfToken: res.locals.csrfToken }));
app.get('/forgot-password', (req, res) => res.render('forgot-password', { csrfToken: res.locals.csrfToken }));

// --- Settings ---
app.get("/settings", requireAuth, (req, res) => {
  const userSettings = getSettings(req.user.id);
  res.render("settings", {
    csrfToken: res.locals.csrfToken,
    user: req.user,
    userSettings,
  });
});
const multer = require("multer");
const fs = require("fs");
// --- Multer setup for uploads ---
const upload = multer({
  dest: path.join(__dirname, "database/user-images"),
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB max
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new Error("Only images allowed"));
    }
    cb(null, true);
  }
});

// --- Change PFP ---
app.post("/settings/pfp", requireAuth, upload.single("pfp"), (req, res) => {
  const userId = req.user.id;

  try {
    const { canChangePfp, updateSettings, deletePfp } = require("./userSettings");
    if (!canChangePfp(userId)) {
      return res.status(429).send("❌ You can only change PFP 6 times every 10 minutes.");
    }

    // Delete old pfp if custom
    deletePfp(userId);

    // Save new filename
    const filename = req.file.filename + path.extname(req.file.originalname);
    const fs = require("fs");
    fs.renameSync(req.file.path, path.join(__dirname, "database/user-images", filename));

    updateSettings(userId, { pfp: "/user-images/" + filename });

    res.redirect("/settings");
  } catch (err) {
    console.error(err);
    res.status(500).send("⚠️ Upload failed.");
  }
});

// --- Change Username ---
app.post("/settings/username", requireAuth, (req, res) => {
  const userId = req.user.id;
  const newUsername = req.body.newUsername;

  if (!newUsername || newUsername.trim().length < 3) {
    return res.status(400).send("❌ Username too short.");
  }

  const { canChangeUsername, updateSettings } = require("./userSettings");
  if (!canChangeUsername(userId)) {
    return res.status(429).send("❌ You can only change username once per week.");
  }

  updateSettings(userId, { username: newUsername.trim() });

  res.redirect("/settings");
});


// --- Chat ---
app.get('/chat', requireAuth, (req, res) =>
  res.render('chat', { csrfToken: res.locals.csrfToken, user: req.user })
);

// --- SIGNUP ---
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

          // ✅ Save default settings in LowDB
          updateSettings(this.lastID, {
            username: username,
            pfp: "/images/icon-user.png" // default profile picture
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

// --- LOGIN ---
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
      maxAge: 1000 * 60 * 60 * 2 // 2 hours
    });

    res.redirect('/chat');
  });
});

// --- LOGOUT ---
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// --- Protected test route ---
app.get('/protected', requireAuth, (req, res) =>
  res.render('protected', { user: req.user })
);

// --- Start server ---
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
