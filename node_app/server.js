require('dotenv').config();
const path       = require('path');
const express    = require('express');
const bodyParser = require('body-parser');
const crypto     = require('crypto');
const bcrypt     = require('bcrypt');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const session    = require('express-session');
const SQLiteStore= require('connect-sqlite3')(session);
const csurf      = require('csurf');
const { db }     = require('./db');    // our main database connection

const app = express(); 

app.use(express.static(path.join(__dirname, 'public')));

// --- Environment / Secrets ---
const SECRET_KEY     = process.env.SECRET_KEY;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const PORT           = process.env.PORT || 3000;
const IN_PROD        = process.env.PRODUCTION === 'true';

if (!SECRET_KEY) {
  console.error('❌ Missing SECRET_KEY in .env');
  process.exit(1);
}

// derive a 32-byte AES key from SECRET_KEY
const AES_KEY = crypto.createHash('sha256').update(SECRET_KEY).digest();
const SALT_ROUNDS = 12;

// --- App setup ---
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

// --- Security middlewares ---
app.use(helmet());

// limit repeated login/signup attempts
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: 'Too many attempts, please try again later.'
});

// session store (SQLite backed) – ensure ./database exists!
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: path.resolve(__dirname, '../database')   // safe absolute path
  }),
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: IN_PROD,      // enable true in production with HTTPS
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
}));

// CSRF protection
app.use(csurf());
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});

// --- Helper functions ---

// AES-256-GCM encryption → base64(iv:tag:cipher)
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
    const iv  = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const ct  = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', AES_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch (err) {
    console.error('Decryption failed:', err);
    return null;
  }
}

// HMAC email hash for lookup (prevents rainbow tables)
function emailHmac(email) {
  return crypto.createHmac('sha256', SECRET_KEY)
               .update(String(email).toLowerCase())
               .digest('hex');
}

// --- Routes ---
app.get('/contact', (req, res) => {
  res.render('contact', { csrfToken: res.locals.csrfToken, user: req.session?.user || null });
});

app.get('/about-us', (req, res) => {
  res.render('about-us', { csrfToken: res.locals.csrfToken, user: req.session?.user || null });
});

app.get('/', (req, res) => {
  res.render('home', { user: req.session.user || null });
});
app.get('/home', (req, res) => {
  res.render('home', { csrfToken: res.locals.csrfToken, user: req.session?.user || null });
});
app.get('/settings', (req, res) => {
  res.render('settings', { csrfToken: res.locals.csrfToken, user: req.session?.user || null });
});


const lastRegistrationByIP = {};

app.post('/signup', authLimiter, async (req, res) => {
    const ip = req.ip;
    const now = Date.now();

    // Check if this IP registered within the last 3 minutes
    if (lastRegistrationByIP[ip] && now - lastRegistrationByIP[ip] < 5 * 60 * 1000) {
        return res.status(429).send('Please wait 3 minutes before registering again.');
    }

    const { username, email, password } = req.body;
    if (!username || !email || !password)
        return res.status(400).send('Missing fields');

    const email_hash = emailHmac(email);
    db.get("SELECT id FROM database_utenti WHERE email_hash = ?", [email_hash], async (err, row) => {
        if (err) return res.status(500).send('Server error');
        if (row) return res.status(400).send('Email already registered');

        try {
            const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
            const encUsername = encrypt(username);
            const encEmail    = encrypt(email);

            db.run(
                "INSERT INTO database_utenti(username,password,email,email_hash) VALUES (?,?,?,?)",
                [encUsername, hashedPassword, encEmail, email_hash],
                (err2) => {
                    if (err2) return res.status(500).send('Database insert error');

                    // Store the registration time for this IP
                    lastRegistrationByIP[ip] = Date.now();

                    res.redirect('/login');
                }
            );
        } catch (e) {
            console.error(e);
            res.status(500).send('Server error');
        }
    });
});

app.get('/signup', (req, res) =>
  res.render('signup', { csrfToken: res.locals.csrfToken })
);

app.post('/signup', authLimiter, async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).send('Missing fields');

  const email_hash = emailHmac(email);
  db.get("SELECT id FROM database_utenti WHERE email_hash = ?", [email_hash], async (err, row) => {
    if (err) return res.status(500).send('Server error');
    if (row) return res.status(400).send('Email already registered');

    try {
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      const encUsername = encrypt(username);
      const encEmail    = encrypt(email);

      db.run(
        "INSERT INTO database_utenti(username,password,email,email_hash) VALUES (?,?,?,?)",
        [encUsername, hashedPassword, encEmail, email_hash],
        (err2) => {
          if (err2) return res.status(500).send('Database insert error');
          res.redirect('/login');
        }
      );
    } catch (e) {
      console.error(e);
      res.status(500).send('Server error');
    }
  });
});

app.get('/login', (req, res) =>
  res.render('login', { csrfToken: res.locals.csrfToken })
);

app.post('/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).send('Missing fields');

  const email_hash = emailHmac(email);
  db.get("SELECT * FROM database_utenti WHERE email_hash = ?", [email_hash], async (err, user) => {
    if (err) return res.status(500).send('Server error');
    if (!user) return res.status(401).send('Invalid credentials');

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).send('Invalid credentials');

    req.session.user = {
      id: user.id,
      username: decrypt(user.username),
      email: decrypt(user.email)
    };
    res.redirect('/');
  });
});

app.post('/logout', (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie('sid');
    res.redirect('/');
  });
});

app.get('/protected', (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  res.render('protected', { user: req.session.user });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
