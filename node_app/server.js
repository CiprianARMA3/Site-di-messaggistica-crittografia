require('dotenv').config();
const path        = require('path');
const express     = require('express');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const bcrypt      = require('bcrypt');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const csurf       = require('csurf');
const jwt         = require('jsonwebtoken');
const cookieParser= require('cookie-parser');
const { db }      = require('./db'); // main database connection

const app = express();

// --- Environment / Secrets ---
const SECRET_KEY     = process.env.SECRET_KEY;
const JWT_SECRET     = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
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
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// --- Security middlewares ---
app.use(helmet());

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many attempts, please try again later.'
});

// CSRF protection (still works with JWT)
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
    const iv  = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const ct  = buf.slice(28);
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
app.get('/', (req, res) => {
  res.render('home', { csrfToken: res.locals.csrfToken, user: null });
});

app.get('/home', (req, res) => {
  res.render('home', { csrfToken: res.locals.csrfToken, user: null });
});

app.get('/about-us', (req, res) => {
  res.render('about-us', { csrfToken: res.locals.csrfToken });
});

app.get('/contact', (req, res) => {
  res.render('contact', { csrfToken: res.locals.csrfToken });
});

app.get('/settings', (req, res) => {
  res.render('settings', { csrfToken: res.locals.csrfToken });
});

// PROTECTED CHAT
app.get('/chat', requireAuth, (req, res) => {
  res.render('chat', { csrfToken: res.locals.csrfToken, user: req.user });
});

// --- SIGNUP ---
const lastRegistrationByIP = {};

app.get('/signup', redirectIfAuth, (req, res) =>
  res.render('signup', { csrfToken: res.locals.csrfToken })
);

app.post('/signup', authLimiter, async (req, res) => {
  const ip = req.ip;
  const now = Date.now();

  if (lastRegistrationByIP[ip] && now - lastRegistrationByIP[ip] < 5 * 60 * 1000) {
    return res.status(429).render('signup', { csrfToken: res.locals.csrfToken, error: 'Please wait 5 minutes before registering again.' });
  }

  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).render('signup', { csrfToken: res.locals.csrfToken, error: 'All fields are required.' });
  }

  const email_hash = emailHmac(email);
  db.get("SELECT id FROM database_utenti WHERE email_hash = ?", [email_hash], async (err, row) => {
    if (err) return res.status(500).render('signup', { csrfToken: res.locals.csrfToken, error: 'Server error.' });
    if (row) return res.status(400).render('signup', { csrfToken: res.locals.csrfToken, error: 'Email already registered.' });

    try {
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      const encUsername = encrypt(username);
      const encEmail    = encrypt(email);

      db.run(
        "INSERT INTO database_utenti(username,password,email,email_hash) VALUES (?,?,?,?)",
        [encUsername, hashedPassword, encEmail, email_hash],
        (err2) => {
          if (err2) return res.status(500).render('signup', { csrfToken: res.locals.csrfToken, error: 'Database insert error.' });

          lastRegistrationByIP[ip] = Date.now();
          res.redirect('/login');
        }
      );
    } catch (e) {
      console.error(e);
      res.status(500).render('signup', { csrfToken: res.locals.csrfToken, error: 'Unexpected server error.' });
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
    return res.status(400).render('login', { csrfToken: res.locals.csrfToken, error: 'Please fill in all fields.' });
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

    // Send JWT as an httpOnly cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: IN_PROD,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 2 // 2h
    });

    res.redirect('/chat');
  });
});

// --- LOGOUT ---
app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// --- PROTECTED TEST ---
app.get('/protected', requireAuth, (req, res) => {
  res.render('protected', { user: req.user });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
