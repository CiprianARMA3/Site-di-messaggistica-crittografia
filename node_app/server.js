require("dotenv").config();
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const fs = require("fs");
const sharp = require("sharp");
const session = require("express-session");
const chatDB = require("./chatDB");
const { getMessages, addMessage, getFriends, getRequests } = chatDB;
const { db } = require("./db");
const { userOnline, userOffline, getOnlineUsers, isOnline } = require("./onlineUsers");
const http = require("http");
const { Server } = require("socket.io");

const {
  getSettings,
  updateSettings,
  deletePfp,
  canChangeUsername,
  ensureSettings,
} = require("./userSettings");

const app = express();

// --- Environment / Secrets ---
const PORT = process.env.PORT || 3000;
const IN_PROD = process.env.PRODUCTION === "true";
const SECRET_KEY = process.env.SECRET_KEY;
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");
const SALT_ROUNDS = 12;

if (!SECRET_KEY) {
  console.error("❌ Missing SECRET_KEY in .env");
  process.exit(1);
}

const AES_KEY = crypto.createHash("sha256").update(SECRET_KEY).digest();

// --- Sessions ---
app.use(
  session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: IN_PROD,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 2, // 2h
    },
  })
);

// --- Static files ---
app.use(express.static(path.join(__dirname, "public")));
app.use(
  "/user-images",
  express.static(path.join(__dirname, "database/user-images"))
);

// --- App setup ---
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(helmet());

// --- Rate limiting ---
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: "Too many attempts, try later.",
});

// --- CSRF ---
app.use(csurf({ cookie: true }));
app.use((req, res, next) => {
  res.locals.csrfToken = req.csrfToken();
  next();
});
app.use((err, req, res, next) => {
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).render("csrf-error", { csrfToken: res.locals.csrfToken });
  }
  next(err);
});

// --- Helpers ---
function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", AES_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(String(text), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

function decrypt(b64) {
  try {
    const buf = Buffer.from(b64, "base64");
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const ct = buf.slice(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", AES_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

function emailHmac(email) {
  return crypto.createHmac("sha256", SECRET_KEY)
    .update(String(email).toLowerCase())
    .digest("hex");
}

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: "2h" }
  );
}

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function redirectIfAuth(req, res, next) {
  if (req.session.user) return res.redirect("/chat");
  next();
}

// --- Public pages ---
app.get("/", (req, res) => res.render("home", { csrfToken: res.locals.csrfToken, user: null }));
app.get("/home", (req, res) => res.render("home", { csrfToken: res.locals.csrfToken, user: null }));
app.get("/about-us", (req, res) => res.render("about-us", { csrfToken: res.locals.csrfToken }));
app.get("/contact", (req, res) => res.render("contact", { csrfToken: res.locals.csrfToken }));
app.get("/forgot-password", (req, res) => res.render("forgot-password", { csrfToken: res.locals.csrfToken }));

app.get("/ban", (req, res) => res.render("ban", { csrfToken: res.locals.csrfToken }));

// --- Settings ---
app.get("/settings", requireAuth, (req, res) => {
  const userSettings = getSettings(req.session.user.id);
res.render("settings", {
  csrfToken: res.locals.csrfToken,
  user: req.session.user,
  userSettings: getSettings(req.session.user.id),
});
});

// --- Multer setup ---
const userImagesDir = path.join(__dirname, "database/user-images");
if (!fs.existsSync(userImagesDir)) fs.mkdirSync(userImagesDir, { recursive: true });

const upload = multer({
  dest: userImagesDir,
  limits: { fileSize: 1024 * 1024 }, // 1 MB
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith("image/")) {
      return cb(new multer.MulterError("LIMIT_UNEXPECTED_FILE", "Only images allowed"));
    }
    cb(null, true);
  },
});

// --- Change PFP ---
app.post("/settings/pfp", requireAuth, upload.single("pfp"), async (req, res) => {
  const userId = req.session.user.id;
  if (!req.file) {
    return res.status(400).render("settings", {
      csrfToken: res.locals.csrfToken,
      user: req.session.user,
      userSettings: getSettings(userId),
      error: "❌ No file uploaded.",
    });
  }

  try {
    const filename = crypto.randomBytes(12).toString("hex") + ".jpg";
    const filepath = path.join(userImagesDir, filename);

    await sharp(req.file.path)
      .resize(500, 500, { fit: "inside" })
      .jpeg({ quality: 80 })
      .toFile(filepath);

    fs.unlinkSync(req.file.path);

    deletePfp(userId);
    updateSettings(userId, { pfp: "/user-images/" + filename });

    res.redirect("/settings");
  } catch (err) {
    console.error(err);
    res.status(500).render("settings", {
      csrfToken: res.locals.csrfToken,
      user: req.session.user,
      userSettings: getSettings(userId),
      error: "⚠️ Upload failed.",
    });
  }
});

// ---------------- Change username ----------------
app.post("/settings/username", requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const newUsername = req.body.newUsername;

  if (!newUsername || newUsername.trim().length < 3) {
    return res.status(400).render("settings", {
      csrfToken: res.locals.csrfToken,
      user: req.session.user,
      userSettings: getSettings(userId),
      error: "❌ Username too short."
    });
  }

  // update username logic here...

  res.redirect("/settings");
}); // ✅ properly closes the route callback


// Separate chat route
// app.post("/chat/:friendId", requireAuth, async (req, res) => {
//   try {
//     const friendId = req.params.friendId;
//     const { content, type } = req.body;

//     if (!content || !type) {
//       return res.status(400).json({ error: "Invalid message format" });
//     }

//     const message = {
//       senderId: req.session.user.id,
//       content,
//       type, // "text" | "image" | ...
//       timestamp: Date.now()
//     };

//     await addMessage(req.session.user.id, friendId, message);

//     res.json({ success: true });
//   } catch (err) {
//     console.error("Error sending message:", err);
//     res.status(500).json({ error: "Failed to send message" });
// //   }
//   const sockets = userSockets.get(String(friendId));
//     if (sockets) {
//       for (const sid of sockets) {
//         io.to(sid).emit("new_message", {
//           from: senderId,
//           content,
//           type,
//           time: new Date().toLocaleTimeString()
//         });
//       }
//     }
// });

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
  const userId = req.session.user.id;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).render('settings', {
      csrfToken: res.locals.csrfToken,
      user: req.session.user,
      userSettings: getSettings(userId),
      error: "❌ Please fill in all fields."
    });
  }

  if (!canChangePassword(userId)) {
    return res.status(429).render('settings', {
      csrfToken: res.locals.csrfToken,
      user: req.session.user,
      userSettings: getSettings(userId),
      error: "❌ You can only change password once per week."
    });
  }

  try {
    db.get("SELECT password FROM database_utenti WHERE id = ?", [userId], async (err, row) => {
      if (err || !row) {
        return res.status(500).render('settings', {
          csrfToken: res.locals.csrfToken,
          user: req.session.user,
          userSettings: getSettings(userId),
          error: "⚠️ Server error."
        });
      }

      const match = await bcrypt.compare(currentPassword, row.password);
      if (!match) {
        return res.status(400).render('settings', {
          csrfToken: res.locals.csrfToken,
          user: req.session.user,
          userSettings: getSettings(userId),
          error: "❌ Current password is incorrect."
        });
      }

      const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
      db.run("UPDATE database_utenti SET password = ? WHERE id = ?", [hashed, userId], (err2) => {
        if (err2) {
          return res.status(500).render('settings', {
            csrfToken: res.locals.csrfToken,
            user: req.session.user,
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
      user: req.session.user,
      userSettings: getSettings(userId),
      error: "⚠️ Unexpected error."
    });
  }
});

// --- Chat ---
app.get("/chat", async (req, res) => {
  try {
    if (!req.session.user) {
      return res.redirect("/login");
    }

    const userId = req.session.user.id;

    // load friends + requests
    const friends = await chatDB.getFriends(userId);
    const requests = await chatDB.getRequests(userId);

    // load settings from DB (or return defaults)
    let userSettings = await getSettings(userId);
    if (!userSettings) {
      userSettings = { pfp: "/images/default.png", username: req.session.user.username };
    }

    res.render("chat", {
    csrfToken: req.csrfToken(),
    user: req.session.user,       // 👈 gives you user.username
    userSettings,      // 👈 gives you userSettings.pfp & .username  // ✅ now chat.ejs won’t crash
      friends,
      requests,
    friendId: friends.length ? friends[0].id : null // open first friend by default
    });

  } catch (err) {
    console.error("Error loading chat:", err);
    res.status(500).send("Error loading chat");
  }
});
app.get("/chat/:friendId", requireAuth, async (req, res) => {
  try {
    const userId = Number(req.session.user.id);
    const friendId = Number(req.params.friendId);
    if (!friendId) return res.status(400).json({ error: "Missing friendId" });

    const messages = await chatDB.getMessages(userId, friendId);

    // Normalize messages for client: decrypt already done inside chatDB.getMessages
    const normalized = (messages || []).map(m => ({
      senderId: m.senderId,
      content: m.content,
      type: m.type,
      // if messages stored with timestamp, expose a human time; otherwise fallback
      time: m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : (m.time || "")
    }));

    res.json({ messages: normalized });
  } catch (err) {
    console.error("Error getting messages:", err);
    res.status(500).json({ error: "Failed to load messages" });
  }
});

// Receive a new message and store it
app.post("/chat/:friendId", requireAuth, async (req, res) => {
  try {
    const senderId = Number(req.session.user.id);
    const friendId = Number(req.params.friendId);
    const { content, type } = req.body;

    if (!friendId || !content || !type) {
      return res.status(400).json({ error: "Invalid message format" });
    }

    const message = {
      senderId,
      content,
      type,
      timestamp: Date.now()
    };

    await chatDB.addMessage(senderId, friendId, message);

    // ✅ Broadcast message to recipient if online
    const sockets = userSockets.get(String(friendId));
    if (sockets) {
      for (const sid of sockets) {
        io.to(sid).emit("new_message", {
          from: senderId,
          content,
          type,
          time: new Date().toLocaleTimeString()
        });
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Error sending message:", err);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// ---------------- FRIENDS API ----------------
// Friends & Requests now only store IDs in LowDB.
// Usernames + PFP are always fetched fresh from database_utenti + userSettings.
// ------------------------------------------------

// Send friend request
app.post("/friends/request", requireAuth, (req, res) => {
  const { friendId } = req.body;
  const senderId = req.session.user.id;

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
  const settings = ensureSettings(req.session.user.id);
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

app.get("/friends/status/:id", (req, res) => {
  const { id } = req.params;
  res.json({ online: isOnline(id) });
});


// Accept friend request
app.post("/friends/accept", requireAuth, (req, res) => {
  const { fromId } = req.body;
  const receiverId = req.session.user.id;
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
  const receiverId = req.session.user.id;
  const receiverSettings = ensureSettings(receiverId);

  if (!Array.isArray(receiverSettings.requests)) {
    return res.json({ success: true });
  }

  receiverSettings.requests = receiverSettings.requests.filter(r => String(r.fromId) !== String(fromId));
  updateSettings(receiverId, receiverSettings);

  res.json({ success: true });
});


app.get("/friends/list", requireAuth, (req, res) => {
  try {
    const settings = ensureSettings(req.session.user.id);
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
        if (err) {
          console.error("DB error in /friends/list:", err);
          return res.status(500).json({ error: "Server error" });
        }

        const friends = rows.map(r => {
          const userSettings = getSettings(r.id);
          const viewedName =
            userSettings?.username || decrypt(r.username) || "Unknown";

          return {
            id: r.id,
            username: viewedName,
            pfp: userSettings?.pfp || "/images/icon-user.png",
            online: isOnline(r.id), // ✅ add online flag from memory
          };
        });

        res.json({ friends });
      }
    );
  } catch (e) {
    console.error("Unexpected error in /friends/list:", e);
    res.status(500).json({ error: "Unexpected server error" });
  }
});

app.get('/online-users', (req, res) => {
  res.json({ online: getOnlineUsers() });
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
    if (err) {
      return res.status(500).render('login', {
        csrfToken: res.locals.csrfToken,
        error: 'Server error.'
      });
    }
    if (!user) {
      return res.status(401).render('login', {
        csrfToken: res.locals.csrfToken,
        error: 'Invalid credentials.'
      });
    }

    if (user.banned === 1) {
      return res.redirect('/ban');
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).render('login', {
        csrfToken: res.locals.csrfToken,
        error: 'Invalid credentials.'
      });
    }

    // ✅ Decrypt values before saving
    const decodedUser = {
      id: user.id,
      username: decrypt(user.username),
      email: decrypt(user.email),
      pfp: user.pfp ? decrypt(user.pfp) : "/images/default.png"
    };

    // ✅ Save into session
    req.session.user = decodedUser;
    // userOnline(decodedUser.id);  // ✅ place it here

    // (Optional) also set token cookie if you need JWT
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
  if (req.session.user) {
    // userOffline(req.session.user.id);  // mark as offline
  }

  req.session.destroy(err => {
    if (err) {
      console.error("Failed to destroy session:", err);
      return res.status(500).send("Logout failed");
    }

    res.clearCookie('token');
    res.clearCookie('connect.sid'); // clear session cookie too
    res.redirect('/');
  });
});

app.use((req, res) => {
  res.status(404).render('404', { csrfToken: res.locals.csrfToken });
});

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: true,  // later restrict to your frontend domain
    methods: ["GET", "POST"]
  }
});

// Socket.IO presence handling
const activeSockets = new Map();
// Instead of one socket per user, allow multiple sockets
const userSockets = new Map();

function broadcastOnlineUsers() {
  const onlineIds = Array.from(userSockets.keys());
  io.emit("online_users", onlineIds); // send full state to ALL clients
}

const disconnectTimers = new Map();

io.on("connect", (socket) => { 
  // fix connection
  console.log("🔌 New socket connected:", socket.id);

  socket.on("auth", ({ userId }) => {
    if (!userId) return;
    const uid = String(userId);
    socket.data.userId = uid;

    // cancel pending offline if reconnects quickly
    if (disconnectTimers.has(uid)) {
      clearTimeout(disconnectTimers.get(uid));
      disconnectTimers.delete(uid);
    }

    const count = activeSockets.get(uid) || 0;
    activeSockets.set(uid, count + 1);

    if (count === 0) {
      userOnline(uid);
      io.emit("user_online", uid);
      console.log(`✅ User ${uid} is now ONLINE`);
      broadcastOnlineUsers();
    } else {
      console.log(`User ${uid} opened another tab (total: ${count + 1})`);
    }
  });
  function broadcastOnlineUsers() {
  const onlineIds = Array.from(userSockets.keys()).map(String);
  io.emit("online_users", onlineIds);
}

  socket.on("user_online", (uid) => {
  console.log("➡️ user_online", uid);
  updateFriendStatus(uid, true);
});

socket.on("user_offline", (uid) => {
  console.log("➡️ user_offline", uid);
  updateFriendStatus(uid, false);
});

socket.on("online_users", (ids) => {
  console.log("📡 Full online list:", ids);

  // First mark everyone offline
  friends.forEach(friend => updateFriendStatus(friend._id, false));

  // Then mark only the ones actually online
  ids.forEach(uid => updateFriendStatus(uid, true));
});

  socket.on("disconnect", () => {
    const uid = socket.data.userId;
    if (!uid) return;

    const count = activeSockets.get(uid) || 0;
    if (count <= 1) {
      activeSockets.delete(uid);

      // delay marking offline (e.g., 2 seconds)
      disconnectTimers.set(uid, setTimeout(() => {
        userOffline(uid);
        io.emit("user_offline", uid);
        disconnectTimers.delete(uid);
        console.log(`❌ User ${uid} is now OFFLINE`);
        broadcastOnlineUsers();
      }, 2000));

    } else {
      activeSockets.set(uid, count - 1);
      console.log(`User ${uid} closed a tab (remaining: ${count - 1})`);
    }
  });
});

server.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});