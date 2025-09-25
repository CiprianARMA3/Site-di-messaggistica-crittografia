const { join } = require("path");
const { LowSync } = require("lowdb");
const { JSONFileSync } = require("lowdb/node");
const fs = require("fs");

// --- Paths ---
const dbDir = join(__dirname, "database");
const imagesDir = join(dbDir, "user-images");
const file = join(dbDir, "user-settings.json");

// Ensure folders exist
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
if (!fs.existsSync(imagesDir)) fs.mkdirSync(imagesDir, { recursive: true });

// --- LowDB setup ---
const adapter = new JSONFileSync(file);
const db = new LowSync(adapter, {});
db.read();
if (!db.data) db.data = {}; // ensure root object

// --- Helpers ---
function ensureSettings(userId) {
  if (!db.data[userId]) {
    db.data[userId] = {};
  }

  if (!("username" in db.data[userId])) db.data[userId].username = null;
  if (!("pfp" in db.data[userId])) db.data[userId].pfp = "/images/icon-user.png";
  if (!("pfpChanges" in db.data[userId])) db.data[userId].pfpChanges = [];
  if (!("lastUsernameChange" in db.data[userId])) db.data[userId].lastUsernameChange = 0;
  if (!("friends" in db.data[userId])) db.data[userId].friends = []; // 👈 add this

  db.write();
  return db.data[userId];
}


function getSettings(userId) {
  return ensureSettings(userId);
}

function updateSettings(userId, settings) {
  const current = ensureSettings(userId);
  db.data[userId] = { ...current, ...settings };
  db.write();
  return db.data[userId];
}

// --- Reset PFP ---
function deletePfp(userId) {
  const current = ensureSettings(userId);

  if (current.pfp && current.pfp.startsWith("/user-images/")) {
    const oldPath = join(imagesDir, current.pfp.replace("/user-images/", ""));
    if (fs.existsSync(oldPath)) {
      fs.unlinkSync(oldPath);
    }
  }

  current.pfp = "/images/icon-user.png";
  db.write();
}

// --- Rate limiters ---
function canChangePfp(userId) {
  const settings = ensureSettings(userId);
  const now = Date.now();

  // Keep only last 10 minutes of history
  settings.pfpChanges = settings.pfpChanges.filter(
    ts => now - ts < 10 * 60 * 1000
  );

  if (settings.pfpChanges.length >= 6) {
    return false; // exceeded
  }

  settings.pfpChanges.push(now);
  db.write();
  return true;
}

function canChangeUsername(userId) {
  const settings = ensureSettings(userId);
  const now = Date.now();

  if (now - settings.lastUsernameChange < 7 * 24 * 60 * 60 * 1000) {
    return false;
  }

  settings.lastUsernameChange = now;
  db.write();
  return true;
}

module.exports = {
  getSettings,
  updateSettings,
  deletePfp,
  ensureSettings,
  canChangePfp,
  canChangeUsername
};



