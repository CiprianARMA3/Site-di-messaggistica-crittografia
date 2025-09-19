// db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.resolve("/home/cipriankali/Documents/JAVASCRIPT/Test2.0/database/database");

// Open DB in read/write mode
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
  if (err) {
    console.error("❌ DB connection error:", err.message);
  } else {
    console.log("✅ Connected to database.");
  }
});

// Prevent "database is locked" errors
db.configure("busyTimeout", 5000);
db.serialize();

module.exports = { db };
