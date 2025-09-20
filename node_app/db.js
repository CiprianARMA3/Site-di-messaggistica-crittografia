// db.js
const path = require("path");
const sqlite3 = require("sqlite3").verbose();

// Always use a real file name (not .sqbpro).
// Here we keep it one level up, in a folder named "database".
const dbPath = path.resolve(__dirname, "../database/database.sqlite");

console.log("Opening SQLite database at:", dbPath);

// OPEN_CREATE makes sure the file is created if missing
const db = new sqlite3.Database(
  dbPath,
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) {
      console.error("❌ DB connection error:", err.message);
    } else {
      console.log("✅ Connected to database.");
    }
  }
);

// Prevent "database is locked" errors
db.configure("busyTimeout", 5000);

// Create table if it doesn’t exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS database_utenti (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      email TEXT NOT NULL,
      email_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

module.exports = { db };
