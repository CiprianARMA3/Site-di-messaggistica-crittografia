// enable_wal.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const dbPath = path.resolve("/home/cipriankali/Documents/JAVASCRIPT/Test2.0/database/database");
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("❌ Error opening DB:", err.message);
  } else {
    console.log("✅ DB opened for WAL setup...");
  }
});

db.run("PRAGMA journal_mode=WAL;", (err) => {
  if (err) {
    console.error("❌ Error enabling WAL:", err.message);
  } else {
    console.log("✅ WAL mode enabled!");
  }
  db.close();
});
