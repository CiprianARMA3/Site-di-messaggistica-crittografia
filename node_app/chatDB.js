// chatDB.js
const path = require("path");
const fs = require("fs");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const { encryptMessage, decryptMessage } = require("./cryptoHelper");
const crypto = require("crypto");

// --- Directories ---
const baseDir = path.join(__dirname, "database/user-chats");
if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });

const friendsFile = path.join(__dirname, "database/friends.json");
const friendsAdapter = new JSONFile(friendsFile);
const friendsDb = new Low(friendsAdapter, { friends: {}, requests: {} });

// --- Helpers ---
function encryptChatId(userId, friendId) {
  const raw = [userId, friendId].sort().join("_");
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function getBucketDate(timestamp = Date.now()) {
  const d = new Date(timestamp);
  const day = Math.floor((d.getDate() - 1) / 15) * 15 + 1; // 1 or 16
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

async function loadChatDb(userId, friendId, timestamp) {
  const chatIdEnc = encryptChatId(userId, friendId);
  const chatDir = path.join(baseDir, chatIdEnc);
  if (!fs.existsSync(chatDir)) fs.mkdirSync(chatDir, { recursive: true });

  const bucket = getBucketDate(timestamp);
  const file = path.join(chatDir, `${bucket}.json`);
  const adapter = new JSONFile(file);
  const db = new Low(adapter, { messages: [] });
  await db.read();
  db.data ||= { messages: [] };
  return db;
}

// --- Messages ---
async function getMessages(userId, friendId) {
  const chatIdEnc = encryptChatId(userId, friendId);
  const chatDir = path.join(baseDir, chatIdEnc);
  if (!fs.existsSync(chatDir)) return [];

  const files = fs.readdirSync(chatDir).filter(f => f.endsWith(".json"));
  let all = [];

  for (const file of files) {
    const adapter = new JSONFile(path.join(chatDir, file));
    const db = new Low(adapter, { messages: [] });
    await db.read();
    all.push(...db.data.messages);
  }

  return all.map(m => {
    if (m.type === "text") {
      try {
        return { ...m, content: decryptMessage(m.content) };
      } catch {
        return { ...m, content: "[Decryption failed]" };
      }
    }
    return m;
  }).sort((a, b) => a.timestamp - b.timestamp);
}

async function addMessage(userId, friendId, message) {
  const db = await loadChatDb(userId, friendId, message.timestamp || Date.now());
  const msgToStore = { ...message };

  if (msgToStore.type === "text") {
    msgToStore.content = encryptMessage(msgToStore.content);
  }

  db.data.messages.push(msgToStore);
  await db.write();
}

// --- Friends ---
async function getFriends(userId) {
  await friendsDb.read();
  friendsDb.data ||= { friends: {}, requests: {} };
  return friendsDb.data.friends[userId] || [];
}

async function addFriend(userId, friendId) {
  await friendsDb.read();
  friendsDb.data ||= { friends: {}, requests: {} };

  if (!friendsDb.data.friends[userId]) friendsDb.data.friends[userId] = [];
  if (!friendsDb.data.friends[friendId]) friendsDb.data.friends[friendId] = [];

  if (!friendsDb.data.friends[userId].includes(friendId)) {
    friendsDb.data.friends[userId].push(friendId);
  }
  if (!friendsDb.data.friends[friendId].includes(userId)) {
    friendsDb.data.friends[friendId].push(userId);
  }

  await friendsDb.write();
}

// --- Friend Requests ---
async function getRequests(userId) {
  await friendsDb.read();
  friendsDb.data ||= { friends: {}, requests: {} };
  return friendsDb.data.requests[userId] || [];
}

async function addRequest(fromUser, toUser) {
  await friendsDb.read();
  friendsDb.data ||= { friends: {}, requests: {} };

  if (!friendsDb.data.requests[toUser]) {
    friendsDb.data.requests[toUser] = [];
  }

  if (!friendsDb.data.requests[toUser].includes(fromUser)) {
    friendsDb.data.requests[toUser].push(fromUser);
  }

  await friendsDb.write();
}

async function acceptRequest(userId, fromUser) {
  await friendsDb.read();
  friendsDb.data ||= { friends: {}, requests: {} };

  if (friendsDb.data.requests[userId]) {
    friendsDb.data.requests[userId] = friendsDb.data.requests[userId].filter(u => u !== fromUser);
  }

  await addFriend(userId, fromUser);
  await friendsDb.write();
}

// --- Export ---
module.exports = {
  getMessages,
  addMessage,
  getFriends,
  addFriend,
  getRequests,
  addRequest,
  acceptRequest
};
