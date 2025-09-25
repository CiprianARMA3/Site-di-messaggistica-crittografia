// chatDB.js
const path = require("path");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const { encryptMessage, decryptMessage } = require("./cryptoHelper");

// Path to chats.json
const file = path.join(__dirname, "database/chats.json");
const adapter = new JSONFile(file);

// ✅ Default structure includes chats, friends, and requests
const db = new Low(adapter, { chats: {}, friends: {}, requests: {} });

// Initialize DB
async function init() {
  await db.read();
  db.data ||= { chats: {}, friends: {}, requests: {} };
  await db.write();
}
init();

/**
 * Utility: generate a stable chatId between two users
 */
function getChatId(userId, friendId) {
  return [userId, friendId].sort().join("_");
}

/**
 * Get all messages for a chat (decrypted automatically).
 */
async function getMessages(userId, friendId) {
  await db.read();
  const chatId = getChatId(userId, friendId);
  const rawMsgs = db.data.chats[chatId] || [];

  return rawMsgs.map(m => {
    if (m.type === "text") {
      try {
        return { ...m, content: decryptMessage(m.content) };
      } catch (e) {
        console.error("Decryption failed:", e.message);
        return { ...m, content: "[Decryption failed]" };
      }
    }
    return m;
  });
}

/**
 * Add a message (encrypt text automatically).
 */
async function addMessage(userId, friendId, message) {
  await db.read();
  const chatId = getChatId(userId, friendId);
  if (!db.data.chats[chatId]) db.data.chats[chatId] = [];

  const msgToStore = { ...message };

  if (msgToStore.type === "text") {
    msgToStore.content = encryptMessage(msgToStore.content);
  }

  db.data.chats[chatId].push(msgToStore);
  await db.write();
}

/**
 * Get friends of a user
 */
async function getFriends(userId) {
  await db.read();
  db.data.friends ||= {};
  return db.data.friends[userId] || [];
}

/**
 * Add a friend relationship
 */
async function addFriend(userId, friendId) {
  await db.read();
  db.data.friends ||= {};

  if (!db.data.friends[userId]) {
    db.data.friends[userId] = [];
  }
  if (!db.data.friends[userId].includes(friendId)) {
    db.data.friends[userId].push(friendId);
  }

  // also add reverse relation
  if (!db.data.friends[friendId]) {
    db.data.friends[friendId] = [];
  }
  if (!db.data.friends[friendId].includes(userId)) {
    db.data.friends[friendId].push(userId);
  }

  await db.write();
}

/**
 * Get pending friend requests for a user
 */
async function getRequests(userId) {
  await db.read();
  db.data.requests ||= {};
  return db.data.requests[userId] || [];
}

/**
 * Add a friend request
 */
async function addRequest(fromUser, toUser) {
  await db.read();
  db.data.requests ||= {};

  if (!db.data.requests[toUser]) {
    db.data.requests[toUser] = [];
  }

  if (!db.data.requests[toUser].includes(fromUser)) {
    db.data.requests[toUser].push(fromUser);
    await db.write();
  }
}

/**
 * Accept a friend request
 */
async function acceptRequest(userId, fromUser) {
  await db.read();
  db.data.requests ||= {};

  // remove from requests
  if (db.data.requests[userId]) {
    db.data.requests[userId] = db.data.requests[userId].filter(u => u !== fromUser);
  }

  // add to friends
  await addFriend(userId, fromUser);

  await db.write();
}

module.exports = {
  getMessages,
  addMessage,
  getFriends,
  addFriend,
  getRequests,
  addRequest,
  acceptRequest
};
