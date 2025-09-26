// onlineUsers.js

// userId -> Set of connection IDs (socket IDs or heartbeat IDs)
const userConnections = new Map();

function userOnline(userId, connectionId) {
  if (!userId || !connectionId) return;
  userId = String(userId);

  let conns = userConnections.get(userId);
  if (!conns) {
    conns = new Set();
    userConnections.set(userId, conns);
  }
  conns.add(connectionId);
}

function userOffline(userId, connectionId) {
  if (!userId || !connectionId) return;
  userId = String(userId);

  const conns = userConnections.get(userId);
  if (!conns) return;

  conns.delete(connectionId);
  if (conns.size === 0) {
    userConnections.delete(userId);
  }
}

function getOnlineUsers() {
  return Array.from(userConnections.keys());
}

function isOnline(userId) {
  return userConnections.has(String(userId));
}

module.exports = { userOnline, userOffline, getOnlineUsers, isOnline };
