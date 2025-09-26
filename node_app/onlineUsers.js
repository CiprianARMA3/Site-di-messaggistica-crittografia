// onlineUsers.js
const onlineUsers = new Set();

function userOnline(userId) {
  if (userId == null) return;
  onlineUsers.add(String(userId));
}
function userOffline(userId) {
  if (userId == null) return;
  onlineUsers.delete(String(userId));
}
function getOnlineUsers() {
  return Array.from(onlineUsers);
}
function isOnline(userId) {
  return onlineUsers.has(String(userId));
}

module.exports = { userOnline, userOffline, getOnlineUsers, isOnline };