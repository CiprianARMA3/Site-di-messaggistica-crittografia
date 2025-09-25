const crypto = require("crypto");
require("dotenv").config();

const SECRET_KEY = Buffer.from(process.env.SECRET_KEY, "base64"); // 32 bytes
const ALGO = "aes-256-gcm";

// Encrypt text
function encryptMessage(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, SECRET_KEY, iv);

  let encrypted = cipher.update(text, "utf8", "base64");
  encrypted += cipher.final("base64");

  const authTag = cipher.getAuthTag().toString("base64");

  return {
    iv: iv.toString("base64"),
    content: encrypted,
    tag: authTag
  };
}

// Decrypt text
function decryptMessage({ iv, content, tag }) {
  const decipher = crypto.createDecipheriv(ALGO, SECRET_KEY, Buffer.from(iv, "base64"));
  decipher.setAuthTag(Buffer.from(tag, "base64"));

  let decrypted = decipher.update(content, "base64", "utf8");
  decrypted += decipher.final("utf8");

  return decrypted;
}

module.exports = { encryptMessage, decryptMessage };
