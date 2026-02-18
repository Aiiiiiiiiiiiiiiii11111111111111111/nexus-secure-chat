const crypto = require("crypto");

// AES-GCM encrypt/decrypt
function encryptAES(key, plaintext){
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let enc = cipher.update(plaintext, "utf8");
  enc = Buffer.concat([enc, cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decryptAES(key, data){
  const raw = Buffer.from(data,"base64");
  const iv = raw.slice(0,12);
  const tag = raw.slice(12,28);
  const enc = raw.slice(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
}

// ECDH key generation
function generateECDH(){
  const ecdh = crypto.createECDH("secp384r1");
  ecdh.generateKeys();
  return ecdh;
}

module.exports = { encryptAES, decryptAES, generateECDH };
