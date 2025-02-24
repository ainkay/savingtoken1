const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const SECRET_KEY = 'your-very-secure-secret-key'; // Replace with a strong secret key
const ENCRYPTION_KEY = crypto.randomBytes(32); // 256-bit key
const IV = crypto.randomBytes(16); // Initialization Vector

// Encrypts a JWT token
const encrypt = (payload) => {
  // Create JWT token
  const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

  // Encrypt token using AES-256-CBC
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return {
    token: encrypted,
    iv: IV.toString('hex'), // IV is needed for decryption
  };
};

// Decrypts an encrypted JWT token
const decrypt = ({ token, iv }) => {
  const decipher = crypto.createDecipheriv(
    'aes-256-cbc',
    ENCRYPTION_KEY,
    Buffer.from(iv, 'hex')
  );
  let decrypted = decipher.update(token, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // Verify and decode JWT
  try {
    return jwt.verify(decrypted, SECRET_KEY);
  } catch (error) {
    return { error: 'Invalid or expired token' };
  }
};

module.exports = { encrypt, decrypt };

// ✅ Test the functions
const samplePayload = { userId: 123, role: 'admin' };
const encryptedJWT = encrypt(samplePayload);
console.log('🔒 Encrypted:', encryptedJWT);

const decryptedJWT = decrypt(encryptedJWT);
console.log('🔑 Decrypted:', decryptedJWT);
