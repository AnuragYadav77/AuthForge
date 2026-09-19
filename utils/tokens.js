'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

/**
 * Signs a JWT access token for the given user ID.
 * Expiry is controlled by ACCESS_TOKEN_EXPIRY in .env (e.g. "15m").
 *
 * @param {number|string} userId - The user's database ID to embed in the payload.
 * @returns {string} Signed JWT string.
 */
function signAccessToken(userId) {
  const payload = { sub: userId };
  const secret = process.env.ACCESS_TOKEN_SECRET;
  const options = { expiresIn: process.env.ACCESS_TOKEN_EXPIRY };

  return jwt.sign(payload, secret, options);
}

/**
 * Generates a cryptographically secure random refresh token.
 * Uses crypto.randomBytes — NOT Math.random(), which is not cryptographically
 * secure and predictable by an attacker given enough observations.
 *
 * @returns {string} A 64-character hex string (32 random bytes).
 */
function generateRefreshToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hashes a raw token string using SHA-256.
 * Only the hash is ever stored in the database — the raw token travels over
 * the wire once (to the client) and is never persisted, so a DB leak does not
 * expose usable tokens.
 *
 * @param {string} token - The raw token string to hash.
 * @returns {string} Hex-encoded SHA-256 digest.
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { signAccessToken, generateRefreshToken, hashToken };
