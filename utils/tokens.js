'use strict';

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config(); //loads .env into process.env

function signAccessToken(userId) {
  const payload = { sub: userId }; //sub is the standard JWT claim for "who this token belongs to"
  const secret = process.env.ACCESS_TOKEN_SECRET;
  const options = { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }; //e.g. "15m", controlled from .env

  return jwt.sign(payload, secret, options);
}

function generateRefreshToken() {
  //crypto.randomBytes gives real randomness — Math.random() is NOT cryptographically secure
  return crypto.randomBytes(32).toString('hex'); //32 bytes = 64 hex chars, enough entropy
}

function hashToken(token) {
  //we never store the raw token in the DB, only its hash
  //so even if the DB leaks, the attacker gets useless hashes
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { signAccessToken, generateRefreshToken, hashToken };
