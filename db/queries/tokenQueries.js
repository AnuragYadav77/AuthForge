const pool = require('../pool'); // shared MySQL connection pool

// Inserts a new refresh token row; called on login and after each successful rotation
async function insertRefreshToken(userId, tokenHash, familyId, expiresAt) {
    const [result] = await pool.query(
        'INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?)',
        [userId, tokenHash, familyId, expiresAt]
    );
    return result; // contains result.insertId
}

// Finds a refresh token row by its SHA-256 hash; used during /refresh to validate the incoming token
// Returns the full row (user_id, family_id, revoked, expires_at) — controller needs all of it
async function getTokenByHash(tokenHash) {
    const [rows] = await pool.query(
        'SELECT * FROM refresh_tokens WHERE token_hash = ?',
        [tokenHash]
    );
    return rows[0]; // returns the token object, or undefined if no match found
}

// Marks a single token as revoked after a successful rotation — old token is dead, new one takes its place
async function revokeToken(tokenHash) {
    const [result] = await pool.query(
        'UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = ?',
        [tokenHash]
    );
    return result; // result.affectedRows tells you if a row was actually updated
}

// Revokes every token in a family — triggered when a previously-rotated (dead) token is reused,
// which signals a stolen token. Forces the real user to log in again.
async function revokeFamily(familyId) {
    const [result] = await pool.query(
        'UPDATE refresh_tokens SET revoked = TRUE WHERE family_id = ?',
        [familyId]
    );
    return result; // result.affectedRows tells you how many tokens were killed
}

module.exports = { insertRefreshToken, getTokenByHash, revokeToken, revokeFamily };