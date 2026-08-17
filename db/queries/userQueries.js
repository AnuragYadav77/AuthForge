const pool = require('../pool'); // shared MySQL connection pool

// Inserts a new user row and returns metadata about the insert (e.g. insertId)
async function createUser(email, passwordHash) {
    const [result] = await pool.query(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)', // ? placeholders prevent SQL injection
        [email, passwordHash] // values matched to placeholders, in order
    );
    return result; // contains result.insertId — the new user's auto-generated id
}

// Looks up a single user by email; used during login and signup-duplicate checks
async function getUserByEmail(email) {
    const [rows] = await pool.query(
        'SELECT * FROM users WHERE email = ?',
        [email]
    );
    return rows[0]; // returns the user object, or undefined if no match found
}

module.exports = { createUser, getUserByEmail };