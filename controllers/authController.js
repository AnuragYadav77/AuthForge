'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { createUser, getUserByEmail } = require('../db/queries/userQueries');
const { insertRefreshToken, getTokenByHash, revokeToken, revokeFamily } = require('../db/queries/tokenQueries');
const { signAccessToken, generateRefreshToken, hashToken } = require('../utils/tokens');
const { isValidEmail, isStrongPassword } = require('../utils/validators');

// Pre-hashed dummy constant for timing-safe rejection when the user doesn't exist.
// Without this, an attacker could enumerate valid emails by measuring response time:
// a missing user returns instantly; a wrong password takes ~300ms (bcrypt cost).
// Comparing against this dummy makes both paths take the same time.
const DUMMY_HASH = '$2b$12$invalidhashpaddingtomatchbcryptlengthandpreventearlyexit00';

const REFRESH_TOKEN_EXPIRY_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRY_DAYS, 10) || 7;
const REFRESH_TOKEN_EXPIRY_MS = REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60 * 1000;

// POST /api/auth/signup
async function signup(req, res) {
    const { email, password } = req.body;

    // --- Input validation ---
    // Both fields must be present and well-formed before we touch the DB.
    if (!email || !isValidEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format.' });
    }

    if (!password || !isStrongPassword(password)) {
        return res.status(400).json({
            message: 'Password must be at least 8 characters and contain at least one number.',
        });
    }

    try {
        // --- Duplicate check ---
        // Signup *must* tell the user their email is taken — otherwise they'd
        // never know why they can't register. This is not an enumeration risk
        // in the same way login error messages are.
        const existingUser = await getUserByEmail(email);
        if (existingUser) {
            return res.status(409).json({ message: 'An account with this email already exists.' });
        }

        // --- Hash the password ---
        // 12 salt rounds: deliberate slowness (~300ms) to make brute-force expensive.
        // Never store plaintext passwords.
        const passwordHash = await bcrypt.hash(password, 12);

        // --- Persist the new user ---
        await createUser(email, passwordHash);

        // --- Respond ---
        // 201 Created. Return only a success message — no hash, no user id.
        return res.status(201).json({ message: 'Account created successfully.' });

    } catch (err) {
        // Catch unexpected DB errors or bcrypt failures.
        // Never expose internal error details to the client.
        console.error('[signup] Unexpected error:', err);
        return res.status(500).json({ message: 'Something went wrong. Please try again later.' });
    }
}

// POST /api/auth/login
async function login(req, res) {
    const { email, password } = req.body;

    // Basic presence check — detailed format validation isn't necessary here
    // since we'll return a generic error regardless of *why* auth fails.
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const user = await getUserByEmail(email);

        // --- Timing-safe comparison ---
        // We always run bcrypt.compare, even when the user doesn't exist.
        // This prevents timing attacks: a non-existent user would otherwise
        // return in microseconds vs ~300ms for a real (wrong) password.
        const hashToCompare = user ? user.password_hash : DUMMY_HASH;
        const passwordMatch = await bcrypt.compare(password, hashToCompare);

        // --- Enumeration-safe rejection ---
        // Both "no such user" and "wrong password" produce the same response.
        // The client gets no signal about which part failed.
        if (!user || !passwordMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // --- Build the session ---
        // family_id ties every refresh token from this login together.
        // If any rotated token is reused, we can revoke the entire family.
        const familyId = crypto.randomUUID();
        const accessToken = signAccessToken(user.id);
        const refreshToken = generateRefreshToken();  // raw — goes in the cookie only
        const tokenHash = hashToken(refreshToken);    // stored in DB — never the raw token
        const expiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS);

        await insertRefreshToken(user.id, tokenHash, familyId, expiresAt);

        // --- Set the refresh token cookie ---
        // httpOnly: JS cannot read it — blocks XSS token theft
        // secure: HTTPS only
        // sameSite strict: not sent on cross-site requests — blocks CSRF
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: REFRESH_TOKEN_EXPIRY_MS,
        });

        // Access token goes in the response body — short-lived, client stores in memory
        return res.status(200).json({ accessToken });

    } catch (err) {
        console.error('[login] Unexpected error:', err);
        return res.status(500).json({ message: 'Something went wrong. Please try again later.' });
    }
}

// POST /api/auth/refresh
async function refresh(req, res) {
    const rawToken = req.cookies?.refreshToken;

    // No cookie at all — reject without touching the DB.
    if (!rawToken) {
        return res.status(401).json({ message: 'Refresh token missing.' });
    }

    try {
        const tokenHash = hashToken(rawToken);
        const tokenRow = await getTokenByHash(tokenHash);

        // --- Case 1: Token not in DB ---
        // Could be forged, garbage, or from a wiped DB.
        // We have no family_id, so there's nothing to revoke — just reject.
        if (!tokenRow) {
            return res.status(401).json({ message: 'Invalid refresh token.' });
        }

        // --- Case 2: Token exists but already revoked ---
        // This is the theft-detection signal. Under normal rotation, the client
        // discards the old token immediately after receiving the new one.
        // If a revoked token is presented again, it means a second party still
        // has it — either the real user or an attacker. We can't tell which,
        // so we revoke the entire family. Both parties are forced to re-login.
        if (tokenRow.revoked) {
            await revokeFamily(tokenRow.family_id);
            return res.status(401).json({ message: 'Token reuse detected. Please log in again.' });
        }

        // --- Case 3: Token exists, not revoked, but naturally expired ---
        // No threat signal — the session simply ran out. No family action needed.
        if (new Date(tokenRow.expires_at) < new Date()) {
            return res.status(401).json({ message: 'Refresh token expired. Please log in again.' });
        }

        // --- Valid token: rotate ---
        // Revoke the current token first, then issue the new pair.
        // Order matters: if the insert fails after revoking, the user gets a 500
        // and must re-login. The reverse order risks two live tokens coexisting.
        await revokeToken(tokenHash);

        const newRefreshToken = generateRefreshToken();
        const newTokenHash = hashToken(newRefreshToken);
        const newExpiresAt = new Date(Date.now() + REFRESH_TOKEN_EXPIRY_MS);

        // Reuse the same family_id — this is still the same login session.
        // A new family_id would break the theft-detection chain.
        await insertRefreshToken(tokenRow.user_id, newTokenHash, tokenRow.family_id, newExpiresAt);

        const newAccessToken = signAccessToken(tokenRow.user_id);

        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: REFRESH_TOKEN_EXPIRY_MS,
        });

        return res.status(200).json({ accessToken: newAccessToken });

    } catch (err) {
        console.error('[refresh] Unexpected error:', err);
        return res.status(500).json({ message: 'Something went wrong. Please try again later.' });
    }
}

module.exports = { signup, login, refresh };
