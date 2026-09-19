const jwt = require('jsonwebtoken');
require('dotenv').config();

/**
 * requireAuth middleware
 *
 * Protects routes by verifying the JWT access token supplied in the
 * Authorization header.  On success it attaches the authenticated user's
 * ID to `req.userId` and hands control to the next handler.
 *
 * Expected header format:
 *   Authorization: Bearer <access_token>
 */
const requireAuth = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  // ── 1. Header presence & format check ────────────────────────────────────
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authorization header missing or malformed.' });
  }

  const token = authHeader.split(' ')[1]; // Extract the raw token string

  if (!token) {
    return res.status(401).json({ message: 'Bearer token is missing.' });
  }

  // ── 2. Verify the token ───────────────────────────────────────────────────
  try {
    const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Attach the subject claim (user ID) to the request for downstream handlers
    req.userId = payload.sub;

    next();
  } catch (err) {
    // Distinguish between an expired token and any other verification failure
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Access token has expired.' });
    }

    // Covers JsonWebTokenError (bad signature, malformed, etc.)
    return res.status(401).json({ message: 'Invalid access token.' });
  }
};

module.exports = requireAuth;
