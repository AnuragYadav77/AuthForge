const rateLimit = require('express-rate-limit');

// 15 minutes expressed in milliseconds:
// 15 (min) * 60 (sec/min) * 1000 (ms/sec) = 900_000 ms
const WINDOW_MS = 15 * 60 * 1000;

const loginLimiter = rateLimit({
    windowMs: WINDOW_MS, // 900,000 ms — 15-minute sliding window

    max: 5, // allow at most 5 login attempts per IP within that window

    message: {
        success: false,
        message: 'Too many login attempts from this IP. Please try again after 15 minutes.',
    },

    // standardHeaders: true  → sends rate-limit info in the modern RateLimit-* headers
    //   (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset)
    //   introduced in the IETF draft for HTTP Rate Limit Headers
    standardHeaders: true,

    // legacyHeaders: false  → suppresses the old X-RateLimit-* headers
    //   (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
    //   kept for back-compat in older versions of express-rate-limit,
    //   but redundant now that standardHeaders covers the same info
    legacyHeaders: false,
});

module.exports = loginLimiter;
