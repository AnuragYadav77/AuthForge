const express = require('express');
const cookieParser = require('cookie-parser');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/authRoutes');

const app = express();

// ── Middleware ──────────────────────────────────────────────
app.use(express.json());      // Parse JSON request bodies
app.use(cookieParser());       // Populate req.cookies (needed by refresh/logout)
app.use(cors());               // Enable CORS for all origins

// ── Routes ─────────────────────────────────────────────────
// All auth endpoints live under /api/auth:
//   POST /api/auth/signup
//   POST /api/auth/login
//   POST /api/auth/refresh
//   POST /api/auth/logout
//   GET  /api/auth/me  (protected)
app.use('/api/auth', authRoutes);

// ── Start server ───────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`AuthForge server running on http://localhost:${PORT}`);
});
