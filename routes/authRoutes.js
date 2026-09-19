const express = require('express');
const router = express.Router();

const { signup, login, refresh, logout } = require('../controllers/authController');
const requireAuth = require('../middleware/requireAuth');
const loginLimiter = require('../middleware/loginLimiter');

// Public routes
router.post('/signup', signup);
router.post('/login', loginLimiter, login);
router.post('/refresh', refresh);
router.post('/logout', logout);

// Protected route — requireAuth verifies the access token and attaches req.userId
router.get('/me', requireAuth, (req, res) => {
    res.json({ userId: req.userId });
});

module.exports = router;
