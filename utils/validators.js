'use strict';

function isValidEmail(email) {
    //not RFC-perfect, but catches obvious garbage like "foo", "@bar", "foo@"
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

function isStrongPassword(password) {
    //min 8 chars, at least one number — keeps weak passwords out early
    const passwordRegex = /^(?=.*\d).{8,}$/;
    return passwordRegex.test(password);
}

module.exports = { isValidEmail, isStrongPassword };
