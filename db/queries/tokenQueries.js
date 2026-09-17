async function insertRefreshToken(userId, tokenHash, familyId, expiresAt) {
    const [result] = await pool.query(
        'INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?)',
        [userId, tokenHash, familyId, expiresAt]
    );
    return result;
}