const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const authMiddleware = require(process.cwd(), 'middleware', 'auth'); // Import middleware chung

const router = express.Router();
const ACCOUNTS_DIR = path.join(process.cwd(), 'data', 'auth', 'accounts');

/* -------------------- HELPERS -------------------- */
async function getProfile(uid) {
    try {
        const data = await fs.readFile(path.join(ACCOUNTS_DIR, uid, 'profile.json'), 'utf8');
        return JSON.parse(data);
    } catch (e) { return null; }
}

/* -------------------- ROUTES -------------------- */

/**
 * @route   GET /api/me
 * @desc    Lấy thông tin cá nhân của người đang đăng nhập
 * @access  Private (Cần middleware authMiddleware)
 */
router.get('/me', async (req, res) => {
    try {
        // UID lấy từ Middleware đã giải mã Token trước đó
        const profile = await getProfile(req.user.uid);

        if (!profile) {
            return res.status(404).json({ error: "Hồ sơ người dùng không tồn tại." });
        }

        // Chỉ trả về dữ liệu an toàn để hiển thị giao diện
        return res.status(200).json({
            success: true,
            user: {
                uid: profile.uid,
                username: profile.username,
                name: profile.name || profile.username,
                role: profile.role || ['user'],
                avatar: profile.avatar || null,
                bio: profile.bio || '',
                joined_at: profile.created_at
            }
        });

    } catch (err) {
        console.error("Profile API Error:", err);
        res.status(500).json({ error: "Lỗi máy chủ nội bộ." });
    }
});

module.exports = router;