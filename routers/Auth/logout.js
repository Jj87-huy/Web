const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const jwt = require('jsonwebtoken');

const router = express.Router();

/* -------------------- CONFIGURATION -------------------- */
const JWT_SECRET = process.env.SUPER_SECRET_KEY;
const LOGIN_LOGS_PATH = path.join(process.cwd(), 'data', 'auth', 'security_events.log');

/* -------------------- HELPERS -------------------- */
async function logLogoutEvent(req, uid = 'ANONYMOUS') {
    let ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
    if (ip.includes('::ffff:')) ip = ip.split(':').pop();
    
    const entry = `[${new Date().toISOString()}] LOGOUT | UID: ${uid} | IP: ${ip} | UA: ${req.get('User-Agent')}\n`;
    try {
        await fs.appendFile(LOGIN_LOGS_PATH, entry);
    } catch (err) {
        console.error("Lỗi ghi log logout:", err);
    }
}

/* -------------------- MAIN LOGOUT ROUTE -------------------- */
router.post('/logout', async (req, res) => {
    try {
        let uid = 'GUEST';

        // 1. Cố gắng lấy UID từ Token để ghi Log (không bắt buộc phải valid 100%)
        const token = req.cookies['access_token'];
        if (token) {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                uid = decoded.uid;
            } catch (e) {
                // Token hết hạn hoặc sai cũng không sao, chúng ta vẫn xóa cookie
            }
        }

        // 2. Ghi log sự kiện đăng xuất
        await logLogoutEvent(req, uid);

        // 3. Xóa Cookie access_token 
        // LƯU Ý: Các thuộc tính (path, domain, secure) phải khớp lúc set thì xóa mới ăn
        res.clearCookie('access_token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax', // Khớp với cấu hình ở file Login của bạn
            path: '/'
        });

        // 4. Xóa Cookie XSRF-TOKEN
        res.clearCookie('XSRF-TOKEN', {
            path: '/'
        });

        // 5. Xóa luôn secret CSRF (nếu bạn dùng signedCookies như ở server.js)
        res.clearCookie('_csrfSecret', {
            path: '/',
            signed: true
        });

        return res.status(200).json({ 
            success: true, 
            message: "Đăng xuất thành công. Hẹn gặp lại!" 
        });

    } catch (err) {
        console.error("LOGOUT ERROR:", err);
        return res.status(500).json({ error: "Lỗi hệ thống khi đăng xuất." });
    }
});

module.exports = router;