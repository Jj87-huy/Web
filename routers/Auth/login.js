const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

/* -------------------- CONFIGURATION -------------------- */
const JWT_SECRET = process.env.SUPER_SECRET_KEY || 'default-fallback-key';
const DATA_DIR = path.join(process.cwd(), 'data', 'auth');
const ACCOUNTS_DIR = path.join(DATA_DIR, 'accounts');
const USERNAME_INDEX_PATH = path.join(DATA_DIR, 'username_index.json');
const EMAIL_INDEX_PATH = path.join(DATA_DIR, 'email_index.json');
const LOGIN_LOGS_PATH = path.join(DATA_DIR, 'security_events.log');

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 phút

/* -------------------- HELPERS -------------------- */
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

async function readJSON(filePath) {
    try {
        const content = await fs.readFile(filePath, 'utf8');
        return JSON.parse(content || '{}');
    } catch (e) { return {}; }
}

async function writeJSONAtomic(file, data) {
    const tmp = `${file}.${uuidv4()}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2));
    await fs.rename(tmp, file);
}

// Ghi log bảo mật chi tiết
async function logEvent(uid, status, req, detail = "") {
    let ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
    if (ip.includes('::ffff:')) ip = ip.split(':').pop();
    const ua = req.get('User-Agent') || 'Unknown';
    const entry = `[${new Date().toISOString()}] ${status} | UID: ${uid} | IP: ${ip} | UA: ${ua} | ${detail}\n`;
    await fs.appendFile(LOGIN_LOGS_PATH, entry).catch(() => {});
}

// Trả về lỗi ẩn danh để chống dò tìm tài khoản
const sendAuthError = async (res) => {
    await sleep(1000 + Math.random() * 1000); // Giảm Timing Attack
    return res.status(401).json({ 
        error: "Thông tin đăng nhập không chính xác hoặc tài khoản đã bị tạm khóa." 
    });
};

/* -------------------- MAIN LOGIN ROUTE -------------------- */
router.post('/login', async (req, res) => {
    const { username: identifier, password, rememberMe } = req.body;

    try {
        // 1. Kiểm tra đầu vào
        if (!identifier || !password) return sendAuthError(res);

        const cleanId = identifier.trim().toLowerCase();
        
        // 2. Tra cứu UID qua Index
        const [uIndex, eIndex] = await Promise.all([
            readJSON(USERNAME_INDEX_PATH),
            readJSON(EMAIL_INDEX_PATH)
        ]);
        const uid = uIndex[cleanId] || eIndex[cleanId];

        if (!uid) {
            await logEvent('UNKNOWN', 'AUTH_FAILED_NOT_FOUND', req, `Id: ${cleanId}`);
            return sendAuthError(res);
        }

        // 3. Đọc dữ liệu Auth & Profile
        const authPath = path.join(ACCOUNTS_DIR, uid, 'auth.json');
        const profilePath = path.join(ACCOUNTS_DIR, uid, 'profile.json');
        
        let [authData, profileData] = await Promise.all([
            readJSON(authPath),
            readJSON(profilePath)
        ]);

        // 4. Kiểm tra Account Lock (Brute Force Protection)
        const now = Date.now();
        if (authData.lock_until && authData.lock_until > now) {
            await logEvent(uid, 'AUTH_LOCKED', req);
            return res.status(423).json({ error: "Tài khoản bị khóa tạm thời do nhập sai quá nhiều lần. Thử lại sau." });
        }

        // 5. So khớp mật khẩu
        const isMatch = await bcrypt.compare(password, authData.password_hash);

        if (!isMatch) {
            // Tăng số lần sai
            authData.failed_attempts = (authData.failed_attempts || 0) + 1;
            if (authData.failed_attempts >= MAX_FAILED_ATTEMPTS) {
                authData.lock_until = now + LOCK_TIME;
                authData.failed_attempts = 0;
            }
            await writeJSONAtomic(authPath, authData);
            await logEvent(uid, 'AUTH_FAILED_WRONG_PASS', req);
            return sendAuthError(res);
        }

        // 6. XỬ LÝ ĐĂNG NHẬP THÀNH CÔNG
        // Reset chỉ số thất bại & cập nhật thông tin đăng nhập cuối
        authData.failed_attempts = 0;
        authData.lock_until = null;
        authData.last_login = now;
        authData.last_ip = req.ip;

        await Promise.all([
            writeJSONAtomic(authPath, authData),
            logEvent(uid, 'SUCCESS', req)
        ]);

        // 7. Tạo JWT & Thiết lập phiên
        const jti = uuidv4();
        const expiresIn = rememberMe ? '30d' : '4h';
        const maxAge = rememberMe ? 30*24*60*60*1000 : 4*60*60*1000;

        const token = jwt.sign(
            { uid, role: authData.role || 'user', username: profileData.username, jti },
            JWT_SECRET,
            { expiresIn }
        );

        // Cookie chứa Token (Bảo mật HttpOnly)
        res.cookie('access_token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'Lax', // Cho phép chuyển hướng từ trang login
            maxAge: maxAge
        });

        // 8. Trả về thông tin cho Frontend
        return res.status(200).json({
            success: true,
            message: "Đăng nhập thành công",
            user: {
                uid: uid,
                username: profileData.username,
                role: profileData.role
            }
        });

    } catch (err) {
        console.error("CRITICAL LOGIN ERROR:", err);
        return res.status(500).json({ error: "Lỗi máy chủ nội bộ." });
    }
});

module.exports = router;