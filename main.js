const path = require('path');
const fs = require('fs');
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const cookieParser = require("cookie-parser");
const helmet = require('helmet');
const csrf = require('csrf');

const tokens = new csrf();
const app = express();

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SUPER_SECRET_KEY || 'your-fallback-secret';

const htmlDir = path.join(process.cwd(), 'public');
const authDir = path.join(process.cwd(), 'routers', 'Auth');

// ============================================
// CẤU HÌNH HỆ THỐNG
// ============================================
app.set('trust proxy', true);

// ============================================
// MIDDLEWARE CƠ BẢN (Thứ tự rất quan trọng)
// ============================================
app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
    origin: `http://127.0.0.1:${PORT}`,
    credentials: true // Bắt buộc để gửi/nhận cookie
}));

// Phục vụ file tĩnh TRƯỚC CSRF để không tạo Token vô ích cho ảnh/css/js
app.use('/public', express.static(path.join(process.cwd(), 'public')));
app.use('/src', express.static(path.join(process.cwd(), 'src')));

// Parse Cookie và Body trước khi vào CSRF
app.use(cookieParser(SECRET_KEY));
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: true }));

// ============================================
// MIDDLEWARE CSRF NÂNG CẤP
// ============================================
const csrfProtection = (req, res, next) => {
    // 1. Lấy secret từ signed cookie
    let secret = req.signedCookies._csrfSecret;
    
    // Nếu chưa có secret (người dùng mới), tạo và set cookie ngay
    if (!secret) {
        secret = tokens.secretSync();
        res.cookie('_csrfSecret', secret, {
            signed: true,
            httpOnly: true,
            sameSite: 'lax',
            secure: process.env.NODE_ENV === 'production',
            path: '/'
        });
        // Gán tạm vào req để dùng ngay trong lượt request này nếu cần
        req.csrfSecret = secret;
    }

    // 2. Kiểm tra Token cho các phương thức thay đổi dữ liệu
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
        // Lấy token từ Header (Ưu tiên) hoặc Body
        const clientToken = req.headers['x-xsrf-token'] || (req.body && req.body._csrf);
        
        // Log debug khi gặp lỗi (Xóa khi deploy)
        if (!tokens.verify(secret, clientToken)) {
            console.error(`[CSRF] Thất bại - Method: ${req.method} | URL: ${req.url}`);
            console.error(`[CSRF] Secret hiện tại: ${secret ? 'Đã có' : 'Trống'}`);
            console.error(`[CSRF] Token nhận được: ${clientToken ? 'Đã có' : 'Trống'}`);
            return res.status(403).json({ error: "Phiên làm việc lỗi (CSRF), vui lòng tải lại trang." });
        }
        return next();
    }

    // 3. Đối với request GET: Tạo token mới dựa trên secret
    // Lưu ý: tokens.create(secret) luôn tạo ra token khác nhau nhưng cùng gốc secret
    const token = tokens.create(secret);
    
    // Gửi token qua cookie thường (JavaScript có thể đọc được)
    res.cookie('XSRF-TOKEN', token, {
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        path: '/'
    });

    next();
};

// Áp dụng CSRF sau khi đã load static files
app.use(csrfProtection);

// ============================================
// ROUTES
// ============================================
app.use('/api/auth', require(path.join(authDir, 'login.js')));
app.use('/api/auth', require(path.join(authDir, 'register.js')));
app.use('/api/auth', require(path.join(authDir, 'logout.js')));
app.use('/api/auth', require(path.join(authDir, 'profile.js')));

app.get('/auth', (req, res) => {
    res.sendFile(path.join(htmlDir, 'auth.html'));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(htmlDir, 'home.html'))
})

app.listen(PORT, () => {
    console.log(`\n🚀 Server running at http://127.0.0.1:${PORT}`);
});