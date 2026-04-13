const jwt = require('jsonwebtoken');
// Đảm bảo dotenv đã được config ở file main (server.js) để lấy được KEY này
const JWT_SECRET = process.env.SUPER_SECRET_KEY;

const authMiddleware = (req, res, next) => {
    const token = req.cookies['access_token'];

    if (!token) {
        return res.status(401).json({ 
            error: "Yêu cầu đăng nhập để truy cập tính năng này." 
        });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        req.user = {
            uid: decoded.uid,
            role: decoded.role,
            username: decoded.username
        };

        next(); 
    } catch (err) {
        res.clearCookie('access_token');
        return res.status(401).json({ error: "Phiên làm việc đã hết hạn." });
    }
};

// EXPORT TRỰC TIẾP HÀM (Dạng CommonJS chuẩn)
module.exports = authMiddleware;