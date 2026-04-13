const express = require('express');
const fs = require('fs/promises');
const path = require('path');
const bcrypt = require('bcrypt');
const validator = require('validator');
const xss = require('xss');

const router = express.Router();

/* -------------------- CONFIGURATION -------------------- */
const DATA_DIR = path.join(process.cwd(), 'data', 'auth');
const ACCOUNTS_DIR = path.join(DATA_DIR, 'accounts');
const USERNAME_INDEX_PATH = path.join(DATA_DIR, 'username_index.json');
const EMAIL_INDEX_PATH = path.join(DATA_DIR, 'email_index.json');
const LOCK_FILE = path.join(DATA_DIR, '.register.lock');

const SALT_ROUNDS = 12;

/* -------------------- INITIALIZATION -------------------- */
// Đảm bảo các thư mục cần thiết tồn tại khi khởi động router
(async () => {
    try {
        await fs.mkdir(ACCOUNTS_DIR, { recursive: true });
        // Tạo file index trống nếu chưa có
        for (const p of [USERNAME_INDEX_PATH, EMAIL_INDEX_PATH]) {
            try { await fs.access(p); } 
            catch { await fs.writeFile(p, JSON.stringify({})); }
        }
    } catch (err) {
        console.error("❌ Không thể khởi tạo hệ thống dữ liệu:", err);
    }
})();

/* -------------------- UTILS -------------------- */

/**
 * Cơ chế khóa file (Mutex) để tránh xung đột dữ liệu khi nhiều người đăng ký cùng lúc
 */
async function acquireLock() {
    const timeout = 5000;
    const start = Date.now();
    while (Date.now() - start < timeout) {
        try {
            return await fs.open(LOCK_FILE, 'wx'); // 'wx': Ghi nếu file chưa tồn tại, lỗi nếu đã có
        } catch {
            await new Promise(r => setTimeout(r, 100)); // Đợi 100ms rồi thử lại
        }
    }
    throw { status: 503, message: 'Hệ thống đang bận (Lock Timeout), vui lòng thử lại sau.' };
}

async function releaseLock(fd) {
    try {
        if (fd) await fd.close();
        await fs.unlink(LOCK_FILE);
    } catch (e) { /* Ignore error */ }
}

/**
 * Ghi file an toàn: Ghi vào file tạm trước, sau đó mới đổi tên để tránh mất dữ liệu nếu sập nguồn
 */
async function writeJSONAtomic(file, data) {
    const tmp = `${file}.${Date.now()}.${Math.random().toString(36).slice(2)}.tmp`;
    await fs.writeFile(tmp, JSON.stringify(data, null, 2));
    await fs.rename(tmp, file);
}

async function generateUniqueUID(accountsDir) {
    let isUnique = false;
    let newUid = "";

    while (!isUnique) {
        // 1. Tạo chuỗi số: Timestamp (13 số) + Random (4 số)
        newUid = Date.now().toString() + Math.floor(1000 + Math.random() * 9000).toString();
        
        // 2. Kiểm tra xem thư mục mang tên UID này đã tồn tại chưa
        const userFolderPath = path.join(accountsDir, newUid);
        try {
            await fs.access(userFolderPath);
            // Nếu không lỗi -> Thư mục đã tồn tại -> Tiếp tục vòng lặp để tạo lại
            console.warn(`[UID Conflict] ${newUid} đã tồn tại, đang thử lại...`);
        } catch (e) {
            // Nếu lỗi -> Thư mục chưa có -> UID này dùng được!
            isUnique = true;
        }
    }
    return newUid;
}

/* -------------------- MAIN ROUTE -------------------- */

router.post('/register', async (req, res) => {
    let lockFd = null;
    let createdUserDir = null;

    try {
        let { username, email, password, confirmPassword } = req.body;

        // 1. Validation nâng cao
        if (!username || !email || !password || !confirmPassword) {
            return res.status(400).json({ error: 'Vui lòng điền đầy đủ tất cả các trường' });
        }

        username = xss(username.trim());
        email = email.trim().toLowerCase();
        const usernameLow = username.toLowerCase();

        if (username.length < 3 || username.length > 20) {
            return res.status(400).json({ error: 'Tên đăng nhập phải từ 3-20 ký tự' });
        }

        if (!validator.isEmail(email)) {
            return res.status(400).json({ error: 'Định dạng email không hợp lệ' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ error: 'Mật khẩu xác nhận không khớp' });
        }

        if (!validator.isStrongPassword(password, { minLength: 8, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 })) {
            return res.status(400).json({ error: 'Mật khẩu quá yếu (cần 8 ký tự, đủ chữ hoa, số và ký hiệu)' });
        }

        // 2. Kiểm tra nhanh (Sơ bộ) trước khi chiếm Lock để giảm tải
        const [usernameIndex, emailIndex] = await Promise.all([
            fs.readFile(USERNAME_INDEX_PATH, 'utf8').then(JSON.parse).catch(() => ({})),
            fs.readFile(EMAIL_INDEX_PATH, 'utf8').then(JSON.parse).catch(() => ({}))
        ]);

        if (usernameIndex[usernameLow]) return res.status(409).json({ error: 'Tên đăng nhập đã tồn tại' });
        if (emailIndex[email]) return res.status(409).json({ error: 'Email đã được đăng ký' });

        // 3. Hashing mật khẩu (Thực hiện trước khi lock để giảm thời gian giữ lock)
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

        // 4. CHIẾM LOCK & GHI DỮ LIỆU (Critical Section)
        lockFd = await acquireLock();

        // Đọc lại lần cuối bên trong Lock để đảm bảo không ai "chen ngang"
        const finalUserIndex = JSON.parse(await fs.readFile(USERNAME_INDEX_PATH, 'utf8'));
        const finalEmailIndex = JSON.parse(await fs.readFile(EMAIL_INDEX_PATH, 'utf8'));

        if (finalUserIndex[usernameLow] || finalEmailIndex[email]) {
            throw { status: 409, message: 'Dữ liệu vừa bị thay đổi bởi người dùng khác, vui lòng thử lại' };
        }

        // 5. TẠO UID VÀ ĐỐI TƯỢNG DỮ LIỆU
        const uid = await generateUniqueUID(ACCOUNTS_DIR);
        createdUserDir = path.join(ACCOUNTS_DIR, uid);
        await fs.mkdir(createdUserDir, { recursive: true });

        const profile = { 
            uid, username, 
            name: username, 
            role: ["user"], status: "active",
            avatar: null, bio: "",
            social: { facebook: null, github: null },
            created_at: Date.now() 
        };
        
        const auth = { 
            uid, email, password_hash, 
            email_verified: false,
            link_accounts: { google: null, discord: null },
            created_at: Date.now() 
        };

        // 6. CẬP NHẬT INDEX VÀ LƯU FILE
        finalUserIndex[usernameLow] = uid;
        finalEmailIndex[email] = uid;

        await Promise.all([
            fs.writeFile(path.join(createdUserDir, 'profile.json'), JSON.stringify(profile, null, 2)),
            fs.writeFile(path.join(createdUserDir, 'auth.json'), JSON.stringify(auth, null, 2)),
            writeJSONAtomic(USERNAME_INDEX_PATH, finalUserIndex),
            writeJSONAtomic(EMAIL_INDEX_PATH, finalEmailIndex)
        ]);

        return res.status(201).json({ 
            success: true, 
            message: 'Đăng ký thành công! Chào mừng bạn gia nhập.' 
        });

    } catch (err) {
        // Rollback: Xóa thư mục user nếu việc ghi file bị lỗi nửa chừng
        if (createdUserDir) {
            await fs.rm(createdUserDir, { recursive: true, force: true }).catch(() => {});
        }
        console.error('CRITICAL REGISTER ERROR:', err);
        return res.status(err.status || 500).json({ error: err.message || 'Lỗi hệ thống' });
    } finally {
        if (lockFd) await releaseLock(lockFd);
    }
});

module.exports = router;