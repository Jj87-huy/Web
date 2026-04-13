/* ========== VIDEO BACKGROUND LOGIC ========== */
const vei_max = 3;
const vei_now = 1;

// Thay đổi trong file JS của bạn
const API_BASE_URL = 'http://localhost:3000'; // Đổi port cho đúng với Backend

const bgVideo = document.getElementById('bgVideo');
const bgOverlay = document.getElementById('bgOverlay');

function disableVideo() {
    bgVideo.classList.add('video-hidden');
    bgOverlay.classList.add('video-hidden');
}

// Check threshold
if (vei_now >= vei_max) {
    disableVideo();
}

// Fallback if video fails to load
bgVideo.addEventListener('error', disableVideo);
bgVideo.querySelector('source').addEventListener('error', disableVideo);

/* ========== THEME TOGGLE ========== */
const themeToggle = document.getElementById('themeToggle');
themeToggle.addEventListener('click', () => {
    const html = document.documentElement;
    const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
});

/* ========== TABS ========== */
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('panel-' + btn.dataset.tab).classList.add('active');
    });
});

/* ========== FOCUS LABEL HIGHLIGHT ========== */
document.querySelectorAll('.form-input').forEach(input => {
    input.addEventListener('focus', () => input.closest('.form-group').classList.add('focused'));
    input.addEventListener('blur', () => input.closest('.form-group').classList.remove('focused'));
});

/* ========== PASSWORD TOGGLE ========== */
document.querySelectorAll('.pw-toggle').forEach(btn => {
    btn.addEventListener('click', () => {
        const target = document.getElementById(btn.dataset.target);
        const isPassword = target.type === 'password';
        target.type = isPassword ? 'text' : 'password';
        const icon = btn.querySelector('i');
        icon.setAttribute('data-lucide', isPassword ? 'eye-off' : 'eye');
        lucide.createIcons();
    });
});

const strengthColors = ['#EF4444', '#F59E0B', '#3B82F6', '#22C55E'];
const strengthLabels = ['Yếu', 'Trung bình', 'Khá', 'Mạnh'];

document.getElementById('regPw').addEventListener('input', function() {
    const val = this.value;
    
    // 1. Định nghĩa các tiêu chí (Rules)
    const requirements = [
        val.length >= 8,                      // Ít nhất 8 ký tự (Chuẩn bảo mật mới)
        /[A-Z]/.test(val) && /[a-z]/.test(val), // Cả hoa và thường
        /\d/.test(val),                       // Có số
        /[^A-Za-z0-9]/.test(val)              // Có ký tự đặc biệt
    ];

    // 2. Tính điểm dựa trên số tiêu chí thỏa mãn
    const score = requirements.filter(req => req).length;
    
    // 3. Cập nhật giao diện UI
    const segments = [0, 1, 2, 3];
    segments.forEach(i => {
        const segmentEl = document.getElementById('seg' + i);
        if (val.length === 0) {
            segmentEl.style.background = 'var(--strength-bg)';
        } else {
            // Hiển thị màu theo score hiện tại nếu i < score
            segmentEl.style.background = i < score ? strengthColors[score - 1] : 'var(--strength-bg)';
        }
    });

    // 4. Cập nhật Label
    const labelEl = document.getElementById('strengthLabel');
    if (val) {
        const index = Math.max(0, score - 1);
        labelEl.textContent = strengthLabels[index];
        labelEl.style.color = strengthColors[index];
    } else {
        labelEl.textContent = '';
    }

    if (typeof checkMatch === "function") checkMatch();
});

/* ========== CONFIRM MATCH ========== */
function checkMatch() {
    const pw = document.getElementById('regPw').value;
    const confirm = document.getElementById('regPwConfirm').value;
    const msg = document.getElementById('matchMsg');
    if (!confirm) {
        msg.textContent = '';
        return;
    }
    if (pw === confirm) {
        msg.textContent = 'Mật khẩu trùng khớp ✓';
        msg.className = 'match-msg ok';
    } else {
        msg.textContent = 'Mật khẩu không trùng khớp';
        msg.className = 'match-msg no';
    }
}
document.getElementById('regPwConfirm').addEventListener('input', checkMatch);

/* ========== FORM SUBMISSIONS (UPDATED WITH API) ========== */

// Quản lý trạng thái nút bấm (loading)
function setSubmitting(formId, isSubmitting) {
    const form = document.getElementById(formId);
    const btn = form.querySelector('button[type="submit"]');
    if (!btn) return;

    if (isSubmitting) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Đang xử lý...';
    } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText || 'Gửi';
    }
}

/* ========== HELPERS ========== */
const getCookie = (name) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return decodeURIComponent(parts.pop().split(';').shift());
    return null;
};

/* ========== LOGIN FORM SUBMISSION ========== */
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const username = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPw').value;
    const rememberMe = document.getElementById('loginRemember').checked;
    
    // Lấy CSRF Token từ Cookie
    const csrfToken = getCookie('XSRF-TOKEN');

    if (!username || !password) {
        showToast('Vui lòng nhập đầy đủ thông tin', 'warning');
        return;
    }

    if (!csrfToken) {
        showToast('Phiên làm việc lỗi. Vui lòng làm mới trang (F5)', 'error');
        return;
    }

    try {
        setSubmitting('loginForm', true);
        
        const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'x-xsrf-token': getCookie('XSRF-TOKEN') // Gửi kèm Header để Backend verify
            },
            credentials: 'include', // Bắt buộc để nhận HttpOnly Cookie
            body: JSON.stringify({ 
                username, 
                password, 
                rememberMe 
            })
        });

        const data = await response.json();

        if (response.ok) {
            showToast(data.message || 'Đăng nhập thành công!', 'success');
            
            // Lưu thông tin cơ bản vào localStorage để hiển thị nhanh ở trang sau
            if (data.user) {
                localStorage.setItem('user_profile', JSON.stringify(data.user));
            }

            // Chuyển hướng sau 1.2 giây
            setTimeout(() => {
                window.location.href = '/'; 
            }, 1200);

        } else {
            // Xử lý các mã lỗi đặc biệt từ Backend nâng cấp
            if (response.status === 423) {
                showToast('Tài khoản đã bị khóa tạm thời. Thử lại sau 15p.', 'error');
            } else if (response.status === 403) {
                showToast('Lỗi bảo mật (CSRF). Vui lòng F5 trang.', 'error');
            } else {
                showToast(data.error || 'Thông tin đăng nhập không đúng.', 'error');
            }
        }
    } catch (err) {
        showToast('Không thể kết nối tới máy chủ', 'error');
    } finally {
        setSubmitting('loginForm', false);
    }
});

/* ========== REGISTER FORM SUBMISSION ========== */
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const user = document.getElementById('regUser').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const pw = document.getElementById('regPw').value;
    const pw2 = document.getElementById('regPwConfirm').value;
    const terms = document.getElementById('termsCheck').checked;
    const csrfToken = getCookie('XSRF-TOKEN');

    if (!user || !email || !pw || !pw2) {
        showToast('Vui lòng điền đủ thông tin', 'warning');
        return;
    }

    if (pw !== pw2) {
        showToast('Mật khẩu không khớp', 'error');
        return;
    }

    if (!terms) {
        showToast('Bạn phải đồng ý với điều khoản', 'warning');
        return;
    }

    try {
        setSubmitting('registerForm', true);
        
        const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'x-xsrf-token': getCookie('XSRF-TOKEN') },
            credentials: 'include',
            body: JSON.stringify({ 
                username: user, 
                email, 
                password: pw,
                confirmPassword: pw2
            })
        });

        const data = await response.json();

        if (response.ok) {
            showToast(data.message || 'Đăng ký thành công!', 'success');
            e.target.reset();
            
            // Tự động chuyển về tab Login
            setTimeout(() => {
                const loginTabBtn = document.querySelector('.tab-btn[data-tab="login"]');
                if (loginTabBtn) loginTabBtn.click();
            }, 2000);
        } else {
            // Backend trả về các lỗi như: "Email đã tồn tại", "Username quá ngắn"...
            showToast(data.error || 'Đăng ký thất bại', 'error');
        }
    } catch (err) {
        showToast('Lỗi kết nối máy chủ', 'error');
    } finally {
        setSubmitting('registerForm', false);
    }
});

/* ========== TOAST SYSTEM ========== */
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const icons = {
        success: 'check-circle',
        error: 'x-circle',
        info: 'info',
        warning: 'alert-triangle'
    };
    const el = document.createElement('div');
    el.className = 'toast-item ' + type;
    el.innerHTML = '<i data-lucide="' + icons[type] + '" class="toast-icon"></i><span>' + message + '</span>';
    container.appendChild(el);
    lucide.createIcons();
    setTimeout(() => {
        el.style.animation = 'toastOut 0.3s ease-in forwards';
        el.addEventListener('animationend', () => el.remove());
    }, 3000);
}

/* ========== ELEMENT SDK ========== */
const defaultConfig = {
    background_color: '#F0F2F5',
    card_color: '#FFFFFF',
    accent_color: '#4F6EF7',
    text_color: '#1A1D26',
    input_bg_color: '#F5F6F8',
    font_family: 'Plus Jakarta Sans',
    font_size: 14,
    login_title: 'Chào mừng trở lại',
    login_subtitle: 'Đăng nhập để tiếp tục',
    register_title: 'Tạo tài khoản mới',
    register_subtitle: 'Tham gia cùng chúng tôi hôm nay'
};

function applyConfig(config) {
    const c = {
        ...defaultConfig,
        ...config
    };
    const lt = document.getElementById('loginTitle');
    const ls = document.getElementById('loginSubtitle');
    const rt = document.getElementById('registerTitle');
    const rs = document.getElementById('registerSubtitle');
    if (lt) lt.textContent = c.login_title;
    if (ls) ls.textContent = c.login_subtitle;
    if (rt) rt.textContent = c.register_title;
    if (rs) rs.textContent = c.register_subtitle;

    document.documentElement.style.setProperty('--bg-primary', c.background_color);
    document.documentElement.style.setProperty('--bg-card', c.card_color);
    document.documentElement.style.setProperty('--accent', c.accent_color);
    document.documentElement.style.setProperty('--accent-hover', c.accent_color);
    document.documentElement.style.setProperty('--text-primary', c.text_color);
    document.documentElement.style.setProperty('--bg-input', c.input_bg_color);

    const font = c.font_family || defaultConfig.font_family;
    const stack = font + ', sans-serif';
    document.body.style.fontFamily = stack;

    const base = c.font_size || defaultConfig.font_size;
    document.querySelectorAll('.form-input').forEach(el => el.style.fontSize = base + 'px');
    if (lt) lt.style.fontSize = (base * 1.57) + 'px';
    if (ls) ls.style.fontSize = base + 'px';
    if (rt) rt.style.fontSize = (base * 1.57) + 'px';
    if (rs) rs.style.fontSize = base + 'px';
}

if (window.elementSdk) {
    window.elementSdk.init({
        defaultConfig,
        onConfigChange: async (config) => applyConfig(config),
        mapToCapabilities: (config) => {
            const c = {
                ...defaultConfig,
                ...config
            };

            function mut(key) {
                return {
                    get: () => c[key] || defaultConfig[key],
                    set: (v) => {
                        c[key] = v;
                        window.elementSdk.setConfig({
                            [key]: v
                        });
                    }
                };
            }
            return {
                recolorables: [
                    mut('background_color'),
                    mut('card_color'),
                    mut('text_color'),
                    mut('accent_color'),
                    mut('input_bg_color')
                ],
                borderables: [],
                fontEditable: mut('font_family'),
                fontSizeable: {
                    get: () => c.font_size || defaultConfig.font_size,
                    set: (v) => {
                        c.font_size = v;
                        window.elementSdk.setConfig({
                            font_size: v
                        });
                    }
                }
            };
        },
        mapToEditPanelValues: (config) => {
            const c = {
                ...defaultConfig,
                ...config
            };
            return new Map([
                ['login_title', c.login_title],
                ['login_subtitle', c.login_subtitle],
                ['register_title', c.register_title],
                ['register_subtitle', c.register_subtitle]
            ]);
        }
    });
}

/* Init icons */
lucide.createIcons();