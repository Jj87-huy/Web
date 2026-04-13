// ============================================
// Configuration & State Management
// ============================================
const defaultConfig = {
    user_name: 'Nguyễn Văn A',
    user_email: 'user@example.com',
    primary_color: '#1a1a2e',
    accent_color: '#00d9ff',
    text_color: '#eaeaea'
};
const API_BASE_URL = 'http://localhost:3000'; 

let config = {
    ...defaultConfig
};

// ============================================
// Data
// ============================================
const notifications = [{
        id: 1,
        title: 'Cập nhật hệ thống',
        content: 'Hệ thống đã được nâng cấp lên phiên bản mới với nhiều tính năng hấp dẫn.',
        time: '2 phút trước',
        unread: true
    },
    {
        id: 2,
        title: 'Tin nhắn mới',
        content: 'Bạn có một tin nhắn mới từ Admin. Hãy kiểm tra ngay!',
        time: '1 giờ trước',
        unread: true
    },
    {
        id: 3,
        title: 'Bảo mật',
        content: 'Đăng nhập mới được phát hiện từ thiết bị lạ. Vui lòng xác nhận.',
        time: '3 giờ trước',
        unread: false
    },
    {
        id: 4,
        title: 'Khuyến mãi',
        content: 'Ưu đãi đặc biệt chỉ dành riêng cho bạn. Giảm 50% tất cả dịch vụ!',
        time: '1 ngày trước',
        unread: false
    },
    {
        id: 5,
        title: 'Cộng đồng',
        content: 'Bài viết của bạn đã nhận được 100 lượt thích. Tuyệt vời!',
        time: '10 ngày trước',
        unread: false
    }
];

const avatarMenuItems = [{
        id: 'profile',
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
        label: 'Hồ sơ cá nhân'
    },
    {
        id: 'settings',
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
        label: 'Cài đặt'
    },
    {
        id: 'help',
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        label: 'Trợ giúp'
    }
];

const sideMenuData = [{
        category: 'Trang chủ',
        items: [{
                id: 'home',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
                label: 'Trang chủ',
                active: true
            },
            {
                id: 'dashboard',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>',
                label: 'Bảng điều khiển'
            }
        ]
    },
    {
        category: 'Nội dung',
        items: [{
                id: 'articles',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>',
                label: 'Bài viết'
            },
            {
                id: 'media',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>',
                label: 'Thư viện'
            },
            {
                id: 'messages',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
                label: 'Tin nhắn'
            }
        ]
    },
    {
        category: 'Quản lý',
        items: [{
                id: 'users',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
                label: 'Người dùng'
            },
            {
                id: 'analytics',
                icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>',
                label: 'Thống kê'
            }
        ]
    }
];

const bottomBarItems = [{
        id: 'home',
        icon: '<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
        label: 'Trang chủ',
        active: true
    }
];

// ============================================
// DOM Elements
// ============================================
const elements = {
    menuBtn: document.getElementById('menuBtn'),
    logoBtn: document.getElementById('logoBtn'),
    searchBtn: document.getElementById('searchBtn'),
    searchContainer: document.getElementById('searchContainer'),
    searchClose: document.getElementById('searchClose'),
    searchInput: document.getElementById('searchInput'),
    headerRight: document.getElementById('headerRight'),
    notificationBtn: document.getElementById('notificationBtn'),
    notificationBadge: document.getElementById('notificationBadge'),
    notificationDropdown: document.getElementById('notificationDropdown'),
    notificationList: document.getElementById('notificationList'),
    avatarBtn: document.getElementById('avatarBtn'),
    avatarDropdown: document.getElementById('avatarDropdown'),
    avatarMenu: document.getElementById('avatarMenu'),
    displayName: document.getElementById('displayName'),
    displayEmail: document.getElementById('displayEmail'),
    sideMenu: document.getElementById('sideMenu'),
    sideMenuOverlay: document.getElementById('sideMenuOverlay'),
    bottomBar: document.getElementById('bottomBar')
};

// ============================================
// State
// ============================================
let state = {
    menuOpen: false,
    searchOpen: false,
    avatarDropdownOpen: false,
    notificationDropdownOpen: false
};

// ============================================
// Render Functions
// ============================================
function renderNotifications() {
    const hasUnread = notifications.some(n => n.unread);
    elements.notificationBadge.style.display = hasUnread ? 'block' : 'none';

    elements.notificationList.innerHTML = notifications.map(n => `
<div class="notification-item ${n.unread ? 'unread' : ''}" data-id="${n.id}">
    <div class="notification-title">${n.title}</div>
    <div class="notification-content">${n.content}</div>
    <div class="notification-time">${n.time}</div>
</div>
`).join('');
}

function renderAvatarMenu() {
    elements.avatarMenu.innerHTML = avatarMenuItems.map(item => `
<div class="dropdown-menu-item" data-id="${item.id}">
    ${item.icon}
    <span>${item.label}</span>
</div>
`).join('');
}

function renderSideMenu() {
    elements.sideMenu.innerHTML = sideMenuData.map(section => `
<div class="menu-category">
    <span class="menu-category-title">${section.category}</span>
    <div class="menu-category-line"></div>
</div>
${section.items.map(item => `
    <div class="menu-item ${item.active ? 'active' : ''}" data-id="${item.id}">
    ${item.icon}
    <span>${item.label}</span>
    </div>
`).join('')}
`).join('');
}

function renderBottomBar() {
    elements.bottomBar.innerHTML = bottomBarItems.map(item => `
<div class="bottom-bar-item ${item.active ? 'active' : ''}" data-id="${item.id}">
    ${item.icon}
    <span>${item.label}</span>
</div>
`).join('');
}

// ============================================
// UI Functions
// ============================================
function closeAllDropdowns() {
    if (state.avatarDropdownOpen) toggleAvatarDropdown();
    if (state.notificationDropdownOpen) toggleNotificationDropdown();
    if (state.searchOpen) toggleSearch();
}

function toggleMenu() {
    state.menuOpen = !state.menuOpen;
    elements.menuBtn.classList.toggle('active', state.menuOpen);
    elements.sideMenu.classList.toggle('active', state.menuOpen);
    elements.sideMenuOverlay.classList.toggle('active', state.menuOpen);
}

function toggleSearch() {
    state.searchOpen = !state.searchOpen;
    elements.searchContainer.classList.toggle('active', state.searchOpen);
    elements.headerRight.classList.toggle('search-active', state.searchOpen);
    document.querySelector('.header-left').classList.toggle('search-active', state.searchOpen);

    if (state.searchOpen) {
        setTimeout(() => elements.searchInput.focus(), 300);
    } else {
        elements.searchInput.value = '';
    }
}

function toggleAvatarDropdown() {
    if (state.notificationDropdownOpen) toggleNotificationDropdown();
    state.avatarDropdownOpen = !state.avatarDropdownOpen;
    elements.avatarDropdown.classList.toggle('active', state.avatarDropdownOpen);
}

function toggleNotificationDropdown() {
    if (state.avatarDropdownOpen) toggleAvatarDropdown();
    state.notificationDropdownOpen = !state.notificationDropdownOpen;
    elements.notificationDropdown.classList.toggle('active', state.notificationDropdownOpen);
}

function updateUserInfo() {
    // Ưu tiên: Dữ liệu từ config (đã fetch) > Dữ liệu mặc định
    elements.displayName.textContent = config.name || defaultConfig.user_name;
    elements.displayEmail.textContent = config.email || defaultConfig.user_email;
    
    // Nếu bạn có logo hoặc chỗ nào cần hiển thị tên viết tắt (Avatar fallback)
    const avatarFallback = document.getElementById('avatarFallback');
    if (avatarFallback && config.name) {
        avatarFallback.textContent = config.name.charAt(0).toUpperCase();
    }
}

// ============================================
// Event Listeners
// ============================================
function initEventListeners() {
    // Menu
    elements.menuBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        closeAllDropdowns();
        toggleMenu();
    });

    elements.sideMenuOverlay.addEventListener('click', toggleMenu);

    // Logo / Home
    elements.logoBtn.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });

    // Search
    elements.searchBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        if (state.avatarDropdownOpen) toggleAvatarDropdown();
        if (state.notificationDropdownOpen) toggleNotificationDropdown();
        toggleSearch();
    });

    elements.searchClose.addEventListener('click', toggleSearch);

    // Avatar Dropdown
    elements.avatarBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleAvatarDropdown();
    });

    // Notification Dropdown
    elements.notificationBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleNotificationDropdown();
    });

    // Close dropdowns on outside click
    document.addEventListener('click', (e) => {
        if (!elements.avatarDropdown.contains(e.target) && !elements.avatarBtn.contains(e.target)) {
            if (state.avatarDropdownOpen) toggleAvatarDropdown();
        }
        if (!elements.notificationDropdown.contains(e.target) && !elements.notificationBtn.contains(e.target)) {
            if (state.notificationDropdownOpen) toggleNotificationDropdown();
        }
        if (!elements.searchContainer.contains(e.target) && !elements.searchBtn.contains(e.target)) {
            if (state.searchOpen) toggleSearch();
        }
    });

    // Prevent dropdown close when clicking inside
    elements.avatarDropdown.addEventListener('click', (e) => e.stopPropagation());
    elements.notificationDropdown.addEventListener('click', (e) => e.stopPropagation());

    // Bottom Bar
    elements.bottomBar.addEventListener('click', (e) => {
        const item = e.target.closest('.bottom-bar-item');
        if (item) {
            document.querySelectorAll('.bottom-bar-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
        }
    });

    // Side Menu Items
    elements.sideMenu.addEventListener('click', (e) => {
        const item = e.target.closest('.menu-item');
        if (item) {
            document.querySelectorAll('.menu-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            toggleMenu();
        }
    });

    // View all notifications
    document.getElementById('viewAllNotifications').addEventListener('click', () => {
        toggleNotificationDropdown();
    });

    // Logout
    document.getElementById('logoutBtn').addEventListener('click', () => {
        toggleAvatarDropdown();
    });

    // Escape key to close
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            if (state.searchOpen) toggleSearch();
            if (state.avatarDropdownOpen) toggleAvatarDropdown();
            if (state.notificationDropdownOpen) toggleNotificationDropdown();
            if (state.menuOpen) toggleMenu();
        }
    });
}

// ============================================
// Element SDK Integration
// ============================================
async function onConfigChange(newConfig) {
    config = {
        ...defaultConfig,
        ...newConfig
    };
    updateUserInfo();
}

async function fetchUserProfile() {
    const token = localStorage.getItem('access_token');

    const res = await fetch(`${API_BASE_URL}/api/auth/me`, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });

    const data = await res.json();
    console.log(data);
}

function mapToCapabilities(cfg) {
    return {
        recolorables: [{
                get: () => cfg.primary_color || defaultConfig.primary_color,
                set: (value) => {
                    cfg.primary_color = value;
                    window.elementSdk?.setConfig({
                        primary_color: value
                    });
                }
            },
            {
                get: () => cfg.accent_color || defaultConfig.accent_color,
                set: (value) => {
                    cfg.accent_color = value;
                    window.elementSdk?.setConfig({
                        accent_color: value
                    });
                }
            },
            {
                get: () => cfg.text_color || defaultConfig.text_color,
                set: (value) => {
                    cfg.text_color = value;
                    window.elementSdk?.setConfig({
                        text_color: value
                    });
                }
            }
        ],
        borderables: [],
        fontEditable: undefined,
        fontSizeable: undefined
    };
}

function mapToEditPanelValues(cfg) {
    return new Map([
        ['user_name', cfg.user_name || defaultConfig.user_name],
        ['user_email', cfg.user_email || defaultConfig.user_email]
    ]);
}

// ============================================
// Initialize
// ============================================
async function init() {
    renderNotifications();
    renderAvatarMenu();
    renderSideMenu();
    renderBottomBar();
    initEventListeners();

    // 1. Kiểm tra UID từ localStorage (giả sử bạn lưu uid khi đăng ký thành công)
    const savedUid = localStorage.getItem('access_token') ? JSON.parse(atob(localStorage.getItem('access_token').split('.')[1])).uid : null;
    
    if (savedUid) {
        // Hiện trạng thái đang tải (Optional)
        elements.displayName.textContent = 'Đang tải...';

        const profile = await fetchUserProfile(savedUid);
        
        if (profile) {
            // Cập nhật vào config của SDK để đồng bộ giao diện
            config.user_name = profile.name || profile.username;
            config.user_email = profile.email || "Email chưa xác thực";
            
            // Nếu có avatar từ backend thì cập nhật luôn (nếu bạn có element avatar)
            if (profile.avatar && elements.avatarBtn) {
                const img = elements.avatarBtn.querySelector('img');
                if (img) img.src = profile.avatar;
            }
        }
    }

    // 2. Cập nhật hiển thị lần cuối
    updateUserInfo();

    // 3. Initialize Element SDK
    if (window.elementSdk) {
        window.elementSdk.init({
            defaultConfig,
            onConfigChange,
            mapToCapabilities,
            mapToEditPanelValues
        });
    }
}

init();