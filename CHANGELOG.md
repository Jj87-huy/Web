# Changelog

Tất cả các thay đổi quan trọng của dự án sẽ được ghi lại trong tài liệu này.

Định dạng dựa theo nguyên tắc **Keep a Changelog** và tuân thủ **Semantic Versioning**.

---

## [Unreleased]

### Thêm
- Hoàn thiện hệ thống xác thực người dùng
- Bổ sung cơ chế CSRF token cho các request thay đổi trạng thái
- Middleware bảo mật với HTTP headers
- Lưu trữ tài khoản người dùng bằng cấu trúc file hệ thống

### Cải thiện
- Tối ưu xử lý ghi file theo cơ chế atomic
- Tăng cường kiểm tra dữ liệu đầu vào (username, email, password)
- Cải thiện trải nghiệm đăng nhập/đăng ký

### Sửa lỗi
- Khắc phục lỗi ghi đè index khi tạo tài khoản mới
- Sửa lỗi cookie không hợp lệ khi logout

---

## [1.0.0] - Khởi tạo dự án

### Thêm
- Khởi tạo server với Express
- Cấu trúc thư mục `middleware`, `routers`, `public`
- API cơ bản cho đăng ký, đăng nhập, đăng xuất, lấy profile
- Phục vụ static file từ thư mục `public`
- Áp dụng Helmet, CORS, Cookie Parser
- Sử dụng JWT cho phiên đăng nhập

---