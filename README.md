# 🖥️ Secure WebShell - Giao diện Điều khiển Máy chủ Từ xa Bảo mật

Dự án này là một WebShell tối giản nhưng được thiết kế chuyên biệt để tăng cường tối đa tính bảo mật khi quản trị máy chủ từ xa.

---

## 🔒 Các Tính năng Bảo mật Đã Triển khai

1. **Obscurity (Ẩn mình)**:
   - File chạy chính được đổi tên thành `login123.php`.
   - Truy cập vào đường dẫn gốc thư mục (`/remote/` hoặc `/remote`) sẽ trả về lỗi **404 Not Found** giả (kẻ xấu sẽ không biết thư mục này có tồn tại hay không).
   - Chỉ khi truy cập chính xác tên file `login123.php` mới hiển thị màn hình đăng nhập.
2. **Bảo vệ bằng `.htaccess` (Apache 2.4)**:
   - Ngăn chặn triệt để việc liệt kê thư mục (`Options -Indexes`).
   - Chặn đứng mọi truy cập trực tiếp vào thư mục chứa password `config/` và trả về lỗi **404**.
   - Chặn các định dạng nhạy cảm như `.git`, `.env`, `.json`, `.log`, `.bak`, `.sql`, `.sh` và giả lập lỗi **404** ẩn danh.
3. **Chống Command Injection trên Windows & Linux**:
   - Sử dụng hàm `proc_open` truyền đối số dạng Array thay cho chuỗi ký tự. Giúp chống lại việc chèn các ký tự đặc biệt nguy hiểm như `&`, `|`, `;`, `^`.
4. **Bảo mật Session & Cookie**:
   - Sử dụng cờ `SameSite=Strict` ngăn chặn tấn công giả mạo CSRF qua Cookie.
   - Bật cờ `HttpOnly` ngăn chặn tấn công đọc session qua JavaScript (XSS).
5. **Rate Limiting & Lockout**:
   - Khóa IP tạm thời trong 60 phút nếu đăng nhập sai quá 5 lần.
   - Sử dụng hàm `hash_equals()` so khớp mật khẩu bằng SHA256 chống tấn công Timing Attack.
6. **Xác thực Kép (Dual-Layer Authentication)**:
   - Lớp 1: Xác thực HTTP Basic Auth ngay từ đầu ngõ khi kết nối thông qua Ngrok tunnel.
   - Lớp 2: Kiểm tra mật khẩu truy cập WebShell bằng hash tĩnh SHA256.

---

## ⚙️ Cấu hình Hệ thống

### 1. WebShell Password (`config/password.php`)
Để thay đổi mật khẩu truy cập WebShell:
1. Tạo mã SHA256 của mật khẩu mới bằng các công cụ bên ngoài không thông qua script trên web.
   - *Ví dụ trong PowerShell*: `[System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes("mật_khẩu_của_bạn"))).Replace("-","").ToLower()`
2. Mở file `config/password.php` và cập nhật hằng số:
   ```php
   define('SHELL_PASSWORD_HASH', 'dán_mã_hash_sha256_vào_đây');
   ```

### 2. Ngrok Tunnel với Basic Auth (`ngrok-cmd.yml`)
File cấu hình Ngrok được tối ưu bảo mật sẵn:
```yaml
version: "3"
agent:
  authtoken: <TOKEN_NGROK_CỦA_BẠN>
tunnels:
  cmd-secure:
    proto: http
    addr: http://localhost:80/
    inspect: false
    # Yêu cầu nhập tài khoản/mật khẩu trình duyệt trước khi cho xem trang
    basic_auth:
      - "admin:753159@Lmnnml."
```

---

## 🚀 Hướng dẫn Chạy & Sử dụng

### Dưới Local (localhost):
1. Đảm bảo chạy Web Server (WAMP/XAMPP) trỏ thư mục root vào dự án.
2. Để truy xuất trang đăng nhập, truy cập:
   `http://localhost/remote/login123.php`
   *(Nếu truy cập `http://localhost/remote/` sẽ nhận lỗi 404)*

### Qua Internet (sử dụng Ngrok):
1. Chạy tunnel Ngrok sử dụng file cấu hình bảo mật đi kèm:
   ```bash
   ngrok start --config D:\wamp64\www\remote\ngrok-cmd.yml cmd-secure
   ```
2. Ngrok sẽ cung cấp một đường dẫn public HTTPS dưới dạng: `https://xxxx-xxxx.ngrok-free.app`
3. Khi người dùng truy cập link kia, trình duyệt sẽ yêu cầu nhập **Basic Auth**. Hãy nhập thông tin cấu hình trong file `ngrok-cmd.yml`:
   - **Username**: `admin`
   - **Password**: `753159@Lmnnml.`
4. Nhập xong lớp Basic Auth, truy cập đúng đường dẫn file để bắt đầu đăng nhập WebShell:
   `https://xxxx-xxxx.ngrok-free.app/remote/login123.php`
5. Điền mật khẩu WebShell đã thiết lập để vào giao diện điều khiển.

---

## ⚠️ Khuyến nghị khi đưa lên Production (Môi trường Thật)

Khi cấu hình máy chủ có chứng chỉ SSL (HTTPS), hãy mở file `login123.php` và `.htaccess` thực hiện các thay đổi sau:
- Mở khóa (uncomment) dòng `ini_set('session.cookie_secure', 1);` trong `login123.php` để chỉ truyền session qua giao thức HTTPS bảo mật.
- Mở khóa rule `Strict-Transport-Security` (HSTS) trong `.htaccess` và `login123.php`.
- Trong file `ngrok-cmd.yml`, có thể mở khóa dòng `ip_restriction` để cấu hình chỉ duy nhất IP tĩnh của bạn/công ty được phép kết nối vào đường dẫn public này.
