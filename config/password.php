<?php

/**
 * Webshell Password Configuration
 *
 * Mật khẩu phải được hash bằng SHA256 trước khi điền vào đây.
 * Dùng công cụ online hoặc lệnh:
 *   Linux/Mac : echo -n "your_password" | sha256sum
 *   Windows   : CertUtil -hashfile <(echo your_password) SHA256
 *              hoặc PowerShell: [System.BitConverter]::ToString(
 *                  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
 *                      [System.Text.Encoding]::UTF8.GetBytes("your_password")
 *                  )).Replace("-","").ToLower()
 *
 * ⚠️ KHÔNG ghi mật khẩu gốc (plaintext) vào file này dưới bất kỳ hình thức nào!
 */

// SHA256 hash của mật khẩu - thay bằng hash của mật khẩu bạn chọn
define('SHELL_PASSWORD_HASH', '9bb6022c27420c4530b331e74117dd281c7514a9f9083aa02237c860ee7100f6');

// Tên phiên (session name) - thay đổi để tăng bảo mật
define('SESSION_NAME', 'wsh_s3ss10n_' . substr(hash('sha256', __FILE__), 0, 8));

// Thời gian timeout phiên (giây) - mặc định 4 giờ
define('SESSION_TIMEOUT', 14400);

// IP whitelist - để trống array() để cho phép tất cả IP
// Ví dụ: array('127.0.0.1', '192.168.1.100')
// Dùng biến (tương thích PHP cũ; hằng số mảng cần PHP 5.6+)
$IP_WHITELIST = array();

// Số lần đăng nhập sai tối đa
define('MAX_FAILED_ATTEMPTS', 5);

// Thời gian khóa (giây) sau khi vượt quá số lần sai
define('LOCKOUT_TIME', 3600); // 60 phút
