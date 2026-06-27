<?php
error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/error.log');
ini_set('upload_max_filesize', '100M');
ini_set('post_max_size', '110M');
ini_set('max_execution_time', '600');
ini_set('memory_limit', '512M');
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.cookie_secure', 0);
ini_set('session.gc_maxlifetime', 3600);
ini_set('session.use_strict_mode', 1);
ini_set('session.use_only_cookies', 1);
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 3600,
        'path' => '/',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
}
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
$config_user_base64 = '{{USERNAME_BASE64}}';
$config_pass_hash = '{{PASS_HASH}}';
$base_dir = __DIR__ . '/uploads2/';
$log_dir = __DIR__ . '/logs2/';
$attempts_file = $log_dir . 'login_attempts.json';
$rate_limit_file = $log_dir . 'rate_limit.json';
if (!is_dir($log_dir)) {
    mkdir($log_dir, 0755, true);
}
if (!is_dir($base_dir)) {
    mkdir($base_dir, 0755, true);
}
function getClientIP() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!empty($_SERVER['HTTP_CLIENT_IP']) && filter_var($_SERVER['HTTP_CLIENT_IP'], FILTER_VALIDATE_IP)) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($ips[0]);
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $ip = '0.0.0.0';
        }
    }
    return $ip;
}
function getUserAgent() {
    return $_SERVER['HTTP_USER_AGENT'] ?? '';
}
function checkRateLimit($ip, $limit = 60, $window = 60) {
    global $rate_limit_file;
    $data = json_decode(@file_get_contents($rate_limit_file), true) ?: [];
    $now = time();
    $key = $ip . ':' . date('Y-m-d H:i', floor($now / $window) * $window);
    if (!isset($data[$key])) {
        $data[$key] = 1;
    } else {
        $data[$key]++;
    }
    foreach ($data as $k => $v) {
        $time = strtotime(substr($k, strpos($k, ':') + 1));
        if ($now - $time > 2 * $window) {
            unset($data[$k]);
        }
    }
    file_put_contents($rate_limit_file, json_encode($data));
    return $data[$key] <= $limit;
}
function getAttempts($ip) {
    global $attempts_file;
    $data = json_decode(@file_get_contents($attempts_file), true) ?: [];
    return $data[$ip] ?? ['count' => 0, 'first_attempt' => 0, 'blocked_until' => 0];
}
function saveAttempts($ip, $attempts) {
    global $attempts_file;
    $data = json_decode(@file_get_contents($attempts_file), true) ?: [];
    $data[$ip] = $attempts;
    file_put_contents($attempts_file, json_encode($data));
}
function isIPBlocked($ip) {
    $attempts = getAttempts($ip);
    $now = time();
    if ($attempts['blocked_until'] > $now) {
        return $attempts['blocked_until'];
    }
    return false;
}
function recordFailedAttempt($ip) {
    $attempts = getAttempts($ip);
    $now = time();
    if ($attempts['count'] == 0 || ($now - $attempts['first_attempt']) > 900) {
        $attempts['count'] = 1;
        $attempts['first_attempt'] = $now;
    } else {
        $attempts['count']++;
    }
    $block_duration = 0;
    if ($attempts['count'] >= 20) {
        $block_duration = 86400;
    } elseif ($attempts['count'] >= 10) {
        $block_duration = 3600;
    } elseif ($attempts['count'] >= 5) {
        $block_duration = 1800;
    }
    if ($block_duration > 0) {
        $attempts['blocked_until'] = $now + $block_duration;
    } else {
        $attempts['blocked_until'] = 0;
    }
    saveAttempts($ip, $attempts);
    return $attempts;
}
function clearAttempts($ip) {
    saveAttempts($ip, ['count' => 0, 'first_attempt' => 0, 'blocked_until' => 0]);
}
function generateCSRFToken($prefix = '') {
    $key = $prefix . 'csrf_token';
    if (empty($_SESSION[$key]) || empty($_SESSION[$key . '_time']) || (time() - $_SESSION[$key . '_time']) > 3600) {
        $_SESSION[$key] = bin2hex(random_bytes(32));
        $_SESSION[$key . '_time'] = time();
    }
    return $_SESSION[$key];
}
function verifyCSRFToken($token, $prefix = '') {
    $key = $prefix . 'csrf_token';
    if (empty($_SESSION[$key]) || empty($_SESSION[$key . '_time']) || (time() - $_SESSION[$key . '_time']) > 3600) {
        return false;
    }
    return hash_equals($_SESSION[$key], $token);
}
function regenerateSession() {
    session_regenerate_id(true);
    $_SESSION['user_agent'] = getUserAgent();
    $_SESSION['ip_address'] = getClientIP();
    $_SESSION['created_at'] = time();
}
function validateSession() {
    if (!isset($_SESSION['user_agent']) || $_SESSION['user_agent'] !== getUserAgent()) {
        return false;
    }
    if (!isset($_SESSION['ip_address']) || $_SESSION['ip_address'] !== getClientIP()) {
        return false;
    }
    if (isset($_SESSION['created_at']) && (time() - $_SESSION['created_at']) > 86400) {
        return false;
    }
    return true;
}
$ip = getClientIP();
$blocked_until = isIPBlocked($ip);
if (!checkRateLimit($ip, 60, 60)) {
    if (isset($_POST['action']) || isset($_GET['action'])) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Too many requests.']);
        exit;
    }
    die('Too many requests.');
}
$isAjax = isset($_POST['action']) || isset($_GET['action']);
if ($isAjax) {
    if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Unauthorized.']);
        exit;
    }
    $action = $_POST['action'] ?? $_GET['action'] ?? '';
    $safeActions = ['list', 'tree', 'download'];
    if (!in_array($action, $safeActions)) {
        $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
        if (!verifyCSRFToken($token, 'file_')) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'message' => 'CSRF failed.']);
            exit;
        }
    }
}
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'], $_POST['password'], $_POST['csrf_token'])) {
        if (!verifyCSRFToken($_POST['csrf_token'], '')) {
            $error = 'CSRF failed.';
        } elseif ($blocked_until !== false) {
            $remaining = $blocked_until - time();
            $error = "Blocked for " . ceil($remaining / 60) . " min.";
        } else {
            $username = trim($_POST['username']);
            $password = $_POST['password'];
            $config_user = base64_decode($config_user_base64);
            if (empty($username) || empty($password) || strlen($username) > 50 || strlen($password) > 100) {
                recordFailedAttempt($ip);
                usleep(500000);
                $error = 'Invalid credentials.';
            } else {
                if ($username === $config_user && password_verify($password, $config_pass_hash)) {
                    clearAttempts($ip);
                    regenerateSession();
                    $_SESSION['loggedin'] = true;
                    $_SESSION['username'] = $username;
                    $_SESSION['login_time'] = time();
                    unset($_SESSION['csrf_token']);
                    unset($_SESSION['csrf_token_time']);
                    header('Location: ' . $_SERVER['PHP_SELF']);
                    exit;
                } else {
                    recordFailedAttempt($ip);
                    usleep(500000);
                    $error = 'Invalid credentials.';
                }
            }
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            body { font-family: 'Inter', sans-serif; background: #f1f5f9; }
            .login-card { animation: fadeIn 0.5s ease-out; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
            .error-msg { color: #dc2626; font-size: 0.875rem; margin-top: 0.5rem; }
            .input-field:focus { border-color: #dc2626; box-shadow: 0 0 0 3px rgba(220,38,38,0.2); }
        </style>
    </head>
    <body class="flex items-center justify-center min-h-screen p-4">
        <div class="login-card bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md border border-gray-100">
            <div class="text-center mb-6">
                <svg class="w-16 h-16 mx-auto text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z" />
                </svg>
                <h1 class="text-2xl font-bold text-gray-800 mt-2">Secure File Manager</h1>
                <p class="text-sm text-gray-500 mt-1">Enter your credentials</p>
            </div>
            <?php if (isset($error)): ?>
                <div class="error-msg text-center bg-red-50 border border-red-200 rounded-lg p-2"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if ($blocked_until !== false): ?>
                <div class="error-msg text-center bg-red-50 border border-red-200 rounded-lg p-2">
                    IP blocked. Try again after <?= ceil(($blocked_until - time()) / 60) ?> min.
                </div>
            <?php else: ?>
                <form method="POST" class="mt-4">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(generateCSRFToken('')) ?>">
                    <div class="mb-4">
                        <label class="block text-sm font-medium text-gray-700 mb-1">Username</label>
                        <input type="text" name="username" placeholder="Enter username" class="input-field w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none" required autofocus>
                    </div>
                    <div class="mb-6">
                        <label class="block text-sm font-medium text-gray-700 mb-1">Password</label>
                        <input type="password" name="password" placeholder="Enter password" class="input-field w-full px-4 py-2.5 border border-gray-300 rounded-lg focus:outline-none" required>
                    </div>
                    <button type="submit" class="w-full bg-red-600 hover:bg-red-700 text-white py-2.5 rounded-lg font-semibold transition duration-200 shadow-sm">Sign In</button>
                </form>
            <?php endif; ?>
        </div>
    </body>
    </html>
    <?php
    exit;
}
if (!validateSession()) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
$root_dir = __DIR__;
if (!is_dir($root_dir)) die('Invalid root directory.');
$meminfo = @file('/proc/meminfo');
$mem = [];
if ($meminfo !== false) {
    foreach ($meminfo as $line) {
        if (strpos($line, ':') === false) continue;
        [$key, $value] = explode(':', $line);
        $mem[trim($key)] = (int) filter_var($value, FILTER_SANITIZE_NUMBER_INT);
    }
}
$totalRam = $mem['MemTotal'] ?? 0;
$availableRam = $mem['MemAvailable'] ?? 0;
$usedRam = $totalRam - $availableRam;
$ramPercent = ($totalRam > 0) ? round(($usedRam / $totalRam) * 100, 1) : 0;
$diskTotal = disk_total_space('/');
$diskFree = disk_free_space('/');
$diskUsed = $diskTotal - $diskFree;
$diskPercent = ($diskTotal > 0) ? round(($diskUsed / $diskTotal) * 100, 1) : 0;
$load = sys_getloadavg();
$cores = (int) trim(shell_exec('nproc') ?: '1');
$cpuPercent = ($cores > 0) ? round(($load[0] / $cores) * 100, 1) : 0;
$current_dir = isset($_GET['dir']) ? realpath($_GET['dir']) : $root_dir;
if ($current_dir === false || strpos($current_dir, $root_dir) !== 0) {
    $current_dir = $root_dir;
}
function humanSize($bytes) {
    if ($bytes == 0) return '0 B';
    $k = 1024;
    $sizes = ['B','KB','MB','GB','TB'];
    $i = floor(log($bytes) / log($k));
    return round($bytes / pow($k, $i), 1) . ' ' . $sizes[$i];
}
function safePath($path, $root) {
    $real = realpath($path);
    if ($real === false) return false;
    if (strpos($real, $root) !== 0) return false;
    return $real;
}
function buildTree($dir, $root, $depth = 0) {
    if ($depth > 4) return [];
    $result = [];
    $items = scandir($dir);
    if ($items === false) return [];
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $path = $dir . '/' . $item;
        $isDir = is_dir($path);
        $node = [
            'name' => $item,
            'path' => $path,
            'type' => $isDir ? 'dir' : 'file',
        ];
        if ($isDir) {
            $node['children'] = buildTree($path, $root, $depth + 1);
        }
        $result[] = $node;
    }
    return $result;
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    $action = $_POST['action'];
    $res = ['success' => false, 'message' => ''];
    try {
        switch ($action) {
            case 'list':
                $dir = safePath($_POST['dir'] ?? '', $root_dir);
                if (!$dir) { $res['message'] = 'Invalid.'; break; }
                if (!is_readable($dir)) { $res['message'] = 'Not readable.'; break; }
                $items = [];
                $files = scandir($dir);
                if ($files === false) { $res['message'] = 'Cannot read.'; break; }
                foreach ($files as $f) {
                    if ($f === '.' || $f === '..') continue;
                    $p = $dir . '/' . $f;
                    $is_dir = is_dir($p);
                    $items[] = [
                        'name' => $f,
                        'path' => $p,
                        'is_dir' => $is_dir,
                        'size' => $is_dir ? '-' : humanSize(filesize($p)),
                        'mtime' => date('Y-m-d H:i', filemtime($p)),
                    ];
                }
                usort($items, fn($a,$b) => ($a['is_dir'] === $b['is_dir']) ? strcasecmp($a['name'], $b['name']) : -1);
                $res['success'] = true;
                $res['items'] = $items;
                $res['current_dir'] = $dir;
                break;
            case 'tree':
                $dir = safePath($_POST['dir'] ?? $root_dir, $root_dir);
                if (!$dir) { $res['message'] = 'Invalid.'; break; }
                $tree = buildTree($dir, $root_dir);
                $res['success'] = true;
                $res['tree'] = $tree;
                break;
            case 'mkdir':
                $dir = safePath($_POST['dir'] ?? '', $root_dir);
                $name = trim($_POST['name'] ?? '');
                if (!$dir || !$name) { $res['message'] = 'Invalid.'; break; }
                $new = $dir . '/' . $name;
                if (file_exists($new)) { $res['message'] = 'Exists.'; break; }
                if (mkdir($new, 0755)) { $res['success'] = true; $res['message'] = 'Created.'; }
                else { $res['message'] = 'Error.'; }
                break;
            case 'touch':
                $dir = safePath($_POST['dir'] ?? '', $root_dir);
                $name = trim($_POST['name'] ?? '');
                $content = $_POST['content'] ?? '';
                if (!$dir || !$name) { $res['message'] = 'Invalid.'; break; }
                $new = $dir . '/' . $name;
                if (file_exists($new)) { $res['message'] = 'Exists.'; break; }
                if (file_put_contents($new, $content) !== false) { $res['success'] = true; $res['message'] = 'Created.'; }
                else { $res['message'] = 'Error.'; }
                break;
            case 'delete':
                $p = safePath($_POST['path'] ?? '', $root_dir);
                if (!$p) { $res['message'] = 'Invalid.'; break; }
                if (is_dir($p)) {
                    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($p, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
                    foreach ($it as $f) {
                        if ($f->isDir()) rmdir($f->getPathname());
                        else unlink($f->getPathname());
                    }
                    if (rmdir($p)) { $res['success'] = true; $res['message'] = 'Deleted.'; }
                    else { $res['message'] = 'Error.'; }
                } else {
                    if (unlink($p)) { $res['success'] = true; $res['message'] = 'Deleted.'; }
                    else { $res['message'] = 'Error.'; }
                }
                break;
            case 'rename':
                $old = safePath($_POST['old_path'] ?? '', $root_dir);
                $new_name = trim($_POST['new_name'] ?? '');
                if (!$old || !$new_name) { $res['message'] = 'Invalid.'; break; }
                $new = dirname($old) . '/' . $new_name;
                if (file_exists($new)) { $res['message'] = 'Exists.'; break; }
                if (rename($old, $new)) { $res['success'] = true; $res['message'] = 'Renamed.'; }
                else { $res['message'] = 'Error.'; }
                break;
            case 'get':
                $p = safePath($_POST['path'] ?? '', $root_dir);
                if (!$p || is_dir($p)) { $res['message'] = 'Invalid file.'; break; }
                $ext = strtolower(pathinfo($p, PATHINFO_EXTENSION));
                $allowed = ['txt','php','html','htm','css','js','json','xml','md','sql','csv','log','conf','ini'];
                if (!in_array($ext, $allowed)) { $res['message'] = 'Not allowed.'; break; }
                $content = file_get_contents($p);
                if ($content === false) { $res['message'] = 'Read error.'; break; }
                $res['success'] = true;
                $res['content'] = $content;
                $res['path'] = $p;
                break;
            case 'save':
                $p = safePath($_POST['path'] ?? '', $root_dir);
                $content = $_POST['content'] ?? '';
                if (!$p || is_dir($p)) { $res['message'] = 'Invalid.'; break; }
                if (file_put_contents($p, $content) !== false) { $res['success'] = true; $res['message'] = 'Saved.'; }
                else { $res['message'] = 'Error.'; }
                break;
            case 'upload':
                $dir = safePath($_POST['dir'] ?? '', $root_dir);
                if (!$dir) { $res['message'] = 'Invalid.'; break; }
                if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
                    $res['message'] = 'Upload error.';
                    break;
                }
                $dest = $dir . '/' . basename($_FILES['file']['name']);
                if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
                    $res['success'] = true;
                    $res['message'] = 'Uploaded.';
                } else {
                    $res['message'] = 'Move error.';
                }
                break;
            case 'move':
                $source = safePath($_POST['source'] ?? '', $root_dir);
                $destDir = safePath($_POST['dest_dir'] ?? '', $root_dir);
                if (!$source || !$destDir) { $res['message'] = 'Invalid.'; break; }
                if (!is_dir($destDir)) { $res['message'] = 'Not a directory.'; break; }
                $dest = $destDir . '/' . basename($source);
                if (file_exists($dest)) { $res['message'] = 'Exists.'; break; }
                if (rename($source, $dest)) { $res['success'] = true; $res['message'] = 'Moved.'; }
                else { $res['message'] = 'Error.'; }
                break;
            case 'move_multiple':
                $paths = $_POST['paths'] ?? [];
                $destDir = safePath($_POST['dest_dir'] ?? '', $root_dir);
                if (empty($paths) || !$destDir) { $res['message'] = 'Invalid.'; break; }
                if (!is_dir($destDir)) { $res['message'] = 'Not a directory.'; break; }
                $moved = 0;
                $errors = [];
                foreach ($paths as $p) {
                    $source = safePath($p, $root_dir);
                    if (!$source) { $errors[] = "Invalid: $p"; continue; }
                    $dest = $destDir . '/' . basename($source);
                    if (file_exists($dest)) { $errors[] = "Exists: " . basename($source); continue; }
                    if (rename($source, $dest)) $moved++;
                    else $errors[] = "Cannot move: " . basename($source);
                }
                if ($moved > 0) {
                    $res['success'] = true;
                    $res['message'] = "Moved $moved items. " . (count($errors) ? "Errors: " . implode(', ', $errors) : '');
                } else {
                    $res['message'] = 'No items moved. Errors: ' . implode(', ', $errors);
                }
                break;
            case 'zip':
                if (!class_exists('ZipArchive')) {
                    $res['message'] = 'ZipArchive not installed.';
                    break;
                }
                $source = safePath($_POST['source'] ?? '', $root_dir);
                if (!$source) { $res['message'] = 'Invalid.'; break; }
                $zipName = basename($source) . '.zip';
                $zipPath = dirname($source) . '/' . $zipName;
                if (file_exists($zipPath)) { $res['message'] = 'Zip exists.'; break; }
                $zip = new ZipArchive();
                if ($zip->open($zipPath, ZipArchive::CREATE) !== true) {
                    $res['message'] = 'Cannot create zip.';
                    break;
                }
                if (is_dir($source)) {
                    $files = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($source, FilesystemIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::LEAVES_ONLY
                    );
                    foreach ($files as $file) {
                        if (!$file->isDir()) {
                            $relativePath = substr($file->getPathname(), strlen($source) + 1);
                            $zip->addFile($file->getPathname(), $relativePath);
                        }
                    }
                } else {
                    $zip->addFile($source, basename($source));
                }
                $zip->close();
                $res['success'] = true;
                $res['message'] = 'Zipped.';
                break;
            case 'unzip':
                if (!class_exists('ZipArchive')) {
                    $res['message'] = 'ZipArchive not installed.';
                    break;
                }
                $zipFile = safePath($_POST['path'] ?? '', $root_dir);
                if (!$zipFile || !is_file($zipFile) || strtolower(pathinfo($zipFile, PATHINFO_EXTENSION)) !== 'zip') {
                    $res['message'] = 'Invalid zip.';
                    break;
                }
                $extractDir = dirname($zipFile) . '/' . pathinfo($zipFile, PATHINFO_FILENAME);
                if (!is_dir($extractDir)) mkdir($extractDir, 0755, true);
                $zip = new ZipArchive();
                if ($zip->open($zipFile) !== true) { $res['message'] = 'Cannot open.'; break; }
                if ($zip->extractTo($extractDir)) {
                    $res['success'] = true;
                    $res['message'] = 'Extracted.';
                } else {
                    $res['message'] = 'Extract failed.';
                }
                $zip->close();
                break;
            case 'download':
                $file = safePath($_POST['path'] ?? '', $root_dir);
                if (!$file || !is_file($file)) {
                    $res['message'] = 'Invalid file.';
                    break;
                }
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="' . basename($file) . '"');
                header('Content-Length: ' . filesize($file));
                readfile($file);
                exit;
            default: $res['message'] = 'Unknown action.';
        }
    } catch (Exception $e) {
        $res['message'] = 'Error: ' . $e->getMessage();
    }
    echo json_encode($res);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>File Manager</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs/loader.min.js"></script>
    <style>
        * { font-family: 'Inter', sans-serif; }
        #sidebar { width: 280px; min-width: 280px; max-height: 70vh; overflow-y: auto; border-right: 1px solid #e5e7eb; padding: 12px; background: #f9fafb; }
        .dark #sidebar { background: #1f2937; border-color: #374151; }
        .tree-item { cursor: pointer; padding: 4px 8px; border-radius: 6px; display: flex; align-items: center; gap: 4px; font-size: 0.875rem; transition: background 0.15s; }
        .tree-item:hover { background: #e5e7eb; }
        .dark .tree-item:hover { background: #374151; }
        .tree-item .children { padding-right: 20px; }
        .tree-item .toggle { width: 18px; text-align: center; cursor: pointer; font-size: 12px; user-select: none; }
        .tree-item .item-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .tree-item .icon { flex-shrink: 0; }
        #editorOverlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #1e1e1e; z-index: 9999; display: none; flex-direction: column; }
        #editorOverlay .editor-toolbar { background: #2d2d2d; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #444; flex-shrink: 0; }
        #editorOverlay .editor-toolbar button { background: #444; color: #fff; border: none; padding: 6px 16px; border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.875rem; transition: background 0.2s; }
        #editorOverlay .editor-toolbar button:hover { background: #555; }
        #editorOverlay .editor-toolbar .save-btn { background: #059669; }
        #editorOverlay .editor-toolbar .save-btn:hover { background: #047857; }
        #editorContainer { flex: 1; height: calc(100% - 56px); }
        .file-checkbox { width: 16px; height: 16px; cursor: pointer; }
        @media (max-width: 768px) { #sidebar { display: none; } #sidebarToggle { display: flex; } }
        #sidebarToggle { display: none; }
        .stat-card:hover { transform: translateY(-2px); box-shadow: 0 8px 25px -5px rgba(0,0,0,0.1); }
        .btn-icon { display: inline-flex; align-items: center; gap: 4px; }
        .table-row-hover:hover { background: #f9fafb; }
        .dark .table-row-hover:hover { background: #1f2937; }
        .file-item-actions button { font-weight: 500; }
        .file-item-actions button:hover { text-decoration: underline; }
        .modal-input:focus { outline: none; ring: 2px solid #dc2626; }
        #uploadProgressContainer { display: none; margin: 0 8px; align-items: center; gap: 8px; background: #e5e7eb; border-radius: 9999px; height: 6px; flex: 1; min-width: 80px; }
        .dark #uploadProgressContainer { background: #374151; }
        #uploadProgressBar { height: 100%; border-radius: 9999px; background: #dc2626; width: 0%; transition: width 0.2s; }
        #uploadProgressText { font-size: 0.75rem; font-weight: 600; color: #4b5563; }
        .dark #uploadProgressText { color: #9ca3af; }
    </style>
</head>
<body class="bg-gray-50 dark:bg-gray-900 antialiased">
<div class="container mx-auto px-4 py-6 max-w-7xl">
    <div class="mb-6 flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-extrabold text-gray-900 dark:text-white tracking-tight">File Manager</h1>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-0.5">Manage your files</p>
        </div>
        <div class="flex items-center gap-3">
            <div class="text-sm text-gray-500 dark:text-gray-400 bg-white dark:bg-gray-800 px-4 py-2 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700">
                <span class="font-mono"><?= htmlspecialchars($current_dir) ?></span>
            </div>
        </div>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <div class="stat-card bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 p-5 rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">RAM</p>
                    <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1"><?= $ramPercent ?>%</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= round($usedRam / 1024 / 1024, 2) ?> GB / <?= round($totalRam / 1024 / 1024, 2) ?> GB</p>
                    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-2 overflow-hidden">
                        <div class="bg-red-600 h-2 rounded-full transition-all duration-500" style="width: <?= min($ramPercent, 100) ?>%"></div>
                    </div>
                </div>
                <div class="w-12 h-12 bg-red-50 dark:bg-red-900/20 rounded-xl flex items-center justify-center">
                    <svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <rect x="4" y="4" width="16" height="16" rx="2" ry="2" />
                        <rect x="9" y="9" width="6" height="6" />
                        <line x1="9" y1="1" x2="9" y2="4" />
                        <line x1="15" y1="1" x2="15" y2="4" />
                        <line x1="9" y1="20" x2="9" y2="23" />
                        <line x1="15" y1="20" x2="15" y2="23" />
                        <line x1="20" y1="9" x2="23" y2="9" />
                        <line x1="20" y1="14" x2="23" y2="14" />
                        <line x1="1" y1="9" x2="4" y2="9" />
                        <line x1="1" y1="14" x2="4" y2="14" />
                    </svg>
                </div>
            </div>
        </div>
        <div class="stat-card bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 p-5 rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">CPU Load</p>
                    <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1"><?= $cpuPercent ?>%</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= $cores ?> cores • Load: <?= number_format($load[0], 2) ?></p>
                    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-2 overflow-hidden">
                        <div class="bg-red-600 h-2 rounded-full transition-all duration-500" style="width: <?= min($cpuPercent, 100) ?>%"></div>
                    </div>
                </div>
                <div class="w-12 h-12 bg-red-50 dark:bg-red-900/20 rounded-xl flex items-center justify-center">
                    <svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                    </svg>
                </div>
            </div>
        </div>
        <div class="stat-card bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 p-5 rounded-xl shadow-sm">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Disk</p>
                    <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1"><?= $diskPercent ?>%</p>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-1"><?= round($diskUsed / 1024 / 1024 / 1024, 2) ?> GB / <?= round($diskTotal / 1024 / 1024 / 1024, 2) ?> GB</p>
                    <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mt-2 overflow-hidden">
                        <div class="bg-red-600 h-2 rounded-full transition-all duration-500" style="width: <?= min($diskPercent, 100) ?>%"></div>
                    </div>
                </div>
                <div class="w-12 h-12 bg-red-50 dark:bg-red-900/20 rounded-xl flex items-center justify-center">
                    <svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <line x1="22" y1="12" x2="2" y2="12" />
                        <path d="M5.45 5.11L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
                        <line x1="6" y1="16" x2="6.01" y2="16" />
                        <line x1="10" y1="16" x2="10.01" y2="16" />
                    </svg>
                </div>
            </div>
        </div>
    </div>
    <div class="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm overflow-hidden">
        <div class="flex flex-col md:flex-row">
            <aside id="sidebar">
                <div class="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z" /></svg>
                    Folders
                </div>
                <div id="treeContainer" class="space-y-0.5"></div>
            </aside>
            <button id="sidebarToggle" onclick="toggleSidebar()" class="md:hidden m-3 bg-red-600 text-white px-4 py-2 rounded-lg text-sm font-semibold hover:bg-red-700 transition items-center gap-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M3 7v10a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-6l-2-2H5a2 2 0 0 0-2 2z" /></svg>
                Folders
            </button>
            <div class="flex-1 min-w-0">
                <div class="p-4 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 flex flex-wrap items-center gap-2">
                    <button onclick="refreshList()" class="btn-icon px-3 py-1.5 text-sm font-semibold bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 shadow-sm transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>
                        Refresh
                    </button>
                    <button onclick="goBack()" class="btn-icon px-3 py-1.5 text-sm font-semibold bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 shadow-sm transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6" /></svg>
                        Back
                    </button>
                    <button onclick="showModal('mkdir')" class="btn-icon px-3 py-1.5 text-sm font-semibold bg-red-600 text-white rounded-lg hover:bg-red-700 shadow-sm transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" /><line x1="12" y1="11" x2="12" y2="17" /><line x1="9" y1="14" x2="15" y2="14" /></svg>
                        New Folder
                    </button>
                    <button onclick="showModal('touch')" class="btn-icon px-3 py-1.5 text-sm font-semibold bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 shadow-sm transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="12" y1="18" x2="12" y2="12" /><line x1="9" y1="15" x2="15" y2="15" /></svg>
                        New File
                    </button>
                    <button onclick="document.getElementById('uploadInput').click()" class="btn-icon px-3 py-1.5 text-sm font-semibold bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-600 shadow-sm transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" /></svg>
                        Upload
                    </button>
                    <input type="file" id="uploadInput" style="display:none" onchange="uploadFile(event)" />
                    <div id="uploadProgressContainer">
                        <div id="uploadProgressBar"></div>
                    </div>
                    <span id="uploadProgressText" style="display:none;"></span>
                    <button onclick="moveSelected()" class="btn-icon px-3 py-1.5 text-sm font-semibold bg-blue-600 text-white rounded-lg hover:bg-blue-700 shadow-sm transition">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5" /><polyline points="16 3 21 3 21 8" /><line x1="21" y1="3" x2="12" y2="12" /></svg>
                        Move Selected
                    </button>
                    <span class="text-xs text-gray-500 dark:text-gray-400 ml-auto font-mono truncate max-w-xs" id="currentDirLabel"><?= htmlspecialchars($current_dir) ?></span>
                </div>
                <div class="overflow-x-auto p-4">
                    <table class="min-w-full divide-y divide-gray-200 dark:divide-gray-700 text-sm">
                        <thead>
                            <tr class="bg-gray-50 dark:bg-gray-900">
                                <th class="text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider py-3 px-3 w-8">
                                    <input type="checkbox" id="selectAll" onchange="toggleAllCheckboxes()" />
                                </th>
                                <th class="text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider py-3 px-3">Name</th>
                                <th class="text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider py-3 px-3">Type</th>
                                <th class="text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider py-3 px-3">Size</th>
                                <th class="text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider py-3 px-3">Modified</th>
                                <th class="text-left text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider py-3 px-3">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="fileTableBody" class="divide-y divide-gray-100 dark:divide-gray-700">
                            <tr><td colspan="6" class="py-8 text-center text-gray-500">Loading...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div class="grid grid-cols-2 md:grid-cols-5 gap-3 mt-6">
        <a href="#" onclick="refreshList(); return false;" class="flex flex-col items-center gap-2 p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm hover:shadow-md transition hover:border-red-300 group">
            <svg class="w-6 h-6 text-gray-600 dark:text-gray-400 group-hover:text-red-600 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300 group-hover:text-red-600 transition">Refresh</span>
        </a>
        <a href="#" onclick="goBack(); return false;" class="flex flex-col items-center gap-2 p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm hover:shadow-md transition hover:border-red-300 group">
            <svg class="w-6 h-6 text-gray-600 dark:text-gray-400 group-hover:text-red-600 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24"><polyline points="15 18 9 12 15 6" /></svg>
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300 group-hover:text-red-600 transition">Back</span>
        </a>
        <a href="#" onclick="showModal('mkdir'); return false;" class="flex flex-col items-center gap-2 p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm hover:shadow-md transition hover:border-red-300 group">
            <svg class="w-6 h-6 text-gray-600 dark:text-gray-400 group-hover:text-red-600 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" /><line x1="12" y1="11" x2="12" y2="17" /><line x1="9" y1="14" x2="15" y2="14" /></svg>
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300 group-hover:text-red-600 transition">New Folder</span>
        </a>
        <a href="#" onclick="showModal('touch'); return false;" class="flex flex-col items-center gap-2 p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm hover:shadow-md transition hover:border-red-300 group">
            <svg class="w-6 h-6 text-gray-600 dark:text-gray-400 group-hover:text-red-600 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="12" y1="18" x2="12" y2="12" /><line x1="9" y1="15" x2="15" y2="15" /></svg>
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300 group-hover:text-red-600 transition">New File</span>
        </a>
        <a href="#" onclick="document.getElementById('uploadInput').click(); return false;" class="flex flex-col items-center gap-2 p-4 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm hover:shadow-md transition hover:border-red-300 group">
            <svg class="w-6 h-6 text-gray-600 dark:text-gray-400 group-hover:text-red-600 transition" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" /></svg>
            <span class="text-sm font-semibold text-gray-700 dark:text-gray-300 group-hover:text-red-600 transition">Upload</span>
        </a>
    </div>
</div>
<div id="modalOverlay" class="fixed inset-0 bg-black/50 flex items-center justify-center hidden z-50" onclick="if(event.target===this) closeModal();">
    <div class="bg-white dark:bg-gray-800 rounded-xl p-6 max-w-md w-full mx-4 shadow-2xl border border-gray-200 dark:border-gray-700">
        <h3 id="modalTitle" class="text-lg font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2"></h3>
        <div id="modalBody"></div>
        <div class="mt-6 flex justify-end gap-3">
            <button onclick="closeModal()" class="px-4 py-2 text-sm font-semibold bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition">Cancel</button>
            <button id="modalConfirmBtn" class="px-4 py-2 text-sm font-semibold bg-red-600 text-white rounded-lg hover:bg-red-700 transition">Confirm</button>
        </div>
    </div>
</div>
<div id="editorOverlay">
    <div class="editor-toolbar">
        <span id="editorFileName" class="text-white font-bold text-sm flex items-center gap-2">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>
            Editing: <span id="editorFileNameText">file</span>
        </span>
        <div class="flex gap-2">
            <button onclick="saveEditorContent()" class="save-btn flex items-center gap-1">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" /><polyline points="17 21 17 13 7 13 7 21" /><polyline points="7 3 7 8 15 8" /></svg>
                Save
            </button>
            <button onclick="closeEditor()" class="bg-gray-600 hover:bg-gray-700 flex items-center gap-1">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
                Close
            </button>
        </div>
    </div>
    <div id="editorContainer"></div>
</div>
<script>
let currentDir = '<?= addslashes($current_dir) ?>';
let modalCallback = null;
let editorInstance = null;
let currentEditPath = '';
const csrfToken = '<?= htmlspecialchars(generateCSRFToken('file_')) ?>';
document.addEventListener('DOMContentLoaded', function() {
    refreshList();
    loadTree();
});
function refreshList() {
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=list&dir=' + encodeURIComponent(currentDir)
    })
    .then(r => r.json())
    .then(data => {
        if (!data.success) { alert('Error: ' + data.message); return; }
        const tbody = document.getElementById('fileTableBody');
        tbody.innerHTML = '';
        data.items.forEach(item => {
            const tr = document.createElement('tr');
            tr.className = 'table-row-hover transition';
            const isDir = item.is_dir;
            const nameHtml = isDir
                ? `<a href="#" onclick="changeDir('${item.path}')" class="hover:underline font-medium">${item.name}</a>`
                : `<span class="font-medium">${item.name}</span>`;
            let actionsHtml = `
                <div class="flex flex-wrap gap-2 file-item-actions">
                    ${!isDir ? `<button onclick="openEditor('${item.path}')" class="text-blue-600 dark:text-blue-400 text-xs font-semibold">Edit</button>` : ''}
                    <button onclick="renameItem('${item.path}')" class="text-gray-600 dark:text-gray-400 text-xs font-semibold">Rename</button>
                    <button onclick="deleteItem('${item.path}')" class="text-red-600 dark:text-red-400 text-xs font-semibold">Delete</button>
                    <button onclick="moveItem('${item.path}')" class="text-blue-600 dark:text-blue-400 text-xs font-semibold">Move</button>
                    ${isDir ? `<button onclick="zipItem('${item.path}')" class="text-green-600 dark:text-green-400 text-xs font-semibold">Zip</button>` : ''}
                    ${!isDir && item.name.split('.').pop().toLowerCase() === 'zip' ? `<button onclick="unzipItem('${item.path}')" class="text-purple-600 dark:text-purple-400 text-xs font-semibold">Unzip</button>` : ''}
                    ${!isDir ? `<button onclick="downloadFile('${item.path}')" class="text-indigo-600 dark:text-indigo-400 text-xs font-semibold">Download</button>` : ''}
                </div>
            `;
            tr.innerHTML = `
                <td class="py-2.5 px-3"><input type="checkbox" class="file-checkbox" value="${item.path}" onchange="updateSelectAll()" /></td>
                <td class="py-2.5 px-3"><span class="flex items-center gap-2.5">${isDir ? '<svg class="w-5 h-5 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" /></svg>' : '<svg class="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>'} ${nameHtml}</span></td>
                <td class="py-2.5 px-3 text-sm">${isDir ? 'Folder' : 'File'}</td>
                <td class="py-2.5 px-3 text-sm">${item.size}</td>
                <td class="py-2.5 px-3 text-sm">${item.mtime}</td>
                <td class="py-2.5 px-3">${actionsHtml}</td>
            `;
            tbody.appendChild(tr);
        });
        document.getElementById('currentDirLabel').textContent = data.current_dir;
    })
    .catch(err => alert('Server error: ' + err.message));
}
function changeDir(path) {
    currentDir = path;
    refreshList();
    loadTree();
}
function goBack() {
    const parent = currentDir.substring(0, currentDir.lastIndexOf('/'));
    if (parent.length >= '<?= strlen($root_dir) ?>') {
        changeDir(parent);
    } else {
        changeDir('<?= $root_dir ?>');
    }
}
function loadTree() {
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=tree&dir=' + encodeURIComponent('<?= $root_dir ?>')
    })
    .then(r => r.json())
    .then(data => {
        if (!data.success) { console.warn('Tree error:', data.message); return; }
        const container = document.getElementById('treeContainer');
        container.innerHTML = '';
        renderTree(data.tree, container);
    });
}
function renderTree(nodes, container) {
    nodes.forEach(node => {
        const div = document.createElement('div');
        div.className = 'tree-item';
        const isDir = node.type === 'dir';
        const hasChildren = isDir && node.children && node.children.length > 0;
        let toggleHtml = hasChildren ? `<span class="toggle" onclick="toggleTree(this, event)">▶</span>` : `<span class="toggle" style="visibility:hidden;">▶</span>`;
        let icon = isDir
            ? `<svg class="w-4 h-4 text-yellow-500 icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" /></svg>`
            : `<svg class="w-4 h-4 text-blue-500 icon" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></svg>`;
        let clickAction = isDir ? `changeDir('${node.path}')` : `openEditor('${node.path}')`;
        div.innerHTML = `${toggleHtml}<span class="flex items-center gap-1.5 flex-1 min-w-0" onclick="${clickAction}">${icon}<span class="item-name text-gray-700 dark:text-gray-300">${node.name}</span></span>`;
        container.appendChild(div);
        if (hasChildren) {
            const childContainer = document.createElement('div');
            childContainer.className = 'children';
            childContainer.style.display = 'none';
            div.appendChild(childContainer);
            renderTree(node.children, childContainer);
        }
    });
}
function toggleTree(toggleEl, event) {
    event.stopPropagation();
    const parent = toggleEl.parentElement;
    const childContainer = parent.querySelector('.children');
    if (childContainer) {
        const isHidden = childContainer.style.display === 'none';
        childContainer.style.display = isHidden ? 'block' : 'none';
        toggleEl.textContent = isHidden ? '▼' : '▶';
    }
}
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.style.display = sidebar.style.display === 'none' ? 'block' : 'none';
}
function toggleAllCheckboxes() {
    const checked = document.getElementById('selectAll').checked;
    document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = checked);
}
function updateSelectAll() {
    const checkboxes = document.querySelectorAll('.file-checkbox');
    const checked = document.querySelectorAll('.file-checkbox:checked');
    document.getElementById('selectAll').checked = checkboxes.length === checked.length && checkboxes.length > 0;
}
function getSelectedPaths() {
    return Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value);
}
function moveSelected() {
    const paths = getSelectedPaths();
    if (paths.length === 0) { alert('No items selected.'); return; }
    const dest = prompt('Enter destination directory path:', currentDir);
    if (!dest) return;
    const formData = new URLSearchParams();
    formData.append('action', 'move_multiple');
    formData.append('dest_dir', dest);
    paths.forEach(p => formData.append('paths[]', p));
    formData.append('csrf_token', csrfToken);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) { refreshList(); alert(data.message); }
        else alert('Error: ' + data.message);
    });
}
function deleteItem(path) {
    if (!confirm('Delete this item permanently?')) return;
    const formData = new URLSearchParams();
    formData.append('action', 'delete');
    formData.append('path', path);
    formData.append('csrf_token', csrfToken);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) refreshList();
        else alert('Error: ' + data.message);
    });
}
function renameItem(path) {
    const oldName = path.split('/').pop();
    showModal('rename', oldName, (newName) => {
        if (!newName) return;
        const formData = new URLSearchParams();
        formData.append('action', 'rename');
        formData.append('old_path', path);
        formData.append('new_name', newName);
        formData.append('csrf_token', csrfToken);
        fetch('<?= $_SERVER['PHP_SELF'] ?>', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: formData.toString()
        })
        .then(r => r.json())
        .then(data => {
            if (data.success) { refreshList(); closeModal(); }
            else alert('Error: ' + data.message);
        });
    });
}
function moveItem(path) {
    const dest = prompt('Enter destination directory path:', currentDir);
    if (!dest) return;
    const formData = new URLSearchParams();
    formData.append('action', 'move');
    formData.append('source', path);
    formData.append('dest_dir', dest);
    formData.append('csrf_token', csrfToken);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) refreshList();
        else alert('Error: ' + data.message);
    });
}
function zipItem(path) {
    if (!confirm('Create zip archive from this item?')) return;
    const formData = new URLSearchParams();
    formData.append('action', 'zip');
    formData.append('source', path);
    formData.append('csrf_token', csrfToken);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) { refreshList(); alert(data.message); }
        else alert('Error: ' + data.message);
    });
}
function unzipItem(path) {
    if (!confirm('Extract this zip archive?')) return;
    const formData = new URLSearchParams();
    formData.append('action', 'unzip');
    formData.append('path', path);
    formData.append('csrf_token', csrfToken);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) { refreshList(); alert(data.message); }
        else alert('Error: ' + data.message);
    });
}
function downloadFile(path) {
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '<?= $_SERVER['PHP_SELF'] ?>';
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'action';
    input.value = 'download';
    form.appendChild(input);
    const input2 = document.createElement('input');
    input2.type = 'hidden';
    input2.name = 'path';
    input2.value = path;
    form.appendChild(input2);
    document.body.appendChild(form);
    form.submit();
    document.body.removeChild(form);
}
function uploadFile(event) {
    const file = event.target.files[0];
    if (!file) return;
    const progressContainer = document.getElementById('uploadProgressContainer');
    const progressBar = document.getElementById('uploadProgressBar');
    const progressText = document.getElementById('uploadProgressText');
    progressContainer.style.display = 'flex';
    progressText.style.display = 'inline-block';
    progressBar.style.width = '0%';
    progressText.textContent = '0%';
    const formData = new FormData();
    formData.append('action', 'upload');
    formData.append('dir', currentDir);
    formData.append('file', file);
    formData.append('csrf_token', csrfToken);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '<?= $_SERVER['PHP_SELF'] ?>', true);
    xhr.upload.addEventListener('progress', function(e) {
        if (e.lengthComputable) {
            const percent = Math.round((e.loaded / e.total) * 100);
            progressBar.style.width = percent + '%';
            progressText.textContent = percent + '%';
        }
    });
    xhr.addEventListener('load', function() {
        progressContainer.style.display = 'none';
        progressText.style.display = 'none';
        try {
            const data = JSON.parse(xhr.responseText);
            if (data.success) { refreshList(); alert('File uploaded successfully.'); }
            else alert('Error: ' + data.message);
        } catch (err) { alert('Error parsing server response.'); }
    });
    xhr.addEventListener('error', function() {
        progressContainer.style.display = 'none';
        progressText.style.display = 'none';
        alert('Upload failed due to network error.');
    });
    xhr.send(formData);
    event.target.value = '';
}
function openEditor(path) {
    const formData = new URLSearchParams();
    formData.append('action', 'get');
    formData.append('path', path);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (!data.success) { alert('Error: ' + data.message); return; }
        currentEditPath = data.path;
        document.getElementById('editorFileNameText').textContent = path.split('/').pop();
        document.getElementById('editorOverlay').style.display = 'flex';
        if (!editorInstance) {
            require.config({ paths: { vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.34.1/min/vs' } });
            require(['vs/editor/editor.main'], function() {
                editorInstance = monaco.editor.create(document.getElementById('editorContainer'), {
                    value: data.content,
                    language: 'plaintext',
                    theme: 'vs-dark',
                    automaticLayout: true,
                    fontSize: 14,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                });
                setEditorLanguage(path);
            });
        } else {
            editorInstance.setValue(data.content);
            setEditorLanguage(path);
        }
    });
}
function setEditorLanguage(path) {
    const ext = path.split('.').pop().toLowerCase();
    const langMap = { 'php':'php','js':'javascript','html':'html','css':'css','json':'json','xml':'xml','md':'markdown','sql':'sql','csv':'plaintext','log':'plaintext','txt':'plaintext','ini':'ini','conf':'plaintext','sh':'shell','py':'python','rb':'ruby','go':'go','java':'java','c':'c','cpp':'cpp' };
    if (editorInstance) {
        monaco.editor.setModelLanguage(editorInstance.getModel(), langMap[ext] || 'plaintext');
    }
}
function saveEditorContent() {
    if (!editorInstance || !currentEditPath) return;
    const content = editorInstance.getValue();
    const formData = new URLSearchParams();
    formData.append('action', 'save');
    formData.append('path', currentEditPath);
    formData.append('content', content);
    formData.append('csrf_token', csrfToken);
    fetch('<?= $_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) { alert('File saved successfully.'); refreshList(); }
        else alert('Error: ' + data.message);
    });
}
function closeEditor() {
    document.getElementById('editorOverlay').style.display = 'none';
    if (editorInstance) { editorInstance.dispose(); editorInstance = null; }
    currentEditPath = '';
}
function showModal(type, data, callback) {
    const overlay = document.getElementById('modalOverlay');
    const title = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');
    const confirmBtn = document.getElementById('modalConfirmBtn');
    title.innerHTML = '';
    if (type === 'mkdir') {
        title.innerHTML = `<svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" /><line x1="12" y1="11" x2="12" y2="17" /><line x1="9" y1="14" x2="15" y2="14" /></svg> Create New Folder`;
        body.innerHTML = `<input type="text" id="modalInput" placeholder="Folder name" class="modal-input w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition" autofocus>`;
        modalCallback = () => {
            const name = document.getElementById('modalInput').value.trim();
            if (!name) { alert('Please enter folder name.'); return; }
            const formData = new URLSearchParams();
            formData.append('action', 'mkdir');
            formData.append('dir', currentDir);
            formData.append('name', name);
            formData.append('csrf_token', csrfToken);
            fetch('<?= $_SERVER['PHP_SELF'] ?>', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData.toString()
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) { refreshList(); closeModal(); }
                else alert('Error: ' + data.message);
            });
        };
    } else if (type === 'touch') {
        title.innerHTML = `<svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="12" y1="18" x2="12" y2="12" /><line x1="9" y1="15" x2="15" y2="15" /></svg> Create New File`;
        body.innerHTML = `<input type="text" id="modalInput" placeholder="File name" class="modal-input w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition" autofocus><textarea id="modalTextarea" rows="5" placeholder="File content (optional)" class="w-full mt-3 px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition resize-y"></textarea>`;
        modalCallback = () => {
            const name = document.getElementById('modalInput').value.trim();
            const content = document.getElementById('modalTextarea').value;
            if (!name) { alert('Please enter file name.'); return; }
            const formData = new URLSearchParams();
            formData.append('action', 'touch');
            formData.append('dir', currentDir);
            formData.append('name', name);
            formData.append('content', content);
            formData.append('csrf_token', csrfToken);
            fetch('<?= $_SERVER['PHP_SELF'] ?>', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData.toString()
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) { refreshList(); closeModal(); }
                else alert('Error: ' + data.message);
            });
        };
    } else if (type === 'rename') {
        title.innerHTML = `<svg class="w-6 h-6 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5" /><polyline points="16 3 21 3 21 8" /><line x1="21" y1="3" x2="12" y2="12" /></svg> Rename`;
        body.innerHTML = `<input type="text" id="modalInput" value="${data}" class="modal-input w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-gray-50 dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:ring-2 focus:ring-red-500 focus:border-transparent outline-none transition" autofocus>`;
        modalCallback = () => {
            const newName = document.getElementById('modalInput').value.trim();
            if (callback) callback(newName);
        };
    }
    overlay.classList.remove('hidden');
    confirmBtn.onclick = () => { if (typeof modalCallback === 'function') modalCallback(); };
    setTimeout(() => {
        const input = document.getElementById('modalInput');
        if (input) input.focus();
    }, 100);
}
function closeModal() {
    document.getElementById('modalOverlay').classList.add('hidden');
    modalCallback = null;
}
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
        if (document.getElementById('editorOverlay').style.display === 'flex') { closeEditor(); }
        closeModal();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        if (document.getElementById('editorOverlay').style.display === 'flex') { saveEditorContent(); }
    }
});
</script>
</body>
</html>