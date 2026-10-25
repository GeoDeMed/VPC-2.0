<?php
// API du canevas de proposition de valeur.
// L'adresse e-mail est validée par un code à l'inscription, puis la connexion se fait par adresse + mot de passe.
// Le mot de passe ne quitte jamais le navigateur : il y produit une clé de connexion (seul son hachage est gardé ici)
// et une clé de chiffrement. Le serveur ne stocke que des données chiffrées et des empreintes d'adresses, jamais d'adresse en clair.
declare(strict_types=1);

require __DIR__ . '/config.php';

const SESSION_DAYS = 7;
const CODE_MINUTES = 15;
const FRESH_MINUTES = 3;
const CODES_PER_IP_PER_HOUR = 60;
const SHARES_PER_CANVAS = 50;
const INVITES_PER_HOUR = 30;
const MAX_BLOB = 1500000;
const PBKDF2_ITERATIONS = 600000;
const LOGIN_FAILS = 10;
const LOCK_MINUTES = 15;

$sessionDir = __DIR__ . '/DOSSIER-DES-DONNEES/sessions';
if (!is_dir($sessionDir)) {
    @mkdir($sessionDir, 0700, true);
}
session_save_path($sessionDir);
ini_set('session.gc_maxlifetime', (string) (SESSION_DAYS * 86400));
session_name('vpc_session');
session_set_cookie_params([
    'lifetime' => SESSION_DAYS * 86400,
    'path' => rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/') . '/',
    'secure' => !defined('VPC_INSECURE_COOKIE'),
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function out(int $code, array $data): void
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function fail(int $code, string $error, string $message = ''): void
{
    out($code, $message === '' ? ['error' => $error] : ['error' => $error, 'message' => $message]);
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $sqlite = str_starts_with(DB_DSN, 'sqlite:');
        if ($sqlite && !is_dir(dirname(substr(DB_DSN, 7)))) {
            @mkdir(dirname(substr(DB_DSN, 7)), 0700, true);
        }
        $pdo = new PDO(DB_DSN, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ]);
        if ($sqlite) {
            sqlite_schema($pdo);
        }
    }
    return $pdo;
}

// Avec SQLite, les tables sont créées automatiquement au premier appel.
function sqlite_schema(PDO $pdo): void
{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS vpc_users (id INTEGER PRIMARY KEY AUTOINCREMENT, email_hash TEXT NOT NULL UNIQUE,
            pub TEXT, keys_json TEXT, check_hash TEXT, auth_hash TEXT, fails INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
            session_gen INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS vpc_codes (email_hash TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0, sent_at TEXT NOT NULL, ip_hash TEXT NOT NULL DEFAULT '');
        CREATE INDEX IF NOT EXISTS idx_ip ON vpc_codes (ip_hash, sent_at);
        CREATE TABLE IF NOT EXISTS vpc_canvases (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, owner_wrap TEXT NOT NULL,
            meta_ct TEXT NOT NULL, data_ct TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_owner ON vpc_canvases (owner_id, updated_at);
        CREATE TABLE IF NOT EXISTS vpc_shares (canvas_id TEXT NOT NULL, email_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'view',
            label_ct TEXT NOT NULL, wrap TEXT, created_at TEXT NOT NULL, PRIMARY KEY (canvas_id, email_hash));
        CREATE INDEX IF NOT EXISTS idx_share_email ON vpc_shares (email_hash);
    ");
}

function input(): array
{
    static $data = null;
    if ($data === null) {
        $data = json_decode((string) file_get_contents('php://input'), true);
        $data = is_array($data) ? $data : [];
    }
    return $data;
}

function str_in(string $key, int $max = MAX_BLOB): string
{
    $v = input()[$key] ?? '';
    if (!is_string($v) || $v === '' || strlen($v) > $max) {
        fail(400, 'données');
    }
    return $v;
}

function now(int $offset = 0): string
{
    return gmdate('Y-m-d H:i:s', time() + $offset);
}

function new_id(): string
{
    return substr(strtr(base64_encode(random_bytes(9)), '+/', '-_'), 0, 12);
}

// Clé secrète des empreintes, créée au premier usage dans le dossier des données (fermé au web).
function secret(): string
{
    static $key = null;
    if ($key === null) {
        $file = __DIR__ . '/DOSSIER-DES-DONNEES/empreintes.key';
        if (!is_file($file)) {
            @file_put_contents($file, bin2hex(random_bytes(32)), LOCK_EX);
            @chmod($file, 0600);
        }
        $key = trim((string) @file_get_contents($file));
        if (strlen($key) < 64) {
            throw new RuntimeException('clé des empreintes illisible');
        }
    }
    return $key;
}

// Empreinte d'une adresse e-mail : permet de reconnaître l'adresse sans la stocker.
function email_hash(string $email): string
{
    return hash_hmac('sha256', 'email:' . strtolower(trim($email)), secret());
}

function ip_hash(): string
{
    return substr(hash_hmac('sha256', 'ip:' . ($_SERVER['REMOTE_ADDR'] ?? ''), secret()), 0, 32);
}

function clean_email(string $raw): string
{
    $email = strtolower(trim($raw));
    $domain = strtolower(trim(ALLOWED_DOMAIN));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190 || ($domain !== '' && !str_ends_with($email, '@' . $domain))) {
        fail(400, 'adresse', $domain === '' ? 'Saisissez une adresse e-mail valide.' : 'Saisissez une adresse @' . $domain . '.');
    }
    return $email;
}

// Session valable si son numéro correspond à celui du compte (« Me déconnecter de partout » l'incrémente).
function current_user(): array
{
    $uid = (int) ($_SESSION['uid'] ?? 0);
    $u = false;
    if ($uid) {
        $st = db()->prepare('SELECT id, email_hash, pub, keys_json, check_hash, session_gen FROM vpc_users WHERE id = ?');
        $st->execute([$uid]);
        $u = $st->fetch();
    }
    if (!$u || (int) $u['session_gen'] !== (int) ($_SESSION['gen'] ?? -1)) {
        $_SESSION = [];
        fail(401, 'auth');
    }
    // Inscription non terminée dans le délai du code : on repart de zéro.
    if (!$u['pub'] && !is_fresh()) {
        db()->prepare('DELETE FROM vpc_users WHERE id = ? AND pub IS NULL')->execute([$u['id']]);
        $_SESSION = [];
        fail(401, 'auth');
    }
    $u['id'] = (int) $u['id'];
    return $u;
}

function open_session(int $uid, int $gen, bool $fresh): void
{
    session_regenerate_id(true);
    $_SESSION = ['uid' => $uid, 'gen' => $gen, 'fresh' => $fresh ? time() : 0];
}

function is_fresh(): bool
{
    return (int) ($_SESSION['fresh'] ?? 0) >= time() - FRESH_MINUTES * 60;
}

function require_fresh(): void
{
    if (!is_fresh()) {
        fail(403, 'code', 'Par sécurité, reconnectez-vous avec un nouveau code avant cette action.');
    }
}

function require_keys(array $u): void
{
    if (!$u['pub']) {
        fail(409, 'clés', 'Créez d\'abord votre mot de passe.');
    }
}

// ---------- E-mails ----------

function smtp_send(string $to, string $subject, string $text, string $html): bool
{
    $fp = @stream_socket_client('ssl://' . SMTP_HOST . ':' . SMTP_PORT, $errno, $errstr, 15);
    if (!$fp) {
        error_log("[vpc] SMTP connexion : $errstr");
        return false;
    }
    stream_set_timeout($fp, 15);
    $read = function () use ($fp): string {
        $resp = '';
        while (($line = fgets($fp, 515)) !== false) {
            $resp .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') {
                break;
            }
        }
        return $resp;
    };
    $cmd = function (?string $line, string $expect) use ($fp, $read): bool {
        if ($line !== null) {
            fwrite($fp, $line . "\r\n");
        }
        $resp = $read();
        if (strncmp($resp, $expect, 3) !== 0) {
            // Le journal ne garde que le code de réponse, sans adresse.
            error_log('[vpc] SMTP réponse inattendue : ' . substr(trim($resp), 0, 3));
            return false;
        }
        return true;
    };
    $host = preg_replace('/[^a-z0-9.-]/i', '', (string) ($_SERVER['SERVER_NAME'] ?? 'localhost')) ?: 'localhost';
    $boundary = 'vpc-' . bin2hex(random_bytes(12));
    $data = 'From: =?UTF-8?B?' . base64_encode(MAIL_FROM_NAME) . '?= <' . SMTP_USER . ">\r\n"
        . "To: <$to>\r\n"
        . 'Subject: =?UTF-8?B?' . base64_encode($subject) . "?=\r\n"
        . 'Date: ' . date(DATE_RFC2822) . "\r\n"
        . 'Message-ID: <' . bin2hex(random_bytes(12)) . '@' . substr(strrchr(SMTP_USER, '@'), 1) . ">\r\n"
        . "MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"$boundary\"\r\n\r\n"
        . "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        . chunk_split(base64_encode($text), 76, "\r\n")
        . "--$boundary\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        . chunk_split(base64_encode($html), 76, "\r\n")
        . "--$boundary--\r\n";
    $ok = $cmd(null, '220')
        && $cmd("EHLO $host", '250')
        && $cmd('AUTH LOGIN', '334')
        && $cmd(base64_encode(SMTP_USER), '334')
        && $cmd(base64_encode(SMTP_PASS), '235')
        && $cmd('MAIL FROM:<' . SMTP_USER . '>', '250')
        && $cmd("RCPT TO:<$to>", '250')
        && $cmd('DATA', '354')
        && $cmd($data . "\r\n.", '250');
    @fwrite($fp, "QUIT\r\n");
    fclose($fp);
    return $ok;
}

// Gabarit des e-mails, aux couleurs du site (styles en ligne, mise en page en tableau pour les messageries).
function mail_html(string $title, string $intro, string $block, string $outro): string
{
    $font = "-apple-system,BlinkMacSystemFont,'SF Pro Text','Helvetica Neue',Helvetica,Arial,sans-serif";
    return '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta name="color-scheme" content="light"><title>' . htmlspecialchars($title) . '</title></head>'
        . '<body style="margin:0;padding:0;background:#F5F5F7;">'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#F5F5F7;"><tr><td align="center" style="padding:32px 16px;">'
        . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:520px;background:#FFFFFF;border-radius:18px;">'
        . '<tr><td style="padding:36px 36px 8px;font-family:' . $font . ';">'
        . '<p style="margin:0 0 6px;font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:#6E6E73;">Module II · Design Thinking</p>'
        . '<h1 style="margin:0 0 16px;font-size:26px;line-height:1.2;font-weight:600;color:#1D1D1F;">' . htmlspecialchars($title) . '</h1>'
        . '<p style="margin:0;font-size:16px;line-height:1.55;color:#38383C;">' . $intro . '</p>'
        . '</td></tr>'
        . '<tr><td style="padding:24px 36px;font-family:' . $font . ';">' . $block . '</td></tr>'
        . '<tr><td style="padding:0 36px 32px;font-family:' . $font . ';"><p style="margin:0;font-size:13px;line-height:1.55;color:#6E6E73;">' . $outro . '</p></td></tr>'
        . '</table>'
        . '<p style="margin:18px 0 0;font-family:' . $font . ';font-size:12px;color:#6E6E73;">Canevas de proposition de valeur</p>'
        . '</td></tr></table></body></html>';
}

function send_mail(string $to, string $subject, string $text, string $html, array $test): bool
{
    if (defined('VPC_TEST_MAIL')) {
        if (defined('VPC_TEST_MAIL_DIR')) {
            file_put_contents(VPC_TEST_MAIL_DIR . '/' . preg_replace('/[^a-z0-9]+/', '-', $to . '-' . array_key_first($test)) . '.html', $html);
        }
        return file_put_contents(VPC_TEST_MAIL, json_encode(['to' => $to] + $test) . "\n", FILE_APPEND) !== false;
    }
    return smtp_send($to, $subject, $text, $html);
}

function app_url(): string
{
    if (defined('APP_URL') && APP_URL !== '') {
        return rtrim(APP_URL, '/') . '/';
    }
    return 'https://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/') . '/';
}

// ---------- Canevas ----------

// Droits de l'utilisateur sur un canevas : 'owner', 'edit', 'view', ou null s'il n'y a pas accès.
function canvas_access(string $id, array $u): ?array
{
    $st = db()->prepare('SELECT id, owner_id, owner_wrap, meta_ct, data_ct, rev, updated_at FROM vpc_canvases WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) {
        return null;
    }
    if ((int) $row['owner_id'] === $u['id']) {
        $row['role'] = 'owner';
        $row['wrap'] = $row['owner_wrap'];
        return $row;
    }
    $st = db()->prepare('SELECT role, wrap FROM vpc_shares WHERE canvas_id = ? AND email_hash = ?');
    $st->execute([$id, $u['email_hash']]);
    $share = $st->fetch();
    if (!$share) {
        return null;
    }
    $row['role'] = $share['role'] === 'edit' ? 'edit' : 'view';
    $row['wrap'] = $share['wrap'];
    return $row;
}

function owned_canvas(array $u): array
{
    $row = canvas_access((string) (input()['id'] ?? ''), $u);
    if (!$row) {
        fail(404, 'introuvable');
    }
    if ($row['role'] !== 'owner') {
        fail(403, 'propriétaire', 'Seul le créateur du canevas gère le partage.');
    }
    return $row;
}

// Partages vus par le créateur : adresse chiffrée, droit, et clé publique de la personne quand son accès reste à finaliser.
function shares_of(string $id): array
{
    $st = db()->prepare('SELECT s.email_hash AS h, s.role, s.label_ct, s.wrap, u.pub FROM vpc_shares s
        LEFT JOIN vpc_users u ON u.email_hash = s.email_hash WHERE s.canvas_id = ? ORDER BY s.created_at, s.email_hash');
    $st->execute([$id]);
    return array_map(fn($r) => [
        'h' => $r['h'], 'role' => $r['role'], 'label_ct' => $r['label_ct'], 'pending' => $r['wrap'] === null, 'pub' => $r['pub'],
    ], $st->fetchAll());
}

// ---------- Routes ----------

$action = (string) ($_GET['a'] ?? '');
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'POST' && ($_SERVER['HTTP_X_VPC'] ?? '') !== '1') {
    fail(400, 'requête refusée');
}
if ($method !== 'POST' && !in_array($action, ['config', 'check', 'me', 'keys', 'list', 'get', 'rev'], true)) {
    fail(405, 'méthode');
}

try {
    // Les lignes de codes (empreintes d'adresse et d'IP) sont effacées après 24 heures, à la visite suivante.
    if (in_array($action, ['config', 'me', 'prelogin'], true)) {
        db()->prepare('DELETE FROM vpc_codes WHERE sent_at < ?')->execute([now(-86400)]);
    }
    switch ($action) {
        case 'config':
            out(200, ['domain' => ALLOWED_DOMAIN, 'contact' => defined('CONTACT_RGPD') ? CONTACT_RGPD : '']);

        // Vérification après installation : base accessible, tables présentes, clé des empreintes créée.
        case 'check':
            db()->query('SELECT COUNT(*) FROM vpc_users')->fetchColumn();
            secret();
            out(200, ['ok' => true, 'base' => strtok(DB_DSN, ':'), 'php' => PHP_VERSION]);

        case 'send-code':
            $email = clean_email((string) (input()['email'] ?? ''));
            $h = email_hash($email);
            $st = db()->prepare('SELECT sent_at FROM vpc_codes WHERE email_hash = ?');
            $st->execute([$h]);
            $last = $st->fetchColumn();
            if ($last !== false && $last > now(-60)) {
                fail(429, 'attente', 'Un code vient d\'être envoyé. Attendez une minute avant d\'en demander un autre.');
            }
            $st = db()->prepare('SELECT COUNT(*) FROM vpc_codes WHERE ip_hash = ? AND sent_at > ?');
            $st->execute([ip_hash(), now(-3600)]);
            if ((int) $st->fetchColumn() >= CODES_PER_IP_PER_HOUR) {
                fail(429, 'limite', 'Trop de codes demandés depuis cette connexion. Réessayez dans une heure.');
            }
            $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            db()->prepare('DELETE FROM vpc_codes WHERE email_hash = ? OR sent_at < ?')->execute([$h, now(-86400)]);
            db()->prepare('INSERT INTO vpc_codes (email_hash, code_hash, expires_at, attempts, sent_at, ip_hash) VALUES (?, ?, ?, 0, ?, ?)')
                ->execute([$h, password_hash($code, PASSWORD_DEFAULT), now(CODE_MINUTES * 60), now(), ip_hash()]);
            // Le code figure toujours d'un seul tenant (sans tiret) pour aider la messagerie à le reconnaître.
            $shown = $code;
            $text = "Votre code de vérification est " . $code . ".\r\n\r\nSaisissez-le sur le site pour valider votre adresse e-mail :\r\n\r\n    " . $shown
                . "\r\n\r\nIl est valable " . CODE_MINUTES . " minutes. Si vous n'avez rien demandé, ignorez ce message.\r\n";
            $html = mail_html('Votre code', 'Votre code de vérification est ' . $code . '. Saisissez-le sur le site pour valider votre adresse e‑mail.',
                '<div style="background:#F5F5F7;border-radius:14px;padding:22px;text-align:center;font-size:38px;font-weight:600;letter-spacing:.12em;color:#1D1D1F;font-variant-numeric:tabular-nums;">' . $shown . '</div>',
                'Ce code est valable ' . CODE_MINUTES . ' minutes. Si vous n\'avez rien demandé, ignorez ce message : sans ce code, personne ne peut utiliser votre adresse.');
            if (!send_mail($email, $code . ' est votre code de vérification', $text, $html, ['code' => $code])) {
                db()->prepare('DELETE FROM vpc_codes WHERE email_hash = ?')->execute([$h]);
                fail(502, 'envoi', 'L\'e-mail n\'a pas pu être envoyé. Réessayez dans un instant.');
            }
            out(200, ['ok' => true]);

        case 'verify-code':
            $h = email_hash((string) (input()['email'] ?? ''));
            $code = preg_replace('/\D/', '', (string) (input()['code'] ?? ''));
            $st = db()->prepare('SELECT code_hash, expires_at, attempts FROM vpc_codes WHERE email_hash = ?');
            $st->execute([$h]);
            $row = $st->fetch();
            if (!$row || $row['expires_at'] < now()) {
                fail(400, 'expiré', 'Ce code a expiré. Demandez-en un nouveau.');
            }
            if ((int) $row['attempts'] >= 5) {
                fail(429, 'essais', 'Trop d\'essais. Demandez un nouveau code.');
            }
            if (!password_verify($code, $row['code_hash'])) {
                db()->prepare('UPDATE vpc_codes SET attempts = attempts + 1 WHERE email_hash = ?')->execute([$h]);
                fail(400, 'code', 'Code incorrect.');
            }
            // Le code est consommé ; la ligne reste (sans code valable) pour la limite par connexion.
            db()->prepare('UPDATE vpc_codes SET code_hash = ?, expires_at = ? WHERE email_hash = ?')->execute(['', now(-1), $h]);
            $st = db()->prepare('SELECT id, session_gen FROM vpc_users WHERE email_hash = ?');
            $st->execute([$h]);
            $u = $st->fetch();
            if (!$u) {
                db()->prepare('INSERT INTO vpc_users (email_hash, session_gen, created_at) VALUES (?, 0, ?)')->execute([$h, now()]);
                $u = ['id' => db()->lastInsertId(), 'session_gen' => 0];
            }
            open_session((int) $u['id'], (int) $u['session_gen'], true);
            out(200, ['ok' => true]);

        // Sel du mot de passe d'une adresse. Pour une adresse inconnue, un sel fictif mais stable est renvoyé,
        // pour ne pas révéler quelles adresses ont un compte.
        case 'prelogin':
            $h = email_hash((string) (input()['email'] ?? ''));
            $st = db()->prepare('SELECT keys_json FROM vpc_users WHERE email_hash = ? AND auth_hash IS NOT NULL');
            $st->execute([$h]);
            $keys = json_decode((string) $st->fetchColumn(), true);
            if (is_array($keys) && isset($keys['salt'], $keys['iter'])) {
                out(200, ['salt' => $keys['salt'], 'iter' => $keys['iter']]);
            }
            out(200, ['salt' => base64_encode(substr(hash_hmac('sha256', 'salt:' . $h, secret(), true), 0, 16)), 'iter' => PBKDF2_ITERATIONS]);

        case 'login':
            $h = email_hash((string) (input()['email'] ?? ''));
            $auth = (string) (input()['auth'] ?? '');
            $st = db()->prepare('SELECT id, auth_hash, fails, locked_until, session_gen, pub, keys_json FROM vpc_users WHERE email_hash = ?');
            $st->execute([$h]);
            $u = $st->fetch();
            if ($u && $u['locked_until'] && $u['locked_until'] > now()) {
                fail(429, 'bloqué', 'Trop d\'essais. Réessayez dans ' . LOCK_MINUTES . ' minutes, ou utilisez « Mot de passe oublié ».');
            }
            if (!$u || !$u['auth_hash'] || !password_verify($auth, $u['auth_hash'])) {
                if ($u) {
                    $fails = (int) $u['fails'] + 1;
                    db()->prepare('UPDATE vpc_users SET fails = ?, locked_until = ? WHERE id = ?')
                        ->execute([$fails >= LOGIN_FAILS ? 0 : $fails, $fails >= LOGIN_FAILS ? now(LOCK_MINUTES * 60) : null, $u['id']]);
                } else {
                    password_hash($auth, PASSWORD_DEFAULT); // même durée de réponse qu'avec un compte existant
                }
                fail(400, 'identifiants', 'Adresse ou mot de passe incorrect.');
            }
            db()->prepare('UPDATE vpc_users SET fails = 0, locked_until = NULL WHERE id = ?')->execute([$u['id']]);
            open_session((int) $u['id'], (int) $u['session_gen'], false);
            out(200, ['uid' => (int) $u['id'], 'pub' => $u['pub'], 'keys' => json_decode((string) $u['keys_json'], true)]);

        case 'logout':
            // Une inscription abandonnée ne laisse pas de compte vide derrière elle.
            if (!empty($_SESSION['uid'])) {
                db()->prepare('DELETE FROM vpc_users WHERE id = ? AND pub IS NULL')->execute([(int) $_SESSION['uid']]);
            }
            $_SESSION = [];
            session_destroy();
            out(200, ['ok' => true]);

        case 'logout-all':
            $u = current_user();
            db()->prepare('UPDATE vpc_users SET session_gen = session_gen + 1 WHERE id = ?')->execute([$u['id']]);
            $_SESSION = [];
            session_destroy();
            out(200, ['ok' => true]);

        case 'me':
            $u = current_user();
            out(200, ['uid' => $u['id'], 'pub' => $u['pub'], 'fresh' => is_fresh()]);

        case 'keys':
            $u = current_user();
            require_keys($u);
            out(200, ['pub' => $u['pub'], 'keys' => json_decode((string) $u['keys_json'], true)]);

        // Enregistre le trousseau chiffré du compte.
        // « new » : premier mot de passe. « phrase » : nouveau mot de passe, avec preuve de la clé maîtresse.
        // « reset » : nouveau départ quand mot de passe et clé de secours sont perdus ; les canevas du compte sont supprimés.
        case 'keys-set':
            $u = current_user();
            $mode = (string) (input()['mode'] ?? '');
            $keys = input()['keys'] ?? null;
            $pub = str_in('pub', 1000);
            $check = str_in('check', 200);
            $auth = str_in('auth', 200);
            $keysJson = json_encode($keys);
            if (!is_array($keys) || strlen($keysJson) > 20000) {
                fail(400, 'données');
            }
            if ($mode === 'new') {
                require_fresh();
                if ($u['pub']) {
                    fail(409, 'clés', 'Ce compte a déjà un mot de passe.');
                }
            } elseif ($mode === 'phrase') {
                require_keys($u);
                if (!hash_equals((string) $u['check_hash'], hash('sha256', $check)) || $pub !== $u['pub']) {
                    fail(403, 'preuve', 'La clé ne correspond pas à ce compte.');
                }
            } elseif ($mode === 'reset') {
                require_fresh();
                db()->beginTransaction();
                db()->prepare('DELETE FROM vpc_shares WHERE canvas_id IN (SELECT id FROM vpc_canvases WHERE owner_id = ?)')->execute([$u['id']]);
                db()->prepare('DELETE FROM vpc_canvases WHERE owner_id = ?')->execute([$u['id']]);
                // Les canevas partagés avec ce compte repassent « à finaliser » : leurs créateurs redonneront l'accès.
                db()->prepare('UPDATE vpc_shares SET wrap = NULL WHERE email_hash = ?')->execute([$u['email_hash']]);
                db()->commit();
            } else {
                fail(400, 'mode');
            }
            db()->prepare('UPDATE vpc_users SET pub = ?, keys_json = ?, check_hash = ?, auth_hash = ?, fails = 0, locked_until = NULL WHERE id = ?')
                ->execute([$pub, $keysJson, hash('sha256', $check), password_hash($auth, PASSWORD_DEFAULT), $u['id']]);
            out(200, ['ok' => true]);

        case 'account-delete':
            $u = current_user();
            require_fresh();
            db()->beginTransaction();
            db()->prepare('DELETE FROM vpc_shares WHERE canvas_id IN (SELECT id FROM vpc_canvases WHERE owner_id = ?)')->execute([$u['id']]);
            db()->prepare('DELETE FROM vpc_canvases WHERE owner_id = ?')->execute([$u['id']]);
            db()->prepare('DELETE FROM vpc_shares WHERE email_hash = ?')->execute([$u['email_hash']]);
            db()->prepare('DELETE FROM vpc_codes WHERE email_hash = ?')->execute([$u['email_hash']]);
            db()->prepare('DELETE FROM vpc_users WHERE id = ?')->execute([$u['id']]);
            db()->commit();
            $_SESSION = [];
            session_destroy();
            out(200, ['ok' => true]);

        case 'list':
            $u = current_user();
            $st = db()->prepare('SELECT id, owner_wrap AS wrap, meta_ct, updated_at FROM vpc_canvases WHERE owner_id = ? ORDER BY updated_at DESC');
            $st->execute([$u['id']]);
            $mine = $st->fetchAll();
            foreach ($mine as &$c) {
                $c['shares'] = shares_of($c['id']);
            }
            unset($c);
            $st = db()->prepare('SELECT c.id, s.wrap, c.meta_ct, c.updated_at, s.role FROM vpc_shares s JOIN vpc_canvases c ON c.id = s.canvas_id
                WHERE s.email_hash = ? ORDER BY c.updated_at DESC');
            $st->execute([$u['email_hash']]);
            out(200, ['canvases' => $mine, 'shared' => $st->fetchAll()]);

        case 'get':
            $u = current_user();
            // Sans droit d'accès, la réponse est la même que pour un canevas inexistant.
            $row = canvas_access((string) ($_GET['id'] ?? ''), $u);
            if (!$row) {
                fail(404, 'introuvable');
            }
            out(200, [
                'id' => $row['id'],
                'role' => $row['role'],
                'rev' => (int) $row['rev'],
                'wrap' => $row['wrap'],
                'meta_ct' => $row['meta_ct'],
                'data_ct' => $row['data_ct'],
                'updated_at' => $row['updated_at'],
                'shares' => $row['role'] === 'owner' ? shares_of($row['id']) : [],
            ]);

        // Vérification légère pour la collaboration : le numéro de version du canevas, et sa fiche chiffrée
        // (titre, auteur de la dernière modification) seulement si ce numéro a changé. Le contenu n'est pas lu.
        case 'rev':
            $u = current_user();
            $id = (string) ($_GET['id'] ?? '');
            $st = db()->prepare('SELECT owner_id, rev FROM vpc_canvases WHERE id = ?');
            $st->execute([$id]);
            $row = $st->fetch();
            if ($row && (int) $row['owner_id'] !== $u['id']) {
                $st = db()->prepare('SELECT 1 FROM vpc_shares WHERE canvas_id = ? AND email_hash = ?');
                $st->execute([$id, $u['email_hash']]);
                $row = $st->fetch() ? $row : false;
            }
            if (!$row) {
                fail(404, 'introuvable');
            }
            $res = ['rev' => (int) $row['rev']];
            if ($res['rev'] !== (int) ($_GET['rev'] ?? 0)) {
                $st = db()->prepare('SELECT meta_ct FROM vpc_canvases WHERE id = ?');
                $st->execute([$id]);
                $res['meta_ct'] = $st->fetchColumn();
            }
            out(200, $res);

        case 'create':
            $u = current_user();
            require_keys($u);
            $id = new_id();
            db()->prepare('INSERT INTO vpc_canvases (id, owner_id, owner_wrap, meta_ct, data_ct, rev, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)')
                ->execute([$id, $u['id'], str_in('wrap', 2000), str_in('meta_ct', 5000), str_in('data_ct'), now(), now()]);
            out(200, ['id' => $id, 'rev' => 1]);

        case 'save':
            $u = current_user();
            $row = canvas_access((string) (input()['id'] ?? ''), $u);
            if (!$row) {
                fail(404, 'introuvable');
            }
            if ($row['role'] === 'view') {
                fail(403, 'lecture', 'Ce canevas vous est partagé en lecture seule.');
            }
            // La révision évite qu'un enregistrement écrase les modifications d'une autre personne.
            $rev = (int) (input()['rev'] ?? 0);
            $st = db()->prepare('UPDATE vpc_canvases SET meta_ct = ?, data_ct = ?, rev = rev + 1, updated_at = ? WHERE id = ? AND rev = ?');
            $st->execute([str_in('meta_ct', 5000), str_in('data_ct'), now(), $row['id'], $rev]);
            if ($st->rowCount() !== 1) {
                fail(409, 'conflit', 'Ce canevas a été modifié entre-temps par une autre personne.');
            }
            out(200, ['rev' => $rev + 1]);

        // Nouvelle clé de canevas après le retrait d'une personne : tout est rechiffré et redistribué aux accès restants.
        case 'rekey':
            $u = current_user();
            $row = owned_canvas($u);
            $wraps = input()['shares'] ?? null;
            if (!is_array($wraps)) {
                fail(400, 'données');
            }
            $remove = (string) (input()['remove'] ?? '');
            $current = array_column(shares_of($row['id']), null, 'h');
            unset($current[$remove]);
            if (array_diff_key($current, $wraps) || array_diff_key($wraps, $current)) {
                fail(409, 'conflit', 'La liste de partage a changé. Rechargez la page.');
            }
            $rev = (int) (input()['rev'] ?? 0);
            db()->beginTransaction();
            $st = db()->prepare('UPDATE vpc_canvases SET owner_wrap = ?, meta_ct = ?, data_ct = ?, rev = rev + 1, updated_at = ? WHERE id = ? AND rev = ?');
            $st->execute([str_in('wrap', 2000), str_in('meta_ct', 5000), str_in('data_ct'), now(), $row['id'], $rev]);
            if ($st->rowCount() !== 1) {
                db()->rollBack();
                fail(409, 'conflit', 'Ce canevas a été modifié entre-temps par une autre personne.');
            }
            if ($remove !== '') {
                db()->prepare('DELETE FROM vpc_shares WHERE canvas_id = ? AND email_hash = ?')->execute([$row['id'], $remove]);
            }
            $up = db()->prepare('UPDATE vpc_shares SET wrap = ?, label_ct = ? WHERE canvas_id = ? AND email_hash = ?');
            foreach ($wraps as $h => $w) {
                $wrap = is_array($w) && is_string($w['wrap'] ?? null) && strlen($w['wrap']) < 2000 ? $w['wrap'] : null;
                $label = is_array($w) && is_string($w['label_ct'] ?? null) && strlen($w['label_ct']) < 2000 ? $w['label_ct'] : '';
                $up->execute([$wrap, $label, $row['id'], (string) $h]);
            }
            db()->commit();
            out(200, ['rev' => $rev + 1, 'shares' => shares_of($row['id'])]);

        case 'delete':
            $u = current_user();
            $id = (string) (input()['id'] ?? '');
            $st = db()->prepare('DELETE FROM vpc_canvases WHERE id = ? AND owner_id = ?');
            $st->execute([$id, $u['id']]);
            if ($st->rowCount() === 1) {
                db()->prepare('DELETE FROM vpc_shares WHERE canvas_id = ?')->execute([$id]);
            }
            out(200, ['deleted' => $st->rowCount()]);

        case 'share-add':
            $u = current_user();
            $row = owned_canvas($u);
            $email = clean_email((string) (input()['email'] ?? ''));
            $from = (string) (input()['from'] ?? '');
            $role = (input()['role'] ?? '') === 'edit' ? 'edit' : 'view';
            $h = email_hash($email);
            if ($h === $u['email_hash']) {
                fail(400, 'soi', 'C\'est votre propre adresse : vous avez déjà accès à ce canevas.');
            }
            // L'adresse de l'expéditeur ne sert qu'à l'e-mail d'invitation ; elle doit être celle du compte.
            if (!hash_equals($u['email_hash'], email_hash($from))) {
                fail(400, 'données');
            }
            $st = db()->prepare('SELECT 1 FROM vpc_shares WHERE canvas_id = ? AND email_hash = ?');
            $st->execute([$row['id'], $h]);
            if ($st->fetchColumn()) {
                fail(409, 'déjà', 'Cette adresse a déjà accès à ce canevas.');
            }
            if (count(shares_of($row['id'])) >= SHARES_PER_CANVAS) {
                fail(400, 'limite', 'Ce canevas est déjà partagé avec ' . SHARES_PER_CANVAS . ' adresses.');
            }
            $st = db()->prepare('SELECT COUNT(*) FROM vpc_shares s JOIN vpc_canvases c ON c.id = s.canvas_id WHERE c.owner_id = ? AND s.created_at > ?');
            $st->execute([$u['id'], now(-3600)]);
            if ((int) $st->fetchColumn() >= INVITES_PER_HOUR) {
                fail(429, 'limite', 'Trop d\'invitations envoyées depuis une heure. Réessayez plus tard.');
            }
            db()->prepare('INSERT INTO vpc_shares (canvas_id, email_hash, role, label_ct, wrap, created_at) VALUES (?, ?, ?, ?, NULL, ?)')
                ->execute([$row['id'], $h, $role, str_in('label_ct', 2000), now()]);
            $from = strtolower(trim($from));
            $link = app_url() . '?c=' . rawurlencode($row['id']);
            $what = $role === 'edit' ? 'le consulter et le modifier' : 'le consulter';
            $text = "Bonjour,\r\n\r\n" . $from . ' vous a donné accès à un canevas de proposition de valeur. Vous pouvez ' . $what . " ici :\r\n\r\n    " . $link
                . "\r\n\r\nSi vous n'avez pas encore de compte, cliquez sur « Créer un compte » avec cette adresse e-mail. Les canevas sont chiffrés avec votre mot de passe, que vous seul connaissez.\r\n";
            $html = mail_html('Un canevas vous est partagé', '<b style="color:#1D1D1F;">' . htmlspecialchars($from) . '</b> vous a donné accès à un canevas de proposition de valeur. Vous pouvez ' . $what . '.',
                '<a href="' . htmlspecialchars($link) . '" style="display:inline-block;background:#007AFF;color:#FFFFFF;text-decoration:none;font-size:16px;font-weight:500;border-radius:980px;padding:12px 24px;">Ouvrir le canevas</a>',
                'Si vous n\'avez pas encore de compte, cliquez sur « Créer un compte » avec cette adresse e-mail. Les canevas sont chiffrés avec votre mot de passe, que vous seul connaissez.<br><br>Lien direct : <a href="' . htmlspecialchars($link) . '" style="color:#007AFF;">' . htmlspecialchars($link) . '</a>');
            $notified = send_mail($email, $from . ' vous partage un canevas de proposition de valeur', $text, $html, ['invite' => $row['id'], 'role' => $role, 'link' => $link]);
            out(200, ['shares' => shares_of($row['id']), 'notified' => $notified]);

        // Le créateur transmet la clé du canevas, chiffrée pour chaque personne invitée qui a créé son compte.
        case 'share-keys':
            $u = current_user();
            $row = owned_canvas($u);
            $wraps = input()['wraps'] ?? null;
            if (!is_array($wraps)) {
                fail(400, 'données');
            }
            $up = db()->prepare('UPDATE vpc_shares SET wrap = ? WHERE canvas_id = ? AND email_hash = ? AND wrap IS NULL');
            foreach ($wraps as $h => $w) {
                if (is_string($w) && $w !== '' && strlen($w) < 2000) {
                    $up->execute([$w, $row['id'], (string) $h]);
                }
            }
            out(200, ['shares' => shares_of($row['id'])]);

        case 'share-role':
            $u = current_user();
            $row = owned_canvas($u);
            db()->prepare('UPDATE vpc_shares SET role = ? WHERE canvas_id = ? AND email_hash = ?')
                ->execute([(input()['role'] ?? '') === 'edit' ? 'edit' : 'view', $row['id'], (string) (input()['h'] ?? '')]);
            out(200, ['shares' => shares_of($row['id'])]);

        // Nom affiché, chiffré dans le navigateur avec la clé du compte, rangé avec le trousseau. Vide : nom retiré.
        case 'name-set':
            $u = current_user();
            require_keys($u);
            $ct = input()['name_ct'] ?? '';
            if (!is_string($ct) || strlen($ct) > 2000) {
                fail(400, 'données');
            }
            $keys = json_decode((string) $u['keys_json'], true);
            if ($ct === '') {
                unset($keys['name_ct']);
            } else {
                $keys['name_ct'] = $ct;
            }
            db()->prepare('UPDATE vpc_users SET keys_json = ? WHERE id = ?')->execute([json_encode($keys, JSON_UNESCAPED_SLASHES), $u['id']]);
            out(200, ['ok' => true]);

        case 'share-leave':
            $u = current_user();
            db()->prepare('DELETE FROM vpc_shares WHERE canvas_id = ? AND email_hash = ?')->execute([(string) (input()['id'] ?? ''), $u['email_hash']]);
            out(200, ['ok' => true]);

        default:
            fail(404, 'action inconnue');
    }
} catch (Throwable $e) {
    try {
        if (db()->inTransaction()) {
            db()->rollBack();
        }
    } catch (Throwable $ignored) {
    }
    error_log('[vpc] ' . $e->getMessage());
    fail(500, 'erreur serveur');
}
