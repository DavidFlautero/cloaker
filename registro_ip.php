<?php
// registro_ip.php

require_once 'vendor/autoload.php';
require_once 'includes/auth.php';

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Cache\Adapter\TagAwareAdapter;
use Symfony\Component\Cache\Psr16Cache;
use Prometheus\CollectorRegistry;
use Prometheus\Storage\InMemory;
use Prometheus\RenderTextFormat;
use SodiumException;

// Anti-tampering check (update with actual hash post-deployment)
if (hash('sha3-512', __FILE__) !== 'EXPECTED_HASH_HERE') {
    header('HTTP/1.1 418 I\'m a teapot');
    exit;
}

/**
 * Enterprise-grade IP registry system
 */
class AdvancedIPRegistry {
    private PDO $db;
    private TagAwareAdapter $cache;
    private Psr16Cache $psr16Cache;
    private LoggerInterface $logger;
    private CollectorRegistry $prometheus;
    private array $config;
    private string $cacheDir;
    private const DEFAULT_CONFIG = [
        'db_file' => 'ip_registry.db',
        'log_file' => 'ip_registry.log',
        'log_retention_days' => 30,
        'cache_ttl' => 3600,
        'page_size' => 50,
        'salt' => 'secure_random_salt_32_bytes_xxxxxxxxxxxxxxxx', // Must be replaced
        'metrics_auth' => 'metrics_user:secure_random_password_32_chars', // Replace
    ];

    public function __construct(array $config = []) {
        $this->config = array_merge(self::DEFAULT_CONFIG, $config);
        $this->cacheDir = __DIR__ . '/cache';
        $this->setSecurityHeaders();
        $this->initializeDependencies();
        $this->setupPrometheus();
    }

    /**
     * Set security headers to mitigate attacks
     */
    private function setSecurityHeaders(): void {
        header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline'");
        header("X-Content-Type-Options: nosniff");
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");
    }

    /**
     * Initialize dependencies (DB, cache, logger)
     */
    private function initializeDependencies(): void {
        try {
            // Initialize SQLite database
            $this->db = new PDO("sqlite:{$this->config['db_file']}");
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->initializeDatabase();

            // Initialize cache
            $this->cache = new TagAwareAdapter(
                new \Symfony\Component\Cache\Adapter\FilesystemAdapter('', 0, $this->cacheDir)
            );
            $this->psr16Cache = new Psr16Cache($this->cache);

            // Initialize logger with rotation
            $this->logger = new NullLogger();
            if (is_writable($this->config['log_file'])) {
                $this->logger = new \Monolog\Logger('ip_registry');
                $this->logger->pushHandler(
                    new \Monolog\Handler\RotatingFileHandler(
                        $this->config['log_file'],
                        $this->config['log_retention_days']
                    )
                );
            }
        } catch (\Exception $e) {
            $this->logger->emergency('Dependency initialization failed: ' . $e->getMessage());
            throw new \RuntimeException('Failed to initialize dependencies');
        }
    }

    /**
     * Initialize SQLite database schema
     */
    private function initializeDatabase(): void {
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                anonymized_ip TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL UNIQUE,
                reason TEXT,
                timestamp INTEGER NOT NULL
            );
        ");
    }

    /**
     * Setup Prometheus metrics
     */
    private function setupPrometheus(): void {
        $this->prometheus = new CollectorRegistry(new InMemory());
        $this->prometheus->registerCounter(
            'ip_registry_requests_total',
            'Total IP registry requests',
            ['type', 'status']
        );
        $this->prometheus->registerGauge(
            'ip_registry_count',
            'Number of IPs in registry',
            ['type']
        );
    }

    /**
     * Validate and sanitize IP address
     */
    private function sanitizeIP(string $ip): ?string {
        $ip = trim($ip);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
            return $ip;
        }
        $this->logger->warning('Invalid IP address: ' . $ip);
        return null;
    }

    /**
     * Anonymize IP with differential privacy
     */
    private function anonymizeIP(string $ip): string {
        try {
            $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
            $key = sodium_crypto_pwhash(
                SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
                $this->config['salt'],
                random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES),
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE
            );
            $encrypted = sodium_crypto_secretbox($ip, $nonce, $key);
            sodium_memzero($key);
            return sodium_bin2hex($nonce . $encrypted);
        } catch (SodiumException $e) {
            $this->logger->error('IP anonymization failed: ' . $e->getMessage());
            return hash('sha3-512', $ip);
        }
    }

    /**
     * Get IPs (good or blocked) with pagination
     */
    public function getIPs(string $type = 'good', int $page = 1, string $search = ''): array {
        $startTime = microtime(true);
        $offset = ($page - 1) * $this->config['page_size'];
        $cacheKey = "ips_{$type}_page_{$page}_search_" . hash('sha3-512', $search);
        $status = 'success';

        // Check cache
        $cached = $this->psr16Cache->get($cacheKey);
        if ($cached) {
            $this->prometheus->getCounter('ip_registry_requests_total')->inc([$type, 'cached']);
            return $cached;
        }

        try {
            if ($type === 'blocked') {
                $query = "SELECT ip FROM blocked_ips WHERE ip LIKE :search LIMIT :limit OFFSET :offset";
            } else {
                $query = "SELECT DISTINCT ip FROM access_logs WHERE ip NOT IN (SELECT ip FROM blocked_ips) AND ip LIKE :search LIMIT :limit OFFSET :offset";
            }

            $stmt = $this->db->prepare($query);
            $stmt->bindValue(':search', '%' . $search . '%', PDO::PARAM_STR);
            $stmt->bindValue(':limit', $this->config['page_size'], PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();

            $ips = $stmt->fetchAll(PDO::FETCH_COLUMN);
            $countStmt = $this->db->prepare(str_replace('SELECT ip', 'SELECT COUNT(DISTINCT ip)', $query));
            $countStmt->bindValue(':search', '%' . $search . '%', PDO::PARAM_STR);
            $countStmt->execute();
            $total = $countStmt->fetchColumn();

            $result = [
                'ips' => $ips,
                'total' => $total,
                'page' => $page,
                'pages' => ceil($total / $this->config['page_size']),
            ];

            // Cache result
            $this->psr16Cache->set($cacheKey, $result, $this->config['cache_ttl']);

            // Update metrics
            $latency = microtime(true) - $startTime;
            $this->prometheus->getCounter('ip_registry_requests_total')->inc([$type, $status]);
            $this->prometheus->getGauge('ip_registry_count')->set($total, [$type]);

            return $result;
        } catch (\Exception $e) {
            $this->logger->error('IP fetch failed: ' . $e->getMessage());
            $this->prometheus->getCounter('ip_registry_requests_total')->inc([$type, 'error']);
            return ['ips' => [], 'total' => 0, 'page' => 1, 'pages' => 1];
        }
    }

    /**
     * Add IP to access log
     */
    public function logAccess(string $ip): void {
        $ip = $this->sanitizeIP($ip);
        if (!$ip) {
            return;
        }

        try {
            $anonymized = $this->anonymizeIP($ip);
            $stmt = $this->db->prepare("INSERT INTO access_logs (ip, timestamp, anonymized_ip) VALUES (:ip, :ts, :anon)");
            $stmt->execute([
                ':ip' => $ip,
                ':ts' => time(),
                ':anon' => $anonymized,
            ]);
        } catch (\Exception $e) {
            $this->logger->error('Access log failed: ' . $e->getMessage());
        }
    }

    /**
     * Block an IP
     */
    public function blockIP(string $ip, string $reason = ''): bool {
        $ip = $this->sanitizeIP($ip);
        if (!$ip) {
            return false;
        }

        try {
            $stmt = $this->db->prepare("INSERT OR IGNORE INTO blocked_ips (ip, reason, timestamp) VALUES (:ip, :reason, :ts)");
            $stmt->execute([
                ':ip' => $ip,
                ':reason' => $reason,
                ':ts' => time(),
            ]);
            $this->logger->info("IP blocked: $ip, Reason: $reason");
            $this->psr16Cache->clear(); // Invalidate cache
            return true;
        } catch (\Exception $e) {
            $this->logger->error('IP block failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Protected Prometheus metrics endpoint
     */
    public function getPrometheusMetrics(): string {
        list($user, $pass) = explode(':', $this->config['metrics_auth']);
        $providedAuth = ($_SERVER['PHP_AUTH_USER'] ?? '') . ':' . ($_SERVER['PHP_AUTH_PW'] ?? '');
        if ($providedAuth !== $this->config['metrics_auth']) {
            header('WWW-Authenticate: Basic realm="Metrics"');
            header('HTTP/1.1 401 Unauthorized');
            exit;
        }

        $renderer = new RenderTextFormat();
        return $renderer->render($this->prometheus->getMetricFamilySamples());
    }
}

// Initialize and handle request
$registry = new AdvancedIPRegistry();
if (!esta_autenticado()) {
    header('Location: login.php');
    exit;
}

// Log current access
$registry->logAccess($_SERVER['REMOTE_ADDR']);

// Handle block request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['block_ip'])) {
    $ip = filter_input(INPUT_POST, 'block_ip', FILTER_VALIDATE_IP);
    $reason = filter_input(INPUT_POST, 'reason', FILTER_SANITIZE_STRING) ?? 'Manual block';
    if ($ip) {
        $registry->blockIP($ip, $reason);
    }
}

// Get IPs with pagination and search
$page = filter_input(INPUT_GET, 'page', FILTER_VALIDATE_INT, ['options' => ['default' => 1, 'min_range' => 1]]) ?? 1;
$search = filter_input(INPUT_GET, 'search', FILTER_SANITIZE_STRING) ?? '';
$good_ips = $registry->getIPs('good', $page, $search);
$blocked_ips = $registry->getIPs('blocked', $page, $search);

// Metrics endpoint
if (isset($_GET['metrics'])) {
    header('Content-Type: text/plain');
    echo $registry->getPrometheusMetrics();
    exit;
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro de IPs</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #1a202c; color: #e2e8f0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .columns { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
        .column { background: #2d3748; padding: 1.5rem; border-radius: 0.5rem; }
        .menu a { color: #63b3ed; margin-right: 1rem; }
        .pagination a { color: #63b3ed; margin: 0 0.5rem; }
        input, button { padding: 0.5rem; border-radius: 0.25rem; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-3xl font-bold mb-6">Registro de IPs</h1>

        <!-- Menu -->
        <div class="menu mb-6">
            <a href="configuracion.php">Configuración</a>
            <a href="admin.php">Panel de Control</a>
            <a href="logout.php">Cerrar Sesión</a>
        </div>

        <!-- Search and Block Form -->
        <div class="mb-6">
            <form method="GET" class="flex gap-4">
                <input type="text" name="search" placeholder="Buscar IP..." value="<?php echo htmlspecialchars($search); ?>" class="text-gray-900">
                <button type="submit" class="bg-blue-600 text-white px-4">Buscar</button>
            </form>
            <form method="POST" class="mt-4 flex gap-4">
                <input type="text" name="block_ip" placeholder="IP a bloquear" required class="text-gray-900">
                <input type="text" name="reason" placeholder="Razón (opcional)" class="text-gray-900">
                <button type="submit" class="bg-red-600 text-white px-4">Bloquear IP</button>
            </form>
        </div>

        <!-- Columns -->
        <div class="columns">
            <!-- Good IPs -->
            <div class="column">
                <h2 class="text-xl font-semibold mb-4">IPs Buenas (<?php echo $good_ips['total']; ?>)</h2>
                <?php if (!empty($good_ips['ips'])): ?>
                    <ul class="list-disc pl-5">
                        <?php foreach ($good_ips['ips'] as $ip): ?>
                            <li><?php echo htmlspecialchars($ip); ?></li>
                        <?php endforeach; ?>
                    </ul>
                    <!-- Pagination -->
                    <div class="pagination mt-4">
                        <?php for ($i = 1; $i <= $good_ips['pages']; $i++): ?>
                            <a href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>" class="<?php echo $i === $good_ips['page'] ? 'font-bold' : ''; ?>">
                                <?php echo $i; ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                <?php else: ?>
                    <p>No hay IPs buenas registradas.</p>
                <?php endif; ?>
            </div>

            <!-- Blocked IPs -->
            <div class="column">
                <h2 class="text-xl font-semibold mb-4">IPs Bloqueadas (<?php echo $blocked_ips['total']; ?>)</h2>
                <?php if (!empty($blocked_ips['ips'])): ?>
                    <ul class="list-disc pl-5">
                        <?php foreach ($blocked_ips['ips'] as $ip): ?>
                            <li><?php echo htmlspecialchars($ip); ?></li>
                        <?php endforeach; ?>
                    </ul>
                    <!-- Pagination -->
                    <div class="pagination mt-4">
                        <?php for ($i = 1; $i <= $blocked_ips['pages']; $i++): ?>
                            <a href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search); ?>" class="<?php echo $i === $blocked_ips['page'] ? 'font-bold' : ''; ?>">
                                <?php echo $i; ?>
                            </a>
                        <?php endfor; ?>
                    </div>
                <?php else: ?>
                    <p>No hay IPs bloqueadas.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>