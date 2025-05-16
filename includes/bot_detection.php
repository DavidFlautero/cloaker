<?php
// includes/vpn_detection_advanced.php

declare(strict_types=1);

use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Prometheus\CollectorRegistry;
use Prometheus\Storage\Redis;
use Redis as RedisClient;
use GuzzleHttp\Client;
use GuzzleHttp\Pool;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Exception\RequestException;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;

/**
 * Clase avanzada para detectar VPN, proxy, Tor, hosting y evaluar riesgos de IPs.
 */
class AdvancedVPNDetector {
    private $config;
    private $logger;
    private $cache;
    private $httpClient;
    private $db;
    private $metrics;
    private $rateLimiter;

    // Configuración predeterminada
    private $defaultConfig = [
        'api_timeout' => 3,
        'cache_ttl' => 7200, // 2 horas
        'cache_prefix' => 'vpn_detector_',
        'max_concurrent_requests' => 10,
        'rate_limit_per_minute' => 100,
        'retry_attempts' => 3,
        'retry_backoff_ms' => 500,
        'log_level' => Logger::INFO,
        'db_enabled' => false,
        'metrics_enabled' => true,
        'api_services' => [
            'ipinfo' => [
                'enabled' => true,
                'key' => null,
                'url' => 'https://ipinfo.io/%s/json',
                'weight' => 0.4,
            ],
            'ipapi' => [
                'enabled' => true,
                'key' => null,
                'url' => 'http://ip-api.com/json/%s?fields=status,message,proxy,hosting',
                'weight' => 0.3,
            ],
            'ipqualityscore' => [
                'enabled' => false,
                'key' => null,
                'url' => 'https://ipqualityscore.com/api/json/ip/%s',
                'weight' => 0.3,
            ],
            'abuseipdb' => [
                'enabled' => false,
                'key' => null,
                'url' => 'https://api.abuseipdb.com/api/v2/check?ipAddress=%s',
                'weight' => 0.2,
            ],
        ],
        'redis' => [
            'host' => '127.0.0.1',
            'port' => 6379,
            'timeout' => 1.0,
        ],
        'db' => [
            'driver' => 'pdo_mysql',
            'host' => 'localhost',
            'dbname' => 'vpn_detector',
            'user' => 'root',
            'password' => '',
        ],
        'risk_threshold' => 0.7,
        'anomaly_detection' => true,
    ];

    public function __construct(array $config = []) {
        $this->config = array_merge($this->defaultConfig, $config);
        $this->initializeDependencies();
    }

    /**
     * Detecta si una IP es sospechosa y calcula su puntuación de riesgo.
     *
     * @param string $ip Dirección IP a verificar (IPv4 o IPv6).
     * @param bool $async Procesar la solicitud de forma asíncrona.
     * @return array|PromiseInterface Resultado detallado o promesa asíncrona.
     */
    public function detect(string $ip, bool $async = false) {
        // Validar IP
        if (!$this->isValidIP($ip)) {
            return $this->formatResponse(false, 'Invalid IP address', ['error' => 'Invalid IP format'], 0.0);
        }

        // Verificar rate limiting
        if (!$this->checkRateLimit($ip)) {
            return $this->formatResponse(false, 'Rate limit exceeded', ['error' => 'Too many requests'], 0.0);
        }

        // Verificar caché
        $cacheKey = $this->getCacheKey($ip);
        if ($this->config['cache_ttl'] > 0 && $cachedResult = $this->cache->get($cacheKey)) {
            $this->metrics->increment('cache_hits_total');
            return $cachedResult;
        }

        // Procesar asíncronamente si se solicita
        if ($async) {
            return $this->processAsync($ip, $cacheKey);
        }

        return $this->processSync($ip, $cacheKey);
    }

    /**
     * Inicializa dependencias (logger, caché, DB, métricas, HTTP client).
     */
    private function initializeDependencies(): void {
        // Logger
        $this->logger = new Logger('vpn_detector');
        $this->logger->pushHandler(new StreamHandler(__DIR__ . '/vpn_detector.log', $this->config['log_level']));

        // Caché (Redis)
        try {
            $redis = new RedisClient();
            $redis->connect($this->config['redis']['host'], $this->config['redis']['port'], $this->config['redis']['timeout']);
            $this->cache = new class($redis) {
                private $redis;
                public function __construct($redis) { $this->redis = $redis; }
                public function get($key) {
                    $data = $this->redis->get($key);
                    return $data ? unserialize($data) : null;
                }
                public function set($key, $value, $ttl) {
                    $this->redis->setEx($key, $ttl, serialize($value));
                }
            };
        } catch (Exception $e) {
            $this->logger->error('Redis initialization failed: ' . $e->getMessage());
            $this->cache = new class { public function get($key) { return null; } public function set($key, $value, $ttl) {} };
        }

        // Rate Limiter
        $this->rateLimiter = new class($this->cache, $this->config['rate_limit_per_minute']) {
            private $cache, $limit;
            public function __construct($cache, $limit) { $this->cache = $cache; $this->limit = $limit; }
            public function check($key) {
                $count = $this->cache->get("rate:$key") ?: 0;
                if ($count >= $this->limit) return false;
                $this->cache->set("rate:$key", $count + 1, 60);
                return true;
            }
        };

        // Base de datos
        if ($this->config['db_enabled']) {
            try {
                $this->db = DriverManager::getConnection($this->config['db']);
                $this->initializeDatabase();
            } catch (Exception $e) {
                $this->logger->error('Database initialization failed: ' . $e->getMessage());
                $this->config['db_enabled'] = false;
            }
        }

        // Métricas (Prometheus)
        if ($this->config['metrics_enabled']) {
            $this->metrics = new CollectorRegistry(new Redis(['host' => $this->config['redis']['host']]));
            $this->metrics->getOrRegisterCounter('vpn_detector', 'cache_hits_total', 'Total cache hits');
            $this->metrics->getOrRegisterCounter('vpn_detector', 'api_requests_total', 'Total API requests');
            $this->metrics->getOrRegisterCounter('vpn_detector', 'api_errors_total', 'Total API errors');
        } else {
            $this->metrics = new class { public function increment($name) {} };
        }

        // Cliente HTTP (Guzzle)
        $this->httpClient = new Client([
            'timeout' => $this->config['api_timeout'],
            'verify' => true,
            'headers' => [
                'User-Agent' => 'AdvancedVPNDetector/2.0',
                'Accept' => 'application/json',
            ],
        ]);
    }

    /**
     * Valida si la IP es correcta (IPv4 o IPv6).
     */
    private function isValidIP(string $ip): bool {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Genera una clave para el caché.
     */
    private function getCacheKey(string $ip): string {
        return $this->config['cache_prefix'] . hash('sha256', $ip);
    }

    /**
     * Verifica el límite de solicitudes por minuto.
     */
    private function checkRateLimit(string $ip): bool {
        return $this->rateLimiter->check(hash('sha256', $ip));
    }

    /**
     * Procesa la solicitud de forma síncrona.
     */
    private function processSync(string $ip, string $cacheKey): array {
        $results = $this->queryAPIs($ip);
        $riskScore = $this->calculateRiskScore($results);
        $isSuspicious = $riskScore >= $this->config['risk_threshold'];

        rei

        // Detectar anomalías
        if ($this->config['anomaly_detection']) {
            $anomalyScore = $this->detectAnomalies($results, $ip);
            $isSuspicious = $isSuspicious || $anomalyScore > 0.8;
            $results['anomaly_score'] = $anomalyScore;
        }

        // Guardar en base de datos
        if ($this->config['db_enabled']) {
            $this->storeResult($ip, $isSuspicious, $riskScore, $results);
        }

        // Formatear respuesta
        $response = $this->formatResponse(
            $isSuspicious,
            $isSuspicious ? 'Suspicious IP detected' : 'IP appears clean',
            $results,
            $riskScore
        );

        // Almacenar en caché
        if ($this->config['cache_ttl'] > 0) {
            $this->cache->set($cacheKey, $response, $this->config['cache_ttl']);
        }

        return $response;
    }

    /**
     * Procesa la solicitud de forma asíncrona.
     */
    private function processAsync(string $ip, string $cacheKey) {
        return new \React\Promise\Promise(function ($resolve) use ($ip, $cacheKey) {
            $loop = \React\EventLoop\Factory::create();
            $results = [];

            // Usar Guzzle Pool para consultas asíncronas
            $requests = array_map(function ($service, $config) use ($ip) {
                if (!$config['enabled']) return null;
                $url = sprintf($config['url'], urlencode($ip)) . ($config['key'] ? "?key=" . urlencode($config['key']) : '');
                return new Request('GET', $url);
            }, array_keys($this->config['api_services']), $this->config['api_services']);

            $requests = array_filter($requests);
            $pool = new Pool($this->httpClient, $requests, [
                'concurrency' => $this->config['max_concurrent_requests'],
                'fulfilled' => function ($response, $index) use (&$results) {
                    $service = array_keys($this->config['api_services'])[$index];
                    $data = json_decode((string)$response->getBody(), true);
                    $results[$service] = $data;
                    $this->metrics->increment('api_requests_total');
                },
                'rejected' => function ($reason, $index) {
                    $service = array_keys($this->config['api_services'])[$index];
                    $this->logger->error("Async API query failed for {$service}: " . $reason->getMessage());
                    $this->metrics->increment('api_errors_total');
                },
            ]);

            $promise = $pool->promise();
            $promise->then(function () use ($ip, $cacheKey, &$results, $resolve, $loop) {
                $riskScore = $this->calculateRiskScore($results);
                $isSuspicious = $riskScore >= $this->config['risk_threshold'];

                if ($this->config['anomaly_detection']) {
                    $anomalyScore = $this->detectAnomalies($results, $ip);
                    $isSuspicious = $isSuspicious || $anomalyScore > 0.8;
                    $results['anomaly_score'] = $anomalyScore;
                }

                if ($this->config['db_enabled']) {
                    $this->storeResult($ip, $isSuspicious, $riskScore, $results);
                }

                $response = $this->formatResponse(
                    $isSuspicious,
                    $isSuspicious ? 'Suspicious IP detected' : 'IP appears clean',
                    $results,
                    $riskScore
                );

                if ($this->config['cache_ttl'] > 0) {
                    $this->cache->set($cacheKey, $response, $this->config['cache_ttl']);
                }

                $resolve($response);
                $loop->stop();
            });

            $loop->run();
        });
    }

    /**
     * Realiza consultas a las APIs.
     */
    private function queryAPIs(string $ip): array {
        $results = [];
        foreach ($this->config['api_services'] as $service => $serviceConfig) {
            if (!$serviceConfig['enabled']) {
                continue;
            }

            $attempt = 0;
            while ($attempt <= $this->config['retry_attempts']) {
                try {
                    $url = sprintf($serviceConfig['url'], urlencode($ip));
                    if ($serviceConfig['key']) {
                        $url .= (strpos($url, '?') === false ? '?' : '&') . 'key=' . urlencode($serviceConfig['key']);
                    }

                    $response = $this->httpClient->get($url);
                    $data = json_decode((string)$response->getBody(), true);
                    $results[$service] = $data;
                    $this->metrics->increment('api_requests_total');
                    break;
                } catch (RequestException $e) {
                    $this->logger->error("API query failed for {$service}: " . $e->getMessage());
                    $this->metrics->increment('api_errors_total');
                    $attempt++;
                    usleep($this->config['retry_backoff_ms'] * 1000);
                }
            }
        }
        return $results;
    }

    /**
     * Calcula la puntuación de riesgo basada en los resultados de las APIs.
     */
    private function calculateRiskScore(array $results): float {
        $score = 0.0;
        $totalWeight = 0.0;

        foreach ($results as $service => $data) {
            $weight = $this->config['api_services'][$service]['weight'];
            $totalWeight += $weight;

            switch ($service) {
                case 'ipinfo':
                    if (!empty($data['vpn']) || !empty($data['proxy']) || !empty($data['tor']) || !empty($data['hosting'])) {
                        $score += $weight * 0.9;
                    }
                    break;
                case 'ipapi':
                    if (!empty($data['proxy']) || !empty($data['hosting'])) {
                        $score += $weight * 0.8;
                    }
                    break;
                case 'ipqualityscore':
                    if (!empty($data['vpn']) || !empty($data['proxy']) || !empty($data['tor']) || ($data['fraud_score'] ?? 0) > 75) {
                        $score += $weight * (0.7 + ($data['fraud_score'] ?? 0) / 100);
                    }
                    break;
                case 'abuseipdb':
                    if (($data['data']['abuseConfidenceScore'] ?? 0) > 50) {
                        $score += $weight * ($data['data']['abuseConfidenceScore'] / 100);
                    }
                    break;
            }
        }

        return $totalWeight > 0 ? $score / $totalWeight : 0.0;
    }

    /**
     * Detecta anomalías usando un modelo simulado de ML.
     */
    private function detectAnomalies(array $results, string $ip): float {
        // Simulación de detección de anomalías basada en patrones
        $anomalyScore = 0.0;

        // Ejemplo: IPs de hosting con alta actividad
        if (isset($results['ipinfo']['hosting']) && $results['ipinfo']['hosting']) {
            $anomalyScore += 0.4;
        }

        // Ejemplo: Diferencias entre servicios
        $proxyFlags = array_map(fn($data) => !empty($data['proxy']) || !empty($data['vpn']), $results);
        if (count(array_unique($proxyFlags)) > 1) {
            $anomalyScore += 0.3; // Inconsistencia entre servicios
        }

        return min($anomalyScore, 1.0);
    }

    /**
     * Inicializa la estructura de la base de datos.
     */
    private function initializeDatabase(): void {
        $this->db->executeQuery("
            CREATE TABLE IF NOT EXISTS ip_checks (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                ip VARCHAR(45) NOT NULL,
                is_suspicious BOOLEAN NOT NULL,
                risk_score FLOAT NOT NULL,
                results JSON NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_ip (ip)
            )
        ");
    }

    /**
     * Almacena el resultado en la base de datos.
     */
    private function storeResult(string $ip, bool $isSuspicious, float $riskScore, array $results): void {
        try {
            $this->db->insert('ip_checks', [
                'ip' => $ip,
                'is_suspicious' => $isSuspicious,
                'risk_score' => $riskScore,
                'results' => json_encode($results),
            ]);
        } catch (Exception $e) {
            $this->logger->error('Failed to store result in DB: ' . $e->getMessage());
        }
    }

    /**
     * Formatea la respuesta final.
     */
    private function formatResponse(bool $isSuspicious, string $message, array $details, float $riskScore): array {
        return [
            'is_suspicious' => $isSuspicious,
            'message' => $message,
            'risk_score' => $riskScore,
            'details' => $details,
            'timestamp' => time(),
            'version' => '2.0',
        ];
    }
}

// Ejemplo de uso:
/*
require 'vendor/autoload.php';

$config = [
    'api_services' => [
        'ipinfo' => ['enabled' => true, 'key' => 'TU_IPINFO_KEY'],
        'ipapi' => ['enabled' => true],
        'ipqualityscore' => ['enabled' => true, 'key' => 'TU_IPQUALITYSCORE_KEY'],
        'abuseipdb' => ['enabled' => true, 'key' => 'TU_ABUSEIPDB_KEY'],
    ],
    'redis' => ['host' => 'redis', 'port' => 6379],
    'db_enabled' => true,
    'db —— ['dbname' => 'vpn_detector', 'user' => 'user', 'password' => 'pass'],
    'metrics_enabled' => true,
    'anomaly_detection' => true,
];

$detector = new AdvancedVPNDetector($config);
$result = $detector->detect('8.8.8.8');
var_dump($result);

// Ejemplo asíncrono
//$promise = $detector->detect('8.8.8.8', true);
//$promise->then(function ($result) { var_dump($result); });
*/
?>