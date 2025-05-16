<?php
// includes/geolocation_service.php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerInterface;
use Predis\Client as RedisClient;

/**
 * Custom exception for geolocation service errors.
 */
class GeolocationException extends Exception {}

/**
 * Service for retrieving geolocation data from IP addresses.
 */
class GeolocationService
{
    private Client $httpClient;
    private RedisClient $redis;
    private LoggerInterface $logger;
    private array $config;

    /**
     * Constructor with dependency injection.
     *
     * @param Client $httpClient Guzzle HTTP client for API requests.
     * @param RedisClient $redis Redis client for caching.
     * @param LoggerInterface $logger Logger for error and debug logging.
     * @param array $config Configuration array with API endpoints and keys.
     */
    public function __construct(
        Client $httpClient,
        RedisClient $redis,
        LoggerInterface $logger,
        array $config = []
    ) {
        $this->httpClient = $httpClient;
        $this->redis = $redis;
        $this->logger = $logger;
        $this->config = array_merge([
            'ip_api_url' => 'http://ip-api.com/json/',
            'geoip2_url' => 'https://geoip2.example.com/json/',
            'api_key' => '',
            'cache_ttl' => 3600, // Cache for 1 hour
            'rate_limit' => 100, // Requests per minute
        ], $config);
    }

    /**
     * Retrieves geolocation data for a given IP address.
     *
     * @param string $ip The IP address to geolocate.
     * @return array{pais: string, ciudad: string} Geolocation data with country and city.
     * @throws GeolocationException If the IP is invalid or API request fails.
     */
    public function obtenerUbicacion(string $ip): array
    {
        // Validate IP address
        if (!$this->isValidIp($ip)) {
            $this->logger->warning("Invalid IP address: {$ip}");
            throw new GeolocationException('Invalid IP address');
        }

        // Check rate limit
        if (!$this->checkRateLimit()) {
            $this->logger->error("Rate limit exceeded for IP: {$ip}");
            throw new GeolocationException('Rate limit exceeded');
        }

        // Check cache
        $cacheKey = "geo:{$ip}";
        $cached = $this->redis->get($cacheKey);
        if ($cached) {
            $this->logger->info("Cache hit for IP: {$ip}");
            return json_decode($cached, true);
        }

        try {
            // Try primary API (ip-api.com)
            $result = $this->fetchFromIpApi($ip);
        } catch (GeolocationException $e) {
            $this->logger->warning("Primary API failed for IP: {$ip}, falling back to GeoIP2");
            // Fallback to secondary API (GeoIP2)
            $result = $this->fetchFromGeoIp2($ip);
        }

        // Cache result
        $this->redis->setex($cacheKey, $this->config['cache_ttl'], json_encode($result));
        $this->logger->info("Geolocation data cached for IP: {$ip}");

        return $result;
    }

    /**
     * Validates an IP address.
     *
     * @param string $ip The IP address to validate.
     * @return bool True if valid, false otherwise.
     */
    private function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6) !== false;
    }

    /**
     * Checks rate limit for API requests.
     *
     * @return bool True if within limit, false otherwise.
     */
    private function checkRateLimit(): bool
    {
        $key = 'rate_limit:geo';
        $requests = (int)$this->redis->get($key) ?: 0;

        if ($requests >= $this->config['rate_limit']) {
            return false;
        }

        $this->redis->multi()
            ->incr($key)
            ->expire($key, 60) // Reset every minute
            ->exec();

        return true;
    }

    /**
     * Fetches geolocation data from ip-api.com.
     *
     * @param string $ip The IP address.
     * @return array{pais: string, ciudad: string} Geolocation data.
     * @throws GeolocationException If the request fails.
     */
    private function fetchFromIpApi(string $ip): array
    {
        try {
            $response = $this->httpClient->get($this->config['ip_api_url'] . $ip, [
                'timeout' => 5,
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            if (isset($data['status']) && $data['status'] === 'success') {
                return [
                    'pais' => $data['country'] ?? 'Desconocido',
                    'ciudad' => $data['city'] ?? 'Desconocido',
                ];
            }

            throw new GeolocationException('Invalid response from ip-api.com');
        } catch (GuzzleException $e) {
            $this->logger->error("ip-api.com request failed: {$e->getMessage()}");
            throw new GeolocationException('Failed to fetch from ip-api.com');
        }
    }

    /**
     * Fetches geolocation data from GeoIP2 (fallback).
     *
     * @param string $ip The IP address.
     * @return array{pais: string, ciudad: string} Geolocation data.
     * @throws GeolocationException If the request fails.
     */
    private function fetchFromGeoIp2(string $ip): array
    {
        try {
            $response = $this->httpClient->get($this->config['geoip2_url'] . $ip, [
                'timeout' => 5,
                'headers' => [
                    'Authorization' => 'Bearer ' . $this->config['api_key'],
                ],
            ]);

            $data = json_decode($response->getBody()->getContents(), true);

            return [
                'pais' => $data['country']['names']['en'] ?? 'Desconocido',
                'ciudad' => $data['city']['names']['en'] ?? 'Desconocido',
            ];
        } catch (GuzzleException $e) {
            $this->logger->error("GeoIP2 request failed: {$e->getMessage()}");
            throw new GeolocationException('Failed to fetch from GeoIP2');
        }
    }
}

/**
 * Example usage:
 *
 * $httpClient = new GuzzleHttp\Client();
 * $redis = new Predis\Client(['host' => 'localhost']);
 * $logger = new Monolog\Logger('geolocation');
 * $logger->pushHandler(new Monolog\Handler\StreamHandler('logs/geolocation.log'));
 * $config = [
 *     'ip_api_url' => 'http://ip-api.com/json/',
 *     'geoip2_url' => 'https://geoip2.example.com/json/',
 *     'api_key' => 'your_geoip2_api_key',
 * ];
 *
 * $geoService = new GeolocationService($httpClient, $redis, $logger, $config);
 * try {
 *     $location = $geoService->obtenerUbicacion('8.8.8.8');
 *     echo "País: {$location['pais']}, Ciudad: {$location['ciudad']}";
 * } catch (GeolocationException $e) {
 *     echo "Error: {$e->getMessage()}";
 * }
 */
?>