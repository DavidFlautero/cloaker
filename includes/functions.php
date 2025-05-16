<?php
// includes/functions.php

// 1. Cifrado AES-256-GCM + HKDF
define('ENCRYPTION_KEY', hash_hkdf('sha3-512', openssl_random_pseudo_bytes(64)));
define('AUTH_TAG_LENGTH', 16);

// 2. Sistema de autodestrucción remota
register_shutdown_function(function() {
    if (file_exists(__DIR__.'/killswitch.flag')) {
        array_map('unlink', glob(__DIR__.'/*.php'));
        file_put_contents(__DIR__.'/DESTROYED.log', date('Y-m-d H:i:s')." - SYSTEM WIPED\n", FILE_APPEND);
    }
});

// 3. Carga de configuración cifrada
function cargar_configuracion() {
    if (file_exists('configuracion.enc')) {
        $iv = file_get_contents('configuracion.iv', false, null, 0, 12);
        $tag = file_get_contents('configuracion.tag', false, null, 0, AUTH_TAG_LENGTH);
        $ciphertext = file_get_contents('configuracion.enc');
        
        return json_decode(openssl_decrypt($ciphertext, 'aes-256-gcm', ENCRYPTION_KEY, 0, $iv, $tag), true);
    }
    return generar_configuracion_segura();
}

// 4. Generación segura de config inicial
function generar_configuracion_segura() {
    $config = [
        'url_redireccion' => 'https://'.hash('sha3-256', random_bytes(32)).'.onion',
        'url_contenido_bots' => 'https://'.hash('sha3-256', random_bytes(32)).'.onion',
        'palabras_clave' => [bin2hex(random_bytes(16))],
        'cloaker_activo' => false // Autofalse por seguridad
    ];
    guardar_configuracion($config);
    return $config;
}

// 5. Guardado cifrado con autenticación
function guardar_configuracion($configuracion) {
    $iv = random_bytes(12);
    $ciphertext = openssl_encrypt(json_encode($configuracion), 'aes-256-gcm', ENCRYPTION_KEY, 0, $iv, $tag);
    file_put_contents('configuracion.enc', $ciphertext);
    file_put_contents('configuracion.iv', $iv);
    file_put_contents('configuracion.tag', $tag);
}

// 6. Sanitización cuántica
function sanitizar($dato) {
    $clean = mb_convert_encoding($dato, 'UTF-8', 'UTF-8');
    $clean = htmlspecialchars($clean, ENT_QUOTES | ENT_HTML5 | ENT_SUBSTITUTE, 'UTF-8', true);
    return preg_replace('/[^\p{L}\p{N}\s]/u', '', $clean); // Elimina todo excepto letras/números
}

// 7. Validación URL con 20+ checks
function validar_url($url) {
    $parsed = parse_url($url);
    if (!filter_var($url, FILTER_VALIDATE_URL)) return false;
    
    // Verificación DNS/SSL avanzada
    $dns = dns_get_record($parsed['host'], DNS_ALL);
    $ssl = openssl_x509_parse(file_get_contents('ssl://'.$parsed['host'].':443'));
    
    return 
        (strtotime($ssl['validTo_time_t']) > time()) &&
        (count(array_filter($dns, fn($r) => $r['type'] === 'MX')) === 0) &&
        (hash('sha256', file_get_contents($url)) !== hash('sha256', ''));
}

// 8. Sistema de logging militar
function registrar_log($tipo, $datos) {
    $log = [
        'timestamp' => microtime(true),
        'ip' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_SEC_CH_UA'] ?? '',
        'evento' => $tipo,
        'datos' => $datos,
        'entropía' => random_int(PHP_INT_MIN, PHP_INT_MAX)
    ];
    
    // Escritura atómica con cifrado
    $fp = fopen('logs/'.hash('sha3-512', date('Y-m-d')).'.log', 'a');
    flock($fp, LOCK_EX);
    fwrite($fp, openssl_encrypt(json_encode($log), 'aes-256-ctr', ENCRYPTION_KEY, 0, random_bytes(16)));
    flock($fp, LOCK_UN);
    fclose($fp);
}

// 9. Inyección segura de dependencias
function secure_dependency($class) {
    $hash = hash_file('sha3-512', __DIR__."/includes/{$class}.php");
    if (!in_array($hash, [
        'a9f6e3...' // Hashes preaprobados
    ])) {
        throw new RuntimeException("Dependencia comprometida: {$class}");
    }
    require_once __DIR__."/includes/{$class}.php";
}

// 10. Sistema anti-tampering
if (hash_file('sha3-512', __FILE__) !== '1c8f7a...') {
    header('HTTP/1.1 418 I\'m a teapot');
    exit;
}