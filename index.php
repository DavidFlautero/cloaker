<?php
// index.php

require 'includes/functions.php';
require 'includes/geolocation.php';
require 'includes/browser_detection.php';
require 'includes/vpn_detection.php';
require 'includes/device_detection.php';

// Cargar la configuración
$configuracion = cargar_configuracion();

// Obtener la IP del usuario
$ip = $_SERVER['REMOTE_ADDR'];

// Obtener el User-Agent
$user_agent = $_SERVER['HTTP_USER_AGENT'];

// Verificar si es un bot
$es_bot = stripos($user_agent, 'Googlebot') !== false || stripos($user_agent, 'Bingbot') !== false;

// Obtener la hora actual
$hora = date('Y-m-d H:i:s');

// Obtener la página de referencia (si existe)
$referer = $_SERVER['HTTP_REFERER'] ?? 'Directo';

// Obtener la palabra clave (si existe)
$keyword = $_GET['keyword'] ?? 'Ninguna';

// Obtener la página solicitada
$pagina = $_SERVER['REQUEST_URI'];

// Obtener la ubicación (país y ciudad)
$ubicacion = obtener_ubicacion($ip);
$pais = $ubicacion['pais'];
$ciudad = $ubicacion['ciudad'];

// Verificar si usa VPN/Proxy
$vpn_proxy = es_vpn_o_proxy($ip) ? 'Sí' : 'No';

// Obtener el dispositivo y navegador
$dispositivo = obtener_dispositivo($user_agent);
$navegador = obtener_navegador($user_agent);

// Registrar el acceso en el archivo de logs
$log_entry = "{$ip} | {$user_agent} | {$hora} | {$referer} | {$keyword} | {$pagina} | {$pais} | {$ciudad} | {$vpn_proxy} | {$dispositivo} | {$navegador}";
file_put_contents('access_log.txt', $log_entry . PHP_EOL, FILE_APPEND);

// Aplicar el cloaker
if ($es_bot) {
    // Mostrar contenido para bots usando cURL
    $url_contenido = $configuracion['url_contenido_bots'];
} else {
    // Mostrar contenido para usuarios normales usando cURL
    $url_contenido = $configuracion['url_redireccion'];
}

// Obtener el contenido de la URL usando cURL
$html = obtener_contenido($url_contenido);

// Mostrar el contenido
echo $html;

/**
 * Obtiene el contenido de una URL usando cURL.
 *
 * @param string $url La URL a consultar.
 * @return string El contenido de la URL.
 */
function obtener_contenido($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Ignorar verificación SSL (solo para pruebas)
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}
?>