<?php
// includes/vpn_detection.php

/**
 * Detecta si una IP está asociada a una VPN o proxy.
 *
 * @param string $ip La dirección IP del usuario.
 * @return bool True si la IP está asociada a una VPN o proxy, False en caso contrario.
 */
function es_vpn_o_proxy($ip) {
    // Usar una API para detectar VPN/Proxy (ejemplo: ipinfo.io)
    $url = "https://ipinfo.io/{$ip}/json";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); // Tiempo máximo de espera: 5 segundos

    // Ejecutar la solicitud
    $response = curl_exec($ch);

    // Verificar si hubo errores
    if (curl_errno($ch)) {
        curl_close($ch);
        return false;
    }

    // Cerrar la conexión cURL
    curl_close($ch);

    // Decodificar la respuesta JSON
    $data = json_decode($response, true);

    // Verificar si la IP está asociada a una VPN o proxy
    if (isset($data['vpn']) && $data['vpn'] === true) {
        return true; // Es una VPN
    }
    if (isset($data['proxy']) && $data['proxy'] === true) {
        return true; // Es un proxy
    }

    return false; // No es una VPN ni un proxy
}
?>