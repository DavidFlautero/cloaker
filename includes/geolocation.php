<?php
// includes/geolocation.php

/**
 * Obtiene el nombre del país y la ciudad a partir de una dirección IP usando la API de ip-api.com.
 *
 * @param string $ip La dirección IP del usuario.
 * @return array Un array con el país y la ciudad, o "Desconocido" si no se puede determinar.
 */
function obtener_ubicacion($ip) {
    // Verificar si la IP es válida
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return [
            'pais' => 'Desconocido',
            'ciudad' => 'Desconocido'
        ];
    }

    // URL de la API de ip-api.com
    $url = "http://ip-api.com/json/{$ip}";

    // Inicializar cURL
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); // Tiempo máximo de espera: 5 segundos

    // Ejecutar la solicitud
    $response = curl_exec($ch);

    // Verificar si hubo errores
    if (curl_errno($ch)) {
        curl_close($ch);
        return [
            'pais' => 'Desconocido',
            'ciudad' => 'Desconocido'
        ];
    }

    // Cerrar la conexión cURL
    curl_close($ch);

    // Decodificar la respuesta JSON
    $data = json_decode($response, true);

    // Verificar si la respuesta es válida y contiene el país y la ciudad
    if (isset($data['status']) && $data['status'] === 'success') {
        return [
            'pais' => $data['country'] ?? 'Desconocido', // Nombre del país
            'ciudad' => $data['city'] ?? 'Desconocido'   // Nombre de la ciudad
        ];
    }

    // Si no se pudo obtener la ubicación, devolver "Desconocido"
    return [
        'pais' => 'Desconocido',
        'ciudad' => 'Desconocido'
    ];
}
?>