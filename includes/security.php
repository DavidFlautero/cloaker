<?php
// includes/security.php

/**
 * Sanitiza una cadena de texto para evitar ataques XSS y SQL Injection.
 *
 * @param string $data La cadena de texto a sanitizar.
 * @return string La cadena de texto sanitizada.
 */
function sanitize_input($data) {
    // Eliminar espacios en blanco al inicio y al final
    $data = trim($data);
    // Convertir caracteres especiales a entidades HTML
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    // Escapar caracteres especiales para evitar SQL Injection
    $data = addslashes($data);
    return $data;
}

/**
 * Valida una dirección IP.
 *
 * @param string $ip La dirección IP a validar.
 * @return bool True si la IP es válida, False en caso contrario.
 */
function validar_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP);
}

/**
 * Valida un User-Agent.
 *
 * @param string $user_agent El User-Agent a validar.
 * @return bool True si el User-Agent no está vacío, False en caso contrario.
 */
function validar_user_agent($user_agent) {
    return !empty($user_agent);
}

/**
 * Valida una URL.
 *
 * @param string $url La URL a validar.
 * @return bool True si la URL es válida, False en caso contrario.
 */
function validar_url($url) {
    return filter_var($url, FILTER_VALIDATE_URL);
}

/**
 * Valida una fecha en formato YYYY-MM-DD HH:MM:SS.
 *
 * @param string $fecha La fecha a validar.
 * @return bool True si la fecha es válida, False en caso contrario.
 */
function validar_fecha($fecha) {
    return (bool) strtotime($fecha);
}

/**
 * Valida una palabra clave (keyword).
 *
 * @param string $keyword La palabra clave a validar.
 * @return bool True si la palabra clave no está vacía, False en caso contrario.
 */
function validar_keyword($keyword) {
    return !empty($keyword);
}
?>