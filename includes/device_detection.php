<?php
// includes/device_detection.php

/**
 * Detecta el tipo de dispositivo a partir del User-Agent.
 *
 * @param string $user_agent El User-Agent del navegador.
 * @return string El tipo de dispositivo (mobile, tablet, desktop).
 */
function obtener_dispositivo($user_agent) {
    // Dispositivos móviles
    $dispositivos_moviles = [
        'Mobile', 'Android', 'iPhone', 'iPad', 'Windows Phone', 'BlackBerry', 'Opera Mini', 'IEMobile'
    ];

    // Tablets
    $tablets = [
        'iPad', 'Android', 'Tablet', 'Kindle', 'PlayBook'
    ];

    // Verificar si es un dispositivo móvil
    foreach ($dispositivos_moviles as $dispositivo) {
        if (stripos($user_agent, $dispositivo) !== false) {
            return 'mobile';
        }
    }

    // Verificar si es una tablet
    foreach ($tablets as $tablet) {
        if (stripos($user_agent, $tablet) !== false) {
            return 'tablet';
        }
    }

    // Si no es móvil ni tablet, asumimos que es un escritorio
    return 'desktop';
}
?>