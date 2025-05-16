<?php
// includes/browser_detection.php

/**
 * Detecta el navegador a partir del User-Agent.
 *
 * @param string $user_agent El User-Agent del navegador.
 * @return string El nombre del navegador (chrome, firefox, safari, etc.).
 */
function obtener_navegador($user_agent) {
    if (stripos($user_agent, 'Chrome') !== false) {
        return 'chrome';
    } elseif (stripos($user_agent, 'Firefox') !== false) {
        return 'firefox';
    } elseif (stripos($user_agent, 'Safari') !== false) {
        return 'safari';
    } elseif (stripos($user_agent, 'Opera') !== false || stripos($user_agent, 'OPR') !== false) {
        return 'opera';
    } elseif (stripos($user_agent, 'Edge') !== false) {
        return 'edge';
    } elseif (stripos($user_agent, 'MSIE') !== false || stripos($user_agent, 'Trident') !== false) {
        return 'ie';
    } else {
        return 'desconocido';
    }
}
?>