<?php
// includes/functions.php

/**
 * Carga la configuración desde configuracion.json.
 *
 * @return array La configuración del sistema.
 */
function cargar_configuracion() {
    if (file_exists('configuracion.json')) {
        return json_decode(file_get_contents('configuracion.json'), true);
    }
    return [
        'url_redireccion' => 'https://www.ejemplo.com/pagina-destino',
        'url_contenido_bots' => 'https://www.ejemplo.com/pagina-para-bots',
        'palabras_clave' => ['Argentina'],
        'cloaker_activo' => true
    ];
}

/**
 * Guarda la configuración en configuracion.json.
 *
 * @param array $configuracion La configuración a guardar.
 */
function guardar_configuracion($configuracion) {
    file_put_contents('configuracion.json', json_encode($configuracion));
}

/**
 * Sanitiza una cadena de texto.
 *
 * @param string $dato La cadena a sanitizar.
 * @return string La cadena sanitizada.
 */
function sanitizar($dato) {
    return htmlspecialchars(trim($dato), ENT_QUOTES, 'UTF-8');
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