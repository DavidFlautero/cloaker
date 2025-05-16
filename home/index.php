<?php
// home/index.php

// Incluir funciones auxiliares
require '../includes/functions.php';

// Cargar la configuración
$configuracion = cargar_configuracion();

// URL de la página original (configurada en configuracion.php)
$urloriginal = $configuracion['url_contenido_bots'];

// Verificar si la URL es válida
if (!filter_var($urloriginal, FILTER_VALIDATE_URL)) {
    die('Error: La URL de contenido para bots no es válida.');
}

// Obtener la ruta solicitada
$mivalor = explode('.', $_SERVER["SCRIPT_NAME"]);
$trimmed = trim($_SERVER["REQUEST_URI"], "/");

// Inicializar la variable para almacenar el HTML
$html = '';

// Manejar diferentes casos según la URL solicitada
if ($trimmed != trim($mivalor[0], "/")) {
    if ($_SERVER["REQUEST_URI"] == "/index.php" || $_SERVER["REQUEST_URI"] == "/") {
        // Caso 1: Solicitud a la raíz o a index.php
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $urloriginal);
        curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER["HTTP_USER_AGENT"]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $html = curl_exec($ch);
        curl_close($ch);
    } elseif (substr($_SERVER["REQUEST_URI"], 0, 2) == "/?") {
        // Caso 2: Solicitud con parámetros de consulta (/?)
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $urloriginal);
        curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER["HTTP_USER_AGENT"]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $html = curl_exec($ch);
        curl_close($ch);
    } else {
        // Caso 3: Solicitud a una ruta específica
        $valorurl = parse_url($urloriginal);
        $url_completa = $valorurl["scheme"] . "://" . $valorurl["host"] . $_SERVER["REQUEST_URI"];

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url_completa);
        curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER["HTTP_USER_AGENT"]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        $html = curl_exec($ch);
        curl_close($ch);
    }
} else {
    // Caso 4: Solicitud a la ruta base
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $urloriginal);
    curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER["HTTP_USER_AGENT"]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_VERBOSE, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $html = curl_exec($ch);
    curl_close($ch);
}

// Mostrar el contenido duplicado
echo $html;
?>