<?php
// get_access_log.php

require 'config.php';

// Leer el archivo de logs
$access_log = file_exists(ACCESS_LOG_FILE) ? file(ACCESS_LOG_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

// Convertir los registros en un array asociativo
$logs = [];
foreach ($access_log as $log) {
    list($ip, $user_agent, $hora, $referer, $keyword, $pagina) = explode(' | ', $log);
    $logs[] = [
        'ip' => $ip,
        'pais' => obtener_pais($ip),
        'dispositivo' => obtener_dispositivo($user_agent),
        'navegador' => obtener_navegador($user_agent),
        'hora' => $hora,
        'referer' => $referer,
        'keyword' => $keyword,
        'pagina' => $pagina,
    ];
}

// Devolver los registros en formato JSON
header('Content-Type: application/json');
echo json_encode($logs);
?>