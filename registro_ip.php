<?php
// registro_ip.php

require 'includes/auth.php';
require 'includes/functions.php';

// Verificar autenticación
if (!esta_autenticado()) {
    header('Location: login.php');
    exit;
}

// Leer el archivo de logs
$access_log = file_exists('access_log.txt') ? file('access_log.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

// Leer las IPs bloqueadas
$blocked_ips = file_exists('blocked_ips.txt') ? file('blocked_ips.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];

// Obtener las IPs buenas (no bloqueadas)
$good_ips = [];
foreach ($access_log as $log) {
    $log_data = explode(' | ', $log);
    $ip = $log_data[0] ?? 'Desconocido';
    if (!in_array($ip, $blocked_ips)) {
        $good_ips[] = $ip;
    }
}

// Eliminar duplicados de las IPs buenas
$good_ips = array_unique($good_ips);
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registro de IPs</title>
    <link rel="stylesheet" href="styles.css"> <!-- Asegúrate de incluir tu archivo CSS -->
    <link rel="stylesheet" href="galaxia.css"> <!-- Si tienes un archivo CSS adicional -->
</head>
<body>
    <div class="container">
        <h1>Registro de IPs</h1>

        <!-- Menú de navegación -->
        <div class="menu">
            <a href="configuracion.php">Configuración</a>
            <a href="admin.php">Panel de Control</a>
            <a href="logout.php">Cerrar Sesión</a>
        </div>

        <!-- Contenedor de columnas -->
        <div class="columns">
            <!-- Columna de IPs buenas -->
            <div class="column">
                <h2>IPs Buenas</h2>
                <?php if (count($good_ips) > 0): ?>
                    <ul>
                        <?php foreach ($good_ips as $ip): ?>
                            <li><?php echo htmlspecialchars($ip); ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php else: ?>
                    <p>No hay IPs buenas registradas.</p>
                <?php endif; ?>
            </div>

            <!-- Columna de IPs bloqueadas -->
            <div class="column">
                <h2>IPs Bloqueadas</h2>
                <?php if (count($blocked_ips) > 0): ?>
                    <ul>
                        <?php foreach ($blocked_ips as $ip): ?>
                            <li><?php echo htmlspecialchars($ip); ?></li>
                        <?php endforeach; ?>
                    </ul>
                <?php else: ?>
                    <p>No hay IPs bloqueadas.</p>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>