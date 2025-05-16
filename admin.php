<?php
// admin.php

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

// Bloquear una IP
if (isset($_POST['block_ip'])) {
    $ip_to_block = filter_input(INPUT_POST, 'ip', FILTER_VALIDATE_IP);
    if ($ip_to_block) {
        // Verificar si la IP ya está bloqueada
        if (in_array($ip_to_block, $blocked_ips)) {
            echo "<div class='message error'>La IP $ip_to_block ya está bloqueada.</div>";
        } else {
            file_put_contents('blocked_ips.txt', $ip_to_block . PHP_EOL, FILE_APPEND);
            echo "<div class='message success'>IP $ip_to_block bloqueada.</div>";
            // Actualizar la lista de IPs bloqueadas
            $blocked_ips[] = $ip_to_block;
        }
    } else {
        echo "<div class='message error'>La IP no es válida.</div>";
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Panel de Control</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="stylesheet" href="galaxia.css">
</head>
<body>
    <div class="container">
        <h1>Panel de Control</h1>

        <!-- Contador de visitas -->
        <h2>Total de Visitas: <?php echo count($access_log); ?></h2>

        <!-- Formulario para bloquear IPs -->
        

        <!-- Registro de accesos -->
        <h2>Registro de Accesos</h2>
        <table>
            <thead>
                <tr>
                    <th>IP</th>
                    <th>País</th>
                    <th>Ciudad</th>
                    <th>VPN/Proxy</th>
                    <th>Dispositivo</th>
                    <th>Navegador</th>
                    <th>Hora</th>
                    <th>Referido</th>
                    <th>Palabra Clave</th>
                    <th>Página</th>
                    <th>Acción</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($access_log as $log): ?>
                    <?php
                    // Dividir la entrada del log en un array
                    $log_data = explode(' | ', $log);

                    // Asignar valores predeterminados si el array no tiene suficientes elementos
                    $ip = $log_data[0] ?? 'Desconocido';
                    $user_agent = $log_data[1] ?? 'Desconocido';
                    $hora = $log_data[2] ?? 'Desconocido';
                    $referer = $log_data[3] ?? 'Desconocido';
                    $keyword = $log_data[4] ?? 'Desconocido';
                    $pagina = $log_data[5] ?? 'Desconocido';
                    $pais = $log_data[6] ?? 'Desconocido';
                    $ciudad = $log_data[7] ?? 'Desconocido';
                    $vpn_proxy = $log_data[8] ?? 'Desconocido';
                    $dispositivo = $log_data[9] ?? 'Desconocido';
                    $navegador = $log_data[10] ?? 'Desconocido';
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($ip); ?></td>
                        <td><?php echo htmlspecialchars($pais); ?></td>
                        <td><?php echo htmlspecialchars($ciudad); ?></td>
                        <td><?php echo htmlspecialchars($vpn_proxy); ?></td>
                        <td><?php echo htmlspecialchars($dispositivo); ?></td>
                        <td><?php echo htmlspecialchars($navegador); ?></td>
                        <td><?php echo htmlspecialchars($hora); ?></td>
                        <td><?php echo htmlspecialchars($referer); ?></td>
                        <td><?php echo htmlspecialchars($keyword); ?></td>
                        <td><?php echo htmlspecialchars($pagina); ?></td>
                        <td>
                            <form method="POST" action="">
                                <input type="hidden" name="ip" value="<?php echo htmlspecialchars($ip); ?>">
                                <button type="submit" name="block_ip" class="action-button">Bloquear</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Lista de IPs bloqueadas -->
        
		
        <a href="configuracion.php">Ir a Configuración</a>
        <a href="logout.php">Cerrar Sesión</a>
    </div>
</body>
</html>