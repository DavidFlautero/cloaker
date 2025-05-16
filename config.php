<?php
// configuracion.php

require 'includes/auth.php';
require 'includes/functions.php';

// Verificar autenticacion
if (!esta_autenticado()) {
    header('Location: login.php');
    exit;
}

// Procesar el formulario de configuracion
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitizar y validar entradas
    $url_redireccion = validar_url($_POST['url_redireccion']);
    $url_contenido_bots = validar_url($_POST['url_contenido_bots']);
    $palabras_clave = array_map('sanitizar', explode(',', $_POST['palabras_clave']));
    $cloaker_activo = isset($_POST['cloaker_activo']);

    if (!$url_redireccion || !$url_contenido_bots) {
        echo "<div class='message error'>Las URLs proporcionadas no son validas.</div>";
    } else {
        // Guardar la configuracion
        $configuracion = [
            'url_redireccion' => $url_redireccion,
            'url_contenido_bots' => $url_contenido_bots,
            'palabras_clave' => $palabras_clave,
            'cloaker_activo' => $cloaker_activo
        ];
        guardar_configuracion($configuracion);
        echo "<div class='message success'>Configuracion guardada correctamente.</div>";
    }
}

// Leer la configuracion actual
$configuracion = cargar_configuracion();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuracion</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="stylesheet" href="galaxia.css">
</head>
<body>
    <div class="container">
        <h1>Configuracion del Sistema</h1>
        <form method="POST" action="">
            <!-- URL de Redireccion Externa -->
            <label for="url_redireccion">URL de Redireccion Externa (para usuarios validos):</label>
            <input type="url" id="url_redireccion" name="url_redireccion" value="<?php echo htmlspecialchars($configuracion['url_redireccion']); ?>" required>
            <br>

            <!-- URL de Contenido para Bots -->
            <label for="url_contenido_bots">URL de Contenido para Bots:</label>
            <input type="url" id="url_contenido_bots" name="url_contenido_bots" value="<?php echo htmlspecialchars($configuracion['url_contenido_bots']); ?>" required>
            <br>

            <!-- Palabras Clave -->
            <label for="palabras_clave">Palabras Clave (separadas por comas):</label>
            <input type="text" id="palabras_clave" name="palabras_clave" value="<?php echo htmlspecialchars(implode(',', $configuracion['palabras_clave'])); ?>" required>
            <br>

            <!-- Cloaker Activo -->
            <label for="cloaker_activo">Cloaker Activo:</label>
            <input type="checkbox" id="cloaker_activo" name="cloaker_activo" <?php echo $configuracion['cloaker_activo'] ? 'checked' : ''; ?>>
            <br>

            <!-- Boton de Guardar -->
            <button type="submit">Guardar Configuracion</button>
        </form>
        <a href="admin.php">Volver al Panel de Control</a>
        <a href="logout.php">Cerrar Sesion</a>
    </div>
</body>
</html>