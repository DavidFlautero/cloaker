<?php
// configuracion.php

require 'includes/auth.php';
require 'includes/functions.php';

// Verificar autenticación
if (!esta_autenticado()) {
    header('Location: login.php');
    exit;
}

// Procesar el formulario de configuración
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitizar y validar entradas
    $url_redireccion = filter_input(INPUT_POST, 'url_redireccion', FILTER_VALIDATE_URL);
    $url_contenido_bots = filter_input(INPUT_POST, 'url_contenido_bots', FILTER_VALIDATE_URL);
    $palabras_clave = array_map('trim', explode(',', $_POST['palabras_clave']));
    $cloaker_activo = isset($_POST['cloaker_activo']);

    if (!$url_contenido_bots) {
        echo "<div class='message error'>La URL de contenido para bots no es válida.</div>";
    } else {
        // Guardar la configuración
        $configuracion = [
            'url_redireccion' => $url_redireccion,
            'url_contenido_bots' => $url_contenido_bots,
            'palabras_clave' => $palabras_clave,
            'cloaker_activo' => $cloaker_activo
        ];
        guardar_configuracion($configuracion);
        echo "<div class='message success'>Configuración guardada correctamente.</div>";
    }
}

// Leer la configuración actual
$configuracion = cargar_configuracion();
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Configuración</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="stylesheet" href="galaxia.css">
    <script>
        // Función para mostrar u ocultar campos según el estado del cloaker
        function toggleCloakerFields() {
            const cloakerActivo = document.getElementById('cloaker_activo').checked;
            const camposUsuarios = document.querySelectorAll('.campo-usuario');

            camposUsuarios.forEach(campo => {
                campo.style.display = cloakerActivo ? 'block' : 'none';
            });
        }

        // Ejecutar la función al cargar la página
        window.onload = toggleCloakerFields;
    </script>
</head>
<body>
    <div class="container">
        <h1>Configuración del Sistema</h1>
        <form method="POST" action="">
            <!-- Cloaker Activo -->
            <label for="cloaker_activo">Cloaker Activo:</label>
            <input type="checkbox" id="cloaker_activo" name="cloaker_activo" <?php echo $configuracion['cloaker_activo'] ? 'checked' : ''; ?> onchange="toggleCloakerFields()">
            <br>

            <!-- Campos que dependen del cloaker -->
            <div class="cloaker-field">
                <!-- URL de Redirección Externa -->
                <label for="url_redireccion">URL de Redirección Externa (para usuarios válidos):</label>
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
            </div>

            <!-- Botón de Guardar -->
            <button type="submit">Guardar Configuración</button>
        </form>

        <!-- Menú de navegación -->
        <div class="menu">
            <a href="admin.php">Volver al Panel de Control</a>
            <a href="registro_ip.php">Ver Registro de IPs</a> <!-- Nuevo enlace -->
            <a href="logout.php">Cerrar Sesión</a>
        </div>
    </div>
</body>
</html>