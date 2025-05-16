<?php
// login.php

require 'includes/auth.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $usuario = filter_input(INPUT_POST, 'usuario', FILTER_SANITIZE_STRING);
    $contrasena = filter_input(INPUT_POST, 'contrasena', FILTER_SANITIZE_STRING);

    if (verificar_login($usuario, $contrasena)) {
        header('Location: configuracion.php');
        exit;
    } else {
        echo "<div class='message error'>Usuario o contraseña incorrectos.</div>";
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="stylesheet" href="galaxia.css">
</head>
<body>
    <div class="container">
        <h1>Iniciar Sesión</h1>
        <form method="POST" action="">
            <label for="usuario">Usuario:</label>
            <input type="text" id="usuario" name="usuario" required>
            <br>
            <label for="contrasena">Contraseña:</label>
            <input type="password" id="contrasena" name="contrasena" required>
            <br>
            <button type="submit">Iniciar Sesión</button>
        </form>
    </div>
</body>
</html>