<?php
// includes/auth.php

session_start();

// Credenciales de usuario (en un entorno real, usa una base de datos)
$usuarios = [
    'admin' => password_hash('Alucard33', PASSWORD_BCRYPT)
];

/**
 * Verifica las credenciales de inicio de sesión.
 *
 * @param string $usuario El nombre de usuario.
 * @param string $contrasena La contraseña.
 * @return bool True si las credenciales son válidas, False en caso contrario.
 */
function verificar_login($usuario, $contrasena) {
    global $usuarios;
    if (isset($usuarios[$usuario]) && password_verify($contrasena, $usuarios[$usuario])) {
        $_SESSION['usuario'] = $usuario;
        return true;
    }
    return false;
}

/**
 * Verifica si el usuario está autenticado.
 *
 * @return bool True si el usuario está autenticado, False en caso contrario.
 */
function esta_autenticado() {
    return isset($_SESSION['usuario']);
}

/**
 * Cierra la sesión del usuario.
 */
function cerrar_sesion() {
    session_destroy();
    header('Location: login.php');
    exit;
}