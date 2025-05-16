<?php
// logout.php

require 'includes/auth.php';

// Eliminar al usuario de la lista de usuarios activos
$current_user = $_SESSION['usuario'];
$active_users = file_exists('active_users.txt') ? file('active_users.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
$active_users = array_diff($active_users, [$current_user]);
file_put_contents('active_users.txt', implode(PHP_EOL, $active_users));

// Cerrar la sesión
cerrar_sesion();
?>