<?php
// includes/auth.php

// Database connection (using PDO for security)
function get_db_connection() {
    $dsn = 'mysql:host=localhost;dbname=your_database;charset=utf8mb4';
    $username = 'your_username';
    $password = 'your_password';
    try {
        $pdo = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return $pdo;
    } catch (PDOException $e) {
        die("Connection failed: " . $e->getMessage());
    }
}

// Verify login credentials
function verificar_login($usuario, $contrasena) {
    $pdo = get_db_connection();
    $stmt = $pdo->prepare('SELECT password FROM users WHERE username = ?');
    $stmt->execute([$usuario]);
    $user = $stmt->fetch();

    if ($user && password_verify($contrasena, $user['password'])) {
        return true;
    }
    return false;
}

// Store remember me token
function store_remember_token($usuario, $token) {
    $pdo = get_db_connection();
    $hashed_token = password_hash($token, PASSWORD_DEFAULT);
    $stmt = $pdo->prepare('UPDATE users SET remember_token = ? WHERE username = ?');
    $stmt->execute([$hashed_token, $usuario]);
}
?>