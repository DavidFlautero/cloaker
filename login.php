<?php
// login.php

require 'includes/auth.php';

session_start();

// CSRF token generation
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Rate limiting (max 5 attempts per 15 minutes)
$rate_limit_key = 'login_attempts_' . $_SERVER['REMOTE_ADDR'];
$attempts = apcu_fetch($rate_limit_key) ?: 0;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $attempts < 5) {
    // Verify CSRF token
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
        $error = "Invalid CSRF token.";
    } else {
        $usuario = filter_input(INPUT_POST, 'usuario', FILTER_SANITIZE_STRING);
        $contrasena = filter_input(INPUT_POST, 'contrasena', FILTER_SANITIZE_STRING);

        if (verificar_login($usuario, $contrasena)) {
            // Regenerate session ID to prevent session fixation
            session_regenerate_id(true);
            $_SESSION['user'] = $usuario;

            // Handle "Remember Me"
            if (isset($_POST['remember'])) {
                $token = bin2hex(random_bytes(16));
                setcookie('remember_token', $token, time() + 30 * 24 * 3600, '/', '', true, true);
                // Store token in DB (assumed handled in auth.php)
                store_remember_token($usuario, $token);
            }

            header('Location: configuracion.php');
            exit;
        } else {
            $error = "Usuario o contraseña incorrectos.";
            apcu_store($rate_limit_key, $attempts + 1, 900); // 15 minutes
        }
    }
} elseif ($attempts >= 5) {
    $error = "Demasiados intentos. Intenta de nuevo en 15 minutos.";
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Inicia sesión de forma segura en tu cuenta.">
    <title>Iniciar Sesión</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <style>
        .bg-galaxy {
            background: linear-gradient(135deg, #1a1a3d 0%, #2a4066 100%);
            background-image: url('data:image/svg+xml,%3Csvg ...'); /* Add galaxy effect */
        }
        .error { color: #ef4444; }
        .toggle-password { cursor: pointer; }
    </style>
</head>
<body class="bg-galaxy min-h-screen flex items-center justify-center">
    <div class="container bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <h1 class="text-2xl font-bold text-center mb-6">Iniciar Sesión</h1>
        <?php if (isset($error)): ?>
            <div class="message error bg-red-100 p-4 rounded mb-4" role="alert"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <form method="POST" action="" id="login-form" class="space-y-4">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div>
                <label for="usuario" class="block text-sm font-medium">Usuario:</label>
                <input type="text" id="usuario" name="usuario" required
                       class="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500"
                       aria-describedby="usuario-error" maxlength="50">
                <div id="usuario-error" class="error text-sm hidden">El usuario es requerido.</div>
            </div>
            <div>
                <label for="contrasena" class="block text-sm font-medium">Contraseña:</label>
                <div class="relative">
                    <input type="password" id="contrasena" name="contrasena" required
                           class="w-full p-2 border rounded focus:ring-2 focus:ring-blue-500"
                           aria-describedby="contrasena-error" maxlength="100">
                    <span class="toggle-password absolute right-3 top-3" onclick="togglePassword()">👁️</span>
                </div>
                <div id="contrasena-error" class="error text-sm hidden">La contraseña es requerida.</div>
            </div>
            <div class="flex items-center">
                <input type="checkbox" id="remember" name="remember" class="mr-2">
                <label for="remember" class="text-sm">Recordarme</label>
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700">Iniciar Sesión</button>
        </form>
        <p class="text-center mt-4 text-sm">
            ¿No tienes cuenta? <a href="register.php" class="text-blue-600 hover:underline">Regístrate</a>
        </p>
    </div>
    <script>
        // Client-side validation and password toggle
        const form = document.getElementById('login-form');
        const usuarioInput = document.getElementById('usuario');
        const contrasenaInput = document.getElementById('contrasena');
        const usuarioError = document.getElementById('usuario-error');
        const contrasenaError = document.getElementById('contrasena-error');

        form.addEventListener('submit', (e) => {
            let valid = true;
            if (!usuarioInput.value.trim()) {
                usuarioError.classList.remove('hidden');
                valid = false;
            } else {
                usuarioError.classList.add('hidden');
            }
            if (!contrasenaInput.value) {
                contrasenaError.classList.remove('hidden');
                valid = false;
            } else {
                contrasenaError.classList.add('hidden');
            }
            if (!valid) e.preventDefault();
        });

        function togglePassword() {
            const input = contrasenaInput;
            const toggle = document.querySelector('.toggle-password');
            if (input.type === 'password') {
                input.type = 'text';
                toggle.textContent = '🙈';
            } else {
                input.type = 'password';
                toggle.textContent = '👁️';
            }
        }
    </script>
</body>
</html>