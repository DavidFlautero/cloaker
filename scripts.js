// scripts.js

// Función para actualizar la tabla en tiempo real
function actualizarTabla() {
    fetch('get_access_log.php') // Endpoint para obtener los registros de acceso
        .then(response => response.json())
        .then(data => {
            const tabla = document.querySelector('table');
            // Limpiar la tabla (excepto la cabecera)
            while (tabla.rows.length > 1) {
                tabla.deleteRow(1);
            }
            // Agregar los nuevos registros
            data.forEach(log => {
                const fila = tabla.insertRow();
                fila.innerHTML = `
                    <td>${log.ip}</td>
                    <td><img src="assets/flags/${log.pais}.png" alt="${log.pais}"> ${log.pais}</td>
                    <td><img src="assets/devices/${log.dispositivo}.png" alt="${log.dispositivo}"> ${log.dispositivo}</td>
                    <td><img src="assets/browsers/${log.navegador}.png" alt="${log.navegador}"> ${log.navegador}</td>
                    <td>${log.hora}</td>
                    <td>${log.referer}</td>
                    <td>${log.keyword}</td>
                    <td>${log.pagina}</td>
                    <td>
                        <form method="POST" action="">
                            <input type="hidden" name="ip" value="${log.ip}">
                            <button type="submit" name="block_ip">Bloquear</button>
                        </form>
                    </td>
                `;
            });
        })
        .catch(error => console.error('Error al actualizar la tabla:', error));
}

// Actualizar la tabla cada 5 segundos
setInterval(actualizarTabla, 5000);

// Ejecutar la función al cargar la página
document.addEventListener('DOMContentLoaded', actualizarTabla);