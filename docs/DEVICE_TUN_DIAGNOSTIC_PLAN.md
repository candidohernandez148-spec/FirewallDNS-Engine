# Plan de diagnóstico Android: VpnService.protect() y entrada TUN

## Estado

Diseño aprobado para implementación aislada. No forma parte de la VPN de producción y no sustituye Firestack.

## Hallazgo del anfitrión actual

`FirewallDNS/app/src/main/java/com/firewall/dns/service/FirewallVpnService.kt` establece el descriptor TUN y lo entrega a `Intra.connect(...)`. La lectura y el procesamiento de paquetes quedan dentro de Firestack. El repositorio anfitrión no expone un lector TUN Kotlin que permita instrumentar latencia de entrada sin modificar el camino productivo.

El adaptador `AndroidEngineRuntime` del motor compone `VpnService.protect()` para sockets upstream, pero aún no tiene lector TUN ni integración con el servicio de producción.

## Objetivo

Añadir al APK independiente `:device-diagnostics` una prueba que solicite consentimiento VPN explícito y mida únicamente:

1. Si `VpnService.protect(DatagramSocket)` devuelve `true` para un socket sintético.
2. Latencia desde el envío de datagramas UDP sintéticos hacia una ruta de prueba hasta que el lector del descriptor TUN de diagnóstico observa cada paquete.
3. P50, P95, P99, paquetes enviados/observados, pérdidas y errores.
4. Versión Android, modelo, transporte activo y estado de red validada, sin recopilar dominios, contenido de otras apps ni consultas DNS personales.

## Diseño aislado

- Implementar un `VpnService` exclusivo del módulo `:device-diagnostics`.
- Solicitar autorización mediante `VpnService.prepare()`; nunca activar la VPN sin interacción del usuario.
- Mostrar una advertencia visible: durante la prueba, Android mostrará el indicador/aviso de VPN y el tráfico que coincida con la ruta sintética se dirigirá al TUN de diagnóstico.
- Establecer una dirección privada de prueba y una única ruta IPv4 reservada para laboratorio (198.18.0.1/32).
- Enviar datagramas con payload binario aleatorio/contador; no usar DNS ni nombres de dominio.
- Leer el TUN en un hilo dedicado. Validar longitud de cabeceras IPv4/UDP antes de extraer el identificador de prueba.
- Medir con reloj monotónico (`elapsedRealtimeNanos` o `System.nanoTime`), correlacionando identificadores; no usar reloj de pared para latencias.
- Llamar a `protect()` sobre un socket de prueba independiente y registrar duración/booleano. No afirmar conectividad externa por el mero hecho de que devuelva true.
- Cerrar descriptor, sockets, hilo y notificación en todos los caminos: éxito, error, cancelación y revocación.
- Exportar un JSON versionado con `vpn_active`, `protect_measured`, `tun_ingress_measured`, contadores y percentiles.
- No capturar paquetes ajenos a la ruta de laboratorio, no reenviar tráfico, no actuar como DNS proxy y no cambiar DNS del sistema.

## Criterios de aceptación

- La app solicita consentimiento del sistema y no arranca el servicio antes de obtenerlo.
- El servicio se detiene al cancelar, revocar o cerrar la prueba; no deja una VPN de diagnóstico activa.
- 100 datagramas sintéticos enviados; cada paquete observado se correlaciona exactamente una vez; los no observados se contabilizan como pérdida.
- Pruebas unitarias del parser IPv4/UDP para cabeceras truncadas, IHL variable, longitud UDP inválida y payload corto.
- JSON validado y explícitamente separado de los diagnósticos loopback/public DNS existentes.
- CI compila el APK independiente y ejecuta pruebas unitarias.
- Repetir en Wi-Fi y datos móviles; no mezclar las muestras.
- Mantener Firestack y el servicio productivo intactos.

## Límites de interpretación

La latencia medida es **envío de socket a observación de paquete en TUN**, no RTT de red, no latencia DNS y no latencia completa de filtrado. Esta prueba no demuestra forwarding, resolución upstream, ausencia de fugas ni paridad funcional con Firestack. Esos puntos requieren etapas separadas y verificables.

## Secuencia de implementación

1. Parser puro IPv4/UDP + pruebas JVM.
2. Servicio VPN diagnóstico con ciclo de vida/consentimiento y lector TUN.
3. Pantalla de ejecución/exportación y schema JSON.
4. CI + instalación en Samsung SM-A346M.
5. Capturar resultados separados en Wi-Fi y datos móviles.
6. Solo después diseñar el siguiente test de forwarding/upstream; no conectar el motor a producción todavía.
