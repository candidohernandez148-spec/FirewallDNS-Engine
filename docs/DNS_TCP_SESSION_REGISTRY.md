# Registro de sesiones DNS sobre TCP

## Propósito

`DnsTcpSessionRegistry` administra el ciclo de vida acotado de los workers DNS/TCP. Mantiene una instancia de `DnsTcpSessionWorker` por identificador de flujo, limita el número de sesiones, actualiza actividad con reloj monotónico y permite expirar sesiones inactivas.

## Contrato del propietario del transporte

El hilo que posee `SocketSet` (cuando se complete el adaptador smoltcp) es el único que debe:

1. Abrir una sesión cuando el socket TCP esté establecido, usando un identificador estable que no se reutilice mientras siga viva la sesión.
2. Entregar a `offer(sessionId, bytes)` los fragmentos recibidos, exactamente en orden. El método copia y encola; no analiza DNS ni realiza I/O.
3. Drenar `drainResponses(sessionId)` y escribir los frames en el socket TCP desde el propietario de `SocketSet`.
4. Cerrar la sesión al recibir FIN/RST, al cerrar el socket o al detener el servicio.
5. Invocar `expireIdleSessions()` desde el ciclo de mantenimiento existente. El registro no crea temporizadores ni hilos globales.

El callback `onResponsesAvailable` solo debe despertar al propietario del transporte. No puede acceder a sockets smoltcp, ejecutar `Interface.poll()` ni hacer I/O desde el worker.

## Límites y fallos

- Máximo predeterminado: 64 sesiones.
- Inactividad predeterminada: 60 segundos, medida con `System.nanoTime()`.
- Cada sesión conserva los límites independientes de entrada/salida del worker.
- Una sesión duplicada o un registro lleno se rechaza explícitamente.
- Si el worker pierde bytes, se satura o falla, se cierra; no se continúa con un stream TCP desincronizado.
- Cerrar una sesión cancela el upstream correspondiente. El callback de cancelación debe ser no bloqueante y cerrar el socket upstream protegido activo.
- No se persisten dominios, consultas ni historial de tráfico.

## Alcance que todavía no cubre

Este registro es una capa JVM de ciclo de vida; no crea sockets TCP, no implementa ACK/SEQ, ventanas, retransmisión, backpressure de smoltcp, MTU, fragmentación IP, JNI, descriptor TUN ni `VpnService.protect()`. Tampoco se conecta por sí solo a `DnsFirewallService`. La integración del plano de datos requiere un adaptador nativo/JNI probado que respete la propiedad exclusiva de `SocketSet`, más pruebas IPv4/IPv6, cierre, carga, upstream protegido y pruebas físicas. TCP/53 de producción debe permanecer deshabilitado hasta superar esas puertas.
