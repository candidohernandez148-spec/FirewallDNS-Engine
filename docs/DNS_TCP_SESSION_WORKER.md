# Worker acotado de sesiones DNS sobre TCP

`DnsTcpSessionWorker` separa el procesador de políticas/upstream del propietario del socket TCP (por ejemplo, el hilo que posee el `SocketSet` de smoltcp).

## Contrato

- Una instancia por conexión TCP; el host entrega fragmentos en orden mediante `offer()`.
- `offer()` copia el fragmento y solo lo encola. No ejecuta parser DNS ni I/O upstream.
- Una cola FIFO y un solo worker por sesión preservan el orden del stream.
- El worker ejecuta `DnsTcpSessionProcessor`, incluyendo la evaluación DNS y el callback upstream síncrono.
- Las respuestas completas quedan en una cola de salida acotada. El propietario del `SocketSet` las extrae mediante `drainResponses()` y es el único que escribe en el socket smoltcp.
- `onResponsesAvailable` es solo una señal de despertar; debe ser breve y no debe tocar sockets ni hacer I/O.
- Si se pierde cualquier fragmento de entrada, se supera el presupuesto de respuestas o falla el procesamiento, la sesión se cierra. No se continúa con un stream TCP desincronizado.
- `close()` debe invocarse al recibir FIN/RST, al expirar el flujo o al detener el servicio. `cancelUpstream` debe cerrar rápidamente el socket upstream protegido activo y no bloquear al llamador.

## Límites y exclusiones

Los límites predeterminados son 256 KiB de entrada encolada, 32 fragmentos, 256 KiB de respuestas y 128 frames de respuesta. Se pueden reducir por host. El procesador mantiene además su propio límite de bytes de framing y de frames por lote.

Esta pieza no crea ni acepta sockets smoltcp, no procesa ACK/SEQ, ventanas, retransmisiones, MTU, IP fragments ni IPv6 extension headers. Tampoco crea JNI, no accede al descriptor TUN, no llama a `VpnService.protect()` y no integra el servicio VPN productivo. El callback upstream debe reutilizar el cliente DNS Android existente y su protector obligatorio.

La llamada a `offer()` y `drainResponses()` debe hacerse desde el propietario del socket; nunca se ejecuta el callback upstream en el lector TUN ni en `Interface.poll()`. La cola llena provoca cierre explícito del flujo en vez de pérdida silenciosa.

## Verificación

`DnsTcpSessionWorkerTest` cubre el recorrido worker→respuesta→drenaje, cierre al llenarse la cola de entrada con cancelación del upstream y cierre cuando la cola de respuestas no puede retener el lote completo. Estas son pruebas JVM del contrato de concurrencia; no sustituyen el siguiente test de integración smoltcp ni una prueba Android real.
