# Adaptador Android JNI para smoltcp DNS/TCP

## Estado actual

El transporte smoltcp 0.14 está conectado al `DnsFirewallService` productivo del repositorio `FirewallDNS` (main, commit `f1c124a`) para DNS TCP/53 IPv4/IPv6. El APK de diagnóstico reutiliza la biblioteca nativa y añade pruebas del límite JNI. La integración de código ya existe; la aceptación en hardware sigue pendiente.

## Arquitectura y propiedad de hilos

- Un único hilo dedicado es propietario de `smoltcp::Interface` y `SocketSet`.
- El lector TUN Android conserva el orden de los paquetes TCP y los ofrece a la cola JNI acotada.
- `nativeEnqueuePacket` solo valida y copia a la cola JNI; no toca smoltcp ni sus sockets.
- El hilo propietario llama a `poll`, drena eventos, encola respuestas, extrae paquetes TX y cierra sesiones.
- Los workers DNS por sesión procesan el decoder y el upstream; no acceden a objetos smoltcp.
- El owner se despierta por eventos y mantiene un tick acotado para procesar timers/retransmisiones.
- El cierre de sesión invalida workers, cierra el transporte y evita que respuestas tardías se escriban en una sesión TUN nueva.

## Camino DNS/TCP productivo

1. `DnsFirewallService` lee el descriptor TUN.
2. `IpFragmentReassembler` reensambla fragmentos IPv4/IPv6 compatibles dentro de límites de memoria y tiempo.
3. `DnsTcpPacketClassifier` identifica paquetes TCP destino 53 que pueden entrar al transporte.
4. El lector entrega los paquetes en orden a `SmoltcpDnsTcpCoordinator.offerPacket()`.
5. JNI añade cada paquete a una cola acotada de hasta 128 paquetes y 256 KiB.
6. Un solo hilo ejecuta `NativeTcpDnsTransport.poll()` y el `TcpDnsTransport` de smoltcp gestiona handshake, ACK, ventanas, retransmisiones, FIN/RST y stream TCP.
7. `SessionOpened` crea un procesador DNS por flujo; los eventos `Data` alimentan el decoder DNS/TCP incremental.
8. El motor compartido aplica BLOCK / OBSERVE / ALLOW. El upstream UDP/TCP usa `DnsUpstreamFailoverClient` y `AndroidDnsSocketProtector`, que llama a `VpnService.protect()` antes de conectar.
9. La respuesta DNS se encola en la sesión smoltcp; los paquetes de salida se escriben por el descriptor TUN original.

Si el transporte nativo no se crea o un paquete no es compatible con el clasificador, el camino alternativo no finge procesar DNS/TCP: el servicio aplica el fallback TCP RST a segmentos válidos. El tráfico TCP/UDP general no-DNS no se reenvía.

## Eventos JNI

Todos los enteros están en big-endian.

- Tipo 1, `SessionOpened`: byte tipo, u64 sessionId, dirección cliente (u8 familia 4/6 + 4/16 bytes), u16 puerto cliente, dirección servidor, u16 puerto servidor.
- Tipo 2, `Data`: byte tipo, u64 sessionId, u32 longitud, bytes.
- Tipo 3, `PeerHalfClosed`: byte tipo, u64 sessionId.
- Tipo 4, `SessionClosed`: byte tipo, u64 sessionId.

Una matriz vacía significa que no hay paquete/evento disponible. Los códigos de retorno de enqueue/queueResponse distinguen aceptación, cola llena, sesión inexistente, framing inválido y límite de respuesta.

## Límites y contabilidad

- Máximo predeterminado: 64 sesiones TCP DNS.
- Buffer TCP smoltcp: 16 KiB RX + 16 KiB TX por sesión.
- Cola de eventos: 256 eventos / 256 KiB.
- Cola de respuestas: 1 MiB global y 128 KiB por sesión.
- Workers DNS y buffers por sesión acotados; expiración de sesión y cancelación upstream.
- DNS TCP framing valida longitud y conserva los límites del mensaje DNS.
- El lector reensambla fragmentos compatibles antes de smoltcp; no se promete soporte para todas las extensiones IPv6 ni jumbograms.
- `smoltcpPacketsAccepted` significa aceptado por la cola JNI, no procesado por smoltcp.
- `smoltcpIngressRejected` suma rechazos en cola JNI y rechazos al insertar en la cola RX del dispositivo smoltcp. Se lee desde un contador atómico y no requiere acceso concurrente a Interface/SocketSet.
- `smoltcpNativeErrors` registra errores del límite JNI/poll; no reemplaza el contador de rechazos.

## Compilación

CI compila Rust para Android ARM64 con NDK/cargo-ndk y empaqueta la biblioteca `libfirewalldns_native.so` en los APK de FirewallDNS y Diagnóstico. Requisitos del workflow: Rust estable, Android NDK 27.2.12479018, cargo-ndk, Gradle y Java 21.

## Pruebas

Las pruebas host-side verifican transporte TCP DNS IPv4/IPv6, lifecycle y round-trip sintético. CI también ejecuta pruebas Rust/JVM, comprobación del target ARM64 y ensamblado de ambos APK. El diagnóstico instalado prueba JNI y, cuando FirewallDNS está activo, realiza consultas DNS UDP/TCP reales por la VPN.

Estas comprobaciones no sustituyen la prueba física completa en Samsung A34 5G: Wi-Fi/datos, reconexión, varias apps/sesiones, saturación de colas, retransmisiones, FIN/RST, protección upstream, pérdidas, latencia, CPU, batería y estabilidad prolongada.

DoH, DoT y DoQ no se inspeccionan mediante este transporte DNS/53. No declarar cobertura de tráfico general ni ausencia global de fugas.