# Adaptador Android JNI para smoltcp DNS/TCP

## Estado

Esta implementación conecta el transporte smoltcp 0.14 al TUN del APK de diagnóstico de FirewallDNS-Engine. No integra todavía el transporte en la aplicación principal FirewallDNS ni habilita TCP/53 en su servicio productivo.

## Arquitectura y propiedad de hilos

- Un único hilo dedicado es propietario de smoltcp Interface y SocketSet.
- El lector TUN entrega los paquetes TCP/53 no fragmentados al coordinador y a la cola JNI de forma síncrona y en orden; JNI los copia a una cola acotada a 128 paquetes y 256 KiB. El trabajo DNS/upstream se ejecuta en workers por sesión.
- El hilo propietario llama a poll(), takeEvent(), queueResponse(), closeSession() y takePacket().
- El puente Rust comprueba ThreadId y rechaza accesos del propietario desde otro hilo.
- Las colas RX/TX del dispositivo smoltcp están limitadas por paquetes y bytes.
- El cierre FIN de una sesión half-closed espera a que las respuestas pendientes hayan entrado en el buffer TCP de smoltcp; si no se pueden drenar, se conserva la sesión hasta timeout en vez de descartar silenciosamente los bytes.
- El sondeo procesa hasta 32 paquetes por lote y hasta cuatro lotes por tick; no usa Interface::poll sin límite.

## Camino DNS/TCP

1. El lector TUN identifica TCP destino puerto 53.
2. El paquete pasa primero por el coordinador Android existente para guardas de bucle y política de seguridad.
3. Solo paquetes IP completos/no fragmentados se ofrecen a smoltcp en el mismo orden en que se leen del TUN. TCP fragmentado permanece en la ruta de reensamblado y pila Kotlin de diagnóstico; no se pasa el fragmento original al motor nativo.
4. smoltcp administra handshake, ACK, ventanas, retransmisiones, FIN/RST y el stream TCP IPv4/IPv6.
5. El evento SessionOpened crea un DnsTcpSessionRegistry entry y un DnsTcpSessionProcessor por flujo.
6. Los bytes Data se entregan en orden al decoder DNS TCP y a la política BLOCK/OBSERVE/ALLOW.
7. Las consultas upstream usan TunDataPlaneCoordinator.exchangeProtectedUpstream(), que reutiliza el cliente failover existente y AuditedDnsSocketProtector. VpnService.protect() se ejecuta antes de connect(); si falla, el intercambio falla cerrado.
8. Las respuestas DNS TCP completas vuelven por queueResponse() a la misma sesión smoltcp y sus paquetes se escriben por el descriptor TUN original.

No se abre un TcpStream Rust directo ni se crea un segundo VpnService.

## Formato de eventos JNI

Todos los enteros están en big-endian.

- Tipo 1, SessionOpened: byte tipo, u64 sessionId, dirección cliente (u8 familia 4/6 + 4/16 bytes), u16 puerto cliente, dirección servidor, u16 puerto servidor.
- Tipo 2, Data: byte tipo, u64 sessionId, u32 longitud, bytes.
- Tipo 3, PeerHalfClosed: byte tipo, u64 sessionId.
- Tipo 4, SessionClosed: byte tipo, u64 sessionId.

Una matriz vacía significa que no hay paquete/evento disponible. Los códigos de retorno de enqueue/queueResponse distinguen aceptación, cola llena, sesión inexistente, framing inválido y límite de respuesta.

## Límites y seguridad

- Máximo predeterminado: 64 sesiones.
- Buffer TCP smoltcp: 16 KiB RX + 16 KiB TX por sesión.
- Cola de eventos: 256 eventos / 256 KiB.
- Cola de respuestas: 1 MiB global y 128 KiB por sesión.
- Workers DNS: entrada y salida acotadas, cancelación por sesión y expiración idle de 60 s.
- smoltcp transport idle timeout: 120 s.
- DNS TCP framing valida longitudes completas de 12 a 65535 bytes.
- smoltcp recibe IPv4/IPv6 no fragmentados; los encabezados de extensión IPv6 solo se delegan cuando los admite el parser del transporte. Los paquetes con encabezado Fragment IPv6 y los fragmentos IPv4 permanecen en la ruta de reensamblado/pila Kotlin de diagnóstico. ESP queda fuera.
- El servicio de diagnóstico conserva la arquitectura UDP y las guardas existentes. La cola nativa recibe TCP/53 en orden; no se usa el pool concurrente de workers para ordenar segmentos TCP.
- DoH, DoT y DoQ no se descifran por inspección DNS TCP; no se declara inspección universal ni ausencia global de fugas.

## Compilación

El APK de diagnóstico se compila para ARM64 (Samsung A34 5G):

- Rust estable 1.91 o posterior.
- Android NDK 27.2.12479018.
- cargo-ndk.
- Gradle 8.12 y Java 21.

El módulo android-adapter ejecuta cargo ndk durante preBuild y empaqueta libfirewalldns_native.so desde build/generated/jniLibs/arm64-v8a.

## Pruebas y lo que todavía falta

CI ejecuta pruebas Rust host-side de handshake, stream y round-trip IPv4, handshake/stream IPv6, pruebas JVM, check de Rust Android ARM64 y ensamblado del APK con JNI.

Estas comprobaciones no sustituyen pruebas físicas. Antes de producción deben validarse en Samsung A34 5G: Wi-Fi/datos, reconexión, múltiples apps/sesiones, presión de colas, retransmisiones, FIN/RST, protección de upstream, consumo de batería, estabilidad prolongada y ausencia de bucles en las rutas realmente interceptadas.

La integración en app/src/main/java/com/firewall/dns/service/DnsFirewallService.kt del repositorio FirewallDNS queda pendiente. TCP/53 permanece deshabilitado en producción hasta superar esas pruebas.
