# Decisión: frontera TUN y transporte smoltcp

## Alcance elegido

Se utiliza smoltcp 0.14.0 para el transporte TCP de DNS/53 en IPv4 e IPv6. No se implementa TCP/IP desde cero ni se activa un túnel de tráfico general. La política DNS continúa en FirewallDNS-Engine; Android conserva el único VpnService y el descriptor TUN.

## Contrato de concurrencia

- Kotlin es propietario del ciclo de vida del descriptor TUN y de sus streams.
- El lector TUN entrega paquetes TCP/53 en orden a una cola JNI acotada.
- Rust mantiene Interface y SocketSet dentro de una única instancia.
- Un único hilo propietario ejecuta poll, lee eventos, encola respuestas y cierra sesiones.
- Los workers DNS por sesión no acceden a objetos smoltcp; solo intercambian bytes y despiertan al propietario.
- Las colas, sesiones y buffers tienen límites explícitos.
- Los sockets upstream deben pasar VpnService.protect() antes de conectarse; un fallo de protección no se convierte en conexión alternativa sin proteger.

## Estado de integración

El camino TUN → JNI → smoltcp → sesión DNS incremental → política → upstream protegido → respuesta por el mismo flujo está conectado al DnsFirewallService de producción de FirewallDNS (main, commit f1c124a). El APK de diagnóstico reutiliza la biblioteca nativa. La integración de código está hecha; la validación física completa sigue pendiente.

El módulo rust-core::l4_packet también ofrece un validador estructural IPv4/IPv6 TCP/UDP con pruebas host-side. Ese validador independiente no debe confundirse con una garantía de que todos sus casos estén habilitados en el camino productivo.

## Fragmentación y límites de paquetes

El lector usa IpFragmentReassembler antes de clasificar paquetes. El reensamblador tiene límites de sesiones, bytes, tamaño de paquete y TTL monotónico; admite fragmentos IPv4 e IPv6 compatibles. Extensiones IPv6 no soportadas, jumbograms y casos fuera de los tests siguen siendo límites explícitos. La cobertura debe confirmarse con tráfico real, no inferirse del mero uso de la clase.

## Puertas restantes

1. Probar DNS TCP/53 real por IPv4 e IPv6 desde aplicaciones del teléfono.
2. Verificar handshake, pérdida/retransmisión, FIN/RST, concurrencia, límites y expiración.
3. Confirmar contadores de rechazo de cola y errores nativos con pruebas de saturación reproducibles.
4. Medir protección upstream y ausencia de recursión en Wi-Fi y datos móviles.
5. Medir latencia, throughput, CPU, memoria, batería y estabilidad prolongada.
6. Comparar resultados contra la implementación anterior antes de retirar cualquier código de referencia.

No habilitar TCP/UDP general ni afirmar inspección de DoH/DoT/DoQ como parte de esta decisión.