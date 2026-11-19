# Decisión: frontera TUN y pila de paquetes

## Decisión de implementación

Se adopta `smoltcp` como candidato de pila IP/TCP/UDP integrada en Rust, sujeto a pruebas de compatibilidad, throughput, latencia, memoria y consumo en el Samsung Galaxy A34 5G. No se implementará TCP/IP desde cero.

La primera pieza es `rust-core::TunPacketDevice`: un adaptador de paquetes IP con colas RX/TX acotadas y límites MTU que implementa `smoltcp::phy::Device`. Es una frontera de datos en memoria, no un TUN Android ni un proxy de Internet.

## Contrato

- Kotlin conserva `VpnService`, el descriptor TUN y su ciclo de vida.
- El adaptador Android será responsable de leer/escribir paquetes completos del descriptor y pasarlos al dispositivo Rust.
- Rust/smoltcp consumirá paquetes RX y producirá paquetes TX.
- Los sockets externos deberán protegerse con `VpnService.protect()` antes de conectar.
- Ninguna cola será ilimitada; cada rechazo debe contabilizarse y comunicarse al host.
- La autoridad de políticas permanece en FirewallDNS-Engine.
- No se activa este dispositivo en la VPN de producción hasta que exista un procesador completo de flujos y pruebas de retorno de paquetes.

## Alcance de esta entrega

Implementa únicamente el dispositivo smoltcp con colas acotadas, validación de tamaño/MTU, contadores de rechazos y pruebas unitarias. No abre sockets, no crea flujos TCP/UDP, no realiza JNI, no lee/escribe el TUN y no se conecta a la VPN de producción.

## Siguientes puertas

1. Adaptador JNI con duplicación/cierre seguro del descriptor TUN y cancelación determinista.
2. Bucle smoltcp con temporización, poll y gestión de sockets.
3. Tabla de flujos UDP y TCP, sockets protegidos y traducción de paquetes bidireccional.
4. DNS UDP/TCP y políticas compartidas sin duplicar decisiones.
5. Pruebas de integración IPv4/IPv6, fragmentación/MTU, cierres, reconexión y saturación.
6. Pruebas en Galaxy A34 5G antes de habilitar la ruta en producción.

Esta secuencia evita sustituir el filtrado DNS que ya funciona por un plano de datos todavía incompleto.
