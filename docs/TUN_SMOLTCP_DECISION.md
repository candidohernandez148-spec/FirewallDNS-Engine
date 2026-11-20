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

## Validador L4 y framing DNS TCP

`rust-core::l4_packet` añade un preflight puro para IPv4/IPv6 TCP y UDP: IHL/longitudes, checksum IPv4, rechazo de fragmentos y extensiones IPv6, Data Offset TCP, checksum TCP con pseudo-cabecera, longitud UDP y semántica de checksum UDP IPv4/IPv6. Incluye pruebas host-side de paquetes válidos, checksums corruptos, truncamiento, fragmentación y extensiones no soportadas. El módulo se exporta desde la crate, pero todavía no se expone por JNI ni se invoca desde el lector TUN Android.

En la aplicación Android, el camino productivo DNS UDP ahora valida el paquete IP/transporte antes de leer puertos. TCP/53 válido recibe un RST conforme a la regla RFC para segmentos con/sin ACK; sigue siendo rechazo temporal, no DNS-over-TCP de cliente. El `DnsTcpFrameCodec` y el cliente upstream existente ya soportan el prefijo de 2 bytes y fallback UDP truncado → TCP en el lado upstream.

**Puerta pendiente para DNS-over-TCP de cliente:** conectar descriptor TUN existente → JNI → `TunPacketDevice` → `smoltcp::Socket<Tcp>` por flujo → decodificador incremental de mensajes DNS → motor de políticas → respuesta en el mismo socket TCP. Cada cola y tabla de flujos debe estar acotada; sockets externos protegidos antes de `connect`; cancelación y cierre de sesión deterministas. No habilitar full-tunnel ni sustituir la VPN productiva hasta completar pruebas de ida/vuelta IPv4/IPv6, concurrencia, timeouts, saturación, reconexión y dispositivo real.


## Acumulación incremental DNS sobre TCP

Se añade `DnsTcpStreamDecoder` como componente puro y acotado de `:dns-engine`:
- Mantiene un buffer fijo por instancia/conexión, sin crecimiento dinámico.
- Acepta fragmentos arbitrarios del flujo, incluidos prefijo de 2 bytes y cuerpo divididos entre lecturas.
- Extrae un frame completo por llamada y conserva los bytes posteriores para mensajes concatenados.
- Rechaza de forma atómica escrituras que exceden el presupuesto y pasa a estado terminal ante una longitud DNS inferior a 12 bytes.
- Permite limpiar el estado al cerrar/reutilizar una conexión mediante `reset()`.

Este componente no administra TCP, ACK, retransmisiones, ventanas ni sockets. Debe existir una instancia por conexión TCP aceptada por smoltcp y el consumidor debe drenar frames completos antes de aceptar más datos. No habilita DNS-over-TCP en el TUN productivo; sigue pendiente el puente TUN/JNI/smoltcp y la conexión con el motor de políticas y la respuesta por el mismo flujo.
