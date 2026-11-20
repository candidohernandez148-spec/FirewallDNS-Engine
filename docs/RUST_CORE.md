# Núcleo nativo Rust: etapa experimental

## Decisión

Kotlin conserva el ciclo de vida Android (VpnService, TUN, permisos, sockets protegidos y UI). Rust se introduce gradualmente para componentes de procesamiento de paquetes que puedan demostrar una mejora medible. No se migra de golpe el motor de políticas ni el runtime.

## Primera entrega

rust-core compila como cdylib y exporta una función JNI que valida datagramas DNS/UDP transportados directamente por IPv4 o IPv6. Comprueba límites IP/UDP, destino UDP 53, checksum de cabecera IPv4, checksum UDP cuando está presente en IPv4 y checksum UDP obligatorio en IPv6. Rechaza fragmentos IPv4 y cabeceras de extensión IPv6 en esta primera versión.

La función devuelve:
- 4: paquete DNS/UDP IPv4 estructuralmente válido.
- 6: paquete DNS/UDP IPv6 estructuralmente válido.
- 0: paquete no admitido o inválido.
- -1: error al copiar el arreglo desde JNI.

## Límites explícitos

- No parsea ni decide dominios DNS.
- No ejecuta BLOCK / OBSERVE / ALLOW.
- No abre sockets, no accede al TUN y no hace I/O.
- No implementa TCP, fragmentación ni cabeceras de extensión IPv6.
- No sustituye TunDnsPacketProcessor.
- No se utiliza todavía en la ruta de producción: la llamada JNI adicional debe justificarse con un benchmark A/B frente al parser Kotlin, no asumirse más rápida.
- El primer artefacto Android se compila para arm64-v8a, ABI del Galaxy A34 5G. No implica cobertura de otros ABI.

## Base de paquetes UDP no DNS (primera etapa)

Se añade `udp_packet`, un decodificador puro que valida datagramas UDP IPv4/IPv6 completos y no fragmentados, comprueba longitudes y checksums, y expone direcciones, puertos y payload sin copiarlo. A diferencia del preflight DNS existente, acepta puertos de destino distintos de 53. Rechaza fragmentos IPv4 y cabeceras de extensión IPv6 hasta que el stack elegido gestione esos casos.

Este cambio **no transporta ni reenvía tráfico**: no abre sockets, no llama a `VpnService.protect()`, no accede al TUN, no modifica `TunDnsPacketProcessor` ni cambia la ruta DNS de producción. Es la frontera de validación previa para la siguiente etapa, donde se probará el flujo UDP con el stack smoltcp y un adaptador de sockets protegidos. No debe conectarse a la VPN activa todavía.

Pruebas añadidas: UDP no DNS por IPv4 e IPv6, checksum IPv4 opcional, checksum IPv6 obligatorio, puertos y payload, fragmentación, cabeceras de extensión, longitudes incorrectas, checksum corrupto y protocolo no UDP.

## Prueba de socket UDP sobre smoltcp (etapa de laboratorio)

Se incorpora `rust-core/tests/smoltcp_udp_device.rs` como prueba de integración host-side. Construye una interfaz smoltcp con una dirección IPv4 de laboratorio, enlaza un socket UDP, genera un datagrama hacia el puerto 443 y comprueba que el paquete emitido por la cola TX acotada pasa la validación UDP independiente (direcciones, puertos, payload y checksum). La prueba utiliza la API `PacketBuffer` de smoltcp 0.11.

Esta prueba valida únicamente el tramo **socket UDP smoltcp → interfaz IP → cola TX virtual**. No representa una conexión a Internet ni una retransmisión por socket Android protegido. No valida recepción desde la red, timeouts, fragmentación, IPv6 end-to-end, control de flujo, protección contra bucles, ni integración con el TUN real. Por tanto, el adaptador no se activa en producción y DNS permanece sin cambios.

Primera pieza del adaptador Android de UDP protegido: `AndroidProtectedUdpSocketFactory` crea un socket no conectado, configura sus límites, exige que `VpnService.protect()` tenga éxito y solo entonces ejecuta `connect()`. Rechaza endpoints no resueltos y límites fuera de rango; ante cualquier fallo cierra el socket y no continúa sin protección. El llamador es dueño del socket y debe cerrarlo al terminar el flujo. Las pruebas JVM comprueban el orden protect→connect, el cierre cuando la protección falla y la validación previa de endpoint/límites.

Se añade `AndroidUdpFlowManager` como gestor experimental de flujos protegidos. Limita el número de flujos, usa una cola de salida acotada por flujo, valida el tamaño de datagramas, procesa cada flujo en un worker dedicado con recepción temporizada y envía los datagramas recibidos al callback. `close()` cierra sockets y cancela los workers; cada flujo también puede cerrarse individualmente. Los contadores locales exponen datagramas enviados, recibidos y rechazados. Las pruebas loopback verifican ida y vuelta, límite de flujos, liberación de capacidad y rechazo de datagramas inválidos.

Este gestor **no es todavía el puente TUN/smoltcp**: no convierte paquetes IP en flujos ni inyecta respuestas en el TUN, no gestiona fragmentación/IPv6 extendido y no está conectado al servicio VPN productivo. Los callbacks se ejecutan en el worker del flujo y deben ser breves/no bloqueantes. El host debe cerrar el gestor al destruir su sesión. DNS productivo permanece intacto. Siguiente puerta: integrar este transporte en un servicio de diagnóstico aislado y conectar RX/TX con smoltcp mediante colas acotadas y pruebas de ida/vuelta antes de considerar cualquier activación.

## Validación

- `cargo test --manifest-path rust-core/Cargo.toml`: pruebas deterministas del parser Rust.
- `cargo ndk -t arm64-v8a -o android-adapter/src/main/jniLibs build --manifest-path rust-core/Cargo.toml --release`: genera `libfirewalldns_native.so` para empaquetarlo en Android.
- `:android-adapter:assembleDebugAndroidTest`: compila la prueba instrumentada.
- `NativePacketCoreInstrumentedTest`: en un dispositivo ARM64 confirma que la biblioteca incluida en el APK carga, valida paquetes IPv4/IPv6 y rechaza entradas corruptas/truncadas.
- `gradle :android-adapter:connectedDebugAndroidTest`: ejecuta en dispositivo la comprobación de paridad y el benchmark A/B de preflight Kotlin frente a JNI Rust.
- Consultar las métricas con `adb logcat -s FirewallDNSBenchmark:I`. Se registran P50/P95/P99 en microsegundos para IPv4 e IPv6.

El benchmark mide exclusivamente la validación estructural equivalente y el coste de la llamada JNI; no mide la evaluación DNS completa, upstream, `VpnService.protect()`, el TUN activo ni la radio Wi-Fi/datos. No se usa un umbral automático ni se activa Rust en producción por el mero hecho de completar el test. La adopción exige resultados repetibles en el Samsung A34 5G y ausencia de regresiones funcionales.

La validación JNI en CI no demuestra rendimiento ni compatibilidad de la ruta TUN en el Galaxy A34. La adopción en producción exige pruebas comparativas, latencia P50/P95/P99, CPU, memoria, batería, concurrencia y cobertura de protocolos.


## Colas smoltcp limitadas por bytes (preparación del puente)

`TunPacketDevice` ahora limita RX y TX por dos dimensiones independientes: cantidad de paquetes y bytes retenidos. El constructor compatible `new()` deriva presupuestos de `MTU × capacidad`; `new_with_byte_limits()` permite fijarlos explícitamente. Al consumir un paquete RX o extraer un paquete TX, los bytes se liberan y vuelven a estar disponibles. Los rechazos por presupuesto RX se distinguen como `ReceiveByteLimit`; los TX se contabilizan en `tx_rejected`.

Esta mejora evita que una cola con pocos paquetes grandes retenga más memoria de la prevista y prepara el límite de memoria del futuro puente TUN/smoltcp. No crea todavía el ciclo de polling, asociación de flujos ni reenvío a sockets Android. El TUN productivo y el DNS siguen sin cambios. Las pruebas unitarias cubren saturación por bytes, liberación de presupuesto y recuperación tras dequeue.


## Prueba de ingreso UDP desde TUN a smoltcp (laboratorio)

Se añade `rust-core/tests/smoltcp_udp_rx.rs`. La prueba construye un paquete IPv4/UDP de entrada con checksum IPv4 válido, lo introduce en la cola RX acotada de `TunPacketDevice`, ejecuta `Interface.poll()` y comprueba que el socket UDP enlazado al puerto destino recibe exactamente el payload y el endpoint remoto esperados. También verifica que el consumo libera los bytes retenidos en RX.

Junto con la prueba TX existente, esto cubre ambos sentidos del dispositivo virtual: **cola RX → interfaz smoltcp → socket UDP** y **socket UDP → interfaz smoltcp → cola TX**. Sigue siendo una prueba host-side con paquetes sintéticos; no conecta sockets Android, no llama a `VpnService.protect()`, no prueba Internet ni el descriptor TUN real, no implementa el mapeo de flujos ni el ciclo de vida del puente. No habilita UDP general ni modifica DNS productivo.


## Prueba de ida y vuelta UDP smoltcp con socket loopback (laboratorio)

Se añade `rust-core/tests/smoltcp_udp_roundtrip.rs`. La prueba toma un datagrama producido por un socket UDP de smoltcp y extraído de la cola TX, lo valida y lo transporta mediante un socket UDP loopback del host. La respuesta se encapsula en un paquete IPv4/UDP sintético, se introduce en la cola RX acotada y se entrega al socket smoltcp mediante `Interface.poll()`. Se comprueban payload, puertos, endpoint remoto y liberación de la cola RX.

Este es un arnés de ida y vuelta de la frontera smoltcp y del contrato de transporte; el socket loopback sustituye al socket Android. **No prueba `VpnService.protect()`, un descriptor TUN real, JNI persistente, rutas a Internet, IPv6, fragmentación ni la VPN de producción.** No modifica ni intercepta el DNS productivo. La siguiente etapa debe integrar el ciclo de polling y el gestor de sockets Android en un servicio de diagnóstico aislado, manteniendo el protector obligatorio y el cierre ligado al ciclo de vida del servicio.

## Puente UDP TUN protegido (diagnóstico Android aislado)

Se añade `AndroidUdpTunBridge` junto con `UdpTunPacketCodec`. El puente acepta paquetes UDP completos IPv4 y IPv6 básico, rechaza fragmentación IPv4 y cabeceras de extensión IPv6, y deja el puerto destino 53 al procesador DNS existente. Para los demás puertos crea asociaciones acotadas mediante `AndroidUdpFlowManager`; cada socket de salida exige `VpnService.protect()` antes de `connect()`. Las respuestas se reconstruyen como paquetes IP/UDP con checksums y se entregan al callback de escritura TUN.

El APK `device-diagnostics` incorpora `UdpTunBridgeDiagnosticService`: crea un TUN con una única ruta sintética (`198.18.0.1/32`), envía un datagrama de prueba desde el propio dispositivo, lo transporta mediante un socket protegido hacia un eco UDP de loopback y espera la respuesta reconstruida por el TUN. No usa Internet público, no captura consultas DNS, no modifica el servicio VPN productivo y no activa el puente en FirewallDNS.

Esta prueba es el primer recorrido Android real del contrato UDP TUN/protección de sockets, pero **todavía no conecta el procesamiento de paquetes a smoltcp ni al motor Rust**. El puente actual es Kotlin experimental; la migración del parser/ciclo de paquetes a Rust debe mantener paridad de paquetes y pasar las mismas pruebas antes de retirar el adaptador Kotlin. No se afirma compatibilidad con fragmentación, IPv6 extension headers, ICMP, TCP, ni tráfico UDP general en producción.


## Expiración de flujos UDP inactivos

`AndroidUdpFlowManager` aplica un timeout de inactividad monotónico y configurable (60 s por defecto, acotado a 300 s). Si no se envían ni reciben datagramas durante ese periodo, notifica `onIdleTimeout()`, cierra el socket y libera el worker y la plaza del límite de flujos. `AndroidUdpTunBridge` elimina también la asociación correspondiente para que un paquete posterior pueda crear un flujo nuevo. El callback de expiración no cambia la ruta DNS ni activa forwarding productivo.

La expiración se comprueba después de los timeouts de recepción acotados; no requiere un hilo global de temporización. Las pruebas JVM verifican notificación, eliminación del flujo y recuperación de capacidad. Sigue siendo un componente experimental y no valida transporte smoltcp/TCP ni conectividad UDP pública.


## Prueba TCP DNS sobre smoltcp (laboratorio host-side)

Se añade `rust-core/tests/smoltcp_tcp_dns.rs`. La prueba crea dos interfaces smoltcp IPv4 conectadas mediante dos instancias de `TunPacketDevice` con límites simultáneos de paquetes y bytes. Un socket TCP cliente completa SYN/SYN-ACK/ACK contra un listener en el puerto 53; después envía dos mensajes DNS con prefijo de longitud de dos bytes, dividiendo el primer prefijo/cuerpo entre escrituras y concatenando el segundo mensaje en el mismo stream. El servidor recibe el flujo TCP ordenado y se comprueba que los bytes coinciden exactamente con los dos frames esperados.

La prueba demuestra únicamente **handshake TCP, transporte de stream, y movimiento RX/TX a través del dispositivo virtual smoltcp** en host. No interpreta las consultas DNS, no llama a `EngineRuntime`, no abre upstream, no crea JNI persistente, no usa Android `VpnService.protect()` ni un descriptor TUN real. Tampoco valida IPv6, retransmisiones bajo pérdida inducida, límites de concurrencia de sockets ni cierre/reinicio de servicio. No se habilita TCP/53 en FirewallDNS. La siguiente puerta es incorporar límites y ciclo de vida explícitos de sockets TCP, probar timeouts/cierre/reset y conectar el frame completo al decoder DNS y al mismo motor de políticas antes de cualquier adaptador Android.
