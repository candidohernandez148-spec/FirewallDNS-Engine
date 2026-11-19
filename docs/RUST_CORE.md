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

## Validación

- `cargo test --manifest-path rust-core/Cargo.toml`: pruebas deterministas del parser Rust.
- `cargo ndk -t arm64-v8a -o android-adapter/src/main/jniLibs build --manifest-path rust-core/Cargo.toml --release`: genera `libfirewalldns_native.so` para empaquetarlo en Android.
- `:android-adapter:assembleDebugAndroidTest`: compila la prueba instrumentada.
- `NativePacketCoreInstrumentedTest`: en un dispositivo ARM64 confirma que la biblioteca incluida en el APK carga, valida paquetes IPv4/IPv6 y rechaza entradas corruptas/truncadas.
- `gradle :android-adapter:connectedDebugAndroidTest`: ejecuta en dispositivo la comprobación de paridad y el benchmark A/B de preflight Kotlin frente a JNI Rust.
- Consultar las métricas con `adb logcat -s FirewallDNSBenchmark:I`. Se registran P50/P95/P99 en microsegundos para IPv4 e IPv6.

El benchmark mide exclusivamente la validación estructural equivalente y el coste de la llamada JNI; no mide la evaluación DNS completa, upstream, `VpnService.protect()`, el TUN activo ni la radio Wi-Fi/datos. No se usa un umbral automático ni se activa Rust en producción por el mero hecho de completar el test. La adopción exige resultados repetibles en el Samsung A34 5G y ausencia de regresiones funcionales.

La validación JNI en CI no demuestra rendimiento ni compatibilidad de la ruta TUN en el Galaxy A34. La adopción en producción exige pruebas comparativas, latencia P50/P95/P99, CPU, memoria, batería, concurrencia y cobertura de protocolos.
