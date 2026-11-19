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

## Validación

- cargo test --manifest-path rust-core/Cargo.toml: pruebas deterministas del parser Rust.
- cargo ndk -t arm64-v8a -o android-adapter/src/main/jniLibs build --manifest-path rust-core/Cargo.toml --release: genera libfirewalldns_native.so para empaquetarlo en Android.
- :android-adapter:assembleDebugAndroidTest: compila la prueba instrumentada.
- NativePacketCoreInstrumentedTest: en un dispositivo ARM64 confirma que la biblioteca incluida en el APK carga y responde a una entrada truncada.

La validación JNI en CI no demuestra rendimiento ni compatibilidad de la ruta TUN en el Galaxy A34. La adopción en producción exige pruebas comparativas, latencia P50/P95/P99, CPU, memoria, batería, concurrencia y cobertura de protocolos.
