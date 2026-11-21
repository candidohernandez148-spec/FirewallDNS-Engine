# Recuperación de smoltcp como transporte TCP

## Decisión arquitectónica

Se recupera `smoltcp 0.14.0` en `rust-core` como implementación objetivo del transporte TCP del motor. No se continuará ampliando una pila TCP/IP propia en Kotlin. La lógica DNS, las decisiones BLOCK / OBSERVE / ALLOW y la composición del runtime permanecen en Kotlin por ahora; el ciclo de vida Android, `VpnService`, el descriptor TUN y `VpnService.protect()` siguen siendo responsabilidad del adaptador Android.

## Qué se recuperó en esta etapa

- Crate Rust con dependencia explícita de smoltcp 0.14.0 (Rust 1.91+, edición 2024).
- Dispositivo TUN virtual con colas RX/TX limitadas por paquetes y bytes.
- Pruebas host-side de TCP DNS sobre IPv4 e IPv6.
- Pruebas de ciclo de vida TCP (retransmisión, FIN y RST).
- Pruebas UDP smoltcp de dispositivo, RX y round-trip.
- Workflow de validación manual y automática en PRs que modifican el transporte, con pruebas Rust, comprobación del target Android ARM64 y tests Gradle.

## Qué NO significa esta recuperación

- La conexión JNI/TUN existe únicamente en el APK de diagnóstico de este repositorio; todavía no está integrada en el descriptor TUN de la aplicación principal FirewallDNS.
- El `TunTcpStack` Kotlin se conserva como referencia para rutas de diagnóstico que no se delegan al transporte DNS/TCP smoltcp.
- No habilita TCP/53 en el FirewallDNS de producción.
- No demuestra `VpnService.protect()`, ausencia de bucles/fugas, rendimiento ni estabilidad en el Samsung A34.
- Las pruebas host-side usan interfaces y paquetes sintéticos; no son pruebas de red física.

## Migración siguiente

1. Crear un adaptador Rust de propietario único de `smoltcp::iface::Interface` y `SocketSet`; ninguna otra hebra tocará sockets smoltcp.
2. Conectar colas TUN RX/TX acotadas con un ciclo de polling no bloqueante.
3. Implementar el puente de sockets upstream Android protegidos, exigiendo `VpnService.protect()` antes de `connect()` y fallo cerrado si no se protege.
4. Enlazar cada socket TCP DNS con el procesador DNS por sesión ya existente, preservando el orden del stream y límites de memoria/trabajo.
5. Añadir pruebas de ida/vuelta, saturación, cancelación, expiración, FIN/RST, IPv4/IPv6 y fallos de upstream.
6. Comparar la paridad funcional y el rendimiento antes de retirar `TunTcpStack` Kotlin del diagnóstico.
7. Integrar en el `DnsFirewallService` ya existente de la aplicación FirewallDNS, sin crear un segundo `VpnService`.
8. Activar TCP/53 solo después de pruebas físicas en el Samsung A34 5G.

## Compatibilidad temporal

El stack Kotlin actual se conserva únicamente como referencia de diagnóstico mientras se completa el adaptador smoltcp. No se considera la arquitectura objetivo y no debe recibir nuevas funciones TCP. Se retirará en un cambio posterior, cuando smoltcp cubra sus contratos y pruebas.


## Estado de la migración 0.14

La rama `feature/smoltcp-014-transport-foundation` migra la dependencia del núcleo nativo de 0.11 a 0.14.0, adapta el contrato `RxToken` y el atributo JNI requerido por Rust 2024. Esta migración es una base de compatibilidad; no declara implementado el adaptador de sesiones ni la integración con el TUN productivo. La aceptación depende de CI.


## Estado del transporte integrado

- smoltcp 0.14 implementa el transporte stateful DNS/TCP para IPv4 e IPv6.
- El puente JNI mantiene una cola de ingreso independiente y comprueba el hilo propietario de `Interface`/`SocketSet`.
- `DnsFirewallService` en FirewallDNS usa el transporte nativo en producción para TCP/53; el APK de diagnóstico también lo prueba directamente.
- El coordinador reutiliza el decoder incremental, decisiones DNS y upstream protegido, con límites de sesiones, buffers, eventos y colas.
- La CI compila la biblioteca ARM64 y empaqueta ambos APK.
- La aceptación final sigue dependiendo de pruebas físicas en Samsung A34 5G.
