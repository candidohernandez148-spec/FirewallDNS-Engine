# Plan de sustitución de Firestack por FirewallDNS-Engine

## Decisión

La arquitectura final tendrá un solo motor: `FirewallDNS-Engine`. La aplicación `FirewallDNS` será el anfitrión Android y conservará las responsabilidades de interfaz, permisos, ciclo de vida de `VpnService`, configuración y presentación. Firestack se utiliza exclusivamente como referencia temporal de compatibilidad; no será una dependencia ni un segundo motor en el resultado final.

## Capacidades que deben inventariarse y validarse

- Captura y ciclo de vida del túnel VPN IPv4/IPv6.
- Transporte TCP/UDP, gestión de flujos, cierres, errores y reconexión.
- DNS UDP y TCP, EDNS(0), IPv4/IPv6, respuestas válidas y errores.
- Protección de sockets upstream con `VpnService.protect()` antes de conectarlos.
- Identidad de aplicación/UID y reglas por aplicación.
- Bloqueo de dominios, IP de sinkhole, reglas de usuario, listas y excepciones.
- Políticas explicables BLOCK / OBSERVE / ALLOW, con prioridad y procedencia.
- Indicadores integrados/curados, reputación determinista y allowlist de dominios esenciales; sin aprendizaje persistente.
- Métricas en tiempo real sin bloquear la ruta de red.
- Resiliencia a cambios Wi-Fi/datos móviles, suspensión, revocación VPN y falta de upstream.

## Contrato de integración

1. El motor expone interfaces neutrales de plataforma; no depende de clases Android.
2. La aplicación implementa adaptadores Android para TUN, identidad UID, almacenamiento de configuración explícita, reloj y protección de sockets.
3. La decisión de dominio y conexión se realiza exclusivamente en FirewallDNS-Engine.
4. La UI observa snapshots/eventos acotados; nunca ejecuta trabajo pesado en el hilo principal.
5. El upstream y cualquier I/O se ejecutan fuera de la ruta crítica.
6. La aplicación no mantiene una segunda implementación de reglas ni decisiones una vez completada la migración. No se añadirá aprendizaje persistente.

## Puertas de validación antes de retirar Firestack

- Matriz de paridad de funciones y resultados con casos reproducibles.
- Pruebas unitarias y de integración del motor, incluidas entradas malformadas y fallos de red.
- Pruebas Android en dispositivo real para VPN, protección de sockets, UID, Wi-Fi/datos y revocación.
- Verificación de ausencia de bucles DNS y fugas en IPv4/IPv6.
- Comparación de latencia P50/P95, throughput, CPU, memoria y batería.
- Confirmación de que el dashboard y el historial reciben eventos oportunos sin bloquear el filtrado.
- Build debug/release y CI verde.

No se elimina Firestack ni se cambia el servicio VPN predeterminado antes de superar todas estas puertas. Cuando estén superadas, se elimina la dependencia, el puente, los flujos de inicialización y las referencias documentales a Firestack como tecnología activa en un cambio controlado.

## Secuencia de implementación

1. Endurecer los contratos del motor y sus pruebas.
2. Completar DNS upstream, caché de respuestas TTL y concurrencia.
3. Completar políticas, indicadores curados, heurísticas deterministas y monitorización; excluir aprendizaje persistente.
4. Implementar la abstracción de procesamiento de paquetes y conexiones sin crear una pila TCP/IP propia sin justificación.
5. Publicar/versionar el motor y consumirlo desde Android.
6. Implementar adaptadores Android y ejecutar la matriz de pruebas en dispositivo.
7. Cambiar el servicio activo al motor nuevo y retirar Firestack tras la validación.

## Estado actual revisado

El repositorio contiene módulos Gradle para `engine-core`, `dns-engine`, `threat-engine`, `engine-monitor`, `engine-runtime` y `android-adapter`. El adaptador Android implementa la protección de sockets upstream UDP/TCP mediante `VpnService.protect()` y ahora expone `AndroidEngineRuntime` como punto de composición: entrega la fachada `EngineRuntime` y construye clientes DNS failover que usan obligatoriamente el protector asociado al `VpnService` activo. Una prueba JVM de integración verifica el cableado real del cliente UDP hasta `VpnService.protect()` con un responder loopback. También existe un benchmark de instrumentación Android para loopback y caché.

Esta composición no crea un plano de datos VPN: todavía faltan TUN, procesamiento de paquetes/conexiones, identidad Android y pruebas en hardware con una VPN activa y sockets realmente excluidos del túnel. La prueba loopback usa un `VpnService` simulado y no acredita ausencia de bucles o fugas. La sustitución completa no es segura. Firestack debe permanecer como referencia de paridad hasta superar las puertas descritas en este plan.


## Evaluación gradual de Rust

Se añadió un primer crate Rust/JNI aislado para validación de datagramas DNS UDP IPv4/IPv6. No sustituye el runtime Kotlin ni modifica el servicio VPN. CI compila y empaqueta la biblioteca para arm64-v8a y compila una prueba instrumentada de carga JNI. El siguiente paso es ejecutar la prueba en hardware y crear un benchmark A/B; solo si reduce latencia o coste de CPU sin cambiar resultados se migrará esa responsabilidad. Las políticas y decisiones siguen centralizadas en EngineRuntime hasta que una migración posterior tenga contrato, pruebas de paridad y rollback.
