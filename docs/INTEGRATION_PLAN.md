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
- Aprendizaje local, reputación, allowlist de dominios esenciales e historial.
- Métricas en tiempo real sin bloquear la ruta de red.
- Resiliencia a cambios Wi-Fi/datos móviles, suspensión, revocación VPN y falta de upstream.

## Contrato de integración

1. El motor expone interfaces neutrales de plataforma; no depende de clases Android.
2. La aplicación implementa adaptadores Android para TUN, identidad UID, almacenamiento, reloj y protección de sockets.
3. La decisión de dominio y conexión se realiza exclusivamente en FirewallDNS-Engine.
4. La UI observa snapshots/eventos acotados; nunca ejecuta trabajo pesado en el hilo principal.
5. El upstream y cualquier I/O se ejecutan fuera de la ruta crítica.
6. La aplicación no mantiene una segunda implementación de reglas, aprendizaje o decisiones una vez completada la migración.

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
3. Completar políticas, amenazas, aprendizaje persistente y monitorización.
4. Implementar la abstracción de procesamiento de paquetes y conexiones sin crear una pila TCP/IP propia sin justificación.
5. Publicar/versionar el motor y consumirlo desde Android.
6. Implementar adaptadores Android y ejecutar la matriz de pruebas en dispositivo.
7. Cambiar el servicio activo al motor nuevo y retirar Firestack tras la validación.

## Estado inicial revisado

En el estado inspeccionado, el repositorio del motor contiene módulos Gradle JVM para `engine-core`, `dns-engine`, `threat-engine` y `engine-monitor`. Aún no contiene un motor completo de paquetes/conexiones ni un adaptador Android. La aplicación todavía declara Firestack como dependencia y mantiene un servicio DNS clásico separado. Por tanto, la sustitución completa no es segura todavía.
