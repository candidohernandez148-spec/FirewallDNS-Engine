# Arquitectura de FirewallDNS-Engine

## Objetivo
Construir un motor de filtrado y protección de red para Android, desacoplado de FirewallDNS. Será responsable de decisiones rápidas, coherentes, observables y comprobables. La integración ocurrirá solo cuando supere criterios de aceptación y rendimiento.

## Principios
1. Una sola autoridad de políticas: BLOCK, OBSERVE o ALLOW.
2. La ruta crítica no realiza I/O de disco, operaciones de red ni trabajo pesado.
3. Datos locales por defecto: aprendizaje, historial y reglas permanecen en el dispositivo.
4. Fail-safe explícito: cada error tiene comportamiento definido.
5. Separación entre plano de control y plano de datos.
6. Medición antes de optimización: latencia P50/P95, throughput, CPU, memoria, batería y pérdidas.
7. No reinventar TCP/IP sin evidencia; evaluar stacks probados/nativos.

## Componentes lógicos
| Módulo | Responsabilidad |
|---|---|
| engine-core | Contratos, modelos, ciclo de vida y coordinación |
| policy-engine | Evaluación determinista y prioridad de reglas |
| dns-engine | Normalización, evaluación DNS, caché y respuestas |
| packet-engine | Adaptador TUN y límites con el stack de red |
| connection-engine | Flujos TCP/UDP y ciclo de vida |
| app-identity | Asociación UID/paquete cuando Android lo permita |
| threat-engine | Señales de riesgo, reputación local y aprendizaje |
| fast-cache | Cachés concurrentes con TTL y límites |
| engine-monitor | Métricas, eventos y diagnóstico no bloqueante |

Los nombres son límites lógicos iniciales; se convertirán en módulos Gradle cuando código y dependencias lo justifiquen.

## Flujo de decisión
1. El adaptador recibe una consulta DNS o metadatos de flujo.
2. Normaliza la entrada e identifica la aplicación si es posible.
3. Consulta la caché.
4. Si no hay resultado vigente, Policy Engine evalúa reglas y señales.
5. Devuelve decisión, motivo, regla, confianza y caducidad.
6. Publica evento al monitor de forma asíncrona y acotada.

OBSERVE registra señales y permite el tráfico; no equivale a bloquear.

## Límites técnicos
- Android VpnService entrega paquetes IP mediante TUN; no concede identidad fiable de proceso para cada paquete.
- DNS UDP/TCP puede evaluarse si pasa por el motor. DoH/DoT no son inspeccionables como DNS normal sin capacidades adicionales.
- IPv4/IPv6, fragmentación, MTU, ICMP, TCP, UDP, DNS TCP, checksums, reconexión y protección de sockets requieren pruebas.
- Los sockets fuera de la VPN deben protegerse para evitar recursión.
- No se prometerá inspección total del tráfico cifrado ni atribución de aplicación sin evidencia.

## Estrategia de transporte
Definir interfaces y medir alternativas. Se prefiere integrar un stack probado antes que implementar TCP/IP desde cero. Ningún stack existente se elimina ni sustituye en FirewallDNS hasta que un candidato independiente pase pruebas de compatibilidad, seguridad y rendimiento.

## Estado del prototipo DNS

El módulo `dns-engine` contiene un parser de consultas DNS de una pregunta, con validación de cabecera y QNAME, una sección adicional opcional EDNS(0) OPT, evaluación contra `engine-core` y síntesis NXDOMAIN. La respuesta local conserva ID, pregunta, RD/CD, tamaño UDP anunciado y el bit DNSSEC OK; no copia las opciones EDNS del cliente.

El codec DNS-over-TCP solo maneja el prefijo de longitud de dos bytes y mensajes completos/parciales en buffers. No abre sockets ni implementa reensamblado de flujos. Todavía falta transporte UDP/TCP, reenvío upstream, timeouts, caché TTL y pruebas contra resolvers reales.

Las clases DNS distintas de IN se pasan sin aplicar políticas de dominio. Los tipos A/AAAA y otros tipos IN se evalúan por nombre; el módulo no interpreta RDATA ni genera respuestas A/AAAA permitidas.

## Caché de decisiones DNS\n\nLa caché de decisiones está acotada por número de entradas, usa TTL corto y la revisión monotónica del snapshot de políticas como parte de la clave. La caducidad de una regla limita también la vida de su decisión cacheada. Las lecturas son concurrentes y sin bloqueo; las escrituras usan un bloqueo breve únicamente para mantener el límite estricto. Esta caché no almacena respuestas DNS ni sustituye la futura caché positiva/negativa de respuestas.\n\n## Concurrencia y persistencia
- Evaluación síncrona, acotada y sin disco en la ruta crítica.
- Room/SQLite fuera de la ruta crítica; WAL se evaluará con mediciones.
- Reglas activas como snapshots inmutables.
- Cachés con TTL, límites e invalidación explícita.
- Colas de eventos acotadas; la saturación se contabiliza sin detener el filtrado.

## Evolución
No se fijan todavía lenguaje, versión Android ni dependencias de red. Antes del primer módulo ejecutable se documentarán decisiones tecnológicas y se validará compatibilidad con el nivel mínimo de Android previsto.
