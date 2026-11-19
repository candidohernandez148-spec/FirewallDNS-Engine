# FirewallDNS-Engine

Motor independiente de filtrado y protección de red para Android. Este repositorio se desarrolla separado de [FirewallDNS](https://github.com/candidohernandez148-spec/FirewallDNS) y no modifica ni sustituye su implementación actual.

> Estado: **prototipo Kotlin/JVM en desarrollo**. El núcleo de políticas, un adaptador DNS inicial, inteligencia local y monitorización acotada ya están implementados en una rama de trabajo. Todavía no es un motor listo para proteger tráfico real.

## Componentes implementados en la rama de trabajo
- `engine-core`: reglas BLOCK / OBSERVE / ALLOW, normalización IDN y etiquetas DNS de servicio, reglas por aplicación, prioridades, caducidad y snapshots atómicos con revisión.
- `dns-engine`: parser estricto de consultas DNS de una pregunta, validación EDNS(0), NXDOMAIN sintético, framing DNS-over-TCP, cliente upstream UDP con fallback TCP al recibir TC, timeouts acotados, validación de ID/pregunta y hook para proteger sockets VPN; caché acotada de decisiones con TTL y revisión de políticas.
- `threat-engine`: indicadores locales iniciales de publicidad y tracking, allowlist de dominios esenciales y heurísticas conservadoras que solo generan OBSERVE.
- `engine-monitor`: métricas locales y cola de eventos acotada, sin I/O en la ruta crítica y con dominios/paquetes redactados por defecto.

El parser DNS acepta consultas de una pregunta y, opcionalmente, un único registro EDNS(0) OPT. El cliente upstream ya realiza intercambios UDP y fallback DNS-over-TCP, pero debe invocarse fuera de la ruta crítica y su adaptador Android debe conectar el hook de protección con `VpnService.protect`. Todavía no implementa gestión de flujos, fragmentación, integración TUN ni caché de respuestas DNS. La inteligencia de amenazas es una base local inicial, no un feed exhaustivo de malware/phishing ni una garantía de detección. Los tipos de registro se filtran por nombre de dominio, no se interpretan sus RDATA.

## Decisiones y límites
- Repositorio privado durante el desarrollo; no modifica FirewallDNS.
- Procesamiento local por defecto, sin telemetría externa.
- OBSERVE permite el tráfico; las heurísticas débiles nunca bloquean.
- Reglas explícitas del usuario prevalecen sobre la inteligencia automática.
- Monitorización con cola limitada y datos sensibles desactivados por defecto.
- No se reimplementará TCP/IP desde cero sin evidencia y benchmark.
- No se sustituirá Firestack ni se integrará en FirewallDNS hasta superar pruebas funcionales, seguridad y rendimiento en hardware real.

## Módulos previstos
engine-core, dns-engine, threat-engine, app-identity, packet-engine, connection-engine, fast-cache y engine-monitor.

## Documentación
- [Arquitectura](docs/ARCHITECTURE.md)
- [Hoja de ruta](docs/ROADMAP.md)
- [Estrategia de pruebas](docs/TESTING.md)
- [Seguridad y privacidad](docs/SECURITY.md)
- [Instrucciones para agentes](AGENTS.md)

## No objetivos actuales
- Reimplementar toda la pila TCP/IP.
- Inspeccionar contenido cifrado sin capacidad real para hacerlo.
- Integrar o reemplazar componentes de FirewallDNS.
- Bloquear dominios únicamente por una señal heurística débil.
