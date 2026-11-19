# FirewallDNS-Engine

Motor único e independiente de filtrado y protección de red para Android. [FirewallDNS](https://github.com/candidohernandez148-spec/FirewallDNS) será el anfitrión de plataforma, interfaz y VpnService; este repositorio concentra todas las decisiones de filtrado. Firestack se utiliza solo como referencia temporal de compatibilidad.

> Estado: **prototipo Kotlin/JVM en desarrollo**. El núcleo de políticas, un adaptador DNS inicial, inteligencia basada en indicadores integrados y monitorización acotada ya están implementados en `main`. Todavía no es un motor listo para proteger tráfico real.

## Componentes implementados en la rama de trabajo
- `engine-core`: reglas BLOCK / OBSERVE / ALLOW, normalización IDN y etiquetas DNS de servicio, reglas por aplicación, prioridades, caducidad y snapshots atómicos con revisión.
- `dns-engine`: parser estricto de consultas DNS de una pregunta, validación EDNS(0), NXDOMAIN sintético, framing DNS-over-TCP, cliente upstream UDP con fallback TCP al recibir TC, failover secuencial configurable entre resolutores, timeouts acotados, validación de ID/pregunta y hook para proteger sockets VPN; caché acotada de decisiones con TTL y revisión de políticas, además de caché de respuestas DNS positivas/negativas con TTL, expiración monotónica y límite de memoria.
- `threat-engine`: indicadores curados e integrados de publicidad y tracking, allowlist de dominios esenciales y heurísticas conservadoras; no aprende ni persiste conocimiento.
- `engine-monitor`: métricas locales y cola de eventos acotada, sin I/O en la ruta crítica y con dominios/paquetes redactados por defecto.
- `engine-runtime`: fachada pública única que coordina políticas, DNS, amenazas y monitorización para el adaptador Android.
- `android-adapter`: biblioteca Android aislada que conecta la protección de sockets UDP/TCP con `VpnService.protect()`; aún no está integrada en el servicio VPN de FirewallDNS.

El parser DNS acepta consultas de una pregunta y, opcionalmente, un único registro EDNS(0) OPT. El cliente upstream ya realiza intercambios UDP y fallback DNS-over-TCP, pero debe invocarse fuera de la ruta crítica y exige una estrategia explícita de protección de sockets; el adaptador Android debe conectarla con `VpnService.protect`. La caché de respuestas DNS está integrada en el cliente upstream; no implementa todavía gestión de flujos, fragmentación ni integración TUN. La inteligencia de amenazas es una base local inicial, no un feed exhaustivo de malware/phishing ni una garantía de detección. Los tipos de registro se filtran por nombre de dominio, no se interpretan sus RDATA.

## Decisiones y límites
- Repositorio privado durante el desarrollo; no modifica FirewallDNS.
- Procesamiento local por defecto, sin telemetría externa ni aprendizaje persistente.
- OBSERVE permite el tráfico; las heurísticas débiles nunca bloquean.
- Reglas explícitas del usuario prevalecen sobre los indicadores y heurísticas integrados.
- No existe aprendizaje persistente, entrenamiento local ni actualización automática de conocimiento a partir del tráfico del usuario; las señales se evalúan en tiempo real.
- Monitorización con cola limitada y datos sensibles desactivados por defecto.
- No se reimplementará TCP/IP desde cero sin evidencia y benchmark.
- Firestack es únicamente una referencia de paridad; no será una dependencia ni un motor alternativo en la arquitectura final. Su retirada de Android ocurrirá después de superar pruebas funcionales, seguridad y rendimiento en hardware real.

## Módulos
engine-core, dns-engine, threat-engine, engine-monitor y engine-runtime. app-identity, packet-engine y connection-engine son capacidades pendientes, no módulos implementados.

## Documentación
- [Arquitectura](docs/ARCHITECTURE.md)
- [Plan de sustitución e integración](docs/INTEGRATION_PLAN.md)
- [Hoja de ruta](docs/ROADMAP.md)
- [Estrategia de pruebas](docs/TESTING.md)
- [Seguridad y privacidad](docs/SECURITY.md)
- [Instrucciones para agentes](AGENTS.md)

## No objetivos actuales
- Reimplementar toda la pila TCP/IP.
- Inspeccionar contenido cifrado sin capacidad real para hacerlo.
- Retirar Firestack antes de validar la paridad y seguridad del motor nuevo.
- Aprender o entrenar modelos con el historial de tráfico del usuario.
