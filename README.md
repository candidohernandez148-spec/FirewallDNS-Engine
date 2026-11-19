# FirewallDNS-Engine

Motor independiente de filtrado y protección de red para Android. Este repositorio se desarrolla separado de [FirewallDNS](https://github.com/candidohernandez148-spec/FirewallDNS) y no modifica ni sustituye su implementación actual.

> Estado: **prototipo Kotlin/JVM en desarrollo**. El núcleo de políticas y un adaptador DNS inicial están implementados en una rama de trabajo; todavía no es un motor listo para proteger tráfico real.

## Objetivo
Crear un motor rápido, explicable y comprobable que centralice decisiones de red, filtrado DNS, políticas por aplicación, señales locales de amenazas y observabilidad. La prioridad es la fiabilidad del filtrado, la baja latencia y evitar falsos positivos.

## Componentes implementados en la rama de trabajo
- `engine-core`: reglas BLOCK / OBSERVE / ALLOW, normalización de dominios, reglas por aplicación, prioridades, caducidad y publicación atómica de snapshots.
- `dns-engine`: parser estricto para consultas DNS de una pregunta, validación de EDNS(0), evaluación con el motor de políticas y respuesta NXDOMAIN sintética para bloqueos.

El parser DNS actual acepta consultas IN con una pregunta y, opcionalmente, un único registro EDNS(0) OPT. No implementa transporte UDP/TCP, reenvío a upstream, fragmentación, DNS TCP ni integración VPN. Los tipos de registro se filtran por nombre de dominio, no se interpretan sus RDATA.

## Decisiones iniciales
- Repositorio privado durante el desarrollo.
- Procesamiento y aprendizaje locales por defecto.
- Decisiones explícitas: **BLOCK**, **OBSERVE** y **ALLOW**.
- La ruta crítica no realiza operaciones de disco ni trabajo bloqueante.
- Se medirá antes de optimizar; no se inventan cifras objetivo.
- Se evaluarán stacks de red probados antes de plantear TCP/IP propio.
- No se sustituirá Firestack ni se integrará en FirewallDNS hasta superar criterios de aceptación y pruebas reales.

## Módulos previstos
engine-core, policy-engine, dns-engine, packet-engine, connection-engine, app-identity, threat-engine, fast-cache y engine-monitor.

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
