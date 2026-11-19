# FirewallDNS-Engine

Motor independiente de filtrado y protección de red para Android. Este repositorio se desarrolla separado de [FirewallDNS](https://github.com/candidohernandez148-spec/FirewallDNS) y no modifica ni sustituye su implementación actual.

> Estado: **fundamentos y arquitectura**. Todavía no es un motor ejecutable ni debe utilizarse para proteger tráfico real.

## Objetivo
Crear un motor rápido, explicable y comprobable que centralice decisiones de red, filtrado DNS, políticas por aplicación, señales locales de amenazas y observabilidad. La prioridad es la fiabilidad del filtrado, la baja latencia y evitar falsos positivos.

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

Son límites lógicos iniciales; la separación en módulos Gradle se hará cuando se confirmen lenguaje, dependencias y contratos.

## Documentación
- [Arquitectura](docs/ARCHITECTURE.md)
- [Hoja de ruta](docs/ROADMAP.md)
- [Estrategia de pruebas](docs/TESTING.md)
- [Seguridad y privacidad](docs/SECURITY.md)
- [Instrucciones para agentes](AGENTS.md)

## Primer hito
Definir contratos puros de políticas y construir un núcleo pequeño y testeable. Antes se cerrarán las decisiones tecnológicas y se validará una prueba técnica aislada del transporte.

## No objetivos de la primera entrega
- Reimplementar toda la pila TCP/IP.
- Inspeccionar contenido cifrado sin capacidad real para hacerlo.
- Integrar o reemplazar componentes de FirewallDNS.
- Bloquear dominios únicamente por una señal heurística débil.
