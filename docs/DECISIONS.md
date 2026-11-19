# Decisiones técnicas

## ADR-001 — Núcleo Kotlin/JVM independiente de Android
**Estado:** aceptada para el primer prototipo.

Implementar engine-core como módulo Kotlin/JVM sin dependencia del SDK Android. Esto permite probar políticas en JVM sin emulador, desacopla VpnService/UI/persistencia y mantiene la lógica de decisiones separada del transporte.

Consecuencias: esta entrega no procesa paquetes ni inicia VPN. Los adaptadores Android serán independientes. La compatibilidad de runtime Android se verificará antes de integrar. Versiones de Kotlin y Gradle podrán ajustarse según CI.

## ADR-002 — Snapshot inmutable para reglas activas
**Estado:** aceptada para el primer prototipo.

Validar y compilar el conjunto completo de reglas antes de publicarlo atómicamente mediante AtomicReference. Las lecturas no esperan bloqueos de actualización y una configuración inválida no reemplaza parcialmente el conjunto activo.

Las actualizaciones son de reemplazo completo; una capa superior combinará reglas persistidas antes de llamar replaceRules.
