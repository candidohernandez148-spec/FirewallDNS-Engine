# Instrucciones para agentes y colaboradores

1. Lee README.md, docs/ARCHITECTURE.md, docs/SECURITY.md, docs/TESTING.md y docs/ROADMAP.md.
2. FirewallDNS-Engine es el único motor de decisiones y filtrado; FirewallDNS Android es el anfitrión de plataforma, UI y VpnService.
3. Firestack se usa únicamente como referencia de comportamiento y compatibilidad. No debe convertirse en dependencia ni mantenerse como segundo motor en la arquitectura final; retirarlo de Android solo después de superar las puertas de validación documentadas.
4. No implementes una pila TCP/IP completa desde cero sin decisión técnica documentada, pruebas comparativas y aprobación explícita.
5. Mantén la ruta crítica sin I/O de disco, red ni operaciones bloqueantes.
6. Toda decisión es explicable: BLOCK, OBSERVE o ALLOW, con motivo y procedencia.
7. No implementes aprendizaje persistente, entrenamiento local ni conocimiento derivado del historial de tráfico. La inteligencia procede de indicadores integrados/curados y análisis en tiempo real.
8. OBSERVE no bloquea. Evita falsos positivos en apps esenciales y del sistema.
9. Privacidad local por defecto; no agregues telemetría externa sin consentimiento y documentación.
10. Añade pruebas para cada comportamiento nuevo y ejecuta validaciones antes de informar que está terminado.
11. No afirmes compatibilidad, rendimiento o ausencia de fugas sin evidencia reproducible.
12. Haz cambios pequeños y revisables. Documenta decisiones arquitectónicas importantes.
13. La monitorización visible debe actualizarse oportunamente, pero nunca frenar el procesamiento de red.
