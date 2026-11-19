# Instrucciones para agentes y colaboradores

1. Lee README.md, docs/ARCHITECTURE.md, docs/SECURITY.md, docs/TESTING.md y docs/ROADMAP.md.
2. Mantén este repositorio independiente de FirewallDNS hasta que exista una fase de integración aprobada.
3. No retires Firestack ni reemplaces el transporte de la aplicación principal como parte del proyecto inicial.
4. No implementes una pila TCP/IP completa desde cero sin decisión técnica documentada, pruebas comparativas y aprobación explícita.
5. Mantén la ruta crítica sin I/O de disco, red ni operaciones bloqueantes.
6. Toda decisión es explicable: BLOCK, OBSERVE o ALLOW, con motivo y procedencia.
7. OBSERVE no bloquea. Evita falsos positivos en apps esenciales y del sistema.
8. Privacidad local por defecto; no agregues telemetría externa sin consentimiento y documentación.
9. Añade pruebas para cada comportamiento nuevo y ejecuta validaciones antes de informar que está terminado.
10. No afirmes compatibilidad, rendimiento o ausencia de fugas sin evidencia reproducible.
11. Haz cambios pequeños y revisables. Documenta decisiones arquitectónicas importantes.
12. La monitorización visible debe actualizarse oportunamente, pero nunca frenar el procesamiento de red.
