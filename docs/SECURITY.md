# Seguridad y privacidad

## Datos
- Procesamiento y aprendizaje locales por defecto.
- No enviar dominios, UID, paquetes ni historial a servicios externos por defecto.
- Redactar logs y limitar retención.
- Telemetría opt-in y documentada si se incorpora.

## Decisiones
- Cada decisión incluye motivo y procedencia.
- Las heurísticas no anulan silenciosamente reglas explícitas del usuario.
- OBSERVE nunca se presenta como BLOCK.
- Reglas aprendidas con caducidad, límites y revisión.
- Allowlist explícita y pruebas para apps esenciales y del sistema.

## Fallos
- Definir por componente si un error permite, bloquea o degrada.
- Un fallo de almacenamiento o monitorización no cambia silenciosamente la política.
- Colas y cachés con límites para evitar consumo ilimitado.

## Inteligencia local inicial\n- Los indicadores incorporados son una base pequeña y curada para dominios de publicidad y tracking; no representan un feed completo de malware o phishing.\n- Las señales léxicas débiles producen OBSERVE, nunca BLOCK.\n- Solo indicadores confiables con confianza alta y fuente no aprendida pueden sugerir BLOCK.\n- Las reglas explícitas del usuario se evalúan antes de la inteligencia de amenazas.\n- La allowlist protege dominios esenciales frente a heurísticas, pero no invalida una regla explícita del usuario ni un indicador confiable específico.\n\n## Límites
- No afirmar inspección de HTTPS, DoH o DoT si solo se observan metadatos.
- No inferir identidad de aplicación sin evidencia Android.
- No almacenar contenido de paquetes si bastan metadatos.

## Revisión antes de integrar
- Revisar permisos Android y superficie de VpnService.
- Revisar dependencias y licencias del stack elegido.
- Ejecutar pruebas de fugas, recursión, concurrencia y agotamiento de recursos.
- Documentar riesgos residuales y plan de reversión.
