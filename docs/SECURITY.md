# Seguridad y privacidad

## Datos
- Procesamiento y aprendizaje locales por defecto.
- No enviar dominios, UID, paquetes ni historial a servicios externos por defecto.\n- El monitor local redacta dominios y paquetes por defecto; capturarlos requiere opt-in explícito del consumidor.
- Redactar logs y limitar retención.
- Telemetría opt-in y documentada si se incorpora.

## Decisiones
- Cada decisión incluye motivo y procedencia.
- Las heurísticas no anulan silenciosamente reglas explícitas.
- OBSERVE nunca se presenta como BLOCK.
- Reglas aprendidas requieren límites, caducidad y revisión.
- Allowlist explícita y pruebas para aplicaciones esenciales y del sistema.

## Inteligencia local inicial
- Los indicadores incorporados son una base pequeña y curada para dominios de publicidad y tracking; no representan un feed completo de malware o phishing.
- Las señales léxicas débiles producen OBSERVE, nunca BLOCK.
- Solo indicadores confiables con confianza alta y fuente no aprendida pueden sugerir BLOCK.
- Las reglas explícitas del usuario se evalúan antes de la inteligencia de amenazas.
- La allowlist protege dominios esenciales frente a heurísticas, pero no invalida una regla explícita del usuario ni un indicador confiable específico.

## Fallos y límites
- Definir por componente si un error permite, bloquea o degrada.
- Un fallo de almacenamiento o monitorización no cambia silenciosamente la política.
- Colas y cachés con límites para evitar consumo ilimitado.
- No afirmar inspección de HTTPS, DoH o DoT si solo se observan metadatos.
- No inferir identidad de aplicación sin evidencia Android.
- No almacenar contenido de paquetes si bastan metadatos.

## Revisión antes de integrar
- Revisar permisos Android y superficie de VpnService.
- Revisar dependencias y licencias del stack elegido.
- Ejecutar pruebas de fugas, recursión, concurrencia y agotamiento de recursos.
- Documentar riesgos residuales y plan de reversión.
