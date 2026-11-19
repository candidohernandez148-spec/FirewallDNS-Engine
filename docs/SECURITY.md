# Seguridad y privacidad

## Datos
- Procesamiento local por defecto; no existe aprendizaje persistente ni entrenamiento local a partir del tráfico.
- No enviar dominios, UID, paquetes ni historial a servicios externos por defecto.
- El monitor local redacta dominios y paquetes por defecto; capturarlos requiere opt-in explícito del consumidor.
- Redactar logs y limitar retención.
- Telemetría opt-in y documentada si se incorpora.

## Decisiones
- Cada decisión incluye motivo y procedencia.
- Las heurísticas no anulan silenciosamente reglas explícitas.
- OBSERVE nunca se presenta como BLOCK.
- No se generan reglas aprendidas. Las reglas son explícitas del usuario o proceden de indicadores curados e integrados.
- Allowlist explícita y pruebas para aplicaciones esenciales y del sistema.

## Inteligencia integrada sin aprendizaje
- Los indicadores incorporados son una base pequeña y curada para dominios de publicidad y tracking; no representan un feed completo de malware o phishing.
- Las señales léxicas débiles producen OBSERVE, nunca BLOCK.
- Solo indicadores curados, explícitos y de confianza alta pueden sugerir BLOCK según la política definida.
- Las reglas explícitas del usuario se evalúan antes de la inteligencia de amenazas.
- La allowlist protege dominios esenciales frente a heurísticas, pero no invalida una regla explícita del usuario ni un indicador confiable específico.

## Fallos y límites
- Definir por componente si un error permite, bloquea o degrada.
- Un fallo de almacenamiento o monitorización no cambia silenciosamente la política.
- Colas y cachés con límites para evitar consumo ilimitado.
- La caché DNS es volátil, está limitada por entradas y bytes, usa expiración monotónica y no persiste consultas ni respuestas en disco. Las claves aíslan upstream, consulta y opciones EDNS; los TTL se reducen en cada respuesta servida desde caché.
- No afirmar inspección de HTTPS, DoH o DoT si solo se observan metadatos.
- No inferir identidad de aplicación sin evidencia Android.
- No almacenar contenido de paquetes si bastan metadatos.

## Revisión antes de integrar
- Proteger los sockets UDP/TCP upstream con `VpnService.protect` antes de conectarlos y usar direcciones IP numéricas para evitar recursión DNS.
- Revisar permisos Android y superficie de VpnService.
- Revisar dependencias y licencias del stack elegido.
- Ejecutar pruebas de fugas, recursión, concurrencia y agotamiento de recursos.
- Documentar riesgos residuales y plan de reversión.
