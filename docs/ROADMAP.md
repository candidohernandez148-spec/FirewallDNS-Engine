# Hoja de ruta

## Fase 0 — Fundamentos y contratos
- [x] Documentación de arquitectura, seguridad, pruebas y límites.
- [x] Contratos puros de decisión y reglas.
- [x] Build Kotlin/JVM separado de Android.
- [x] CI verde y pruebas reproducibles en cada cambio.

## Fase 1 — Núcleo de políticas
- [x] Modelos BLOCK/OBSERVE/ALLOW.
- [x] Precedencia y prioridades explícitas.
- [x] Evaluación determinista, explicable y con motivo.
- [x] Normalización IDN y etiquetas DNS de servicio.
- [x] Reglas por aplicación, caducidad y activación.
- [x] Reemplazo atómico de reglas con revisión monotónica.
- [ ] Pruebas de concurrencia y benchmark de latencia.

## Fase 2 — DNS y caché
- [x] Parser de consultas de una pregunta y validación de cabecera/QNAME/QTYPE/QCLASS.
- [x] Validación EDNS(0), TLV y límites.
- [x] NXDOMAIN sintético con preservación segura de EDNS.
- [x] Codec de framing DNS-over-TCP.
- [x] Caché de decisiones acotada, con TTL y aislamiento por revisión de reglas.
- [x] Fuzzing y suite ampliada de mensajes malformados.
- [x] Transporte DNS upstream UDP con fallback TCP ante respuestas truncadas.
- [x] Timeouts acotados, validación de respuestas y hook de protección de sockets.
- [x] Adaptador Android aislado para conectar la protección de sockets con VpnService.protect (sin integración en el servicio VPN actual).
- [x] Cancelación estructurada por intercambio: cierre del socket activo durante UDP/TCP; pruebas locales de cancelación.
- [x] Caché acotada de respuestas DNS positivas/negativas con TTL, separada de la caché de decisiones; usa reloj monotónico, clave aislada por upstream/consulta/EDNS/CD, límites de entradas/bytes y reescritura de ID/flags/TTL.
- [x] Harness reproducible de P50/P95/P99 para UDP loopback y caché, con workflow manual y cálculo nearest-rank.
- [ ] Ejecutar medición en Android real (incluido Samsung A34 5G), comparar con Firestack y fijar umbrales con baseline reproducible.

## Fase 3 — Inteligencia integrada y determinista
- [x] Indicadores curados iniciales para redes publicitarias y endpoints de tracking.
- [x] Allowlist inicial de dominios esenciales.
- [x] Heurísticas léxicas conservadoras que solo generan OBSERVE.
- [x] Reglas explícitas del usuario prevalecen sobre indicadores integrados y heurísticas.
- [x] Decisiones deterministas sin aprendizaje persistente ni entrenamiento con el tráfico del usuario.
- [ ] Feed curado, verificable y actualizable de malware/phishing, con firma y caducidad; actualización por versiones revisadas, sin aprendizaje del tráfico del usuario.
- [ ] Medición de falsos positivos en aplicaciones reales.

## Fase 4 — Identidad de aplicación y conexiones
- Resolver UID/paquete con APIs Android compatibles.
- Políticas por aplicación con degradación explícita si falta identidad.
- Metadatos TCP/UDP sin fingir inspección de contenido cifrado.

## Fase 5 — Adaptador VPN y transporte
- Prototipo aislado con VpnService/TUN.
- Evaluar stack probado frente a alternativas nativas.
- Validar IPv4/IPv6, MTU, fragmentación, ICMP, TCP/UDP, DNS TCP, checksums y reconexiones.
- Validar protect(), ausencia de bucles y DNS leaks.

## Fase 6 — Observabilidad y rendimiento
- [x] Contadores locales de decisiones, caché, rechazos y eventos descartados.
- [x] Cola de eventos acotada con publicación no bloqueante y datos sensibles redactados por defecto.
- [x] Harness de latencia DNS P50/P95/P99 separado por upstream y cache hit (loopback JVM; no equivale a medición de dispositivo).
- [ ] Métricas P50/P95, throughput, CPU, RAM, batería y pérdidas en hardware real.
- [ ] Pruebas prolongadas, concurrencia y reconexión.

## Fase 7 — Integración controlada
- Adaptador con FirewallDNS sin duplicar VpnService.
- Feature flag, rollback, canary interno y pruebas A/B.
- Sustituir componentes solo tras superar criterios.

## Criterio de salida global
No integrar ni retirar el transporte actual hasta demostrar compatibilidad funcional, ausencia de fugas conocidas, estabilidad prolongada, falsos positivos aceptables y rendimiento igual o mejor en Samsung A34 5G y otros dispositivos de referencia.
