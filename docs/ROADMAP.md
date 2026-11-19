# Hoja de ruta

## Fase 0 — Fundamentos y contratos
- [x] Documentación de arquitectura, seguridad, pruebas y límites.
- [x] Contratos puros de decisión y reglas.
- [x] Build Kotlin/JVM separado de Android.
- [ ] CI verde y pruebas reproducibles.

## Fase 1 — Núcleo de políticas
- [x] Modelos BLOCK/OBSERVE/ALLOW.
- [x] Precedencia y prioridades explícitas.
- [x] Evaluación determinista, explicable y con motivo.
- [x] Normalización IDN y soporte de etiquetas DNS de servicio.
- [x] Reglas por aplicación, caducidad y activación.
- [x] Reemplazo atómico de reglas.
- [ ] Pruebas de concurrencia y benchmark de latencia.
- [ ] CI verde en GitHub Actions.

## Fase 2 — DNS y caché
- [x] Parser inicial de consultas de una pregunta.
- [x] Validación de cabecera, QNAME, QTYPE/QCLASS y límites.
- [x] Soporte de un registro EDNS(0) OPT y respuesta bloqueada NXDOMAIN.
- [x] Evaluación de DNS a través del motor de políticas.\n- [x] Caché acotada de decisiones con TTL y aislamiento por revisión de reglas.
- [ ] Suite completa de casos malformados y fuzzing.
- [ ] Transporte DNS UDP y TCP.
- [ ] Reenvío upstream, timeouts y cancelación.
- [ ] Caché de respuestas DNS positiva/negativa con TTL, límites e invalidación (separada de la caché de decisiones).
- [ ] Medición DNS P50/P95/P99.

## Fase 3 — Identidad de aplicación y conexiones
- Resolver UID/paquete con APIs compatibles.
- Políticas por aplicación con degradación explícita si falta identidad.
- Metadatos TCP/UDP sin fingir inspección de contenido cifrado.

## Fase 4 — Adaptador VPN y transporte
- Prototipo aislado con VpnService/TUN.
- Evaluar stack probado frente a alternativas nativas.
- Validar IPv4/IPv6, MTU, fragmentación, ICMP, TCP/UDP, DNS TCP, checksums y reconexiones.
- Validar protect(), ausencia de bucles y DNS leaks.

## Fase 5 — Inteligencia local
- Señales explicables para malware, phishing, anuncios y trackers.
- Aprendizaje local con límites, caducidad y corrección.
- No bloquear por una sola señal débil; probar allowlist esencial.
- Medir falsos positivos.

## Fase 6 — Observabilidad y rendimiento
- Métricas P50/P95, throughput, CPU, RAM, batería, pérdidas y caché.
- Eventos oportunos mediante flujo acotado y no bloqueante.
- Pruebas prolongadas y de reconexión.

## Fase 7 — Integración controlada
- Adaptador con FirewallDNS sin duplicar VpnService.
- Feature flag, rollback, canary interno y pruebas A/B.
- Sustituir componentes solo tras superar criterios.

## Criterio de salida global
No integrar ni retirar el transporte actual hasta demostrar compatibilidad funcional, ausencia de fugas conocidas, estabilidad prolongada, falsos positivos aceptables y rendimiento igual o mejor en Samsung A34 5G y otros dispositivos de referencia.
