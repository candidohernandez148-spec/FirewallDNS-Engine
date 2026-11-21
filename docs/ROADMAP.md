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
- [x] Pruebas de concurrencia y benchmark de latencia (`PolicyEngineConcurrencyAndScaleTest` + índice por sufijo de etiquetas `O(labels)`).

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
- [x] Failover secuencial configurable entre upstreams cuando un resolutor falla; conserva cancelación como resultado terminal y no fija proveedores públicos.
- [x] Caché acotada de respuestas DNS positivas/negativas con TTL, separada de la caché de decisiones; usa reloj monotónico, clave aislada por upstream/consulta/EDNS/CD, límites de entradas/bytes y reescritura de ID/flags/TTL.
- [x] Harness reproducible JVM de P50/P95/P99 para UDP loopback, caché y evaluación de políticas, con workflow y cálculo nearest-rank.
- [ ] Compilar y ejecutar el harness Android de instrumentación en Samsung A34 5G; medir después VPN activa/protect(), red real y comparar con Firestack.
- [ ] Ejecutar medición en Android real (incluido Samsung A34 5G), comparar con Firestack y fijar umbrales con baseline reproducible.

## Fase 3 — Inteligencia integrada y determinista
- [x] Indicadores curados iniciales para redes publicitarias y endpoints de tracking.
- [x] Allowlist inicial de dominios esenciales.
- [x] Heurísticas léxicas conservadoras que solo generan OBSERVE.
- [x] Reglas explícitas del usuario prevalecen sobre indicadores integrados y heurísticas.
- [x] Decisiones deterministas sin aprendizaje persistente ni entrenamiento con el tráfico del usuario.
- [x] Feed curado, verificable y actualizable de malware/phishing (`SignedThreatFeed` + `ThreatFeedVerifier` con firma ECDSA-SHA256, versión monotónica y caducidad; sin aprendizaje del tráfico del usuario).
- [ ] Medición de falsos positivos en aplicaciones reales.

## Fase 4 — Identidad de aplicación y conexiones
- [x] Resolver UID/paquete con APIs Android compatibles (`AndroidAppIdentityResolver` vía `ConnectivityManager.getConnectionOwnerUid` en API 29+ con caché TTL acotada).
- [x] Políticas por aplicación con degradación explícita si falta identidad (`AppIdentityResolver` devuelve `null` y aplica reglas globales en `TunDataPlaneCoordinator`).
- [x] Metadatos TCP/UDP sin fingir inspección de contenido cifrado (`TunFlowTracker`).

## Fase 5 — Adaptador VPN y transporte
- [x] Añadir núcleo Rust/JNI experimental para validación estructural de paquetes DNS UDP IPv4/IPv6, aislado de la ruta de producción y compilado para arm64-v8a.
- [x] Añadir gestor Android experimental de flujos UDP protegidos con límite de flujos, colas por flujo, RX/TX loopback, cancelación, expiración monotónica por inactividad y cierre por flujo; aún sin puente TUN/smoltcp ni uso en producción.
- [x] Añadir arnés host-side de ida y vuelta UDP entre smoltcp y un socket loopback, con reinyección de respuesta por cola RX; sin protect() ni TUN Android real.
- [x] Añadir decodificador puro de datagramas UDP IPv4/IPv6 no DNS con validación de longitud/checksum; aún sin sockets, reenvío ni integración TUN.
- [ ] Benchmark A/B Rust frente a Kotlin en Samsung A34 5G y decisión documentada antes de activar el núcleo nativo.
- [x] Prototipo aislado VpnService/TUN para DNS UDP real, limitado a direcciones virtuales y con upstream protegido (diagnóstico; no es VPN de tráfico general).
- Evaluar stack probado frente a alternativas nativas.
- [x] Procesamiento inicial de UDP DNS IPv4/IPv6 básico, checksum de respuestas y decisiones BLOCK/OBSERVE/ALLOW con pruebas unitarias.
- [x] Preflight unificado IPv4/IPv6 TCP+UDP en Rust: longitudes, checksums, Data Offset, rechazo de fragmentos/extensiones no soportadas; API pura con pruebas host-side, todavía fuera de JNI y producción.
- [x] Arnés host-side smoltcp TCP en IPv4: handshake cliente/servidor por colas TUN virtuales acotadas y entrega de frames DNS divididos/concatenados como stream; no conecta aún el decoder/políticas ni Android.

- [x] Arnés host-side de ciclo de vida TCP smoltcp: pérdida inducida del primer SYN, retransmisión, FIN ordenado y aborto con RST (PR #26, CI verde).
- [x] Arnés host-side IPv6 TCP DNS smoltcp: handshake e intercambio bidireccional con framing DNS (PR #27, CI verde); no implica integración Android ni producción.
- [x] Añadir procesador DNS TCP por sesión que conecta el decoder incremental con BLOCK/OBSERVE/ALLOW y upstream, con límites de buffer/trabajo y cierre ante errores (PR de sesión DNS TCP); conectado a `TunTcpStack` con validación de retransmisiones, ventanas deslizantes/cero y cierre FIN/RST bajo carga.
- [x] Conectar una instancia del procesador a cada socket TCP del stack (`TunTcpStack`) y validar ACK/ventanas/retransmisión/cierre bajo carga (`TunTcpStackLoadTest`).
- [x] DNS-over-TCP del lado del cliente en Android, fragmentación IP (`IpFragmentReassembler`) y cabeceras de extensión IPv6 (`TunDnsPacketProcessor` + `TunTcpSegmentCodec`).
- [x] Integrar el plano de datos en producción (`FirewallDnsVpnService` + `TunDataPlaneCoordinator`) tras validar `VpnService.protect()`, ausencia de bucles y cero fugas DNS en puerta preflight y guardas en tiempo de ejecución (`TunDataPlaneIntegrationTest`); pendiente únicamente validación física en dispositivo Samsung Galaxy A34 5G.
- [x] Validar `protect()`, ausencia de bucles y DNS leaks mediante `TunDataPlaneSecurityValidator`, `AuditedDnsSocketProtector`, `LoopAndLeakGuard` y pruebas automatizadas de integración.

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


## Fase 8 — Diagnóstico integral unificado
- [x] Definir una sola herramienta de diagnóstico y sus límites de cobertura.
- [x] Añadir clasificador pasivo por capas para IPv4/IPv6, TCP/UDP/ICMP y firmas DNS/HTTP/TLS/QUIC.
- [x] Separar certeza CONFIRMED/LIKELY/PORT_ONLY/UNKNOWN para evitar falsos positivos por número de puerto.
- [x] Integrar clasificación de cada paquete recibido por el TUN y contadores agregados en el informe JSON unificado v3 (cobertura limitada a las rutas DNS virtuales actuales).
- [x] Implementar seguimiento de flujos con límites estrictos de memoria/TTL y causas de cierre (`TunFlowTracker`).
- [x] Implementar atribución UID/paquete solo cuando Android lo permita, con redacción por defecto (`AndroidAppIdentityResolver` + `TunFlowTrackerConfig.captureAppPackages = false`).
- [ ] Implementar captura full-tunnel únicamente junto con reenvío TCP/UDP funcional y protección obligatoria de sockets.
- [ ] Validar IPv4/IPv6, fragmentación, ICMP, Wi-Fi/datos, cambios de red y continuidad de conectividad en Samsung A34 5G.
- [ ] Publicar el informe integral final con cobertura/exclusiones verificables y sin payload ni datos sensibles.

La primera entrega del clasificador no implica que el TUN actual capture todo el dispositivo: `:device-diagnostics` sigue en modo DNS-only hasta que el reenvío full-tunnel supere sus puertas de seguridad. Ver [Diagnóstico integral de tráfico](INTEGRAL_TRAFFIC_DIAGNOSTIC.md).
