# Estrategia de pruebas

## Pruebas por capa
- Policy Engine: precedencia, conflictos, expiración, reglas por aplicación, decisiones y explicabilidad.
- DNS Engine: nombres inválidos, IDN, etiquetas de servicio, mayúsculas, punto final, EDNS(0), TLV malformado, clases DNS, NXDOMAIN y truncamiento.
- DNS TCP framing: prefijo parcial, cuerpo parcial, longitud inválida, múltiples frames en un buffer y límites.
- DNS upstream: respuesta UDP válida, ID/pregunta incorrectos, registros truncados, punteros de compresión inválidos, bytes sobrantes, framing EDNS malformado, fallback TCP ante TC, clase DNS no IN, timeout, rechazo de socket no protegido, dirección upstream no numérica, aciertos de caché sin segunda consulta de red y cancelación durante espera UDP/TCP.
- DNS failover: resolutor primario sin respuesta y secundario válido, agotamiento de resolutores, límite configurable de intentos, lista vacía, consulta inválida, fallo local de protección de sockets y cancelación terminal. Solo se reintentan fallos de transporte o respuestas upstream defectuosas; no se repiten errores locales permanentes. El orden, endpoints y máximo de intentos los configura el host; el motor no selecciona proveedores ni modifica Private DNS.
- DNS response cache: TTL positivo mínimo, RFC 2308 negativo (SOA TTL/MINIMUM), expiración monotónica, decremento de TTL en hits, aislamiento por consulta/upstream, límite de entradas y exclusión de TTL=0/SERVFAIL/TC/mensajes malformados.
- Fast Cache: concurrencia, expiración, invalidación, presión de memoria y resultados obsoletos.
- App Identity: UID no disponible, paquete eliminado, perfiles de trabajo y restricciones Android.
- Packet/Connection: IPv4/IPv6, UDP/TCP, ICMP, fragmentación, MTU, checksums, DNS TCP, cierres y reconexiones.
- VPN: protección de sockets, prevención de bucles, DNS leak, cambio Wi-Fi/datos y suspensión/reanudación.
- Threat Engine: falsos positivos, allowlist esencial, señales contradictorias y ausencia de aprendizaje persistente.
- Monitor: orden de eventos, capacidad máxima, descartes contabilizados, redacción de datos sensibles, métricas concurrentes y UI no bloqueante.

## Robustez DNS y fuzzing
- `DnsMessageParserFuzzTest` cubre casos malformados conocidos, entradas aleatorias y mutaciones deterministas de consultas válidas.
- `DnsEdnsRobustnessTest` cubre OPT válido, múltiples opciones, DO bit, TLV truncado, longitud de opción excesiva y RDLENGTH inconsistente.
- `DnsTcpFrameCodecTest` y `DnsTcpFrameFuzzTest` cubren prefijo/cuerpo parciales, longitudes 0–11, múltiples frames, tamaño máximo, mutaciones y entradas aleatorias.
- `DnsUpstreamMalformedResponseTest` comprueba rechazo de cabeceras upstream truncadas y paquetes que no son respuestas.
- Estas pruebas son smoke-fuzzers reproducibles; no sustituyen fuzzing guiado por cobertura, sanitización ni campañas prolongadas.
- Ejecutar la suite en CI y registrar semilla/iteración si aparece una regresión para convertir el caso en fixture permanente. Los resolutores reales se validan mediante `DnsLiveResolverIntegrationTest`; la cancelación UDP/TCP se cubre con sockets locales deterministas.

### Resolutores DNS reales (integración optativa)
- `DnsLiveResolverIntegrationTest` consulta `example.com` directamente por UDP a Cloudflare (1.1.1.1), Google Public DNS (8.8.8.8) y Quad9 (9.9.9.9), validando respuesta, RCODE y pregunta.
- Estas pruebas no se ejecutan en la suite normal. Para ejecutarlas manualmente: `FIREWALLDNS_RUN_LIVE_DNS_TESTS=true gradle :dns-engine:test --tests "*DnsLiveResolverIntegrationTest"`.
- El workflow `DNS Live Resolver Checks` permite lanzarlas desde GitHub Actions → Actions → DNS Live Resolver Checks → Run workflow.
- Requieren salida de red UDP/TCP 53. Un fallo por bloqueo de red debe distinguirse de un fallo del parser o del protocolo.
- El fallback TCP continúa cubierto con servidor local determinista; no se fuerza una condición de truncamiento en los resolutores públicos.

## Matriz mínima
- Samsung Galaxy A34 5G como dispositivo de referencia.
- Android mínimo soportado y versión Android reciente.
- Wi-Fi, datos móviles, cambio entre redes, IPv4, IPv6 y redes mixtas.
- Pruebas de batería y estabilidad prolongada.

## Métricas
Registrar baseline y candidato:
- Latencia DNS/decisión P50/P95/P99.
- Throughput y paquetes por segundo.
- CPU y memoria máxima/promedio.
- Batería en escenarios comparables.
- Pérdida de paquetes, errores, reconexiones y eventos descartados.
- Falsos positivos y aplicaciones esenciales afectadas.

## Puertas de aceptación
1. Sin regresión funcional crítica en DNS y conectividad.
2. Sin bucles VPN ni fugas DNS reproducibles en escenarios cubiertos.
3. Manejo correcto de IPv4/IPv6 y fallos de identidad.
4. Sin I/O de disco ni bloqueos prolongados en ruta crítica.
5. Resultados repetibles y trazables.
6. Rollback disponible antes de integrar en FirewallDNS.

Los umbrales numéricos se fijarán tras capturar línea base en hardware real; no se inventarán objetivos sin medición.

## Benchmark DNS optativo en JVM

- `DnsLatencyBenchmarkTest` contiene una prueba siempre activa para verificar el cálculo nearest-rank de P50/P95/P99 y un benchmark optativo que mide 500 muestras tras 50 calentamientos.
- Ejecuta tres escenarios separados: UDP upstream contra un responder DNS local de loopback (cada muestra usa un QNAME distinto para forzar miss), hit de caché de respuestas (mismo QNAME, nuevo ID DNS) y evaluación determinista de políticas con 128 reglas (el match al final fuerza recorrer el conjunto). No mezcla las distribuciones.
- Ejecutar manualmente: `FIREWALLDNS_RUN_DNS_BENCHMARKS=true gradle :dns-engine:test --tests "*DnsLatencyBenchmarkTest" --info` o lanzar el workflow `DNS Latency Benchmarks` desde GitHub Actions.
- La salida `DNS_BENCHMARK` informa número de muestras, calentamientos y P50/P95/P99 en microsegundos. El cálculo usa nearest-rank; no aplica umbrales de rendimiento automáticos porque el host CI y la carga no son una línea base de dispositivo.
- El escenario de políticas mide el evaluador JVM sin transporte; los otros dos caracterizan cliente upstream y caché. Ninguno mide latencia de Internet, `VpnService.protect()`, TUN, radio Wi-Fi/móvil ni rendimiento del Samsung A34 5G.

## Benchmark Android en dispositivo

- `AndroidDnsLatencyBenchmarkTest` es una prueba de instrumentación del módulo `:android-adapter`. Ejecuta 30 calentamientos y 250 muestras por escenario en el runtime Android, con un responder DNS UDP local en loopback.
- Informa `DNS_BENCHMARK` para `android_loopback_udp` y `android_response_cache_hit`, con P50/P95/P99 en microsegundos. El log usa la etiqueta `FirewallDNSBenchmark`.
- Compilar el APK de pruebas: `gradle :android-adapter:assembleDebugAndroidTest`. Con un dispositivo conectado y depuración USB autorizada, ejecutar: `gradle :android-adapter:connectedDebugAndroidTest`.
- Consultar las medidas con: `adb logcat -s FirewallDNSBenchmark:I`.
- **Límite importante:** esta prueba usa un protector no-op deliberado. Mide el runtime Android, sockets loopback, cliente y caché; no mide `VpnService.protect()`, un túnel TUN activo, un resolutor público ni la radio Wi-Fi/datos. No es evidencia de ausencia de fugas o bucles VPN.
- La medición real con VPN activa, comparación con Firestack, throughput, CPU, RAM, batería, pérdidas y pruebas de cambio de red siguen pendientes. Los resultados deben registrarse con modelo de dispositivo, versión Android, tipo de red, estado térmico/carga, commit y configuración.

## Adaptador Android de protección de sockets

El módulo `:android-adapter` se valida en CI con `gradle test` y `gradle :android-adapter:assembleDebug`. Las pruebas unitarias verifican la delegación de sockets UDP y TCP a `VpnService.protect`, tanto cuando Android acepta la protección como cuando la rechaza. La validación en dispositivo real sigue pendiente: confirmar que los sockets upstream quedan fuera del TUN y que no hay bucles ni fugas DNS al alternar Wi-Fi/datos.


### Validación estructural de respuestas upstream
- `DnsUpstreamResponseValidatorTest` verifica límites de registros, nombres comprimidos, RDLENGTH, bytes sobrantes y framing de opciones EDNS antes de que una respuesta sea devuelta como éxito.
- La validación estructural no sustituye la revisión semántica de cada tipo de RDATA ni las pruebas con resolutores reales y respuestas adversariales.
