# Estrategia de pruebas

## Pruebas por capa
- Policy Engine: precedencia, conflictos, expiración, reglas por aplicación, decisiones y explicabilidad.
- DNS Engine: nombres inválidos, IDN, etiquetas de servicio, mayúsculas, punto final, EDNS(0), TLV malformado, clases DNS, NXDOMAIN y truncamiento.
- DNS TCP framing: prefijo parcial, cuerpo parcial, longitud inválida, múltiples frames en un buffer y límites.
- DNS upstream: respuesta UDP válida, ID/pregunta incorrectos, registros truncados, punteros de compresión inválidos, bytes sobrantes, framing EDNS malformado, fallback TCP ante TC, clase DNS no IN, timeout, rechazo de socket no protegido, dirección upstream no numérica, aciertos de caché sin segunda consulta de red y cancelación durante espera UDP/TCP.
- DNS failover: resolutor primario sin respuesta y secundario válido, respuesta primaria malformada seguida de secundario válido, agotamiento de resolutores, límite configurable de intentos, lista vacía, consulta inválida, fallo local de protección de sockets, cancelación terminal y observación monotónica de duración/resultado por intento. Los fallos del callback de telemetría no alteran la decisión DNS. Solo se reintentan fallos de transporte o respuestas upstream defectuosas; no se repiten errores locales permanentes. El orden, endpoints y máximo de intentos los configura el host; el motor no selecciona proveedores ni modifica Private DNS.
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

## Diagnóstico Android de failover DNS

- La pantalla de prueba de red incluye **Probar failover real del motor**. Cada muestra usa un resolutor primario local silencioso para provocar un timeout controlado y, a continuación, el cliente de failover del motor intenta un secundario público (Cloudflare o Google) por UDP/53.
- Ejecutar 10 muestras por secundario. El informe JSON v2 registra transporte detectado, recuperaciones correctas, fallos, errores y distribuciones separadas: duración del intento primario, RTT del intento secundario y latencia total del failover (P50/P95/P99 donde aplica). Los tiempos por intento usan reloj monotónico; la latencia total incluye ambos intentos y el procesamiento entre ellos.
- Repetir manualmente con Wi-Fi y con datos móviles. No cambia DNS del sistema ni recoge dominios personales.
- Este diagnóstico ejercita el failover del motor en el dispositivo y la salida UDP/53 al secundario, pero usa un protector no-op: no mide VpnService.protect(), VPN activa, TUN ni demuestra ausencia de fugas/bucles. El primario es una falla simulada local, no un proveedor público defectuoso.

## Benchmark Android en dispositivo

- `AndroidDnsLatencyBenchmarkTest` es una prueba de instrumentación del módulo `:android-adapter`. Ejecuta 30 calentamientos y 250 muestras por escenario en el runtime Android, con un responder DNS UDP local en loopback.
- Informa `DNS_BENCHMARK` para `android_loopback_udp` y `android_response_cache_hit`, con P50/P95/P99 en microsegundos. El log usa la etiqueta `FirewallDNSBenchmark`.
- Compilar el APK de pruebas: `gradle :android-adapter:assembleDebugAndroidTest`. Con un dispositivo conectado y depuración USB autorizada, ejecutar: `gradle :android-adapter:connectedDebugAndroidTest`.
- Consultar las medidas con: `adb logcat -s FirewallDNSBenchmark:I`.
- **Límite importante:** esta prueba usa un protector no-op deliberado. Mide el runtime Android, sockets loopback, cliente y caché; no mide `VpnService.protect()`, un túnel TUN activo, un resolutor público ni la radio Wi-Fi/datos. No es evidencia de ausencia de fugas o bucles VPN.
- La medición real con VPN activa, comparación con Firestack, throughput, CPU, RAM, batería, pérdidas y pruebas de cambio de red siguen pendientes. Los resultados deben registrarse con modelo de dispositivo, versión Android, tipo de red, estado térmico/carga, commit y configuración.

## Gestor experimental de flujos UDP protegidos

- `AndroidUdpFlowManagerTest` verifica ida y vuelta UDP real sobre loopback, límite de flujos simultáneos, liberación de capacidad al cerrar un flujo, rechazo de datagramas vacíos/sobredimensionados y cierre del gestor.
- La cola de salida se limita por flujo y el número de workers por el máximo de flujos configurado. Los contadores de enviados/recibidos/rechazados permiten observar presión y actividad.
- El callback de recepción corre en el worker del flujo; debe copiar/encolar rápidamente y no realizar I/O bloqueante. El consumidor es responsable de cerrar el gestor al terminar la sesión.
- Estas pruebas JVM no prueban `VpnService.protect()` real, TUN, smoltcp, Wi-Fi/datos ni ausencia de bucles/fugas. La integración Android aislada y la validación en Samsung A34 5G siguen pendientes.

## Adaptador Android de protección de sockets

El módulo `:android-adapter` se valida en CI con `gradle test` y `gradle :android-adapter:assembleDebug`. Las pruebas unitarias verifican la delegación de sockets UDP y TCP a `VpnService.protect`, tanto cuando Android acepta la protección como cuando la rechaza. La validación en dispositivo real sigue pendiente: confirmar que los sockets upstream quedan fuera del TUN y que no hay bucles ni fugas DNS al alternar Wi-Fi/datos.


### Validación estructural de respuestas upstream
- `DnsUpstreamResponseValidatorTest` verifica límites de registros, nombres comprimidos, RDLENGTH, bytes sobrantes y framing de opciones EDNS antes de que una respuesta sea devuelta como éxito.
- La validación estructural no sustituye la revisión semántica de cada tipo de RDATA ni las pruebas con resolutores reales y respuestas adversariales.


## Adaptador de paquetes DNS sobre TUN

- `TunDnsPacketProcessorTest` comprueba solicitudes UDP DNS IPv4 e IPv6 básico, inversión de direcciones y puertos, checksum IPv4, checksum UDP no nulo en IPv6, decisión BLOCK sin upstream y rechazo explícito de TCP/fragmentos.
- El APK independiente `:device-diagnostics` contiene `EngineTunVpnService`. Usa direcciones DNS virtuales y rutas /32 y /128, lector TUN, cola acotada de 256 paquetes, cuatro trabajadores y upstreams protegidos por `VpnService.protect()`.
- La ejecución en CI compila el servicio y genera el APK, pero no sustituye la prueba en el Samsung A34 5G. En el dispositivo hay que confirmar que el contador de paquetes aumenta, que se reciben respuestas DNS, que BLOCK no llega al upstream, que OBSERVE sí reenvía, y que al detener el servicio se recupera el DNS normal.
- Alcance actual: UDP DNS sobre IPv4 sin fragmentación y IPv6 sin cabeceras de extensión. DNS-over-TCP desde el cliente, fragmentos, DoT/DoH, atribución por UID y tráfico IP ajeno a DNS no están cubiertos. No activar como VPN general ni retirar Firestack en FirewallDNS con esta evidencia.


## Diagnóstico TUN real: informe JSON v2

- El informe v2 desglosa los descartes mutuamente excluyentes en `processor_no_response`, `processor_failed`, `queue_rejected`, `response_write_failed` y `stopped_before_response`. `dropped` es la suma de esas causas; no debe interpretarse como cantidad de consultas DNS inválidas sin revisar el desglose.
- `processor_returned_response` cuenta respuestas completas devueltas por el procesador, antes de intentar escribirlas en TUN. `responses_out` y el alias histórico `dns_processed` solo aumentan después de escribir y hacer flush correctamente.
- `packets_in` cuenta todos los paquetes leídos desde TUN, no solo DNS válido. Paquetes no compatibles o malformados pueden terminar en `processor_no_response`.
- Los contadores BLOCK/OBSERVE/ALLOW/REJECTED pertenecen al monitor del runtime y representan evaluaciones de política; no se deben sumar ni comparar directamente con `responses_out`. Una evaluación puede no producir respuesta (por ejemplo, rechazo) y una respuesta puede fallar después en el transporte.
- El informe no registra dominios, direcciones, consultas ni payloads. Repetir la prueba durante 15 minutos (900 s), detener desde la pantalla y guardar el JSON final. Confirmar manualmente que el estado sea `stopped`, que el archivo incluya `schema_version: 2` y que el contador de duración se aproxime al tiempo real.
- Limitación: los contadores son instantáneas concurrentes; durante una parada abrupta pueden quedar tareas en ejecución al emitirse el último broadcast. No usar aún el informe para declarar cero pérdidas ni para aprobar integración de producción. La validación de cierre consistente y la prueba física de 15 minutos siguen siendo obligatorias.


## Núcleo Rust/JNI experimental

- La suite Rust ejecuta fixtures deterministas IPv4/IPv6, checksum IPv4, checksum UDP IPv6 obligatorio, puerto DNS, truncamiento y fragmentación IPv4: cargo test --manifest-path rust-core/Cargo.toml.
- CI compila libfirewalldns_native.so para arm64-v8a con cargo-ndk y la empaqueta en android-adapter/jniLibs antes de ensamblar los artefactos Android.
- NativePacketCoreInstrumentedTest confirma en un dispositivo/emulador ARM64 que la biblioteca se carga mediante JNI y rechaza un paquete truncado.
- Esta prueba confirma carga e invocación, no rendimiento ni paridad completa. Antes de usar Rust en la ruta TUN se requiere un benchmark A/B Kotlin/Rust con fixtures idénticos, throughput, P50/P95/P99, CPU, memoria y consumo en el Samsung A34 5G.


## Arnés UDP de ida y vuelta smoltcp (host-side)

- `smoltcp_udp_roundtrip.rs` verifica un ciclo completo de laboratorio: socket UDP smoltcp → paquete IP en cola TX → socket UDP loopback del host → respuesta encapsulada → cola RX → socket smoltcp.
- Comprueba payload, puertos, endpoint remoto y liberación de bytes RX. La prueba usa loopback local y no necesita acceso a Internet.
- No prueba el socket Android protegido, `VpnService.protect()`, TUN real, JNI, IPv6 ni ausencia de bucles/fugas. No habilita la pila en producción.

## Puente UDP TUN protegido en dispositivo Android

- En el APK `device-diagnostics`, pulsa **Probar UDP por TUN + socket protegido** y concede el permiso VPN temporal.
- No ejecutar mientras otra VPN esté activa: Android permite una VPN activa por perfil y la prueba debe evitar reemplazar o interrumpir la VPN que se esté usando.
- El servicio enruta únicamente `198.18.0.1/32`, usa un eco UDP en loopback y exige `VpnService.protect()` en el socket del puente.
- El resultado debe incluir `success: true`, un paquete recibido por TUN y una respuesta escrita al TUN. El informe identifica modelo/Android y confirma que no se usó red pública ni se interceptó DNS.
- Repetir en Samsung Galaxy A34 5G con Wi-Fi y datos móviles activos; guardar cada JSON por separado.
- La prueba valida el camino Android TUN/socket protegido/reinyección UDP local, no conectividad UDP a Internet, smoltcp, TCP, fragmentación, IPv6 end-to-end, rendimiento de radio ni ausencia general de fugas.
