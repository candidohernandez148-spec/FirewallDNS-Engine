# Arquitectura de FirewallDNS-Engine

## Objetivo
Construir un motor de filtrado y protección de red para Android, desacoplado de FirewallDNS. Será responsable de decisiones rápidas, coherentes, observables y comprobables. La integración ocurrirá solo cuando supere criterios de aceptación y rendimiento.

## Principios
1. Una sola autoridad de políticas: BLOCK, OBSERVE o ALLOW.
2. La ruta crítica no realiza I/O de disco, operaciones de red ni trabajo pesado.
3. Conocimiento determinista: indicadores y heurísticas integrados/curados; no hay aprendizaje persistente ni entrenamiento con el tráfico del usuario.
4. Fail-safe explícito: cada error tiene comportamiento definido.
5. Separación entre plano de control y plano de datos.
6. Medición antes de optimización: latencia P50/P95, throughput, CPU, memoria, batería y pérdidas.
7. No reinventar TCP/IP sin evidencia; evaluar stacks probados/nativos.

## Componentes lógicos
| Módulo | Responsabilidad |
|---|---|
| engine-core | Contratos, modelos, ciclo de vida y coordinación |
| policy-engine | Evaluación determinista y prioridad de reglas |
| dns-engine | Normalización, evaluación DNS, caché y respuestas |
| packet-engine | Adaptador TUN y límites con el stack de red |
| connection-engine | Flujos TCP/UDP y ciclo de vida |
| app-identity | Asociación UID/paquete cuando Android lo permita |
| threat-engine | Indicadores de riesgo integrados/curados y heurísticas deterministas |
| fast-cache | Cachés concurrentes con TTL y límites |
| engine-monitor | Métricas, eventos y diagnóstico no bloqueante |

Los límites implementados son módulos Gradle. `engine-runtime` expone una fachada única para que Android no tenga que coordinar directamente varios módulos internos.

## Flujo de decisión
1. El adaptador recibe un paquete DNS validado desde TUN o metadatos de flujo.
2. Normaliza la entrada e identifica la aplicación si es posible.
3. Consulta la caché.
4. Si no hay resultado vigente, Policy Engine evalúa reglas explícitas.
5. Solo cuando no existe regla coincidente, Threat Engine evalúa indicadores locales y heurísticas.
6. Devuelve decisión, motivo, regla, confianza y caducidad.
7. Publica evento al monitor de forma asíncrona y acotada.

OBSERVE registra señales y permite el tráfico; no equivale a bloquear.

## Límites técnicos
- Android VpnService entrega paquetes IP mediante TUN; no concede identidad fiable de proceso para cada paquete.
- DNS UDP/TCP puede evaluarse si pasa por el motor. DoH/DoT no son inspeccionables como DNS normal sin capacidades adicionales.
- IPv4/IPv6, fragmentación, MTU, ICMP, TCP, UDP, DNS TCP, checksums, reconexión y protección de sockets requieren pruebas.
- Los sockets fuera de la VPN deben protegerse para evitar recursión.
- No se prometerá inspección total del tráfico cifrado ni atribución de aplicación sin evidencia.

## Estrategia de transporte
Definir interfaces y medir alternativas. Se prefiere integrar un stack probado antes que implementar TCP/IP desde cero. Firestack se toma como referencia temporal para inventariar capacidades y comparar resultados, no como motor alternativo ni dependencia objetivo. FirewallDNS-Engine será la única autoridad de políticas y filtrado. La retirada de Firestack en Android se habilita solo cuando el motor nuevo cubra las capacidades necesarias y supere pruebas de compatibilidad, seguridad, estabilidad y rendimiento.

## Inteligencia integrada sin aprendizaje persistente

El módulo `threat-engine` utiliza indicadores integrados y curados de publicidad y tracking. Las señales de alta confianza pueden sugerir BLOCK según las reglas y prioridades definidas; las heurísticas débiles solo sugieren OBSERVE. Una allowlist evita afectar dominios esenciales conocidos. Las reglas explícitas del usuario se evalúan antes y prevalecen. El motor no aprende del tráfico, no entrena modelos localmente y no guarda conocimiento derivado de consultas. La mejora de cobertura se realiza mediante versiones revisadas de indicadores y reglas, con pruebas antes de distribuirlas. No hay todavía feed firmado ni cobertura exhaustiva de malware/phishing.

## Estado del monitor local

El módulo `engine-monitor` mantiene contadores con acumuladores concurrentes y una cola lock-free acotada para eventos locales. Publicar eventos no realiza I/O y no espera a un consumidor; al llenarse la cola, descarta el evento y aumenta un contador. Los dominios y paquetes se redactan por defecto y solo se incluyen mediante opt-in local. El consumidor puede extraer eventos mediante polling o lotes; no se crea un hilo de UI ni de almacenamiento dentro del motor.

## Estado del prototipo DNS

El módulo `dns-engine` contiene un parser estricto de consultas de una pregunta, con validación de cabecera, QNAME, QTYPE/QCLASS y una sección adicional EDNS(0) OPT opcional con validación de TLV y límites. El codec DNS-over-TCP maneja el prefijo de longitud de dos bytes. `DnsUpstreamClient` realiza consultas UDP, valida ID/QR/opcode/pregunta y la estructura de todas las secciones de la respuesta (nombres comprimidos, límites RR, RDLENGTH y opciones EDNS) antes de entregarla; cambia a TCP cuando UDP devuelve TC. El constructor exige una estrategia explícita de protección para ambos sockets; el adaptador Android debe llamar a `VpnService.protect` antes de conectarlos. No existe un protector no-op implícito. El upstream exige una dirección IP numérica IPv4/IPv6 para evitar resolución DNS recursiva; los timeouts son configurables y acotados. El cliente es síncrono y debe ejecutarse fuera de la ruta crítica de paquetes.

La caché de respuestas DNS positivas y negativas está integrada en `DnsUpstreamClient`. Es volátil, acotada por entradas y bytes, usa expiración monotónica y limita el TTL almacenado. Las claves aíslan upstream y variante completa de consulta (incluidos EDNS y CD); en los hits reescribe el ID y reduce los TTL restantes. La política de caché negativa usa SOA TTL/MINIMUM conforme a RFC 2308. La caché no persiste datos en disco. Las pruebas optativas contra resolutores reales (Cloudflare, Google y Quad9) se ejecutaron correctamente en CI. La cancelación por intercambio usa un scope explícito que cierra el socket UDP/TCP activo para desbloquear receive/connect/read; no crea hilos ni introduce dependencias de coroutines. El llamador debe ejecutar el intercambio fuera de la ruta crítica y cancelar el scope al terminar su operación.

Las clases DNS distintas de IN se pasan sin aplicar políticas de dominio. Los tipos A/AAAA y otros tipos IN se evalúan por nombre; el módulo no interpreta RDATA ni genera respuestas A/AAAA permitidas.

## Caché de decisiones DNS

La caché de decisiones está acotada por número de entradas, usa TTL corto y la revisión monotónica del snapshot de políticas como parte de la clave. La caducidad de una regla limita también la vida de su decisión cacheada. Las lecturas y escrituras usan primitivas concurrentes sin adquirir bloqueos; un contador atómico reserva capacidad y la expulsión es oportunista para mantener el límite estricto incluso bajo concurrencia. Esta caché no almacena respuestas DNS ni sustituye la caché positiva/negativa de respuestas descrita arriba.

## Concurrencia y estado
- Evaluación acotada y sin I/O de disco en la ruta crítica.
- No se implementará persistencia de aprendizaje, entrenamiento local ni base de datos de conocimiento derivado del tráfico.
- Reglas activas como snapshots inmutables.
- Cachés operativas con TTL, límites e invalidación explícita; no son aprendizaje y no sobreviven como conocimiento aprendido.
- La configuración explícita del usuario y las listas curadas podrán persistirse en la capa de aplicación, separadas de cualquier aprendizaje.
- Colas de eventos acotadas; la saturación se contabiliza sin detener el filtrado.

## Adaptador Android de protección DNS

El módulo aislado `:android-adapter` implementa `DnsSocketProtector` mediante `VpnService.protect(DatagramSocket)` y `VpnService.protect(Socket)`. Delega directamente el resultado booleano de Android y no conecta ni envía datos por sí mismo. `DnsUpstreamClient` realiza la protección antes de conectar cada socket; un resultado falso se trata como fallo y no se intenta el transporte sin proteger. La instancia de `VpnService` debe pertenecer al servicio VPN activo y el adaptador no debe conservarla más allá de su ciclo de vida.

Este módulo compila como Android Library (minSdk 24, compileSdk 36) y depende de `:dns-engine`. Su existencia no implica que el servicio VPN de FirewallDNS ya use el motor: la integración del plano de datos permanece bloqueada hasta completar las pruebas de paridad, compatibilidad, fugas, estabilidad y rendimiento.

## Evolución
No se fijan todavía lenguaje, versión Android ni dependencias de red. Antes del primer módulo ejecutable se documentarán decisiones tecnológicas y se validará compatibilidad con el nivel mínimo de Android previsto.


## Primer recorrido real TUN DNS (diagnóstico aislado)

El módulo Android contiene `TunDnsPacketProcessor`, que acepta únicamente datagramas UDP DNS IPv4 (sin fragmentos) e IPv6 básico (sin cabeceras de extensión). Valida límites IP/UDP, entrega el payload DNS al `EngineRuntime`, devuelve NXDOMAIN sintético para BLOCK, y reenvía OBSERVE/ALLOW mediante un callback upstream. Construye el paquete de respuesta invirtiendo direcciones/puertos y recalculando checksums IPv4/UDP, incluido el pseudo-header IPv6. Las respuestas DNS que superan el límite configurado se marcan como truncadas para respetar el MTU; el cliente puede intentar DNS-over-TCP, que este prototipo todavía no termina localmente.

`device-diagnostics:EngineTunVpnService` configura un TUN Android con rutas únicamente a sus servidores DNS virtuales IPv4/IPv6. El lector TUN no hace I/O de red: copia paquetes a una cola acotada y un grupo de trabajadores realiza evaluación/upstream. Los sockets de salida se protegen con `VpnService.protect()`. Este servicio es de diagnóstico y no sustituye aún el servicio VPN de FirewallDNS; tampoco captura tráfico general ni demuestra paridad funcional de producción.


## Núcleo nativo Rust experimental

El módulo `NativePacketCore`/preflight Rust para validación estructural es distinto del transporte `NativeTcpDnsTransport`: el primero no decide políticas ni sustituye al parser productivo; el segundo sí participa en la ruta smoltcp de DNS TCP/53. No activar validadores redundantes en el camino crítico sin demostrar que añaden seguridad sin duplicar trabajo. El detalle de ABI, códigos de retorno y límites está en `docs/RUST_CORE.md` y `docs/SMOLTCP_ANDROID_JNI.md`.
