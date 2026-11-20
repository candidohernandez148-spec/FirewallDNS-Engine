# Diagnóstico integral de tráfico FirewallDNS

## Objetivo

Mantener **una sola herramienta de diagnóstico** que reúna clasificación de paquetes, flujos, atribución de aplicación cuando Android lo permita, métricas de red y exportación de un informe JSON. No crear un APK distinto por protocolo ni pedir diagnósticos parciales cada vez que se agregue una capacidad.

El diagnóstico es pasivo: no bloquea, altera ni reenvía tráfico por el hecho de clasificarlo. La VPN productiva de FirewallDNS y sus decisiones DNS no se modifican durante esta etapa.

## Estado de la entrega actual: informe unificado v3

El servicio `EngineTunVpnService` ahora clasifica cada paquete que Android entrega a su TUN y agrega, en memoria acotada, contadores por familia IP, transporte, protocolo de aplicación, certeza y motivo. También informa bytes clasificados y latencia del clasificador P50/P95/P99. La clasificación ocurre antes de admitir el paquete en la cola, de modo que un paquete rechazado por saturación también queda reflejado en las métricas de protocolo. El informe exportado usa `schema_version: 3` e incluye dispositivo, rutas, cobertura y privacidad.

**Límite que el propio informe declara:** el servicio sigue configurando solo las rutas DNS virtuales `/32` y `/128`. Por tanto, los contadores TCP/UDP describen únicamente paquetes que Android efectivamente entregue a esas rutas; no son una captura general ni un inventario de las conexiones de todas las aplicaciones. No hay seguimiento de flujos ni atribución UID todavía. No se habilitan rutas por defecto ni forwarding general en esta entrega.

## Estado de esta primera entrega

Se incorpora `FirewallDnsTrafficClassifier`, un clasificador puro por paquete en el APK `:device-diagnostics`. Trabaja con bytes del paquete que el servicio diagnóstico ya haya recibido y devuelve etiquetas por capas:

- Red: IPv4 o IPv6.
- Transporte: TCP, UDP, ICMP u otro.
- Aplicación: DNS, HTTP en claro, TLS, candidato DoT, candidato HTTPS/TLS, QUIC, fragmento, protocolo desconocido o paquete malformado.
- Certeza: CONFIRMED, LIKELY, PORT_ONLY o UNKNOWN.
- Puertos de origen/destino y motivo técnico, sin guardar el payload.

La clasificación no es excluyente entre capas: un paquete se describe simultáneamente por IP, transporte y, si hay evidencia suficiente, protocolo de aplicación.

### Reglas anti-falsos positivos

- El puerto TCP 443 por sí solo nunca se etiqueta HTTPS.
- El puerto UDP 443 por sí solo nunca se etiqueta QUIC.
- Un registro TLS en TCP/443 se presenta como candidato HTTPS/TLS, no como prueba del contenido HTTP.
- TLS en TCP/853 se presenta como candidato DoT, no como DNS confirmado.
- DNS se reconoce por puerto 53 y tamaño mínimo de cabecera; el análisis semántico de la consulta sigue perteneciendo al procesador DNS.
- HTTP se identifica solo por firmas de métodos en texto claro.
- No se descifra TLS, QUIC, ECH, DoH ni tráfico cifrado. DoH no puede confirmarse por el puerto 443; DoQ tampoco se afirma sin analizar el protocolo.
- Fragmentos IP se contabilizan como fragmentos y no se clasifican por un payload que puede no estar presente.

## Puerta de seguridad para captura integral

El servicio actual `EngineTunVpnService` enruta únicamente las dos direcciones DNS virtuales (/32 IPv4 y /128 IPv6). Por tanto, **no observa el tráfico general de las aplicaciones**. El clasificador no convierte esa captura DNS en una captura total.

No se deben añadir rutas por defecto IPv4/IPv6 al TUN actual como simple cambio de diagnóstico: Android enviaría tráfico general al túnel y, al no existir un plano de reenvío TCP/UDP completo, se interrumpiría la conectividad.

Para habilitar cobertura integral sin romper Internet, la misma herramienta debe incorporar una sesión de diagnóstico full-tunnel con un plano de reenvío probado. La aceptación de esa fase exige:

1. Ruta de captura IPv4 e IPv6 completa, con exclusiones explícitas y cobertura reportada.
2. Reenvío TCP y UDP bidireccional, timeouts, límites por flujo y cierre determinista.
3. ICMP/ICMPv6 y tratamiento explícito de fragmentación, MTU y cabeceras de extensión IPv6.
4. Todos los sockets de salida protegidos con `VpnService.protect()` antes de conectarse.
5. Sin bucles VPN, fugas DNS ni pérdida de conectividad al iniciar, cambiar Wi-Fi/datos, suspender, revocar o detener.
6. Comparación de tráfico antes/durante/después y prueba prolongada en Samsung Galaxy A34 5G.
7. Un informe que declare qué rutas, protocolos y aplicaciones quedaron fuera de la captura; nunca presentar cobertura parcial como total.

No se activará un full-tunnel de captura sin forwarding funcional y pruebas de conectividad. Se debe preferir un stack probado (smoltcp u otra alternativa evaluada) frente a implementar TCP/IP desde cero.

## Clasificación de protocolos y límites

| Evidencia disponible | Etiqueta permitida | Lo que no debe afirmarse |
|---|---|---|
| UDP/TCP puerto 53 y cabecera DNS suficiente | DNS | Que todo el contenido DNS está completo o válido sin parsearlo |
| HTTP method en texto claro | HTTP | HTTPS |
| Registro TLS válido | TLS | Sitio/URL o contenido descifrado |
| TLS observado en TCP/443 | Candidato HTTPS/TLS | HTTPS confirmado solo por puerto |
| TLS observado en TCP/853 | Candidato DoT | DNS-over-TLS confirmado por puerto únicamente |
| Cabecera larga QUIC válida en UDP/443 | QUIC | HTTP/3 si no se obtiene ALPN h3 |
| UDP/443 sin cabecera QUIC válida | UDP/443 desconocido | QUIC |
| TCP/443 sin firma TLS | TCP/443 desconocido | TLS/HTTPS |
| Flujo TLS cifrado o ECH | Metadatos observables | Hostname/contenido no visible |

La inspección TLS/QUIC debe limitarse a metadatos disponibles en claro y a buffers completos que ya estén presentes. La fragmentación de segmentos, ClientHello dividido, ECH y cifrado pueden impedir ver SNI o ALPN. No se debe guardar payload para intentar reconstruirlos.

## Modelo del informe único

La siguiente versión del informe consolidará, como mínimo:

- Metadatos de sesión: versión de esquema, versión app/motor, modelo/Android, inicio/fin y tipo de red observado (Wi-Fi/móvil/otra cuando Android lo permita).
- Cobertura: familias IP, protocolos observados, rutas capturadas, exclusiones y límites.
- Paquetes y bytes por IPv4/IPv6 y TCP/UDP/ICMP/otros.
- Conteos de DNS, HTTP, TLS, candidatos DoT/HTTPS, QUIC y desconocidos, separados por nivel de certeza.
- Flujos: duración, puertos, bytes/paquetes, estado/cierre/timeout y error; con límite de memoria, TTL y agregación.
- Atribución UID/paquete solo cuando Android la proporcione; por defecto el informe exportado no incluirá nombres de paquetes ni UID identificables.
- Pérdidas por causa: fragmento no soportado, cabecera malformada, cola llena, flujo rechazado, timeout, fallo upstream, escritura TUN y cierre de sesión.
- Latencias P50/P95/P99, contadores de cola, CPU/memoria cuando puedan medirse de forma fiable.
- Errores de cobertura y protocolo desconocido, sin payload, dominios ni historial de consultas por defecto.

Los contadores y eventos visibles se publicarán en lotes acotados y oportunos. La UI nunca debe bloquear el lector TUN ni el transporte. No se persiste el contenido de paquetes.

## Secuencia de entrega

1. **Clasificador puro y pruebas sintéticas** (esta entrega): reconocer firmas seguras por capas y evitar inferencias por puerto.
2. Integrar el clasificador en el servicio diagnóstico existente y extender el esquema de informe actual, sin cambiar todavía las rutas DNS-only.
3. Implementar y probar el plano de reenvío full-tunnel en la misma herramienta; no habilitar rutas por defecto hasta superar las pruebas de conectividad.
4. Incorporar seguimiento de flujos, contadores en tiempo real, atribución UID opcional y exportación JSON unificada.
5. Ejecutar la matriz Wi-Fi/datos, IPv4/IPv6 y estabilidad en hardware; declarar explícitamente cobertura real y limitaciones.
6. Solo después de la evidencia de diagnóstico, decidir qué capacidades se integran en la VPN productiva.

## Privacidad y seguridad

- Todo el análisis permanece local.
- No se registran payloads, dominios, URLs, SNI, UID o nombres de paquetes por defecto.
- La atribución de app se limita a la información que Android permita resolver y se agrega/redacta en la exportación.
- No se descifra TLS/QUIC ni se instalan certificados raíz.
- No se altera la política BLOCK/OBSERVE/ALLOW ni se usa la observación para aprender o persistir conocimiento.
- El diagnóstico no modifica el servicio VPN productivo ni reemplaza el motor DNS.

## Pruebas de la primera entrega

`FirewallDnsTrafficClassifierTest` valida DNS UDP, HTTP en claro, TLS en puerto 443, DoT candidato, QUIC, falsos positivos por puerto 443, fragmentos, entradas truncadas y ausencia de payload en el resultado. Las pruebas sintéticas no acreditan captura integral ni reenvío en Android; esas puertas requieren la fase de transporte y el Samsung A34 5G.
