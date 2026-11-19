# Estrategia de pruebas

## Pruebas por capa
- Policy Engine: precedencia, conflictos, expiración, reglas por aplicación, decisiones y explicabilidad.
- DNS Engine: nombres inválidos, IDN, etiquetas de servicio, mayúsculas, punto final, EDNS(0), TLV malformado, clases DNS, NXDOMAIN y truncamiento.
- DNS TCP framing: prefijo parcial, cuerpo parcial, longitud inválida, múltiples frames en un buffer y límites.
- DNS upstream: respuesta UDP válida, ID/pregunta incorrectos, fallback TCP ante TC, clase DNS no IN, timeout, rechazo de socket no protegido, dirección upstream no numérica y aciertos de caché sin segunda consulta de red.
- DNS response cache: TTL positivo mínimo, RFC 2308 negativo (SOA TTL/MINIMUM), expiración monotónica, decremento de TTL en hits, aislamiento por consulta/upstream, límite de entradas y exclusión de TTL=0/SERVFAIL/TC/mensajes malformados.
- Fast Cache: concurrencia, expiración, invalidación, presión de memoria y resultados obsoletos.
- App Identity: UID no disponible, paquete eliminado, perfiles de trabajo y restricciones Android.
- Packet/Connection: IPv4/IPv6, UDP/TCP, ICMP, fragmentación, MTU, checksums, DNS TCP, cierres y reconexiones.
- VPN: protección de sockets, prevención de bucles, DNS leak, cambio Wi-Fi/datos y suspensión/reanudación.
- Threat Engine: falsos positivos, allowlist esencial, señales contradictorias y ausencia de aprendizaje persistente.
- Monitor: orden de eventos, capacidad máxima, descartes contabilizados, redacción de datos sensibles, métricas concurrentes y UI no bloqueante.

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
