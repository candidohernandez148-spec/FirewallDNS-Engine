# smoltcp como transporte DNS/TCP de FirewallDNS

## Decisión

FirewallDNS utiliza smoltcp 0.14.0 como implementación probada del transporte TCP para DNS/53. No se desarrolla una pila TCP/IP propia. El motor de políticas sigue siendo la autoridad única de BLOCK, OBSERVE y ALLOW; Android conserva el ciclo de vida de VpnService, el descriptor TUN y la protección de sockets upstream.

## Integración actual

En candidohernandez148-spec/FirewallDNS (rama main, commit f1c124a), el DnsFirewallService productivo ya conecta:

1. Lector del descriptor TUN y reensamblado de fragmentos compatibles.
2. Clasificación de paquetes DNS TCP/53 IPv4/IPv6.
3. Cola JNI acotada y NativeTcpDnsTransport.
4. Un único hilo propietario de smoltcp::Interface y SocketSet.
5. Eventos de sesión hacia SmoltcpDnsTcpCoordinator.
6. Decoder DNS/TCP incremental por sesión y decisiones del motor compartido.
7. Upstream UDP/TCP protegido mediante VpnService.protect() antes de connect().
8. Respuesta TCP generada por smoltcp y escrita en el mismo TUN.

El APK de diagnóstico reutiliza el transporte y permite probar la biblioteca ARM64 instalada. No se crea un segundo VpnService.

## Límites

- El transporte integrado inspecciona DNS/53 por TCP; no es un túnel TCP/UDP general.
- No demuestra inspección de DoH, DoT ni DoQ.
- La integración de código y una compilación correcta no demuestran ausencia de fugas, latencia adecuada o estabilidad en hardware.
- Las pruebas host-side usan paquetes sintéticos y no sustituyen las pruebas de red real.
- No retirar el código de referencia del arnés hasta que las pruebas de paridad y carga indiquen que ya no es necesario.

## Colas y contabilidad

Todas las colas tienen límites de paquetes y bytes. Los rechazos en la cola JNI y los rechazos al transferir paquetes a la cola RX de smoltcp se acumulan en un contador atómico nativo y se exponen como ingressRejected. Así no se pierden silenciosamente los descartes ocurridos entre ambas colas. El contador no representa paquetes enviados correctamente al upstream; solo rechazos en el ingreso.

## Validación pendiente en dispositivo

En Samsung Galaxy A34 5G:
- DNS TCP/53 real por IPv4 e IPv6.
- Handshake, retransmisión, ACK, FIN, RST y sesiones concurrentes.
- Saturación de cada cola, expiración, cancelación y reconexión.
- Resultado de VpnService.protect() para upstream UDP y TCP.
- Cambio Wi-Fi/datos móviles, latencia P50/P95/P99, pérdidas, CPU, memoria y batería.
- Comparación A/B contra la ruta anterior bajo el mismo escenario y versión Android.

No declarar terminado el motor hasta que estos resultados se documenten como medidos, fallidos o no verificados.