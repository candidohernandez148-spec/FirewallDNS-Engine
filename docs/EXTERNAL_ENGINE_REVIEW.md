# Revisión de motores VPN y firewall externos

## Objetivo

Tomar patrones técnicos probados sin añadir una segunda VPN, duplicar la autoridad de políticas ni copiar código sin revisar compatibilidad y licencia. Esta revisión compara alcance y arquitectura; no afirma que se hayan ejecutado los proyectos externos en nuestro Samsung.

## Comparación

| Proyecto | Capacidades relevantes | Licencia observada | Uso recomendado en FirewallDNS |
|---|---|---|---|
| [Rethink DNS + Firewall + VPN](https://github.com/celzero/rethink-app) | DNS con blocklists, firewall por aplicación, monitor de conexiones y varios modos de red. Su README describe un motor de red basado en Firestack/Go. | Apache-2.0 ([LICENSE](https://github.com/celzero/rethink-app/blob/main/LICENSE)) | Referencia para separar planos DNS/firewall/monitor y explicar conexiones por app. No portar Firestack como segundo motor: la arquitectura actual ya tiene smoltcp + motor DNS compartido. |
| [NetGuard](https://github.com/M66B/NetGuard) | Firewall local sin root, reglas por aplicación y por Wi-Fi/datos móviles, con VPN local. | GPL-3.0 ([LICENSE](https://github.com/M66B/NetGuard/blob/master/LICENSE)) | Usar como matriz de comportamiento y casos límite de reglas por aplicación/red. No copiar código sin aceptar las obligaciones GPL-3.0 y revisar el impacto en la distribución del proyecto. |
| [HevSocks5Tunnel](https://github.com/heiher/hev-socks5-tunnel) | Tun2socks nativo, IPv4/IPv6, TCP/UDP general, SOCKS5 y límites de sesiones. | MIT ([LICENSE](https://github.com/heiher/hev-socks5-tunnel/blob/main/LICENSE)) | Candidato para evaluar si el producto decide convertirse en un túnel TCP/UDP general. No es reemplazo directo del motor DNS: requiere un proxy SOCKS5 y cambia el alcance y la ruta de datos. |

## Decisión para la arquitectura actual

1. Mantener un solo VpnService: DnsFirewallService.
2. Mantener FirewallDNS-Engine como autoridad única de BLOCK / OBSERVE / ALLOW.
3. Mantener smoltcp como transporte TCP de DNS/53 ya integrado en producción; no añadir Firestack, NetGuard ni Hev como un segundo stack en paralelo.
4. Adoptar de Rethink y NetGuard patrones de observabilidad, atribución de aplicación y reglas por transporte/red, pero implementarlos con las interfaces y pruebas propias.
5. Usar Hev solo como referencia comparativa para una posible fase de túnel general, después de decidir explícitamente ese alcance y medirlo en dispositivo.
6. No retirar el código de referencia ni ampliar el túnel hasta demostrar paridad, protección upstream, ausencia de recursión, estabilidad y rendimiento en el dispositivo.

## Puertas de aceptación

- Cada componente externo que se proponga integrar debe tener licencia, versión/commit, archivos copiados y avisos de copyright registrados.
- Cada sustitución debe tener una prueba que falle antes y pase después, además de pruebas de regresión.
- No se habilita TCP/UDP general por el mero hecho de que un motor externo lo soporte.
- Las métricas deben distinguir paquetes recibidos, encolados, rechazados, procesados y respuestas realmente escritas.

## Fuentes

- Rethink README y licencia: https://github.com/celzero/rethink-app
- NetGuard README y licencia GPL-3.0: https://github.com/M66B/NetGuard
- HevSocks5Tunnel README y licencia MIT: https://github.com/heiher/hev-socks5-tunnel