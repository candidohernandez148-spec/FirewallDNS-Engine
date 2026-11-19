# Diagnóstico TUN aislado en Android

El APK `:device-diagnostics` incorpora una prueba experimental de `VpnService` separada del servicio VPN de FirewallDNS.

## Qué mide

- Resultado y duración de `VpnService.protect()` sobre un socket UDP sintético independiente. El resultado positivo solo confirma que Android aceptó proteger ese socket; no demuestra conectividad externa.
- Latencia desde el envío de cada datagrama UDP de prueba hasta que el lector del descriptor TUN observa el paquete.
- 100 paquetes, paquetes observados, pérdidas, errores y percentiles P50/P95/P99.

## Seguridad y alcance

- Android solicita autorización VPN antes de iniciar la prueba.
- El servicio usa una ruta única de laboratorio `198.18.0.1/32` y una dirección TUN `10.77.0.1/32`.
- No se envían consultas DNS, no se cambian los DNS del sistema y no se reenvía tráfico a Internet.
- Solo se aceptan paquetes UDP dirigidos a la ruta/puerto de laboratorio y con una marca binaria del propio benchmark.
- El servicio detiene la VPN de diagnóstico al terminar; el usuario debe apagar FirewallDNS y cualquier otra VPN antes de empezar.
- El JSON declara explícitamente que la prueba es una VPN de diagnóstico y que no recoge consultas DNS personales.

## Cómo ejecutar en el teléfono

1. Instala el APK independiente más reciente de GitHub Actions.
2. Abre **FirewallDNS - Prueba de red**.
3. Desactiva FirewallDNS y cualquier otra VPN.
4. Pulsa **Medir VpnService.protect() y entrada TUN** y acepta el diálogo de Android.
5. Espera el resultado y pulsa **Guardar informe JSON**.
6. Repite por separado en Wi-Fi y en datos móviles.

## Interpretación

La latencia es envío UDP local → observación en TUN. No es RTT de Internet, latencia DNS, coste de filtrado del motor ni forwarding. La prueba tampoco acredita ausencia de fugas ni paridad con Firestack. El lector TUN de diagnóstico no está conectado al servicio VPN productivo.

## Validación automatizada

`Ipv4UdpProbeParserTest` cubre cabeceras IPv4 con opciones, truncamiento, protocolo/puerto/destino incorrectos, longitud UDP inválida, fragmentación y marca binaria. El workflow `Engine Core` ejecuta `gradle test`, ensambla el adaptador Android, compila pruebas Android y genera el APK de diagnóstico.
