# Diagnóstico desde un teléfono Android

El módulo `:device-diagnostics` genera una aplicación Android independiente para medir el coste del cliente DNS y de la caché en el runtime del dispositivo, sin Android Studio.

## Generar el APK

El workflow **Engine Core** compila `:device-diagnostics:assembleDebug` y publica el APK como artefacto descargable de GitHub Actions. Descarga `firewalldns-device-diagnostics-debug`, instala el APK en el teléfono y abre **FirewallDNS Diagnóstico**.

## Ejecutar y compartir

1. Pulsa **Ejecutar diagnóstico** y espera a que termine.
2. Pulsa **Guardar informe JSON**.
3. Guarda `firewalldns-diagnostico.json` en Descargas o en una carpeta que recuerdes.
4. Adjunta ese JSON en la conversación.

El informe contiene únicamente modelo/fabricante, versión Android, fecha UTC y resultados agregados de latencia. No registra nombres de dominio personales, historial, IP pública, credenciales ni contenido de tráfico.

## Alcance y límites

- Usa un servidor DNS UDP local en loopback y 250 muestras tras 30 calentamientos.
- Mide también 250 aciertos de la caché de respuestas.
- El protector de sockets de esta aplicación de diagnóstico es deliberadamente simulado/no-op.
- **No mide** `VpnService.protect()`, una VPN activa, recorrido TUN, DNS público, Wi-Fi frente a datos móviles, consumo energético ni el bloqueo de tráfico real.
- No cambia la configuración de red, no inicia ni detiene FirewallDNS y no sustituye Firestack.
- Los resultados deben interpretarse como mediciones del runtime del dispositivo, no como prueba de producción.

La validación de la VPN real requerirá una segunda etapa con integración controlada al servicio VPN anfitrión y pruebas explícitas de no fuga DNS.
