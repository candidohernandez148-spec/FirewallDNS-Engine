# Hoja de ruta

## Fase 0 — Fundamentos y contratos
- Definir contratos de decisión, identidad, eventos y ciclo de vida.
- Documentar política de errores y privacidad.
- Elegir stack y estructura Gradle tras una prueba técnica pequeña.
- Salida: arquitectura revisada y decisiones registradas.

## Fase 1 — Núcleo de políticas
- Modelos BLOCK/OBSERVE/ALLOW.
- Precedencia explícita de reglas de usuario, reglas administradas, allowlist esencial y señales heurísticas.
- Evaluación determinista, explicable y con motivo.
- Pruebas unitarias y de concurrencia.
- Salida: motor puro, sin dependencias Android ni I/O en ruta crítica.

## Fase 2 — DNS y caché
- Normalización segura de nombres DNS (IDN, minúsculas, punto final y validación).
- Evaluación A/AAAA y otros tipos según semántica del registro.
- Caché positiva/negativa con TTL, límites e invalidación.
- Pruebas UDP/TCP, respuestas malformadas, NXDOMAIN y latencia.

## Fase 3 — Identidad de aplicación y conexiones
- Resolver UID/paquete con APIs compatibles.
- Políticas por aplicación con degradación explícita si falta identidad.
- Metadatos TCP/UDP sin fingir inspección de contenido cifrado.

## Fase 4 — Adaptador VPN y transporte
- Prototipo aislado con VpnService/TUN.
- Evaluar stack probado frente a alternativas nativas.
- Validar IPv4/IPv6, MTU, fragmentación, ICMP, TCP/UDP, DNS TCP, checksums y reconexiones.
- Validar protect(), ausencia de bucles y DNS leaks.

## Fase 5 — Inteligencia local
- Señales explicables para malware, phishing, anuncios y trackers.
- Aprendizaje local con límites, caducidad y corrección.
- No bloquear por una sola señal débil; probar allowlist esencial.
- Medir falsos positivos.

## Fase 6 — Observabilidad y rendimiento
- Métricas P50/P95, throughput, CPU, RAM, batería, pérdidas y caché.
- Eventos oportunos mediante flujo acotado y no bloqueante.
- Pruebas prolongadas y de reconexión.

## Fase 7 — Integración controlada
- Adaptador con FirewallDNS sin duplicar VpnService.
- Feature flag, rollback, canary interno y pruebas A/B.
- Sustituir componentes solo tras superar criterios.

## Criterio de salida global
No integrar ni retirar el transporte actual hasta demostrar compatibilidad funcional, ausencia de fugas conocidas, estabilidad prolongada, falsos positivos aceptables y rendimiento igual o mejor en Samsung A34 5G y otros dispositivos de referencia.
