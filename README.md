# FirewallDNS-Engine

Deterministic DNS filtering, threat reputation, runtime orchestration, and Android VPN diagnostics engine.

## Gradle Modules

- **`:engine-core`**: Domain normalization (`DomainNormalizer`), immutable policy snapshot models (`PolicyModels`), and deterministic rule evaluation (`PolicyEngine`).
- **`:threat-engine`**: Curated advertising/tracking indicators, safe domain allowlist, and conservative lexical heuristics (`ThreatAnalyzer`).
- **`:engine-monitor`**: Bounded non-blocking local event queue and counters (`EngineMonitor`).
- **`:dns-engine`**: RFC 1035 DNS message parser (`DnsMessageParser`), decision/response caches (`DnsDecisionCache`, `DnsResponseCache`), policy NXDOMAIN synthesizer (`DnsPolicyAdapter`), upstream UDP/TCP client (`DnsUpstreamClient`), failover client (`DnsUpstreamFailoverClient`), and exchange cancellation.
- **`:engine-runtime`**: Unified `EngineRuntime` facade coordinating policy evaluation, threat signals, and monitoring.
- **`:android-adapter`**: `VpnService.protect()` socket protector (`AndroidDnsSocketProtector`, `AuditedDnsSocketProtector`), `AndroidEngineRuntime`, IPv4/IPv6 fragment reassembler (`IpFragmentReassembler`), UDP/53 TUN processor (`TunDnsPacketProcessor`), per-session TCP/53 stack (`TunTcpStack`), preflight & runtime security guards (`TunDataPlaneSecurityValidator`, `LoopAndLeakGuard`), and unified data-plane coordinator (`TunDataPlaneCoordinator`).
- **`:app`**: Android VPN & diagnostics application (`PublicDnsActivity`, `MainActivity`, `FirewallDnsVpnService`, `EngineTunVpnService`, `TunDiagnosticVpnService`, `UdpTunBridgeDiagnosticService`, benchmarks, and traffic classifier).

## Build

```bash
./gradlew :app:assembleDebug
```
