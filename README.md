# FirewallDNS-Engine

Deterministic DNS filtering, threat reputation, runtime orchestration, and Android VPN diagnostics engine.

## Gradle Modules

- **`:engine-core`**: Domain normalization (`DomainNormalizer`), immutable policy snapshot models (`PolicyModels`), and deterministic rule evaluation (`PolicyEngine`).
- **`:threat-engine`**: Curated advertising/tracking indicators, safe domain allowlist, and conservative lexical heuristics (`ThreatAnalyzer`).
- **`:engine-monitor`**: Bounded non-blocking local event queue and counters (`EngineMonitor`).
- **`:dns-engine`**: RFC 1035 DNS message parser (`DnsMessageParser`), decision/response caches (`DnsDecisionCache`, `DnsResponseCache`), policy NXDOMAIN synthesizer (`DnsPolicyAdapter`), upstream UDP/TCP client (`DnsUpstreamClient`), failover client (`DnsUpstreamFailoverClient`), and exchange cancellation.
- **`:engine-runtime`**: Unified `EngineRuntime` facade coordinating policy evaluation, threat signals, and monitoring.
- **`:android-adapter`**: `VpnService.protect()` socket protector (`AndroidDnsSocketProtector`, `AuditedDnsSocketProtector`), `AndroidEngineRuntime`, IPv4/IPv6 fragment reassembler (`IpFragmentReassembler`), UDP/53 TUN processor (`TunDnsPacketProcessor`), the smoltcp 0.14 JNI transport (`NativeTcpDnsTransport`) and the per-session DNS TCP bridge (`SmoltcpDnsTcpCoordinator`). The production FirewallDNS `DnsFirewallService` and companion diagnostic APK route client DNS TCP/53 through smoltcp 0.14 over the existing TUN. This is DNS-only TCP transport, not a general TCP/UDP tunnel; device-level validation remains required.
- **`:app`**: Android VPN & diagnostics application (`PublicDnsActivity`, `MainActivity`, `FirewallDnsVpnService`, `EngineTunVpnService`, `TunDiagnosticVpnService`, `UdpTunBridgeDiagnosticService`, benchmarks, and traffic classifier).

## Build

The diagnostics APK currently targets ARM64. Install Rust 1.91+, Android NDK 27.2.12479018 and cargo-ndk before building:

```bash
cargo install cargo-ndk --locked
./gradlew :app:assembleDebug
```

See [smoltcp Android JNI](docs/SMOLTCP_ANDROID_JNI.md) for thread ownership, event format, limits and test coverage. See [external engine review](docs/EXTERNAL_ENGINE_REVIEW.md) for the comparison and license decision on Rethink, NetGuard and HevSocks5Tunnel.
