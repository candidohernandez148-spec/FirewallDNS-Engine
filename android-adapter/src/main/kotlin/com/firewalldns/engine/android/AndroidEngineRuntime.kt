package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.dns.DnsResponseCache
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamFailoverClient
import com.firewalldns.engine.monitor.EngineMonitor
import com.firewalldns.engine.runtime.EngineRuntime
import com.firewalldns.engine.threat.ThreatAnalyzer

/** Android host adapter binding EngineRuntime and VpnService socket protection. */
class AndroidEngineRuntime(
    vpnService: VpnService,
    initialRules: Collection<PolicyRule> = emptyList(),
    threatAnalyzer: ThreatAnalyzer = ThreatAnalyzer(),
    monitor: EngineMonitor = EngineMonitor(),
) {
    val engine = EngineRuntime(initialRules, threatAnalyzer, monitor)
    val socketProtector = AndroidDnsSocketProtector(vpnService)
    private val sharedResponseCache = DnsResponseCache()

    fun createDnsFailover(
        configs: List<DnsUpstreamConfig>,
        maxAttempts: Int = configs.size,
    ): DnsUpstreamFailoverClient {
        val clients = configs.map { cfg ->
            DnsUpstreamClient(cfg, socketProtector, sharedResponseCache)
        }
        return DnsUpstreamFailoverClient(clients, maxAttempts)
    }
}
