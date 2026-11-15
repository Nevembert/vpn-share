package dev.nevembert.vpnshare

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities

data class DnsEntry(
    val network: String,
    val interfaceName: String,
    val servers: List<String>,
    val domains: String
)
data class DnsInventory(val entries: List<DnsEntry>, val notes: List<String>)

/** Public Android API; observes DNS without changing settings or leaking queries. */
object DnsInspector {
    fun collect(context: Context): DnsInventory {
        val notes = mutableListOf<String>()
        val entries = mutableListOf<DnsEntry>()
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            for (network in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                val link = cm.getLinkProperties(network) ?: continue
                val kind = if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) "VPN" else "Сеть"
                entries += DnsEntry(
                    kind,
                    link.interfaceName ?: "неизвестно",
                    link.dnsServers.map { it.hostAddress ?: "?" },
                    link.domains ?: ""
                )
            }
        } catch (e: Exception) {
            notes += "DNS-данные недоступны: ${e.javaClass.simpleName}"
        }
        notes += "DNS на телефоне не доказывает, какой DNS используется подключёнными клиентами."
        notes += "Private DNS и VPN могут изменять фактический путь DNS-запросов."
        return DnsInventory(entries, notes)
    }
}
