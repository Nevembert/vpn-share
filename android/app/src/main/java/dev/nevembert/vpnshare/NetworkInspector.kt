package dev.nevembert.vpnshare

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import java.net.NetworkInterface

data class NetworkInterfaceInfo(
    val name: String,
    val addresses: List<String>,
    val up: Boolean,
    val isVpnCandidate: Boolean,
    val isHotspotCandidate: Boolean
)

data class NetworkInventory(
    val interfaces: List<NetworkInterfaceInfo>,
    val vpnInterfaces: List<String>,
    val hotspotCandidates: List<String>,
    val routes: List<String>,
    val observations: List<String>
)

/**
 * Read-only inventory. Android does not provide a public API for reliable tethering
 * interface discovery; names are candidates, never authoritative.
 */
object NetworkInspector {
    fun collect(context: Context): NetworkInventory {
        val notes = mutableListOf<String>()
        val interfaces = try {
            val all = NetworkInterface.getNetworkInterfaces()
            val result = mutableListOf<NetworkInterfaceInfo>()
            while (all != null && all.hasMoreElements()) {
                val item = all.nextElement()
                val addresses = item.inetAddresses.toList().map { it.hostAddress ?: "" }
                    .filter { it.isNotBlank() }
                val name = item.name ?: "unknown"
                result += NetworkInterfaceInfo(
                    name = name,
                    addresses = addresses,
                    up = runCatching { item.isUp }.getOrDefault(false),
                    isVpnCandidate = name.startsWith("tun") || name.startsWith("ppp") ||
                        name.startsWith("wg"),
                    isHotspotCandidate = name.startsWith("ap") || name.startsWith("swlan") ||
                        name.startsWith("wlan") || name.startsWith("rndis")
                )
            }
            result.sortedBy { it.name }
        } catch (e: Exception) {
            notes += "Список интерфейсов недоступен: ${e.javaClass.simpleName}"
            emptyList()
        }
        val routes = mutableListOf<String>()
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            for (network in cm.allNetworks) {
                val caps: NetworkCapabilities = cm.getNetworkCapabilities(network) ?: continue
                val props: LinkProperties = cm.getLinkProperties(network) ?: continue
                val kind = if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) "VPN" else "network"
                for (route in props.routes) routes += "$kind: ${route.destination} via ${route.gateway ?: "direct"} dev ${props.interfaceName ?: "?"}"
            }
        } catch (e: Exception) {
            notes += "Маршруты Android API недоступны: ${e.javaClass.simpleName}"
        }
        notes += "Имена интерфейсов — эвристика, не доказательство работы точки доступа."
        notes += "Android API показывает не все системные таблицы маршрутизации и NAT."
        return NetworkInventory(
            interfaces,
            interfaces.filter { it.isVpnCandidate }.map { it.name },
            interfaces.filter { it.isHotspotCandidate }.map { it.name },
            routes.distinct().sorted(),
            notes
        )
    }
}
