package dev.nevembert.vpnshare

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import java.io.BufferedReader
import java.io.InputStreamReader
import java.util.concurrent.TimeUnit

data class Finding(
    val code: String,
    val severity: String,
    val title: String,
    val evidence: String,
    val location: String,
    val repair: String,
    val verification: String
)
data class Snapshot(
    val internet: Boolean,
    val vpn: Boolean,
    val rootAvailable: Boolean,
    val hotspot: String,
    val findings: List<Finding>
)

object Diagnostics {
    // Root is opt-in. Detection does not request a grant or execute commands as root.
    fun rootBinaryPresent(): Boolean =
        listOf("/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
            "/data/adb/magisk/magisk").any { java.io.File(it).exists() }

    fun collect(context: Context, rootMode: Boolean): Snapshot {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networks = manager.allNetworks.mapNotNull { manager.getNetworkCapabilities(it) }
        val vpn = networks.any { it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) }
        val internet = networks.any {
            it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
                it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
        val root = rootBinaryPresent()
        val findings = mutableListOf<Finding>()
        if (!internet) findings += Finding("NET-101", "error", "Нет подтверждённого интернета",
            "Android не сообщает о валидированном интернет-соединении.",
            "ConnectivityManager / активные сети",
            "Проверьте мобильные данные или Wi-Fi, затем откройте сайт и повторите проверку.",
            "Android сообщает NET_CAPABILITY_VALIDATED.")
        if (!vpn) findings += Finding("VPN-201", "warning", "VPN не обнаружен",
            "Среди доступных сетей нет TRANSPORT_VPN.",
            "Android VPN / VpnService",
            "Подключите VPN-клиент и разрешите VPN в системном диалоге.",
            "В диагностике появится активный VPN.")
        if (rootMode && !root) findings += Finding("ROOT-301", "warning", "Root не обнаружен",
            "Не найдены распространённые пути к su; это не окончательная проверка root.",
            "Root-права / su",
            "Проверьте наличие root-менеджера и предоставьте разрешение только доверенному приложению.",
            "Root-провайдер подтверждает выдачу прав.")
        if (!rootMode) findings += Finding("HOTSPOT-401", "info", "Раздача VPN ограничена Android",
            "Обычный API не предоставляет управление NAT мобильной точки доступа.",
            "Android tethering / маршрутизация",
            "Включите точку доступа вручную в настройках Android. Работа VPN у клиентов не гарантируется.",
            "Проверьте внешний IP с подключённого устройства.")
        if (rootMode && root) findings += Finding("ROOT-302", "info", "Root-режим: только диагностика",
            "Обнаружен возможный su, но права и маршруты ещё не проверены.",
            "Маршрутизация / NAT / iptables или nftables",
            "Не изменяйте NAT до определения интерфейсов, IPv4-подсети и существующих правил.",
            "Проверка маршрутов и безопасный откат будут добавлены отдельно.")
        return Snapshot(internet, vpn, root, "Точка доступа: состояние недоступно через публичный API", findings)
    }
}
