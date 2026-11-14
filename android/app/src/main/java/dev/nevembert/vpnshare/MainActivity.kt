package dev.nevembert.vpnshare

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                var rootMode by remember { mutableStateOf(false) }
                var page by remember { mutableStateOf(0) }
                var rootProbe by remember { mutableStateOf<RootProbe?>(null) }
                var snapshot by remember { mutableStateOf(Diagnostics.collect(this, false)) }
                var inventory by remember { mutableStateOf(NetworkInspector.collect(this)) }
                fun refresh() { snapshot = Diagnostics.collect(this, rootMode); inventory = NetworkInspector.collect(this) }
                Column(Modifier.fillMaxSize().padding(16.dp)) {
                    Text("VPN Share", style = MaterialTheme.typography.headlineMedium)
                    Spacer(Modifier.height(12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        listOf("Обзор", "Диагностика", "Сеть", "Настройки").forEachIndexed { index, label ->
                            FilterChip(selected = page == index, onClick = { page = index }, label = { Text(label) })
                        }
                    }
                    Spacer(Modifier.height(12.dp))
                    Column(Modifier.weight(1f).verticalScroll(rememberScrollState())) {
                        when (page) {
                            0 -> {
                                Text("Режим: " + if (rootMode) "Root (проверка)" else "Без root")
                                Text("Интернет: " + if (snapshot.internet) "доступ подтверждён Android" else "не подтверждён")
                                Text("VPN: " + if (snapshot.vpn) "обнаружен" else "не обнаружен")
                                Text(snapshot.hotspot)
                                Spacer(Modifier.height(16.dp))
                                Text("Раздача VPN пока не включается приложением. Это диагностическая alpha-версия.")
                                Spacer(Modifier.height(12.dp))
                                Button(onClick = { startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS)) }) { Text("Настройки сети Android") }
                            }
                            1 -> {
                                if (snapshot.findings.isEmpty()) Text("Известных проблем по проверенным признакам нет.")
                                snapshot.findings.forEach { issue ->
                                    ElevatedCard(Modifier.fillMaxWidth().padding(bottom = 10.dp)) {
                                        Column(Modifier.padding(14.dp)) {
                                            Text("${issue.code} · ${issue.title}", style = MaterialTheme.typography.titleMedium)
                                            Text("Уровень: ${issue.severity}")
                                            Text("Обнаружено: ${issue.evidence}")
                                            Text("Место: ${issue.location}")
                                            Text("Исправление: ${issue.repair}")
                                            Text("Проверка: ${issue.verification}")
                                        }
                                    }
                                }
                            }
                            2 -> {
                                Text("Интерфейсы Android", style = MaterialTheme.typography.titleLarge)
                                inventory.interfaces.forEach { item ->
                                    ElevatedCard(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                                        Column(Modifier.padding(12.dp)) {
                                            Text(item.name + if (item.up) " · UP" else " · DOWN")
                                            Text(item.addresses.joinToString(", ").ifBlank { "IP-адресов не обнаружено" })
                                            if (item.isVpnCandidate) Text("Возможный VPN-интерфейс")
                                            if (item.isHotspotCandidate) Text("Возможный интерфейс Wi-Fi/точки доступа")
                                        }
                                    }
                                }
                                Spacer(Modifier.height(12.dp))
                                Text("Маршруты (публичный Android API)", style = MaterialTheme.typography.titleMedium)
                                if (inventory.routes.isEmpty()) Text("Доступные маршруты не обнаружены")
                                inventory.routes.forEach { Text(it, Modifier.padding(vertical = 4.dp)) }
                                Spacer(Modifier.height(12.dp))
                                inventory.observations.forEach { Text(it) }
                            }
                            else -> {
                                Text("Возможности", style = MaterialTheme.typography.titleLarge)
                                Row { Text("Root-режим (экспериментальный)", Modifier.weight(1f)); Switch(checked = rootMode, onCheckedChange = { rootMode = it; refresh() }) }
                                Text("Root запрашивается только при нажатии кнопки проверки. Маршруты и правила файрвола не меняются.")
                                if (rootMode) {
                                    Spacer(Modifier.height(12.dp))
                                    Button(onClick = {
                                        Thread {
                                            val result = RootInspector.probe()
                                            runOnUiThread { rootProbe = result }
                                        }.start()
                                    }) { Text("Проверить root-доступ (только чтение)") }
                                    rootProbe?.let { Text("Root: ${it.status} — ${it.output}") }
                                }
                                Text("Без root Android не гарантирует VPN-трафик для клиентов точки доступа.")
                            }
                        }
                    }
                    Button(onClick = { refresh() }, modifier = Modifier.fillMaxWidth()) { Text("Повторить проверку") }
                }
            }
        }
    }
}
