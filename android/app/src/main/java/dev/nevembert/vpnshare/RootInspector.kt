package dev.nevembert.vpnshare

import java.util.concurrent.TimeUnit

data class RootProbe(val status: String, val output: String)

// Read-only probe; never writes routing, firewall, DNS, or tethering settings.
object RootInspector {
    fun probe(): RootProbe {
        var process: Process? = null
        return try {
            process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
            if (!process.waitFor(3, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                RootProbe("timeout", "Root-провайдер не ответил за 3 секунды")
            } else {
                val result = process.inputStream.bufferedReader().readText().take(300)
                if (process.exitValue() == 0 && result.contains("uid=0"))
                    RootProbe("granted", result)
                else RootProbe("denied", result.ifBlank { "su не предоставил root" })
            }
        } catch (e: Exception) {
            RootProbe("unavailable", e.javaClass.simpleName)
        } finally {
            process?.destroy()
        }
    }
}
