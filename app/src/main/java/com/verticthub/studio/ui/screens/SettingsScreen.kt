package com.verticthub.studio.ui.screens

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.verticthub.studio.engine.EngineStatusState
import com.verticthub.studio.storage.StorageManager
import com.verticthub.studio.ui.theme.*

@Composable
fun SettingsScreen(
    engineState: EngineStatusState,
    storageManager: StorageManager,
    onReinitEngine: () -> Unit
) {
    var storageStats by remember { mutableStateOf(storageManager.computeStorageStats()) }
    var cacheMessage by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("ENGINE DIAGNOSTICS & SETTINGS", style = MaterialTheme.typography.titleMedium, color = ElectricBlue)

        // Live Engine Status
        Card(
            colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
            border = BorderStroke(1.dp, SlateBorder),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("RUNTIME & ABI TELEMETRY", style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                Text("Application : VertictHub Studio v1.0.0", style = MaterialTheme.typography.bodySmall)
                Text("Engine Status : ${engineState.status}", style = MaterialTheme.typography.bodySmall)
                Text("Python Runtime : CPython ${engineState.pythonVersion}", style = MaterialTheme.typography.bodySmall)
                Text("Device ABIs : ${Build.SUPPORTED_ABIS.joinToString()}", style = MaterialTheme.typography.bodySmall)
                Text("Core Modules : ${engineState.coreDetails?.optInt("verified_count") ?: 0}/34 Verified", style = MaterialTheme.typography.bodySmall)
                Text("PyCryptodome : ${if (engineState.cryptoAvailable) "AES-256-CBC + SHA256 + Ed25519 VERIFIED" else "UNAVAILABLE"}", style = MaterialTheme.typography.bodySmall)
                Text("Network Policy : 100% OFFLINE (No INTERNET permission)", style = MaterialTheme.typography.bodySmall, color = EmeraldReady)
                Spacer(Modifier.height(4.dp))
                FilledTonalButton(onClick = onReinitEngine) {
                    Text("Re-Verify Runtime & Core", style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        // Core Module Audit List
        engineState.coreDetails?.optJSONArray("modules")?.let { arr ->
            Card(
                colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
                border = BorderStroke(1.dp, SlateBorder),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    Text("CORE INVENTORY AUDIT (${arr.length()} MODULES)", style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                    for (i in 0 until arr.length()) {
                        val m = arr.getJSONObject(i)
                        val st = m.optString("status")
                        Text(
                            "• ${m.optString("module")}.py — $st (${m.optDouble("load_ms")} ms)",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (st == "VERIFIED") TextPrimary else CrimsonFail
                        )
                    }
                }
            }
        }

        // Dependency Status List
        engineState.dependencyDetails?.optJSONArray("dependencies")?.let { deps ->
            Card(
                colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
                border = BorderStroke(1.dp, SlateBorder),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("LOCAL DEPENDENCY MANIFEST", style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                    for (i in 0 until deps.length()) {
                        val d = deps.getJSONObject(i)
                        val st = d.optString("status")
                        Text(
                            "• ${d.optString("name")} [${d.optString("abi")}] -> $st",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (st == "VERIFIED" || st == "AVAILABLE") EmeraldReady else TextSecondary
                        )
                    }
                }
            }
        }

        // Storage & Cache Management
        Card(
            colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
            border = BorderStroke(1.dp, SlateBorder),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("INTERNAL STORAGE MANAGEMENT", style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                Text("Workspace Root : ${storageManager.projectsDir.absolutePath}", style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                Text("Runtime Size : ${(storageStats["runtime_bytes"] ?: 0L) / 1024} KB", style = MaterialTheme.typography.bodySmall)
                Text("Projects Size : ${(storageStats["projects_bytes"] ?: 0L) / 1024} KB", style = MaterialTheme.typography.bodySmall)
                Text("Outputs Size : ${(storageStats["outputs_bytes"] ?: 0L) / 1024} KB", style = MaterialTheme.typography.bodySmall)
                Text("Cache Size : ${(storageStats["cache_bytes"] ?: 0L) / 1024} KB", style = MaterialTheme.typography.bodySmall)

                OutlinedButton(onClick = {
                    val freed = storageManager.clearTemporaryCache()
                    storageStats = storageManager.computeStorageStats()
                    cacheMessage = "Cleared ${freed / 1024} KB temporary cache & logs"
                }) {
                    Text("Clear Temporary Cache", style = MaterialTheme.typography.labelSmall)
                }
                cacheMessage?.let {
                    Text(it, style = MaterialTheme.typography.labelSmall, color = EmeraldReady)
                }
            }
        }
    }
}
