package com.verticthub.studio.ui.screens

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.verticthub.studio.model.HistoryEntry
import com.verticthub.studio.model.ObfuscationSettings
import com.verticthub.studio.storage.HistoryRepository
import com.verticthub.studio.ui.theme.*
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun HistoryScreen(
    historyRepository: HistoryRepository,
    onReuseObfuscationConfig: (ObfuscationSettings) -> Unit
) {
    var entries by remember { mutableStateOf(historyRepository.getAll()) }
    var selectedEntry by remember { mutableStateOf<HistoryEntry?>(null) }
    val fmt = remember { SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("LOCAL EXECUTION HISTORY (${entries.size})", style = MaterialTheme.typography.titleMedium, color = ElectricBlue)
            if (entries.isNotEmpty()) {
                TextButton(onClick = {
                    historyRepository.clearAll()
                    entries = emptyList()
                }) {
                    Text("Clear All", color = CrimsonFail, style = MaterialTheme.typography.labelSmall)
                }
            }
        }

        if (entries.isEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
                border = BorderStroke(1.dp, SlateBorder)
            ) {
                Text(
                    "Belum ada riwayat operasi. Jalankan Obfuscate atau Build untuk mencatat log lokal.",
                    modifier = Modifier.padding(16.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = TextSecondary
                )
            }
        }

        entries.forEach { item ->
            val ok = item.status == "SUCCESS"
            Card(
                onClick = { selectedEntry = item },
                colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
                border = BorderStroke(1.dp, if (ok) SlateBorder else CrimsonFail),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text("${item.operationType} • ${item.inputFile}", style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                        Text(item.status, style = MaterialTheme.typography.labelSmall, color = if (ok) EmeraldReady else CrimsonFail)
                    }
                    Text(
                        "Project: ${item.projectName} | ${fmt.format(Date(item.timestampMs))}",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (item.operationType == "OBFUSCATE") {
                            TextButton(onClick = {
                                val parsed = ObfuscationSettings.fromJson(JSONObject(item.configJson))
                                onReuseObfuscationConfig(parsed)
                            }) {
                                Text("Reuse Config", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                        TextButton(onClick = {
                            historyRepository.deleteById(item.id)
                            entries = historyRepository.getAll()
                        }) {
                            Text("Delete", color = CrimsonFail, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }

    selectedEntry?.let { entry ->
        AlertDialog(
            onDismissRequest = { selectedEntry = null },
            title = { Text("${entry.operationType} (${entry.status})") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    Text("Input: ${entry.projectName}/${entry.inputFile}", style = MaterialTheme.typography.labelSmall)
                    if (entry.outputPath.isNotEmpty()) {
                        Text("Saved Output: ${entry.outputPath}", style = MaterialTheme.typography.labelSmall, color = EmeraldReady)
                    }
                    if (entry.errorLog.isNotEmpty()) {
                        Text("Error Log:\n${entry.errorLog}", style = MaterialTheme.typography.bodySmall, color = CrimsonFail)
                    }
                    if (entry.outputPreview.isNotEmpty()) {
                        Text("Output Preview:\n${entry.outputPreview.take(1500)}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { selectedEntry = null }) { Text("Close") }
            }
        )
    }
}
