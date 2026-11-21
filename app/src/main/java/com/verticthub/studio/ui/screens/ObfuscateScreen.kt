package com.verticthub.studio.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.verticthub.studio.bridge.PythonBridge
import com.verticthub.studio.engine.EngineStatusState
import com.verticthub.studio.model.ObfuscationSettings
import com.verticthub.studio.model.ProjectFile
import com.verticthub.studio.model.StudioProject
import com.verticthub.studio.storage.HistoryRepository
import com.verticthub.studio.storage.StorageManager
import com.verticthub.studio.ui.theme.*
import kotlinx.coroutines.launch

@Composable
fun ObfuscateScreen(
    engineState: EngineStatusState,
    activeProject: StudioProject,
    activeFile: ProjectFile,
    sourceCode: String,
    settings: ObfuscationSettings,
    onSettingsChanged: (ObfuscationSettings) -> Unit,
    storageManager: StorageManager,
    historyRepository: HistoryRepository
) {
    val scope = rememberCoroutineScope()
    var isRunning by remember { mutableStateOf(false) }
    var outputCode by remember { mutableStateOf("") }
    var leakReport by remember { mutableStateOf("") }
    var runSummary by remember { mutableStateOf("") }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    val exportOutputLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/x-python")
    ) { uri: Uri? ->
        if (uri != null && outputCode.isNotEmpty()) {
            scope.launch {
                storageManager.exportTextToUri(uri, outputCode)
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("CORE PYOBFUSCATOR PIPELINE", style = MaterialTheme.typography.titleMedium, color = ElectricBlue)
        Text(
            "Target: ${activeProject.name}/${activeFile.relativePath}",
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary
        )

        // Configuration Presets
        Row(
            modifier = Modifier.horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            listOf(
                "balanced" to "Balanced",
                "maximum_ast" to "Maximum AST",
                "cjk_unicode" to "CJK Unicode",
                "diagnostic_pinning" to "Diagnostics"
            ).forEach { (id, label) ->
                FilterChip(
                    selected = settings.presetId == id,
                    onClick = {
                        val updated = when (id) {
                            "maximum_ast" -> settings.copy(
                                presetId = id,
                                encryptStrings = true,
                                renameIdentifiers = true,
                                constantProtection = true,
                                controlFlowObfuscation = true,
                                dataFlowObfuscation = true,
                                expressionObfuscation = true,
                                functionTransformation = true,
                                attributeObfuscation = true,
                                importObfuscation = true,
                                injectDecoyMethods = true,
                                junkIntensity = 8,
                                hookDetection = true
                            )
                            "cjk_unicode" -> settings.copy(
                                presetId = id,
                                encryptStrings = true,
                                renameIdentifiers = true,
                                cjkIdentifiers = true,
                                constantProtection = true,
                                dataFlowObfuscation = true,
                                expressionObfuscation = true,
                                importObfuscation = true,
                                junkIntensity = 6
                            )
                            "diagnostic_pinning" -> settings.copy(
                                presetId = id,
                                antiDebug = true,
                                periodicRecheck = true,
                                bytecodeIntegrityCheck = true,
                                enableAntisandbox = true,
                                hookDetection = true
                            )
                            else -> ObfuscationSettings(presetId = "balanced")
                        }
                        onSettingsChanged(updated)
                    },
                    label = { Text(label, style = MaterialTheme.typography.labelSmall) }
                )
            }
        }

        // Feature Toggles Card
        Card(
            colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
            border = BorderStroke(1.dp, SlateBorder),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("AST & PROTECTION PASSES", style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                OptionToggle("Identifier Renaming", settings.renameIdentifiers) {
                    onSettingsChanged(settings.copy(presetId = "custom", renameIdentifiers = it))
                }
                OptionToggle("CJK Unicode Identifiers", settings.cjkIdentifiers) {
                    onSettingsChanged(settings.copy(presetId = "custom", cjkIdentifiers = it))
                }
                OptionToggle("String Literal Encryption", settings.encryptStrings) {
                    onSettingsChanged(settings.copy(presetId = "custom", encryptStrings = it))
                }
                OptionToggle("Constant Protection", settings.constantProtection) {
                    onSettingsChanged(settings.copy(presetId = "custom", constantProtection = it))
                }
                OptionToggle("Control Flow Flattening", settings.controlFlowObfuscation) {
                    onSettingsChanged(settings.copy(presetId = "custom", controlFlowObfuscation = it))
                }
                OptionToggle("Data Flow Obfuscation", settings.dataFlowObfuscation) {
                    onSettingsChanged(settings.copy(presetId = "custom", dataFlowObfuscation = it))
                }
                OptionToggle("Expression Obfuscation", settings.expressionObfuscation) {
                    onSettingsChanged(settings.copy(presetId = "custom", expressionObfuscation = it))
                }
                OptionToggle("Function Transformation", settings.functionTransformation) {
                    onSettingsChanged(settings.copy(presetId = "custom", functionTransformation = it))
                }
                OptionToggle("Attribute Obfuscation", settings.attributeObfuscation) {
                    onSettingsChanged(settings.copy(presetId = "custom", attributeObfuscation = it))
                }
                OptionToggle("Import Obfuscation", settings.importObfuscation) {
                    onSettingsChanged(settings.copy(presetId = "custom", importObfuscation = it))
                }
                OptionToggle("Inject Decoy Methods", settings.injectDecoyMethods) {
                    onSettingsChanged(settings.copy(presetId = "custom", injectDecoyMethods = it))
                }
                OptionToggle("Runtime Integrity Diagnostics (antidebug)", settings.antiDebug) {
                    onSettingsChanged(settings.copy(presetId = "custom", antiDebug = it))
                }
                OptionToggle("Bytecode Integrity Snapshot", settings.bytecodeIntegrityCheck) {
                    onSettingsChanged(settings.copy(presetId = "custom", bytecodeIntegrityCheck = it))
                }
                OptionToggle("HTTP Hook Integrity Check", settings.hookDetection) {
                    onSettingsChanged(settings.copy(presetId = "custom", hookDetection = it))
                }
                OptionToggle("Sandbox Environment Diagnostics", settings.enableAntisandbox) {
                    onSettingsChanged(settings.copy(presetId = "custom", enableAntisandbox = it))
                }

                Spacer(Modifier.height(4.dp))
                Text("Junk Code Intensity: ${settings.junkIntensity}", style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                Slider(
                    value = settings.junkIntensity.toFloat(),
                    onValueChange = { onSettingsChanged(settings.copy(presetId = "custom", junkIntensity = it.toInt())) },
                    valueRange = 0f..10f,
                    steps = 9
                )

                OutlinedTextField(
                    value = settings.sslPinSha256,
                    onValueChange = { onSettingsChanged(settings.copy(presetId = "custom", sslPinSha256 = it)) },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("SPKI SHA-256 Pins (optional, comma-separated)", style = MaterialTheme.typography.labelSmall) },
                    singleLine = true
                )
            }
        }

        Button(
            enabled = engineState.status == "READY" && !isRunning && sourceCode.isNotBlank(),
            onClick = {
                scope.launch {
                    isRunning = true
                    errorMessage = null
                    val cfgJsonStr = settings.toJson().toString()
                    val res = PythonBridge.call("run_obfuscation", sourceCode, activeFile.relativePath, cfgJsonStr)
                    if (res.optBoolean("ok", false)) {
                        outputCode = res.optString("obfuscated_source", "")
                        leakReport = res.optString("leak_report", "")
                        val outName = activeFile.relativePath.substringAfterLast('/').removeSuffix(".py") + "_obf.py"
                        val saved = storageManager.saveOutputArtifact(outName, outputCode)
                        runSummary = "OK (${res.optDouble("elapsed_ms")} ms) | ${res.optInt("input_bytes")}B -> ${res.optInt("output_bytes")}B"
                        historyRepository.record(
                            projectName = activeProject.name,
                            inputFile = activeFile.relativePath,
                            operationType = "OBFUSCATE",
                            configJson = cfgJsonStr,
                            status = "SUCCESS",
                            outputPath = saved.absolutePath,
                            outputPreview = outputCode
                        )
                    } else {
                        val err = res.optString("error", "Obfuscation failed")
                        errorMessage = err
                        historyRepository.record(
                            projectName = activeProject.name,
                            inputFile = activeFile.relativePath,
                            operationType = "OBFUSCATE",
                            configJson = cfgJsonStr,
                            status = "FAILED",
                            outputPath = "",
                            outputPreview = "",
                            errorLog = err
                        )
                    }
                    isRunning = false
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = PrimaryBlue)
        ) {
            Text(
                if (isRunning) "Running Core Pipeline..." else "Execute Local Obfuscation",
                color = TextPrimary
            )
        }

        errorMessage?.let { err ->
            Card(
                colors = CardDefaults.cardColors(containerColor = SlateCard),
                border = BorderStroke(1.dp, CrimsonFail)
            ) {
                Text(err, modifier = Modifier.padding(12.dp), style = MaterialTheme.typography.bodySmall, color = CrimsonFail)
            }
        }

        if (outputCode.isNotEmpty()) {
            Card(
                colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
                border = BorderStroke(1.dp, EmeraldReady),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(runSummary, style = MaterialTheme.typography.labelSmall, color = EmeraldReady)
                        OutlinedButton(
                            onClick = {
                                val outName = activeFile.relativePath.substringAfterLast('/').removeSuffix(".py") + "_obf.py"
                                exportOutputLauncher.launch(outName)
                            },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Text("Export .py", style = MaterialTheme.typography.labelSmall)
                        }
                    }

                    if (leakReport.isNotBlank()) {
                        Text(leakReport, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                    }

                    OutlinedTextField(
                        value = outputCode.take(6000),
                        onValueChange = {},
                        readOnly = true,
                        modifier = Modifier.fillMaxWidth().height(200.dp),
                        textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace)
                    )
                }
            }
        }
    }
}

@Composable
private fun OptionToggle(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = TextPrimary, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
