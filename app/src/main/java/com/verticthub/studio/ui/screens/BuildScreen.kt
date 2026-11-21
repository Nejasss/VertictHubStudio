package com.verticthub.studio.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.verticthub.studio.bridge.PythonBridge
import com.verticthub.studio.engine.EngineStatusState
import com.verticthub.studio.model.ProjectFile
import com.verticthub.studio.model.StudioProject
import com.verticthub.studio.storage.HistoryRepository
import com.verticthub.studio.storage.StorageManager
import com.verticthub.studio.ui.theme.*
import kotlinx.coroutines.launch
import org.json.JSONObject

data class BuildTargetOption(
    val id: String,
    val title: String,
    val subtitle: String,
    val offlineGuaranteed: Boolean
)

@Composable
fun BuildScreen(
    engineState: EngineStatusState,
    activeProject: StudioProject,
    activeFile: ProjectFile,
    sourceCode: String,
    storageManager: StorageManager,
    historyRepository: HistoryRepository
) {
    val scope = rememberCoroutineScope()
    val targets = remember {
        listOf(
            BuildTargetOption(
                "packed_loader",
                "Packed Bytecode Loader (.py)",
                "AST Obfuscation + CPython 3.14 marshal + HKDF-SHA256 multi-fragment XOR packer",
                true
            ),
            BuildTargetOption(
                "signed_bundle",
                "Signed Release Bundle (.py + Ed25519 Manifest)",
                "Packed loader + deterministic SHA-256 manifest signed with local Ed25519 keypair",
                true
            ),
            BuildTargetOption(
                "leak_audit",
                "Sensitive Vocabulary Leak Audit (.txt)",
                "Extracts identifiers/strings and scans artifact bytes for plaintext leaks",
                true
            ),
            BuildTargetOption(
                "cython_native",
                "Cython Native ELF Check",
                "Requires local on-device ARM64 Cython + clang/gcc + python3-config",
                false
            ),
            BuildTargetOption(
                "c_embed",
                "C Embed ELF Check",
                "Requires local on-device ARM64 C compiler + libpython3.14 headers",
                false
            ),
            BuildTargetOption(
                "native_launcher",
                "Native C Launcher Check",
                "Requires local on-device ARM64 clang/gcc compiler",
                false
            ),
            BuildTargetOption(
                "rust_launcher",
                "Rust ELF Launcher Check (--offline)",
                "Requires local on-device offline cargo + rustc toolchain",
                false
            )
        )
    }

    var selectedMode by remember { mutableStateOf("packed_loader") }
    var isBuilding by remember { mutableStateOf(false) }
    var buildLog by remember { mutableStateOf("") }
    var artifactContent by remember { mutableStateOf("") }
    var artifactName by remember { mutableStateOf("output_protected.py") }
    var buildSuccess by remember { mutableStateOf<Boolean?>(null) }

    val exportArtifactLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("*/*")
    ) { uri: Uri? ->
        if (uri != null && artifactContent.isNotEmpty()) {
            scope.launch {
                storageManager.exportTextToUri(uri, artifactContent)
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
        Text("LOCAL BUILD & PACKAGING PIPELINE", style = MaterialTheme.typography.titleMedium, color = ElectricBlue)
        Text(
            "Input: ${activeProject.name}/${activeFile.relativePath}",
            style = MaterialTheme.typography.bodySmall,
            color = TextSecondary
        )

        targets.forEach { target ->
            val selected = target.id == selectedMode
            Card(
                onClick = { selectedMode = target.id },
                colors = CardDefaults.cardColors(containerColor = if (selected) SlateCard else CharcoalSurface),
                border = BorderStroke(1.dp, if (selected) ElectricBlue else SlateBorder),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(target.title, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                        Text(
                            if (target.offlineGuaranteed) "BUILT-IN" else "TOOLCHAIN CHECK",
                            style = MaterialTheme.typography.labelSmall,
                            color = if (target.offlineGuaranteed) EmeraldReady else AmberWarn
                        )
                    }
                    Text(target.subtitle, style = MaterialTheme.typography.bodySmall, color = TextSecondary)
                }
            }
        }

        Button(
            enabled = engineState.status == "READY" && !isBuilding,
            onClick = {
                scope.launch {
                    isBuilding = true
                    buildSuccess = null
                    val opts = JSONObject().apply {
                        put("key_dir", "${storageManager.configsDir.absolutePath}/keys")
                    }.toString()
                    val res = PythonBridge.call("run_build", sourceCode, activeFile.relativePath, selectedMode, opts)
                    val ok = res.optBoolean("ok", false)
                    buildSuccess = ok
                    if (ok) {
                        buildLog = res.optString("log", "Build completed")
                        artifactContent = res.optString("artifact_content", "")
                        artifactName = res.optString("artifact_filename", "build_output.txt")
                        val savedPath = if (artifactContent.isNotEmpty()) {
                            storageManager.saveOutputArtifact(artifactName, artifactContent).absolutePath
                        } else ""
                        historyRepository.record(
                            projectName = activeProject.name,
                            inputFile = activeFile.relativePath,
                            operationType = "BUILD:$selectedMode",
                            configJson = opts,
                            status = "SUCCESS",
                            outputPath = savedPath,
                            outputPreview = buildLog
                        )
                    } else {
                        val err = "${res.optString("error")}
Recovery: ${res.optString("recovery")}"
                        buildLog = err
                        artifactContent = ""
                        historyRepository.record(
                            projectName = activeProject.name,
                            inputFile = activeFile.relativePath,
                            operationType = "BUILD:$selectedMode",
                            configJson = opts,
                            status = "FAILED",
                            outputPath = "",
                            outputPreview = "",
                            errorLog = err
                        )
                    }
                    isBuilding = false
                }
            },
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = PrimaryBlue)
        ) {
            Text(if (isBuilding) "Executing Build..." else "Run Build Pipeline", color = TextPrimary)
        }

        if (buildLog.isNotEmpty()) {
            val border = when (buildSuccess) {
                true -> EmeraldReady
                false -> CrimsonFail
                null -> SlateBorder
            }
            Card(
                colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
                border = BorderStroke(1.dp, border),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("BUILD EXECUTION LOG", style = MaterialTheme.typography.labelSmall, color = border)
                    Text(buildLog, style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                    if (artifactContent.isNotEmpty()) {
                        OutlinedButton(onClick = { exportArtifactLauncher.launch(artifactName) }) {
                            Text("Export $artifactName", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
        }
    }
}
