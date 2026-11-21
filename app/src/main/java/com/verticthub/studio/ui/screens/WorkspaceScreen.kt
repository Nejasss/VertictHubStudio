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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.verticthub.studio.bridge.PythonBridge
import com.verticthub.studio.engine.EngineStatusState
import com.verticthub.studio.model.ProjectFile
import com.verticthub.studio.model.StudioProject
import com.verticthub.studio.storage.StorageManager
import com.verticthub.studio.ui.theme.*
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

@Composable
fun WorkspaceScreen(
    engineState: EngineStatusState,
    storageManager: StorageManager,
    activeProject: StudioProject,
    activeFile: ProjectFile,
    sourceCode: String,
    onSourceChanged: (String) -> Unit,
    onProjectSelected: (StudioProject) -> Unit,
    onFileSelected: (ProjectFile) -> Unit,
    onNavigateToObfuscate: () -> Unit,
    onNavigateToBuild: () -> Unit,
    onReinitEngine: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var projects by remember { mutableStateOf(storageManager.listProjects()) }
    var files by remember { mutableStateOf(storageManager.listProjectFiles(activeProject)) }
    var astResult by remember { mutableStateOf<JSONObject?>(null) }
    var isAnalyzing by remember { mutableStateOf(false) }
    var statusBanner by remember { mutableStateOf<String?>(null) }
    var showNewProjectDialog by remember { mutableStateOf(false) }
    var showPasteDialog by remember { mutableStateOf(false) }

    LaunchedEffect(activeProject.id) {
        files = storageManager.listProjectFiles(activeProject)
    }

    val importPyLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            scope.launch {
                try {
                    val imported = storageManager.importPyFromUri(uri, activeProject)
                    files = storageManager.listProjectFiles(activeProject)
                    onFileSelected(imported)
                    statusBanner = "Imported ${imported.relativePath} (${imported.sizeBytes} B)"
                } catch (e: Exception) {
                    statusBanner = "Import gagal: ${e.message}"
                }
            }
        }
    }

    val importZipLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            scope.launch {
                try {
                    val importedProj = storageManager.importZipProjectFromUri(uri)
                    projects = storageManager.listProjects()
                    onProjectSelected(importedProj)
                    statusBanner = "Project ZIP '${importedProj.name}' berhasil diimpor"
                } catch (e: Exception) {
                    statusBanner = "Import ZIP gagal: ${e.message}"
                }
            }
        }
    }

    val exportZipLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/zip")
    ) { uri: Uri? ->
        if (uri != null) {
            scope.launch {
                try {
                    storageManager.exportProjectZipToUri(uri, activeProject)
                    statusBanner = "Project '${activeProject.name}' diekspor ke ZIP"
                } catch (e: Exception) {
                    statusBanner = "Export gagal: ${e.message}"
                }
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
        // Engine Status Telemetry Card
        EngineStatusBanner(engineState = engineState, onReinit = onReinitEngine)

        // Project Selector & Actions
        Card(
            colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
            border = BorderStroke(1.dp, SlateBorder),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("ACTIVE WORKSPACE PROJECT", style = MaterialTheme.typography.labelSmall, color = ElectricBlue)
                        Text(activeProject.name, style = MaterialTheme.typography.titleMedium, color = TextPrimary)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        FilledTonalButton(
                            onClick = { showNewProjectDialog = true },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Icon(Icons.Default.CreateNewFolder, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("New", style = MaterialTheme.typography.labelSmall)
                        }
                        OutlinedButton(
                            onClick = { exportZipLauncher.launch("${activeProject.name}.zip") },
                            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 4.dp)
                        ) {
                            Icon(Icons.Default.IosShare, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Export ZIP", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }

                // Switch existing projects
                if (projects.size > 1) {
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        projects.forEach { proj ->
                            FilterChip(
                                selected = proj.id == activeProject.id,
                                onClick = { onProjectSelected(proj) },
                                label = { Text(proj.name, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }
                }

                // Import & Paste Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { importPyLauncher.launch(arrayOf("text/x-python", "text/*", "*/*")) },
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Import .py", style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = { importZipLauncher.launch(arrayOf("application/zip", "application/octet-stream")) },
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.FolderZip, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Import .zip", style = MaterialTheme.typography.labelSmall)
                    }
                    OutlinedButton(
                        onClick = { showPasteDialog = true },
                        modifier = Modifier.weight(1f),
                        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 6.dp)
                    ) {
                        Icon(Icons.Default.ContentPaste, contentDescription = null, modifier = Modifier.size(15.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Paste Code", style = MaterialTheme.typography.labelSmall)
                    }
                }

                // File Explorer Strip
                Text("FILES (${files.size})", style = MaterialTheme.typography.labelSmall, color = TextSecondary)
                Row(
                    modifier = Modifier.horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    files.forEach { file ->
                        FilterChip(
                            selected = file.relativePath == activeFile.relativePath,
                            onClick = { onFileSelected(file) },
                            label = {
                                Text(
                                    "${file.relativePath} (${file.sizeBytes}B)",
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        )
                    }
                }
            }
        }

        statusBanner?.let { msg ->
            Surface(
                color = SlateCard,
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, ElectricBlue)
            ) {
                Text(
                    msg,
                    modifier = Modifier.padding(10.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = ElectricBlue
                )
            }
        }

        // Source Code Editor & AST Controls
        Card(
            colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
            border = BorderStroke(1.dp, SlateBorder),
            shape = RoundedCornerShape(10.dp)
        ) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "SOURCE: ${activeFile.relativePath}",
                        style = MaterialTheme.typography.labelSmall,
                        color = ElectricBlue
                    )
                    Text(
                        "${sourceCode.lines().size} lines | ${sourceCode.toByteArray().size} B",
                        style = MaterialTheme.typography.labelSmall,
                        color = TextSecondary
                    )
                }

                OutlinedTextField(
                    value = sourceCode,
                    onValueChange = { onSourceChanged(it) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 210.dp, max = 320.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = FontFamily.Monospace,
                        color = TextPrimary
                    )
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FilledTonalButton(
                        onClick = {
                            File(activeFile.absolutePath).writeText(sourceCode)
                            files = storageManager.listProjectFiles(activeProject)
                            statusBanner = "Saved ${activeFile.relativePath}"
                        },
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Save, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Save", style = MaterialTheme.typography.labelSmall)
                    }

                    Button(
                        enabled = engineState.status == "READY" && !isAnalyzing,
                        onClick = {
                            scope.launch {
                                isAnalyzing = true
                                File(activeFile.absolutePath).writeText(sourceCode)
                                astResult = PythonBridge.call("analyze_ast", sourceCode, activeFile.relativePath)
                                isAnalyzing = false
                            }
                        },
                        modifier = Modifier.weight(1.3f)
                    ) {
                        Icon(Icons.Default.AccountTree, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text(if (isAnalyzing) "Parsing..." else "AST Analyze", style = MaterialTheme.typography.labelSmall)
                    }
                }

                // Quick Actions to Obfuscate / Build
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = onNavigateToObfuscate,
                        colors = ButtonDefaults.buttonColors(containerColor = PrimaryBlue),
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Obfuscate File", style = MaterialTheme.typography.labelSmall, color = TextPrimary)
                    }
                    FilledTonalButton(
                        onClick = onNavigateToBuild,
                        modifier = Modifier.weight(1f)
                    ) {
                        Icon(Icons.Default.Build, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                        Text("Build Bundle", style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }

        // AST & Syntax Analysis Report Card
        astResult?.let { res ->
            Card(
                colors = CardDefaults.cardColors(containerColor = SlateCard),
                border = BorderStroke(1.dp, if (res.optBoolean("valid_syntax", false)) EmeraldReady else CrimsonFail),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (!res.optBoolean("ok", false)) {
                        Text("AST ENGINE ERROR", style = MaterialTheme.typography.labelSmall, color = CrimsonFail)
                        Text(res.optString("error"), style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                    } else if (!res.optBoolean("valid_syntax", false)) {
                        val syn = res.optJSONObject("syntax_error")
                        Text(
                            "SYNTAX ERROR at Line ${syn?.optInt("lineno")}:Col ${syn?.optInt("offset")}",
                            style = MaterialTheme.typography.labelSmall,
                            color = CrimsonFail
                        )
                        Text(syn?.optString("message") ?: "", style = MaterialTheme.typography.bodySmall, color = TextPrimary)
                        Text(syn?.optString("text") ?: "", style = MaterialTheme.typography.bodySmall, color = AmberWarn)
                    } else {
                        Text(
                            "AST VALIDATION PASSED (${res.optDouble("analysis_ms")} ms)",
                            style = MaterialTheme.typography.labelSmall,
                            color = EmeraldReady
                        )
                        Text(
                            "Nodes: ${res.optInt("ast_node_count")} | Functions: ${res.optJSONArray("functions")?.length() ?: 0} | " +
                                    "Classes: ${res.optJSONArray("classes")?.length() ?: 0} | Constants: ${res.optInt("protected_constants_candidates")}",
                            style = MaterialTheme.typography.bodySmall,
                            color = TextPrimary
                        )
                        Text(
                            "SHA-256: ${res.optString("sha256").take(32)}...",
                            style = MaterialTheme.typography.labelSmall,
                            color = TextSecondary
                        )
                    }
                }
            }
        }
    }

    if (showNewProjectDialog) {
        var newName by remember { mutableStateOf("") }
        var newFile by remember { mutableStateOf("main.py") }
        AlertDialog(
            onDismissRequest = { showNewProjectDialog = false },
            title = { Text("Create New Project") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(value = newName, onValueChange = { newName = it }, label = { Text("Project Name") })
                    OutlinedTextField(value = newFile, onValueChange = { newFile = it }, label = { Text("Entry File (.py)") })
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val created = storageManager.createProject(newName, newFile.ifBlank { "main.py" })
                    projects = storageManager.listProjects()
                    onProjectSelected(created)
                    showNewProjectDialog = false
                }) { Text("Create") }
            },
            dismissButton = {
                TextButton(onClick = { showNewProjectDialog = false }) { Text("Cancel") }
            }
        )
    }

    if (showPasteDialog) {
        var pasted by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showPasteDialog = false },
            title = { Text("Paste Python Source Code") },
            text = {
                OutlinedTextField(
                    value = pasted,
                    onValueChange = { pasted = it },
                    modifier = Modifier.fillMaxWidth().height(200.dp),
                    placeholder = { Text("Paste Python 3.14 source here...") }
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    if (pasted.isNotBlank()) {
                        onSourceChanged(pasted)
                        File(activeFile.absolutePath).writeText(pasted)
                        files = storageManager.listProjectFiles(activeProject)
                    }
                    showPasteDialog = false
                }) { Text("Load into Editor") }
            },
            dismissButton = {
                TextButton(onClick = { showPasteDialog = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
fun EngineStatusBanner(engineState: EngineStatusState, onReinit: () -> Unit) {
    val borderColor = when (engineState.status) {
        "READY" -> EmeraldReady
        "FAILED" -> CrimsonFail
        else -> AmberWarn
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = CharcoalSurface),
        border = BorderStroke(1.dp, borderColor),
        shape = RoundedCornerShape(10.dp)
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "VERTICTHUB STUDIO • ENGINE ${engineState.status}",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = borderColor
                )
                Text(
                    "OFFLINE MODE: ACTIVE",
                    style = MaterialTheme.typography.labelSmall,
                    color = EmeraldReady
                )
            }
            Text(
                "Python: ${engineState.pythonVersion} | Arch: ${engineState.architecture} | Core: ${engineState.coreStatus} | Crypto: ${if (engineState.cryptoAvailable) "AVAILABLE" else "PENDING"}",
                style = MaterialTheme.typography.bodySmall,
                color = TextPrimary
            )
            if (engineState.status == "FAILED") {
                Text(
                    "Failed: ${engineState.failedComponent} — ${engineState.failureCause}",
                    style = MaterialTheme.typography.bodySmall,
                    color = CrimsonFail
                )
                Text(
                    "Path: ${engineState.relatedPath}\nFix: ${engineState.recoveryStep}",
                    style = MaterialTheme.typography.labelSmall,
                    color = TextSecondary
                )
                TextButton(onClick = onReinit) {
                    Text("Retry Engine INIT")
                }
            }
        }
    }
}
