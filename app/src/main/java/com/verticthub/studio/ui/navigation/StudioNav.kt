package com.verticthub.studio.ui.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import com.verticthub.studio.engine.EngineInitializer
import com.verticthub.studio.model.ObfuscationSettings
import com.verticthub.studio.model.ProjectFile
import com.verticthub.studio.storage.HistoryRepository
import com.verticthub.studio.storage.StorageManager
import com.verticthub.studio.ui.screens.*
import com.verticthub.studio.ui.theme.CharcoalSurface
import com.verticthub.studio.ui.theme.DeepNavyBg
import com.verticthub.studio.ui.theme.ElectricBlue
import kotlinx.coroutines.launch
import java.io.File

enum class StudioTab(val label: String, val icon: ImageVector) {
    Workspace("Workspace", Icons.Default.Folder),
    Obfuscate("Obfuscate", Icons.Default.Security),
    Build("Build", Icons.Default.Build),
    History("History", Icons.Default.History),
    Settings("Settings", Icons.Default.Settings)
}

@Composable
fun VertictHubStudioApp(
    engineInitializer: EngineInitializer,
    storageManager: StorageManager,
    historyRepository: HistoryRepository
) {
    val scope = rememberCoroutineScope()
    val engineState by engineInitializer.state.collectAsState()
    var currentTab by remember { mutableStateOf(StudioTab.Workspace) }

    val initialProject = remember {
        storageManager.listProjects().firstOrNull() ?: storageManager.createProject("DefaultProject")
    }
    var activeProject by remember { mutableStateOf(initialProject) }
    var activeFile by remember(activeProject.id) {
        val files = storageManager.listProjectFiles(activeProject)
        val chosen = files.firstOrNull { it.relativePath == activeProject.activeFileRelativePath }
            ?: files.firstOrNull()
            ?: ProjectFile("main.py", File(activeProject.rootPath, "main.py").apply {
                if (!exists()) writeText(StorageManager.DEFAULT_STARTER_CODE)
            }.absolutePath, 0L)
        mutableStateOf(chosen)
    }
    var sourceCode by remember(activeFile.absolutePath) {
        mutableStateOf(
            File(activeFile.absolutePath).takeIf { it.exists() }?.readText()
                ?: StorageManager.DEFAULT_STARTER_CODE
        )
    }
    var obfSettings by remember { mutableStateOf(ObfuscationSettings()) }

    Scaffold(
        containerColor = DeepNavyBg,
        bottomBar = {
            NavigationBar(containerColor = CharcoalSurface) {
                StudioTab.entries.forEach { tab ->
                    NavigationBarItem(
                        selected = currentTab == tab,
                        onClick = { currentTab = tab },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label, style = MaterialTheme.typography.labelSmall) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = ElectricBlue,
                            selectedTextColor = ElectricBlue
                        )
                    )
                }
            }
        }
    ) { innerPadding ->
        Surface(
            modifier = Modifier.padding(innerPadding),
            color = DeepNavyBg
        ) {
            when (currentTab) {
                StudioTab.Workspace -> WorkspaceScreen(
                    engineState = engineState,
                    storageManager = storageManager,
                    activeProject = activeProject,
                    activeFile = activeFile,
                    sourceCode = sourceCode,
                    onSourceChanged = { sourceCode = it },
                    onProjectSelected = { activeProject = it },
                    onFileSelected = { activeFile = it },
                    onNavigateToObfuscate = { currentTab = StudioTab.Obfuscate },
                    onNavigateToBuild = { currentTab = StudioTab.Build },
                    onReinitEngine = { scope.launch { engineInitializer.initialize() } }
                )
                StudioTab.Obfuscate -> ObfuscateScreen(
                    engineState = engineState,
                    activeProject = activeProject,
                    activeFile = activeFile,
                    sourceCode = sourceCode,
                    settings = obfSettings,
                    onSettingsChanged = { obfSettings = it },
                    storageManager = storageManager,
                    historyRepository = historyRepository
                )
                StudioTab.Build -> BuildScreen(
                    engineState = engineState,
                    activeProject = activeProject,
                    activeFile = activeFile,
                    sourceCode = sourceCode,
                    storageManager = storageManager,
                    historyRepository = historyRepository
                )
                StudioTab.History -> HistoryScreen(
                    historyRepository = historyRepository,
                    onReuseObfuscationConfig = { reused ->
                        obfSettings = reused
                        currentTab = StudioTab.Obfuscate
                    }
                )
                StudioTab.Settings -> SettingsScreen(
                    engineState = engineState,
                    storageManager = storageManager,
                    onReinitEngine = { scope.launch { engineInitializer.initialize() } }
                )
            }
        }
    }
}
