package com.verticthub.studio

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.lifecycleScope
import com.verticthub.studio.ui.navigation.VertictHubStudioApp
import com.verticthub.studio.ui.theme.VertictHubTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val app = application as VertictHubApp
        lifecycleScope.launch {
            app.engineInitializer.initialize()
        }
        setContent {
            VertictHubTheme {
                VertictHubStudioApp(
                    engineInitializer = app.engineInitializer,
                    storageManager = app.storageManager,
                    historyRepository = app.historyRepository
                )
            }
        }
    }
}
