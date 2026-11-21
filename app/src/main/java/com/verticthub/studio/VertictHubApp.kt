package com.verticthub.studio

import android.app.Application
import com.verticthub.studio.engine.EngineInitializer
import com.verticthub.studio.storage.HistoryRepository
import com.verticthub.studio.storage.StorageManager

class VertictHubApp : Application() {
    lateinit var storageManager: StorageManager
        private set
    lateinit var engineInitializer: EngineInitializer
        private set
    lateinit var historyRepository: HistoryRepository
        private set

    override fun onCreate() {
        super.onCreate()
        storageManager = StorageManager(this)
        storageManager.ensureDirectoryLayout()
        engineInitializer = EngineInitializer(this, storageManager)
        historyRepository = HistoryRepository(storageManager.historyDir)
    }
}
