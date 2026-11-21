package com.verticthub.studio.storage

import com.verticthub.studio.model.HistoryEntry
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

class HistoryRepository(private val historyDir: File) {

    private val dbFile: File get() = File(historyDir, "history_index.json")

    @Synchronized
    fun getAll(): List<HistoryEntry> {
        if (!dbFile.exists()) return emptyList()
        return try {
            val arr = JSONArray(dbFile.readText())
            (0 until arr.length()).map { i ->
                val o = arr.getJSONObject(i)
                HistoryEntry(
                    id = o.getString("id"),
                    projectName = o.optString("project_name", "Workspace"),
                    inputFile = o.optString("input_file", "script.py"),
                    operationType = o.optString("operation_type", "OBFUSCATE"),
                    timestampMs = o.optLong("timestamp_ms", 0L),
                    configJson = o.optString("config_json", "{}"),
                    status = o.optString("status", "UNKNOWN"),
                    outputPath = o.optString("output_path", ""),
                    outputPreview = o.optString("output_preview", ""),
                    errorLog = o.optString("error_log", "")
                )
            }.sortedByDescending { it.timestampMs }
        } catch (_: Exception) {
            emptyList()
        }
    }

    @Synchronized
    fun record(
        projectName: String,
        inputFile: String,
        operationType: String,
        configJson: String,
        status: String,
        outputPath: String,
        outputPreview: String,
        errorLog: String = ""
    ): HistoryEntry {
        historyDir.mkdirs()
        val entry = HistoryEntry(
            id = UUID.randomUUID().toString(),
            projectName = projectName,
            inputFile = inputFile,
            operationType = operationType,
            timestampMs = System.currentTimeMillis(),
            configJson = configJson,
            status = status,
            outputPath = outputPath,
            outputPreview = outputPreview.take(4000),
            errorLog = errorLog
        )
        val updated = listOf(entry) + getAll()
        persist(updated)
        return entry
    }

    @Synchronized
    fun deleteById(id: String) {
        persist(getAll().filterNot { it.id == id })
    }

    @Synchronized
    fun clearAll() {
        persist(emptyList())
    }

    private fun persist(entries: List<HistoryEntry>) {
        val arr = JSONArray()
        entries.forEach { e ->
            arr.put(JSONObject().apply {
                put("id", e.id)
                put("project_name", e.projectName)
                put("input_file", e.inputFile)
                put("operation_type", e.operationType)
                put("timestamp_ms", e.timestampMs)
                put("config_json", e.configJson)
                put("status", e.status)
                put("output_path", e.outputPath)
                put("output_preview", e.outputPreview)
                put("error_log", e.errorLog)
            })
        }
        val tmp = File(historyDir, "history_index.json.tmp")
        tmp.writeText(arr.toString(2))
        tmp.renameTo(dbFile)
    }
}
