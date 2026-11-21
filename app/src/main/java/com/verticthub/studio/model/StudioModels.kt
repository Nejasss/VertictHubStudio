package com.verticthub.studio.model

import org.json.JSONObject

data class ProjectFile(
    val relativePath: String,
    val absolutePath: String,
    val sizeBytes: Long
)

data class StudioProject(
    val id: String,
    val name: String,
    val rootPath: String,
    val activeFileRelativePath: String,
    val createdAt: Long
)

data class ObfuscationSettings(
    val presetId: String = "balanced",
    val encryptStrings: Boolean = true,
    val minStringLen: Int = 1,
    val renameIdentifiers: Boolean = true,
    val cjkIdentifiers: Boolean = false,
    val constantProtection: Boolean = true,
    val controlFlowObfuscation: Boolean = false,
    val dataFlowObfuscation: Boolean = false,
    val expressionObfuscation: Boolean = false,
    val functionTransformation: Boolean = false,
    val attributeObfuscation: Boolean = false,
    val importObfuscation: Boolean = false,
    val injectDecoyMethods: Boolean = true,
    val junkIntensity: Int = 5,
    val antiDebug: Boolean = true,
    val periodicRecheck: Boolean = false,
    val bytecodeIntegrityCheck: Boolean = false,
    val enableAntisandbox: Boolean = false,
    val antisandboxThreshold: Int = 6,
    val hookDetection: Boolean = false,
    val lockFilename: Boolean = false,
    val requireLauncherGate: Boolean = false,
    val sslPinSha256: String = ""
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("preset_id", presetId)
        put("encrypt_strings", encryptStrings)
        put("min_string_len", minStringLen)
        put("rename_identifiers", renameIdentifiers)
        put("cjk_identifiers", cjkIdentifiers)
        put("constant_protection", constantProtection)
        put("control_flow_obfuscation", controlFlowObfuscation)
        put("data_flow_obfuscation", dataFlowObfuscation)
        put("expression_obfuscation", expressionObfuscation)
        put("function_transformation", functionTransformation)
        put("attribute_obfuscation", attributeObfuscation)
        put("import_obfuscation", importObfuscation)
        put("inject_decoy_methods", injectDecoyMethods)
        put("junk_intensity", junkIntensity)
        put("anti_debug", antiDebug)
        put("periodic_recheck", periodicRecheck)
        put("bytecode_integrity_check", bytecodeIntegrityCheck)
        put("enable_antisandbox", enableAntisandbox)
        put("antisandbox_threshold", antisandboxThreshold)
        put("hook_detection", hookDetection)
        put("lock_filename", lockFilename)
        put("require_launcher_gate", requireLauncherGate)
        put("ssl_pin_sha256", sslPinSha256)
    }

    companion object {
        fun fromJson(obj: JSONObject): ObfuscationSettings = ObfuscationSettings(
            presetId = obj.optString("preset_id", "custom"),
            encryptStrings = obj.optBoolean("encrypt_strings", true),
            minStringLen = obj.optInt("min_string_len", 1),
            renameIdentifiers = obj.optBoolean("rename_identifiers", true),
            cjkIdentifiers = obj.optBoolean("cjk_identifiers", false),
            constantProtection = obj.optBoolean("constant_protection", true),
            controlFlowObfuscation = obj.optBoolean("control_flow_obfuscation", false),
            dataFlowObfuscation = obj.optBoolean("data_flow_obfuscation", false),
            expressionObfuscation = obj.optBoolean("expression_obfuscation", false),
            functionTransformation = obj.optBoolean("function_transformation", false),
            attributeObfuscation = obj.optBoolean("attribute_obfuscation", false),
            importObfuscation = obj.optBoolean("import_obfuscation", false),
            injectDecoyMethods = obj.optBoolean("inject_decoy_methods", true),
            junkIntensity = obj.optInt("junk_intensity", 5),
            antiDebug = obj.optBoolean("anti_debug", true),
            periodicRecheck = obj.optBoolean("periodic_recheck", false),
            bytecodeIntegrityCheck = obj.optBoolean("bytecode_integrity_check", false),
            enableAntisandbox = obj.optBoolean("enable_antisandbox", false),
            antisandboxThreshold = obj.optInt("antisandbox_threshold", 6),
            hookDetection = obj.optBoolean("hook_detection", false),
            lockFilename = obj.optBoolean("lock_filename", false),
            requireLauncherGate = obj.optBoolean("require_launcher_gate", false),
            sslPinSha256 = obj.optString("ssl_pin_sha256", "")
        )
    }
}

data class HistoryEntry(
    val id: String,
    val projectName: String,
    val inputFile: String,
    val operationType: String,
    val timestampMs: Long,
    val configJson: String,
    val status: String,
    val outputPath: String,
    val outputPreview: String,
    val errorLog: String
)
