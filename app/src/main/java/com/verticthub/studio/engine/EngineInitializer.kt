package com.verticthub.studio.engine

import android.content.Context
import android.os.Build
import com.verticthub.studio.bridge.PythonBridge
import com.verticthub.studio.storage.StorageManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

data class EngineStatusState(
    val status: String = "INITIALIZING",
    val pythonVersion: String = "3.14.10",
    val architecture: String = "ARM64",
    val coreStatus: String = "VERIFYING",
    val dependencyStatus: String = "VERIFYING",
    val cryptoAvailable: Boolean = false,
    val offlineMode: Boolean = true,
    val failedComponent: String? = null,
    val failureCause: String? = null,
    val relatedPath: String? = null,
    val recoveryStep: String? = null,
    val runtimeDetails: JSONObject? = null,
    val coreDetails: JSONObject? = null,
    val dependencyDetails: JSONObject? = null
)

class EngineInitializer(
    private val context: Context,
    private val storageManager: StorageManager
) {
    private val _state = MutableStateFlow(EngineStatusState())
    val state: StateFlow<EngineStatusState> = _state.asStateFlow()

    suspend fun initialize(): EngineStatusState {
        _state.value = EngineStatusState(status = "INITIALIZING")

        val supportedAbis = Build.SUPPORTED_ABIS.toList()
        if (!supportedAbis.contains("arm64-v8a")) {
            return fail(
                component = "Android ABI Check",
                cause = "Perangkat tidak mendukung arm64-v8a (terdeteksi: $supportedAbis)",
                path = context.applicationInfo.nativeLibraryDir,
                recovery = "Jalankan VertictHub Studio di perangkat Android ARM64 (aarch64)."
            )
        }

        storageManager.ensureDirectoryLayout()

        val runtimeRoot = try {
            storageManager.extractBundledPythonIfNeeded()
        } catch (e: Exception) {
            return fail(
                component = "Runtime Resource Extraction",
                cause = e.message ?: "Gagal mengekstrak bundled Python 3.14.10",
                path = storageManager.runtimeDir.absolutePath,
                recovery = "Periksa kapasitas penyimpanan internal dan bersihkan cache."
            )
        }

        val appPythonDir = storageManager.appPythonScriptsDir.absolutePath
        val nativeLibDir = context.applicationInfo.nativeLibraryDir

        val initRes = try {
            PythonBridge.initRuntime(
                pythonHome = runtimeRoot.absolutePath,
                appPythonPath = appPythonDir,
                nativeLibDir = nativeLibDir
            )
        } catch (e: Throwable) {
            return fail(
                component = "CPython JNI Native Load",
                cause = e.message ?: "UnsatisfiedLinkError pada libpython3.14.so",
                path = nativeLibDir,
                recovery = "Pastikan APK dibangun khusus ABI arm64-v8a dengan CPython 3.14.10 terbundel."
            )
        }

        if (!initRes.optBoolean("ok", false)) {
            return fail(
                component = "CPython JNI Init",
                cause = initRes.optString("error", "Gagal menginisialisasi libpython3.14.so"),
                path = nativeLibDir,
                recovery = "Bersihkan cache runtime di Settings lalu jalankan Re-Initialize Engine."
            )
        }

        val rtInfo = PythonBridge.call("get_runtime_info")
        if (!rtInfo.optBoolean("ok", false) || !rtInfo.optBoolean("is_3_14_10", false)) {
            return fail(
                component = "CPython Version Check",
                cause = "Versi terdeteksi: ${rtInfo.optString("python_version", "unknown")} (wajib 3.14.10)",
                path = runtimeRoot.absolutePath,
                recovery = "Pastikan paket CPython 3.14.10 ARM64 resmi (SHA-256 tervalidasi) dibundel saat build."
            )
        }

        val coreInfo = PythonBridge.call("verify_core_modules")
        if (!coreInfo.optBoolean("ok", false) || !coreInfo.optBoolean("all_verified", false)) {
            return fail(
                component = "Core PyObfuscator Verification",
                cause = "Hanya ${coreInfo.optInt("verified_count")}/${coreInfo.optInt("total")} modul Core terverifikasi.",
                path = "$appPythonDir/vh/core",
                recovery = "Periksa detail modul gagal pada tab Settings -> Core Audit."
            )
        }

        val depInfo = PythonBridge.call("verify_dependencies")
        val cryptoOk = depInfo.optBoolean("ok", false) && depInfo.optBoolean("crypto_available", false)
        if (!cryptoOk) {
            return fail(
                component = "PyCryptodome ARM64 Verification",
                cause = "PyCryptodome gagal import atau gagal self-test enkripsi AES-256-CBC/SHA256.",
                path = nativeLibDir,
                recovery = "Pastikan ekstensi C PyCryptodome cp314-android_arm64_v8a dibundel saat build."
            )
        }

        val ready = EngineStatusState(
            status = "READY",
            pythonVersion = rtInfo.optString("python_version", "3.14.10"),
            architecture = "ARM64",
            coreStatus = "ALL VERIFIED",
            dependencyStatus = "VERIFIED",
            cryptoAvailable = true,
            offlineMode = true,
            runtimeDetails = rtInfo,
            coreDetails = coreInfo,
            dependencyDetails = depInfo
        )
        _state.value = ready
        return ready
    }

    private fun fail(
        component: String,
        cause: String,
        path: String,
        recovery: String
    ): EngineStatusState {
        val errState = EngineStatusState(
            status = "FAILED",
            coreStatus = "FAILED",
            dependencyStatus = "FAILED",
            cryptoAvailable = false,
            offlineMode = true,
            failedComponent = component,
            failureCause = cause,
            relatedPath = path,
            recoveryStep = recovery
        )
        _state.value = errState
        return errState
    }
}
