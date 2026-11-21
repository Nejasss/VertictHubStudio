package com.verticthub.studio.bridge

import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.concurrent.Executors

object PythonBridge {
    init {
        System.loadLibrary("python3.14")
        System.loadLibrary("verticthub_jni")
    }

    private val pythonDispatcher = Executors.newSingleThreadExecutor { r ->
        Thread(r, "CPython-3.14.10-Worker").apply { isDaemon = true }
    }.asCoroutineDispatcher()

    private external fun nativeInitRuntime(
        pythonHome: String,
        appPythonPath: String,
        nativeLibDir: String
    ): String

    private external fun nativeCallBridge(
        funcName: String,
        args: Array<String>
    ): String

    external fun nativeShutdown()

    suspend fun initRuntime(
        pythonHome: String,
        appPythonPath: String,
        nativeLibDir: String
    ): JSONObject = withContext(pythonDispatcher) {
        JSONObject(nativeInitRuntime(pythonHome, appPythonPath, nativeLibDir))
    }

    suspend fun call(funcName: String, vararg args: String): JSONObject =
        withContext(pythonDispatcher) {
            JSONObject(nativeCallBridge(funcName, arrayOf(*args)))
        }
}
