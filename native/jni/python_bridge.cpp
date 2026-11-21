#include <jni.h>
#include <Python.h>
#include <android/log.h>
#include <mutex>
#include <string>

#define LOG_TAG "VertictHubJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace {
std::mutex g_py_mutex;
bool g_initialized = false;

std::string fetch_python_error() {
    if (!PyErr_Occurred()) return "";
    PyObject *ptype = nullptr, *pvalue = nullptr, *ptraceback = nullptr;
    PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);

    std::string result = "PythonException";
    if (pvalue != nullptr) {
        PyObject* str_obj = PyObject_Str(pvalue);
        if (str_obj != nullptr) {
            const char* c_str = PyUnicode_AsUTF8(str_obj);
            if (c_str) result = c_str;
            Py_DECREF(str_obj);
        }
    }
    Py_XDECREF(ptype);
    Py_XDECREF(pvalue);
    Py_XDECREF(ptraceback);
    return result;
}
} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_verticthub_studio_bridge_PythonBridge_nativeInitRuntime(
        JNIEnv* env,
        jobject /* this */,
        jstring jPythonHome,
        jstring jAppPythonPath,
        jstring jNativeLibDir) {
    std::lock_guard<std::mutex> lock(g_py_mutex);
    if (g_initialized && Py_IsInitialized()) {
        return env->NewStringUTF("{\"ok\":true,\"status\":\"ALREADY_INITIALIZED\"}");
    }

    const char* pythonHome = env->GetStringUTFChars(jPythonHome, nullptr);
    const char* appPythonPath = env->GetStringUTFChars(jAppPythonPath, nullptr);
    const char* nativeLibDir = env->GetStringUTFChars(jNativeLibDir, nullptr);

    setenv("PYTHONHOME", pythonHome, 1);
    setenv("PYTHONPATH", appPythonPath, 1);
    setenv("PYTHONDONTWRITEBYTECODE", "1", 1);
    setenv("PYTHONUTF8", "1", 1);
    setenv("VH_OFFLINE_MODE", "1", 1);
    setenv("VH_NATIVE_LIB_DIR", nativeLibDir, 1);

    PyConfig config;
    PyConfig_InitIsolatedConfig(&config);
    config.write_bytecode = 0;
    config.use_environment = 0;

    PyStatus status = PyConfig_SetBytesString(&config, &config.home, pythonHome);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        env->ReleaseStringUTFChars(jPythonHome, pythonHome);
        env->ReleaseStringUTFChars(jAppPythonPath, appPythonPath);
        env->ReleaseStringUTFChars(jNativeLibDir, nativeLibDir);
        return env->NewStringUTF("{\"ok\":false,\"error\":\"PyConfig_SetBytesString(home) gagal\"}");
    }

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);

    if (PyStatus_Exception(status)) {
        std::string err = status.err_msg ? status.err_msg : "Py_InitializeFromConfig gagal";
        env->ReleaseStringUTFChars(jPythonHome, pythonHome);
        env->ReleaseStringUTFChars(jAppPythonPath, appPythonPath);
        env->ReleaseStringUTFChars(jNativeLibDir, nativeLibDir);
        std::string json = "{\"ok\":false,\"error\":\"" + err + "\"}";
        return env->NewStringUTF(json.c_str());
    }

    std::string setup_paths =
        "import sys\n"
        "for p in [r'" + std::string(appPythonPath) + "', r'" +
        std::string(appPythonPath) + "/stdlib', r'" +
        std::string(appPythonPath) + "/site-packages', r'" +
        std::string(pythonHome) + "/lib/python3.14', r'" +
        std::string(nativeLibDir) + "']:\n"
        "    if p and p not in sys.path:\n"
        "        sys.path.insert(0, p)\n";
    PyRun_SimpleString(setup_paths.c_str());

    g_initialized = true;
    LOGI("CPython 3.14.10 ARM64 initialized successfully");

    env->ReleaseStringUTFChars(jPythonHome, pythonHome);
    env->ReleaseStringUTFChars(jAppPythonPath, appPythonPath);
    env->ReleaseStringUTFChars(jNativeLibDir, nativeLibDir);
    return env->NewStringUTF("{\"ok\":true,\"status\":\"INITIALIZED\"}");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_verticthub_studio_bridge_PythonBridge_nativeCallBridge(
        JNIEnv* env,
        jobject /* this */,
        jstring jFuncName,
        jobjectArray jArgs) {
    std::lock_guard<std::mutex> lock(g_py_mutex);
    if (!g_initialized || !Py_IsInitialized()) {
        return env->NewStringUTF("{\"ok\":false,\"error\":\"Interpreter belum diinisialisasi\"}");
    }

    PyGILState_STATE gstate = PyGILState_Ensure();
    const char* funcName = env->GetStringUTFChars(jFuncName, nullptr);

    PyObject* moduleName = PyUnicode_FromString("studio_bridge");
    PyObject* module = PyImport_Import(moduleName);
    Py_DECREF(moduleName);

    if (!module) {
        std::string err = fetch_python_error();
        env->ReleaseStringUTFChars(jFuncName, funcName);
        PyGILState_Release(gstate);
        std::string json = "{\"ok\":false,\"error\":\"Gagal import studio_bridge: " + err + "\"}";
        return env->NewStringUTF(json.c_str());
    }

    PyObject* func = PyObject_GetAttrString(module, funcName);
    env->ReleaseStringUTFChars(jFuncName, funcName);
    Py_DECREF(module);

    if (!func || !PyCallable_Check(func)) {
        Py_XDECREF(func);
        PyGILState_Release(gstate);
        return env->NewStringUTF("{\"ok\":false,\"error\":\"Fungsi bridge tidak ditemukan\"}");
    }

    jsize argc = jArgs ? env->GetArrayLength(jArgs) : 0;
    PyObject* pyArgs = PyTuple_New(argc);
    for (jsize i = 0; i < argc; ++i) {
        auto jStr = static_cast<jstring>(env->GetObjectArrayElement(jArgs, i));
        const char* cStr = env->GetStringUTFChars(jStr, nullptr);
        PyTuple_SetItem(pyArgs, i, PyUnicode_FromString(cStr));
        env->ReleaseStringUTFChars(jStr, cStr);
        env->DeleteLocalRef(jStr);
    }

    PyObject* pyResult = PyObject_CallObject(func, pyArgs);
    Py_DECREF(pyArgs);
    Py_DECREF(func);

    std::string outJson;
    if (!pyResult) {
        std::string err = fetch_python_error();
        outJson = "{\"ok\":false,\"error\":\"" + err + "\"}";
    } else {
        const char* resStr = PyUnicode_AsUTF8(pyResult);
        outJson = resStr ? resStr : "{\"ok\":false,\"error\":\"Return non-UTF8\"}";
        Py_DECREF(pyResult);
    }

    PyGILState_Release(gstate);
    return env->NewStringUTF(outJson.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_verticthub_studio_bridge_PythonBridge_nativeShutdown(JNIEnv*, jobject) {
    std::lock_guard<std::mutex> lock(g_py_mutex);
    if (g_initialized && Py_IsInitialized()) {
        Py_FinalizeEx();
        g_initialized = false;
    }
}
