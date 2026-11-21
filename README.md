# VertictHub Studio

**Embedded CPython 3.14.10 | Android ARM64 (`arm64-v8a`) | 100% Offline Core PyObfuscator Studio**

VertictHub Studio adalah aplikasi Android native (Kotlin + Jetpack Compose + C++ JNI) yang menjalankan seluruh 34 modul **Core PyObfuscator** secara lokal dan 100% offline di atas interpreter resmi **CPython 3.14.10 Android AArch64**.

## Spesifikasi Teknis
- **Platform:** Android API 24+ (`arm64-v8a` / AArch64 only)
- **Python Runtime:** CPython `3.14.10` (`SHA-256: 423c80b957330cf0ebb92b9b20f2294c292144a441bdb0ceb8c69d14928e569b`)
- **Native JNI Bridge:** `native/jni/python_bridge.cpp` (`libverticthub_jni.so`)
- **Offline Policy:** Tanpa backend, tanpa API key, tanpa cloud sync, tanpa `android.permission.INTERNET`

## Struktur Proyek
- `app/src/main/java/com/verticthub/studio/` — UI Jetpack Compose (Workspace, Obfuscate, Build, History, Settings), EngineInitializer, StorageManager, HistoryRepository, PythonBridge
- `app/src/main/assets/python/vh/core/` — Seluruh 34 modul Core PyObfuscator hasil audit `vh.zip`
- `app/src/main/assets/python/studio_bridge.py` — Bridge JSON deterministik yang dipanggil dari JNI C++
- `native/jni/` — `CMakeLists.txt` & `python_bridge.cpp`
- `.github/workflows/build.yml` — Pipeline CI GitHub Actions untuk mengunduh CPython 3.14.10 ARM64 resmi, memvalidasi SHA-256, cross-compile PyCryptodome, dan menghasilkan `VertictHub-Studio.apk`

## Cara Build APK via GitHub Actions
1. Push seluruh isi folder ini ke repository GitHub baru (mis. `Nejasss/VertictHubStudio`).
2. Buka tab **Actions** -> pilih workflow **Build VertictHub Studio (ARM64 Offline APK)** -> klik **Run workflow**.
3. Unduh artifact `VertictHub-Studio-ARM64-Release` berisi `VertictHub-Studio.apk`, `VertictHub-Studio-Source.zip`, dan `SHA256SUMS.txt`.
