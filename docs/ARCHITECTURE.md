# Arsitektur Sistem VertictHub Studio

1. **Kotlin UI Layer (Jetpack Compose Dark Theme):** Terpisah total dari engine Python; berkomunikasi melalui `StateFlow` dan coroutine dispatcher.
2. **EngineInitializer:** Menjalankan 7 tahap pemeriksaan berurutan (`ABI arm64-v8a` -> `Internal Storage Layout` -> `Ekstraksi Stdlib/Core` -> `Py_InitializeFromConfig` -> `Validasi sys.version_info == (3, 14, 10)` -> `Import 34 Modul Core` -> `Self-test PyCryptodome AES-256-CBC/SHA256/Ed25519`).
3. **Native JNI Layer (`libverticthub_jni.so`):** Menggunakan `PyConfig_InitIsolatedConfig` dan mutex + `PyGILState_Ensure()` agar eksekusi interpreter aman dan bebas konflik thread.
4. **SELinux W^X Compliance:** Seluruh `.so` (`libpython3.14.so`, CPython `lib-dynload/*.so`, dan ekstensi C PyCryptodome) ditempatkan di `jniLibs/arm64-v8a/` dengan `android:extractNativeLibs="true"` agar dimuat langsung dari `nativeLibraryDir`.
