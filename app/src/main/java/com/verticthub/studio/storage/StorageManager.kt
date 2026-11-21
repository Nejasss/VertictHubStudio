package com.verticthub.studio.storage

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.verticthub.studio.model.ProjectFile
import com.verticthub.studio.model.StudioProject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.util.UUID
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class StorageManager(private val context: Context) {

    val workspaceDir: File get() = File(context.filesDir, "workspace")
    val projectsDir: File get() = File(context.filesDir, "projects")
    val outputsDir: File get() = File(context.filesDir, "outputs")
    val historyDir: File get() = File(context.filesDir, "history")
    val logsDir: File get() = File(context.filesDir, "logs")
    val configsDir: File get() = File(context.filesDir, "configs")
    val cacheDir: File get() = File(context.filesDir, "cache")
    val runtimeDir: File get() = File(context.filesDir, "runtime")
    val pythonHomeDir: File get() = File(runtimeDir, "python-3.14.10")
    val appPythonScriptsDir: File get() = File(runtimeDir, "app_python")

    fun ensureDirectoryLayout() {
        listOf(
            workspaceDir, projectsDir, outputsDir, historyDir,
            logsDir, configsDir, cacheDir, runtimeDir,
            pythonHomeDir, appPythonScriptsDir
        ).forEach { it.mkdirs() }
    }

    suspend fun extractBundledPythonIfNeeded(): File = withContext(Dispatchers.IO) {
        ensureDirectoryLayout()
        val stampFile = File(runtimeDir, ".extracted_3.14.10_v1")
        if (!stampFile.exists()) {
            copyAssetDir("python", appPythonScriptsDir)
            val bundledStdlib = File(appPythonScriptsDir, "stdlib")
            val targetStdlib = File(pythonHomeDir, "lib/python3.14")
            if (bundledStdlib.exists()) {
                targetStdlib.mkdirs()
                bundledStdlib.copyRecursively(targetStdlib, overwrite = true)
            }
            copyAssetDir("configs", configsDir)
            stampFile.writeText("CPython 3.14.10 ARM64 Offline Ready")
        }
        pythonHomeDir
    }

    private fun copyAssetDir(assetPath: String, destDir: File) {
        val items = context.assets.list(assetPath) ?: return
        if (items.isEmpty()) {
            destDir.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                FileOutputStream(destDir).use { output ->
                    input.copyTo(output)
                }
            }
        } else {
            destDir.mkdirs()
            for (item in items) {
                copyAssetDir("$assetPath/$item", File(destDir, item))
            }
        }
    }

    fun listProjects(): List<StudioProject> {
        ensureDirectoryLayout()
        return projectsDir.listFiles()
            ?.filter { it.isDirectory }
            ?.mapNotNull { dir ->
                val meta = File(dir, ".project.json")
                if (meta.exists()) {
                    val j = JSONObject(meta.readText())
                    StudioProject(
                        id = j.optString("id", dir.name),
                        name = j.optString("name", dir.name),
                        rootPath = dir.absolutePath,
                        activeFileRelativePath = j.optString("active_file", "main.py"),
                        createdAt = j.optLong("created_at", dir.lastModified())
                    )
                } else {
                    StudioProject(dir.name, dir.name, dir.absolutePath, "main.py", dir.lastModified())
                }
            }
            ?.sortedByDescending { it.createdAt }
            ?: emptyList()
    }

    fun createProject(name: String, initialFileName: String = "main.py", initialCode: String = DEFAULT_STARTER_CODE): StudioProject {
        ensureDirectoryLayout()
        val safeSlug = name.trim().replace(Regex("[^a-zA-Z0-9_-]"), "_").ifEmpty { "project_${System.currentTimeMillis()}" }
        val projDir = File(projectsDir, safeSlug).apply { mkdirs() }
        val targetFile = File(projDir, initialFileName)
        targetFile.parentFile?.mkdirs()
        targetFile.writeText(initialCode)

        val project = StudioProject(
            id = UUID.randomUUID().toString(),
            name = name.trim().ifEmpty { safeSlug },
            rootPath = projDir.absolutePath,
            activeFileRelativePath = initialFileName,
            createdAt = System.currentTimeMillis()
        )
        saveProjectMetadata(project)
        return project
    }

    fun saveProjectMetadata(project: StudioProject) {
        val meta = File(project.rootPath, ".project.json")
        meta.writeText(JSONObject().apply {
            put("id", project.id)
            put("name", project.name)
            put("active_file", project.activeFileRelativePath)
            put("created_at", project.createdAt)
        }.toString(2))
    }

    fun listProjectFiles(project: StudioProject): List<ProjectFile> {
        val root = File(project.rootPath)
        if (!root.exists()) return emptyList()
        return root.walkTopDown()
            .filter { it.isFile && it.name != ".project.json" }
            .map { file ->
                ProjectFile(
                    relativePath = file.relativeTo(root).path,
                    absolutePath = file.absolutePath,
                    sizeBytes = file.length()
                )
            }
            .sortedBy { it.relativePath }
            .toList()
    }

    suspend fun importPyFromUri(uri: Uri, targetProject: StudioProject): ProjectFile = withContext(Dispatchers.IO) {
        val displayName = resolveDisplayName(uri) ?: "imported_${System.currentTimeMillis()}.py"
        val safeName = displayName.substringAfterLast('/').substringAfterLast('\\')
        val destFile = File(targetProject.rootPath, safeName)
        context.contentResolver.openInputStream(uri)?.use { input ->
            FileOutputStream(destFile).use { output -> input.copyTo(output) }
        } ?: error("Tidak dapat membaca file dari URI: $uri")
        ProjectFile(safeName, destFile.absolutePath, destFile.length())
    }

    suspend fun importZipProjectFromUri(uri: Uri): StudioProject = withContext(Dispatchers.IO) {
        val zipName = (resolveDisplayName(uri) ?: "imported_zip").removeSuffix(".zip")
        val project = createProject(zipName, "main.py", "# Extracted from $zipName.zip\n")
        val root = File(project.rootPath).canonicalFile
        var firstPy: String? = null

        context.contentResolver.openInputStream(uri)?.use { rawIn ->
            ZipInputStream(rawIn).use { zis ->
                var entry: ZipEntry? = zis.nextEntry
                while (entry != null) {
                    if (!entry.isDirectory) {
                        val outFile = File(root, entry.name).canonicalFile
                        if (!outFile.path.startsWith(root.path)) {
                            throw SecurityException("Zip path traversal terdeteksi: ${entry.name}")
                        }
                        outFile.parentFile?.mkdirs()
                        FileOutputStream(outFile).use { out -> zis.copyTo(out) }
                        val rel = outFile.relativeTo(root).path
                        if (firstPy == null && rel.endsWith(".py")) {
                            firstPy = rel
                        }
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        } ?: error("Gagal membuka arsip ZIP dari URI")

        val defaultMain = File(root, "main.py")
        if (firstPy != null && firstPy != "main.py" && defaultMain.length() < 40) {
            defaultMain.delete()
        }
        val updated = project.copy(activeFileRelativePath = firstPy ?: "main.py")
        saveProjectMetadata(updated)
        updated
    }

    suspend fun exportTextToUri(uri: Uri, content: String) = withContext(Dispatchers.IO) {
        context.contentResolver.openOutputStream(uri)?.use { out ->
            out.write(content.toByteArray(Charsets.UTF_8))
        } ?: error("Gagal menulis output ke lokasi terpilih")
    }

    suspend fun exportProjectZipToUri(uri: Uri, project: StudioProject) = withContext(Dispatchers.IO) {
        val root = File(project.rootPath)
        context.contentResolver.openOutputStream(uri)?.use { rawOut ->
            ZipOutputStream(rawOut).use { zos ->
                root.walkTopDown().filter { it.isFile && it.name != ".project.json" }.forEach { f ->
                    val rel = f.relativeTo(root).path
                    zos.putNextEntry(ZipEntry(rel))
                    f.inputStream().use { it.copyTo(zos) }
                    zos.closeEntry()
                }
            }
        } ?: error("Gagal mengekspor project ZIP")
    }

    fun saveOutputArtifact(filename: String, content: String): File {
        ensureDirectoryLayout()
        val out = File(outputsDir, "${System.currentTimeMillis()}_$filename")
        out.writeText(content)
        return out
    }

    fun clearTemporaryCache(): Long {
        var freed = 0L
        listOf(cacheDir, logsDir).forEach { dir ->
            dir.walkBottomDown().filter { it.isFile }.forEach { f ->
                freed += f.length()
                f.delete()
            }
        }
        return freed
    }

    fun computeStorageStats(): Map<String, Long> {
        fun dirSize(d: File): Long = d.walkTopDown().filter { it.isFile }.sumOf { it.length() }
        return mapOf(
            "runtime_bytes" to dirSize(runtimeDir),
            "projects_bytes" to dirSize(projectsDir),
            "outputs_bytes" to dirSize(outputsDir),
            "history_bytes" to dirSize(historyDir),
            "cache_bytes" to dirSize(cacheDir)
        )
    }

    private fun resolveDisplayName(uri: Uri): String? {
        context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && cursor.moveToFirst()) {
                return cursor.getString(idx)
            }
        }
        return uri.lastPathSegment
    }

    companion object {
        val DEFAULT_STARTER_CODE = """
            import hashlib

            class TokenValidator:
                def __init__(self, secret_salt: str):
                    self.secret_salt = secret_salt

                def compute_digest(self, user_id: str) -> str:
                    payload = f"{self.secret_salt}:{user_id}".encode("utf-8")
                    return hashlib.sha256(payload).hexdigest()

            def main():
                validator = TokenValidator("VERTICTHUB_OFFLINE_SEED_2026")
                print("Digest:", validator.compute_digest("arm64_node_01"))

            if __name__ == "__main__":
                main()
        """.trimIndent()
    }
}
