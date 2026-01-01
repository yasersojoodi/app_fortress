package com.app.fortress

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Proxy
import java.net.ProxySelector
import java.net.Socket
import java.net.URI
import java.security.MessageDigest

/**
 * AppFortressPlugin - Production-Grade Security Plugin for Flutter
 *
 * Multi-layer security implementation with:
 * - Play Integrity API attestation (Android)
 * - Root/Jailbreak detection (multi-layer)
 * - Emulator/Simulator detection (scoring-based to avoid false positives)
 * - Hooking framework detection (Frida, Xposed, Substrate)
 * - Debugger detection (build-type aware)
 * - App signature verification
 * - Install source verification
 * - Native security checks via JNI
 *
 * @author App Fortress Team
 * @version 2.0.0
 */
class AppFortressPlugin : FlutterPlugin, MethodCallHandler {

    private lateinit var channel: MethodChannel
    private lateinit var context: Context
    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var nativeLibLoaded = false

    companion object {
        private const val TAG = "AppFortress"
        private const val CHANNEL_NAME = "com.app.fortress/security"
        var cloudProjectNumber: Long = 0L

        // Trusted install sources
        private val TRUSTED_INSTALLERS = setOf(
            "com.android.vending",      // Google Play Store
            "com.amazon.venezia",       // Amazon App Store
            "com.huawei.appmarket",     // Huawei AppGallery
            "com.sec.android.app.samsungapps", // Samsung Galaxy Store
            "com.oppo.market",          // OPPO App Market
            "com.xiaomi.mipicks"        // Xiaomi GetApps
        )
    }

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, CHANNEL_NAME)
        channel.setMethodCallHandler(this)
        context = binding.applicationContext
        loadNativeLibrary()
    }

    private fun loadNativeLibrary() {
        try {
            System.loadLibrary("app_fortress_native")
            nativeLibLoaded = true
        } catch (e: UnsatisfiedLinkError) {
            nativeLibLoaded = false
        }
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        scope.cancel()
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "configure" -> {
                cloudProjectNumber = (call.argument<Number>("cloudProjectNumber"))?.toLong() ?: 0L
                result.success(true)
            }
            "requestAttestation" -> {
                val nonce = call.argument<String>("nonce")
                if (nonce.isNullOrEmpty()) {
                    result.error("INVALID_ARGUMENT", "Nonce is required", null)
                    return
                }
                requestAttestation(nonce, result)
            }
            "getDeviceSecurityInfo" -> getDeviceSecurityInfo(result)
            "isRooted" -> result.success(isRooted())
            "isEmulator" -> result.success(isEmulator())
            "isDebuggerAttached" -> result.success(isDebuggerAttached())
            "isHookingDetected" -> result.success(isHookingDetected())
            "verifySignature" -> {
                @Suppress("UNCHECKED_CAST")
                val expected = call.argument<List<String>>("expectedSignatures") ?: emptyList()
                result.success(verifySignature(expected))
            }
            "runFullSecurityCheck" -> runFullSecurityCheck(result)
            "getPlatformVersion" -> result.success("Android ${Build.VERSION.RELEASE}")
            "isFromTrustedSource" -> result.success(isFromTrustedInstallSource())
            "getSignature" -> result.success(getSignatureSha256())
            "isProxyEnabled" -> result.success(isProxyEnabled())
            "isVpnActive" -> result.success(isVpnActive())
            else -> result.notImplemented()
        }
    }

    // ==================== PLAY INTEGRITY API ====================

    private fun requestAttestation(nonce: String, result: Result) {
        if (cloudProjectNumber == 0L) {
            result.error("CONFIGURATION_ERROR", "Cloud project number not configured", null)
            return
        }

        scope.launch {
            try {
                val integrityManager = IntegrityManagerFactory.create(context)
                val request = IntegrityTokenRequest.builder()
                    .setCloudProjectNumber(cloudProjectNumber)
                    .setNonce(nonce)
                    .build()

                val tokenResponse = withContext(Dispatchers.IO) {
                    integrityManager.requestIntegrityToken(request)
                }

                tokenResponse.addOnSuccessListener { response ->
                    result.success(hashMapOf(
                        "token" to response.token(),
                        "platform" to "android",
                        "timestamp" to System.currentTimeMillis(),
                        "metadata" to hashMapOf(
                            "packageName" to context.packageName,
                            "sdkVersion" to Build.VERSION.SDK_INT
                        )
                    ))
                }

                tokenResponse.addOnFailureListener { e ->
                    val errorCode = when {
                        e.message?.contains("API_NOT_AVAILABLE") == true -> "SERVICE_UNAVAILABLE"
                        e.message?.contains("NETWORK") == true -> "NETWORK_ERROR"
                        e.message?.contains("TOO_MANY_REQUESTS") == true -> "RATE_LIMITED"
                        else -> "ATTESTATION_FAILED"
                    }
                    result.error(errorCode, e.message, null)
                }
            } catch (e: Exception) {
                result.error("ATTESTATION_FAILED", e.message, null)
            }
        }
    }

    // ==================== DEVICE SECURITY INFO ====================

    @SuppressLint("HardwareIds")
    private fun getDeviceSecurityInfo(result: Result) {
        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )

            val threats = mutableListOf<Map<String, Any>>()

            if (isRooted()) {
                threats.add(mapOf(
                    "code" to "ROOT_DETECTED",
                    "severity" to "high",
                    "message" to "Device root access detected",
                    "blocking" to true
                ))
            }

            if (isEmulator()) {
                threats.add(mapOf(
                    "code" to "EMULATOR_DETECTED",
                    "severity" to "medium",
                    "message" to "Running on emulator/simulator",
                    "blocking" to false
                ))
            }

            if (isDebuggerAttached()) {
                threats.add(mapOf(
                    "code" to "DEBUGGER_DETECTED",
                    "severity" to "critical",
                    "message" to "Debugger attached to process",
                    "blocking" to true
                ))
            }

            if (isHookingDetected()) {
                threats.add(mapOf(
                    "code" to "HOOKING_DETECTED",
                    "severity" to "critical",
                    "message" to "Hooking framework detected (Frida/Xposed)",
                    "blocking" to true
                ))
            }

            if (isDebuggable()) {
                threats.add(mapOf(
                    "code" to "DEBUGGABLE_BUILD",
                    "severity" to "low",
                    "message" to "App is built in debug mode",
                    "blocking" to false
                ))
            }

            if (!isFromTrustedInstallSource()) {
                threats.add(mapOf(
                    "code" to "UNTRUSTED_INSTALL_SOURCE",
                    "severity" to "medium",
                    "message" to "App not installed from trusted store",
                    "blocking" to false
                ))
            }

            if (isProxyEnabled()) {
                threats.add(mapOf(
                    "code" to "PROXY_DETECTED",
                    "severity" to "high",
                    "message" to "HTTP proxy is configured on device",
                    "blocking" to true
                ))
            }

            if (isVpnActive()) {
                threats.add(mapOf(
                    "code" to "VPN_DETECTED",
                    "severity" to "medium",
                    "message" to "VPN connection is active",
                    "blocking" to false
                ))
            }

            val deviceInfo = hashMapOf<String, Any?>(
                "platform" to "android",
                "model" to Build.MODEL,
                "manufacturer" to Build.MANUFACTURER,
                "osVersion" to Build.VERSION.RELEASE,
                "sdkVersion" to Build.VERSION.SDK_INT,
                "appVersion" to packageInfo.versionName,
                "appVersionCode" to getVersionCode(packageInfo),
                "packageName" to context.packageName,
                "isRooted" to isRooted(),
                "isEmulator" to isEmulator(),
                "isDebuggerAttached" to isDebuggerAttached(),
                "isHookingDetected" to isHookingDetected(),
                "isDebuggable" to isDebuggable(),
                "installSource" to getInstallSource(),
                "isFromTrustedSource" to isFromTrustedInstallSource(),
                "signatureSha256" to getSignatureSha256(),
                "securityPatch" to Build.VERSION.SECURITY_PATCH,
                "isProxyEnabled" to isProxyEnabled(),
                "isVpnActive" to isVpnActive(),
                "threats" to threats,
                "timestamp" to System.currentTimeMillis()
            )

            result.success(deviceInfo)
        } catch (e: Exception) {
            result.error("DEVICE_INFO_ERROR", e.message, null)
        }
    }

    @Suppress("DEPRECATION")
    private fun getVersionCode(packageInfo: android.content.pm.PackageInfo): Long {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.longVersionCode
        } else {
            packageInfo.versionCode.toLong()
        }
    }

    // ==================== ROOT DETECTION (Multi-Layer) ====================

    fun isRooted(): Boolean {
        return checkSuBinary() ||
                checkRootApps() ||
                checkMagisk() ||
                checkKernelSU() ||
                checkTestKeys() ||
                checkRootCloaking() ||
                checkBusyBox() ||
                checkRWSystem() ||
                nativeCheck { nativeIsRooted() }
    }

    private fun checkSuBinary(): Boolean {
        val paths = arrayOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/su", "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/mu", "/data/local/xbin/su",
            "/data/local/bin/su", "/data/local/su",
            "/su/bin/su", "/magisk/.core/bin/su",
            "/system/bin/failsafe/su", "/data/local/tmp/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkRootApps(): Boolean {
        val packages = arrayOf(
            "com.topjohnwu.magisk",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.koushikdutta.superuser",
            "com.zachspong.temprootremovejb",
            "com.ramdroid.appquarantine",
            "me.phh.superuser",
            "io.github.vvb2060.magisk"
        )
        return packages.any { isPackageInstalled(it) }
    }

    private fun checkMagisk(): Boolean {
        val magiskPaths = arrayOf(
            "/sbin/.magisk", "/cache/.disable_magisk",
            "/dev/.magisk.unblock", "/data/adb/magisk",
            "/data/adb/magisk.img", "/data/adb/magisk.db"
            // NOTE: /data/adb/modules removed - can exist on MIUI/FunTouch without Magisk
        )
        if (magiskPaths.any { File(it).exists() }) return true

        return try {
            val process = Runtime.getRuntime().exec("getprop")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val props = reader.readText()
            reader.close()
            process.waitFor()
            props.contains("magisk", ignoreCase = true)
        } catch (_: Exception) {
            false
        }
    }

    private fun checkKernelSU(): Boolean {
        val kernelSuIndicators = arrayOf(
            "/data/adb/ksu",
            "/data/adb/ksud"
        )
        return kernelSuIndicators.any { File(it).exists() } ||
                isPackageInstalled("me.weishu.kernelsu")
    }

    private fun checkTestKeys(): Boolean {
        return Build.TAGS?.contains("test-keys") == true
    }

    private fun checkRootCloaking(): Boolean {
        val cloakingApps = arrayOf(
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "com.formyhm.hideroot",
            "com.amphoras.hidemyroot",
            "com.saurik.substrate"
        )
        return cloakingApps.any { isPackageInstalled(it) }
    }

    private fun checkBusyBox(): Boolean {
        val busyboxPaths = arrayOf(
            "/system/xbin/busybox",
            "/system/bin/busybox",
            "/sbin/busybox"
        )
        return busyboxPaths.any { File(it).exists() }
    }

    private fun checkRWSystem(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("mount")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            var isSystemRW = false
            reader.forEachLine { line ->
                // Check if this specific line mounts /system as rw
                // Mount line format: "device /mountpoint type options"
                // We need to check if /system mount point has "rw" in its options
                if (line.contains(" /system ") && line.contains(" rw,")) {
                    isSystemRW = true
                }
            }
            reader.close()
            process.waitFor()
            isSystemRW
        } catch (_: Exception) {
            false
        }
    }

    // ==================== EMULATOR DETECTION (Scoring-Based) ====================

    fun isEmulator(): Boolean {
        var score = 0
        val threshold = 3

        // Strong indicators (2 points)
        if (checkEmulatorHardwareFiles()) score += 2
        if (checkQemuProperties()) score += 2
        if (Build.HARDWARE.contains("goldfish") || Build.HARDWARE.contains("ranchu")) score += 2
        if (Build.PRODUCT.equals("sdk", ignoreCase = true) ||
            Build.PRODUCT.equals("google_sdk", ignoreCase = true) ||
            Build.PRODUCT.contains("sdk_gphone")) score += 2

        // Medium indicators (1 point)
        if (Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK")) score += 1
        if (Build.MANUFACTURER.equals("Genymotion", ignoreCase = true)) score += 1
        if (Build.BRAND.equals("generic", ignoreCase = true) &&
            Build.DEVICE.startsWith("generic")) score += 1
        if (Build.BOARD.lowercase().contains("nox") ||
            Build.BOARD.lowercase().contains("vbox")) score += 1
        if (Build.FINGERPRINT.contains("generic/sdk") ||
            Build.FINGERPRINT.contains("generic_x86")) score += 1
        if (Build.HARDWARE.contains("vbox") || Build.HARDWARE.contains("virtualbox")) score += 1

        // Native check
        if (nativeCheck { nativeIsEmulator() }) score += 2

        return score >= threshold
    }

    private fun checkEmulatorHardwareFiles(): Boolean {
        val files = arrayOf(
            "/dev/socket/qemud", "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace", "/system/bin/qemu-props",
            "/dev/goldfish_pipe"
        )
        return files.any { File(it).exists() }
    }

    private fun checkQemuProperties(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("getprop")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val props = reader.readText()
            reader.close()
            process.waitFor()
            props.contains("ro.kernel.qemu=1") ||
                    props.contains("ro.hardware.virtual") ||
                    props.contains("init.svc.qemud") ||
                    props.contains("ro.bootimage.build.fingerprint.*generic")
        } catch (_: Exception) {
            false
        }
    }

    // ==================== DEBUGGER DETECTION (Build-Type Aware) ====================

    fun isDebuggerAttached(): Boolean {
        // Primary checks - always reliable
        if (Debug.isDebuggerConnected()) return true
        if (Debug.waitingForDebugger()) return true

        // For DEBUG builds only: use additional sensitive checks
        // This avoids false positives from Samsung Knox on release builds
        if (isDebuggable()) {
            if (checkJdwpThread()) return true
            if (isBeingTraced()) return true
            if (nativeCheck { nativeIsDebuggerAttached() }) return true
        }

        return false
    }

    private fun checkJdwpThread(): Boolean {
        return try {
            Thread.getAllStackTraces().keys.any { thread ->
                val name = thread.name.lowercase()
                name.contains("jdwp") || name == "debugger"
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun isBeingTraced(): Boolean {
        return try {
            val statusFile = File("/proc/self/status")
            if (!statusFile.exists()) return false
            BufferedReader(FileReader(statusFile)).use { reader ->
                reader.lineSequence().forEach { line ->
                    if (line.startsWith("TracerPid:")) {
                        val pid = line.substringAfter(":").trim().toIntOrNull()
                        return pid != null && pid > 0
                    }
                }
            }
            false
        } catch (_: Exception) {
            false
        }
    }

    // ==================== HOOKING DETECTION (Comprehensive) ====================

    fun isHookingDetected(): Boolean {
        return checkXposed() ||
               checkFrida() ||
               checkSubstrate() ||
               checkMagiskHide() ||
               nativeCheck { nativeIsHooked() }
    }

    private fun checkXposed(): Boolean {
        // Check for Xposed class
        try {
            Class.forName("de.robv.android.xposed.XposedBridge")
            return true
        } catch (_: ClassNotFoundException) {}

        // Check for Xposed files
        val xposedFiles = arrayOf(
            "/system/framework/XposedBridge.jar",
            "/system/bin/app_process.orig",
            "/system/bin/app_process_xposed",
            "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so"
        )
        if (xposedFiles.any { File(it).exists() }) return true

        // Check for Xposed installer apps
        val xposedApps = arrayOf(
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager"
        )
        if (xposedApps.any { isPackageInstalled(it) }) return true

        // Stack trace check
        try {
            throw Exception()
        } catch (e: Exception) {
            for (element in e.stackTrace) {
                if (element.className.contains("xposed", ignoreCase = true) ||
                    element.className.contains("lsposed", ignoreCase = true)) {
                    return true
                }
            }
        }
        return false
    }

    private fun checkFrida(): Boolean {
        // Check for Frida files
        val fridaPaths = arrayOf(
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida",
            "/sdcard/frida-server"
        )
        if (fridaPaths.any { File(it).exists() }) return true

        // Check Frida default port
        if (checkPort(27042)) return true
        if (checkPort(27043)) return true

        // Check /proc/self/maps for Frida libraries
        if (checkMapsForStrings(listOf("frida", "gadget"))) return true

        // Check for Frida named pipe
        if (File("/data/local/tmp/frida-server-pipe").exists()) return true

        return false
    }

    private fun checkSubstrate(): Boolean {
        if (isPackageInstalled("com.saurik.substrate")) return true

        val substratePaths = arrayOf(
            "/system/lib/libsubstrate.so",
            "/system/lib/libsubstrate-dvm.so"
        )
        return substratePaths.any { File(it).exists() }
    }

    private fun checkMagiskHide(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("getprop")
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val props = reader.readText()
            reader.close()
            process.waitFor()
            props.contains("ro.magisk.hide") || props.contains("persist.magisk.hide")
        } catch (_: Exception) {
            false
        }
    }

    private fun checkMapsForStrings(suspicious: List<String>): Boolean {
        return try {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.exists()) return false
            val content = mapsFile.readText().lowercase()
            suspicious.any { content.contains(it.lowercase()) }
        } catch (_: Exception) {
            false
        }
    }

    private fun checkPort(port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.soTimeout = 100
                socket.connect(InetSocketAddress("127.0.0.1", port), 100)
                true
            }
        } catch (_: Exception) {
            false
        }
    }

    // ==================== SIGNATURE VERIFICATION ====================

    fun verifySignature(expectedSignatures: List<String>): Boolean {
        if (expectedSignatures.isEmpty()) return true
        val actualSignature = getSignatureSha256() ?: return false
        return expectedSignatures.any { expected ->
            expected.replace(":", "").equals(actualSignature, ignoreCase = true)
        }
    }

    @Suppress("DEPRECATION", "PackageManagerGetSignatures")
    fun getSignatureSha256(): String? {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signature = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners?.firstOrNull()
            } else {
                packageInfo.signatures?.firstOrNull()
            }

            signature?.let {
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(it.toByteArray())
                digest.joinToString("") { byte -> "%02X".format(byte) }
            }
        } catch (_: Exception) {
            null
        }
    }

    // ==================== INSTALL SOURCE VERIFICATION ====================

    fun isFromTrustedInstallSource(): Boolean {
        val source = getInstallSource()
        return TRUSTED_INSTALLERS.contains(source)
    }

    private fun getInstallSource(): String {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                context.packageManager.getInstallSourceInfo(context.packageName)
                    .installingPackageName ?: "unknown"
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getInstallerPackageName(context.packageName) ?: "unknown"
            }
        } catch (_: Exception) {
            "unknown"
        }
    }

    // ==================== UTILITY FUNCTIONS ====================

    private fun isDebuggable(): Boolean {
        return (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    private fun isPackageInstalled(packageName: String): Boolean {
        return try {
            context.packageManager.getPackageInfo(packageName, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    private fun runFullSecurityCheck(result: Result) {
        val threats = mutableListOf<Map<String, Any>>()

        if (isRooted()) {
            threats.add(mapOf("code" to "ROOT", "severity" to "high", "blocking" to true,
                "message" to "Device is rooted"))
        }
        if (isEmulator()) {
            threats.add(mapOf("code" to "EMULATOR", "severity" to "medium", "blocking" to false,
                "message" to "Running on emulator"))
        }
        if (isDebuggerAttached()) {
            threats.add(mapOf("code" to "DEBUGGER", "severity" to "critical", "blocking" to true,
                "message" to "Debugger attached"))
        }
        if (isHookingDetected()) {
            threats.add(mapOf("code" to "HOOKING", "severity" to "critical", "blocking" to true,
                "message" to "Hooking framework detected"))
        }
        if (isDebuggable()) {
            threats.add(mapOf("code" to "DEBUGGABLE", "severity" to "low", "blocking" to false,
                "message" to "Debug build"))
        }
        if (isProxyEnabled()) {
            threats.add(mapOf("code" to "PROXY", "severity" to "high", "blocking" to true,
                "message" to "HTTP proxy enabled"))
        }
        if (isVpnActive()) {
            threats.add(mapOf("code" to "VPN", "severity" to "medium", "blocking" to false,
                "message" to "VPN connection active"))
        }

        result.success(mapOf(
            "isSecure" to threats.none { it["blocking"] == true },
            "threats" to threats,
            "timestamp" to System.currentTimeMillis()
        ))
    }

    // ==================== PROXY DETECTION (Production-Grade Multi-Layer) ====================

    /**
     * Check if HTTP proxy is configured on the device
     * Uses multiple detection methods for maximum reliability:
     * 1. Android Proxy API (recommended method)
     * 2. LinkProperties proxy check
     * 3. Global/Secure settings check
     * 4. System properties check
     * 5. Java system properties check
     */
    /**
     * Check if HTTP proxy is ACTIVELY configured on the device.
     *
     * This only checks for active system-level proxy settings.
     * Having a proxy app installed but not actively used will NOT trigger this.
     *
     * Use isProxyOrMitmToolsInstalled() to check for installed proxy/MITM apps.
     */
    fun isProxyEnabled(): Boolean {
        // Only check for ACTIVE system proxy, not just installed apps
        if (checkProxySelectorApi()) {
            Log.d(TAG, "PROXY: Active proxy detected via ProxySelector API")
            return true
        }
        if (checkAndroidProxyApi()) {
            Log.d(TAG, "PROXY: Active proxy detected via Android Proxy API")
            return true
        }
        if (checkLinkPropertiesProxy()) {
            Log.d(TAG, "PROXY: Active proxy detected via LinkProperties")
            return true
        }
        if (checkSettingsProxy()) {
            Log.d(TAG, "PROXY: Active proxy detected via Settings")
            return true
        }
        if (checkJavaSystemProxy()) {
            Log.d(TAG, "PROXY: Active proxy detected via Java System Properties")
            return true
        }
        if (checkSystemPropertiesProxy()) {
            Log.d(TAG, "PROXY: Active proxy detected via Android System Properties")
            return true
        }
        // NOTE: App installation checks are REMOVED from isProxyEnabled()
        // Just having an app installed doesn't mean proxy is active
        Log.d(TAG, "PROXY: No active proxy detected")
        return false
    }

    /**
     * Check if proxy apps or MITM tools are INSTALLED (not necessarily active).
     * This is a separate, optional check for additional security awareness.
     */
    fun isProxyOrMitmToolsInstalled(): Boolean {
        return checkProxyAppsInstalled() || checkMitmToolsInstalled()
    }

    /**
     * Check if known proxy apps are installed
     * These apps can intercept and modify network traffic
     */
    private fun checkProxyAppsInstalled(): Boolean {
        val proxyApps = listOf(
            // Proxy Apps
            "org.proxydroid",                    // ProxyDroid
            "com.drony",                         // Drony
            "com.v2cross.proxy",                 // V2Cross
            "com.github.nicknux.ssproxy",        // SS Proxy
            "com.evozi.injector",                // HTTP Injector
            "com.evozi.injector.lite",           // HTTP Injector Lite
            "com.napsternetv.napsternetv",       // NapsternetV
            "com.andyberry.tunnel",              // Psiphon
            "ca.psiphon.psibot",                 // Psiphon Pro
            "com.lantern.android",               // Lantern
            "io.lantern.android",                // Lantern (alt)
            "net.openvpn.openvpn",               // OpenVPN (often used with proxy)
            "de.blinkt.openvpn",                 // OpenVPN for Android
            "com.proxifier.android",             // Proxifier
            "com.socks.proxy",                   // SOCKS Proxy
            "com.socksproxy",                    // Socks Proxy
            "com.wangyihui.seproxy",             // SE Proxy
            "com.reqable.android",               // Reqable (MITM proxy)

            // Proxy Browser Apps (use VPN tunneling but for proxy purposes)
            "com.scheler.superproxy",            // Super Proxy
            "proxy.browser.unblock.sites.proxybrowser.unblocksites", // Proxy Browser
            "com.jrzheng.supervpnfree",          // SuperVPN Free
            "com.free.vpn.super.hotspot.open",   // Super VPN
            "com.vpnify",                        // VPNify
            "com.vpn.free.hotspot.secure.shield", // VPN Hotspot
            "free.vpn.unblock.proxy.turbovpn",   // Turbo VPN
            "com.fast.free.unblock.secure.vpn",  // Fast VPN
            "hotspotshield.android.vpn",         // Hotspot Shield
            "com.ultrareach.android",            // Ultrasurf
            "com.cloudflare.onedotonedotonedotone", // Cloudflare 1.1.1.1
            "org.torproject.android",            // Tor Browser
            "org.torproject.torbrowser",         // Tor Browser (alt)
        )

        // Debug: Log which app is found
        for (pkg in proxyApps) {
            if (isPackageInstalled(pkg)) {
                Log.d(TAG, "PROXY_DEBUG: Found proxy app: $pkg")
                return true
            }
        }
        return false
    }

    /**
     * Check if known MITM/debugging tools are installed
     * These are used for traffic interception and API analysis
     */
    private fun checkMitmToolsInstalled(): Boolean {
        val mitmTools = listOf(
            // Burp Suite / PortSwigger
            "com.portswigger.burp.proxy",
            "portswigger.burp",

            // Charles Proxy
            "com.xk72.charles",
            "com.charlesproxy.charles",

            // Fiddler
            "com.telerik.fiddler",

            // mitmproxy
            "com.mitmproxy.android",

            // Packet Capture / SSL Capture
            "app.greyshirts.sslcapture",         // SSL Capture
            "jp.co.taosoftware.android.packetcapture", // Packet Capture
            "com.emanuelef.remote_capture",      // PCAPdroid
            "com.minhui.networkcapture",         // Network Capture
            "com.guoshi.httpcanary",             // HttpCanary
            "com.egorovandreyrm.pcapremote",     // PCAP Remote

            // HTTP/Network Debugging
            "com.minhui.wificapture",            // WiFi Capture
            "io.anyline.app.networkmonitor",    // Network Monitor
            "com.httpwatch.httpwatch",           // HTTPWatch
            "com.nettool.debug",                 // Network Debug
            "com.http.toolkit",                  // HTTP Toolkit
            "tech.httptoolkit.android.v1",       // HTTP Toolkit

            // Security Testing / Pentesting
            "com.zimperium.zips",                // zIPS (but legitimate)
            "de.robv.android.xposed.installer",  // Xposed (already in hooking)
            "org.lsposed.manager",               // LSPosed (already in hooking)

            // Certificate manipulation
            "com.nianticlabs.pokemongo. Pokemon", // Root checker apps
            "eu.chainfire.cf.stickmount",        // Mount tools
        )

        return mitmTools.any { isPackageInstalled(it) }
    }

    /**
     * MOST RELIABLE METHOD - Uses Java ProxySelector API
     * This detects ANY system-configured proxy regardless of how it was set
     */
    private fun checkProxySelectorApi(): Boolean {
        return try {
            val selector = ProxySelector.getDefault() ?: return false

            // Test with common URLs to see if any proxy is configured
            val testUrls = listOf(
                "http://www.google.com",
                "https://www.google.com",
                "http://connectivitycheck.gstatic.com"
            )

            for (urlStr in testUrls) {
                val uri = URI(urlStr)
                val proxies = selector.select(uri)

                for (proxy in proxies) {
                    if (proxy.type() != Proxy.Type.DIRECT) {
                        val address = proxy.address()
                        if (address is InetSocketAddress) {
                            val host = address.hostString
                            val port = address.port
                            if (!host.isNullOrEmpty() && port > 0) {
                                return true
                            }
                        }
                        // Even if we can't get address, non-DIRECT means proxy exists
                        if (proxy.type() == Proxy.Type.HTTP || proxy.type() == Proxy.Type.SOCKS) {
                            return true
                        }
                    }
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Most reliable method - Uses Android's Proxy class
     * This detects proxy set in WiFi settings
     */
    private fun checkAndroidProxyApi(): Boolean {
        return try {
            // This is the most reliable way to check for proxy on Android
            val proxyHost = android.net.Proxy.getDefaultHost()
            val proxyPort = android.net.Proxy.getDefaultPort()

            if (!proxyHost.isNullOrEmpty() && proxyPort > 0) {
                return true
            }

            // Also check deprecated method for older compatibility
            @Suppress("DEPRECATION")
            val legacyHost = android.net.Proxy.getHost(context)
            @Suppress("DEPRECATION")
            val legacyPort = android.net.Proxy.getPort(context)

            !legacyHost.isNullOrEmpty() && legacyPort > 0
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check proxy via LinkProperties (Android 5.0+)
     */
    private fun checkLinkPropertiesProxy(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) return false

        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return false

            // Check active network
            val activeNetwork = cm.activeNetwork
            if (activeNetwork != null) {
                val linkProps = cm.getLinkProperties(activeNetwork)
                val proxyInfo = linkProps?.httpProxy
                if (proxyInfo != null) {
                    val host = proxyInfo.host
                    val port = proxyInfo.port
                    if (!host.isNullOrEmpty() && port > 0) {
                        return true
                    }
                }
            }

            // Check all networks for proxy
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cm.allNetworks.forEach { network ->
                    val linkProps = cm.getLinkProperties(network)
                    val proxyInfo = linkProps?.httpProxy
                    if (proxyInfo != null) {
                        val host = proxyInfo.host
                        val port = proxyInfo.port
                        if (!host.isNullOrEmpty() && port > 0) {
                            return true
                        }
                    }
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check proxy in system settings (Global and Secure)
     */
    private fun checkSettingsProxy(): Boolean {
        return try {
            // Check Global HTTP_PROXY
            val globalProxy = Settings.Global.getString(
                context.contentResolver,
                Settings.Global.HTTP_PROXY
            )
            if (!globalProxy.isNullOrEmpty() && globalProxy != ":0" && globalProxy.contains(":")) {
                val parts = globalProxy.split(":")
                if (parts.size >= 2 && parts[0].isNotEmpty() && parts[1].toIntOrNull() ?: 0 > 0) {
                    return true
                }
            }

            // Check Secure settings for proxy
            val secureProxy = Settings.Secure.getString(
                context.contentResolver,
                "http_proxy"
            )
            if (!secureProxy.isNullOrEmpty() && secureProxy != ":0" && secureProxy.contains(":")) {
                val parts = secureProxy.split(":")
                if (parts.size >= 2 && parts[0].isNotEmpty() && parts[1].toIntOrNull() ?: 0 > 0) {
                    return true
                }
            }

            // Check for proxy exclusion list (indicates proxy is configured)
            val exclusionList = Settings.Global.getString(
                context.contentResolver,
                "global_http_proxy_exclusion_list"
            )
            if (!exclusionList.isNullOrEmpty()) {
                // If there's an exclusion list, a proxy is likely configured
                val proxyHost = Settings.Global.getString(
                    context.contentResolver,
                    "global_http_proxy_host"
                )
                if (!proxyHost.isNullOrEmpty()) {
                    return true
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check Java system properties for proxy
     */
    private fun checkJavaSystemProxy(): Boolean {
        return try {
            val httpHost = System.getProperty("http.proxyHost")
            val httpPort = System.getProperty("http.proxyPort")
            if (!httpHost.isNullOrEmpty() && !httpPort.isNullOrEmpty()) {
                return true
            }

            val httpsHost = System.getProperty("https.proxyHost")
            val httpsPort = System.getProperty("https.proxyPort")
            if (!httpsHost.isNullOrEmpty() && !httpsPort.isNullOrEmpty()) {
                return true
            }

            val socksHost = System.getProperty("socksProxyHost")
            val socksPort = System.getProperty("socksProxyPort")
            if (!socksHost.isNullOrEmpty() && !socksPort.isNullOrEmpty()) {
                return true
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check Android system properties via getprop
     */
    private fun checkSystemPropertiesProxy(): Boolean {
        return try {
            val proxyProperties = listOf(
                "net.gprs.http-proxy",
                "net.proxy.host",
                "net.proxy.port",
                "wifi.http_proxy.host",
                "wifi.http_proxy.port"
            )

            proxyProperties.forEach { prop ->
                val process = Runtime.getRuntime().exec(arrayOf("getprop", prop))
                val reader = BufferedReader(InputStreamReader(process.inputStream))
                val value = reader.readLine()?.trim()
                reader.close()
                process.waitFor()

                if (!value.isNullOrEmpty() && value != "0" && value != ":0") {
                    return true
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    // ==================== VPN DETECTION (Production-Grade Multi-Layer) ====================

    /**
     * Check if VPN connection is active
     * Uses multiple detection methods for reliability:
     * 1. Network capabilities API (Android 6.0+)
     * 2. Network interface enumeration (tun/tap/ppp)
     * 3. /proc/net/route analysis
     * 4. ConnectivityManager network iteration
     */
    fun isVpnActive(): Boolean {
        return checkVpnNetworkCapabilitiesReliable() ||
               checkVpnNetworkInterfacesReliable() ||
               checkVpnRouteTable() ||
               checkVpnAllNetworks()
    }

    /**
     * Most reliable method for Android 6.0+
     * Checks if active network or any network uses VPN transport
     */
    private fun checkVpnNetworkCapabilitiesReliable(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false

        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return false

            // Check active network first
            val activeNetwork = cm.activeNetwork
            if (activeNetwork != null) {
                val caps = cm.getNetworkCapabilities(activeNetwork)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    return true
                }
            }

            // Check all registered networks
            cm.allNetworks.forEach { network ->
                val caps = cm.getNetworkCapabilities(network)
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                    return true
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Check network interfaces for VPN tunnels
     * Works on all Android versions
     */
    private fun checkVpnNetworkInterfacesReliable(): Boolean {
        return try {
            val vpnInterfacePrefixes = listOf(
                "tun",    // TUN interface (most common)
                "tap",    // TAP interface
                "ppp",    // PPP interface (PPTP, L2TP)
                "pptp",   // PPTP specific
                "l2tp",   // L2TP specific
                "ipsec",  // IPSec VPN
                "utun"    // macOS/iOS style (rare on Android)
                // NOTE: rmnet_data and ccmni are standard mobile data interfaces
                // on Qualcomm and MediaTek chipsets respectively - NOT VPN interfaces
            )

            NetworkInterface.getNetworkInterfaces()?.toList()?.forEach { networkInterface ->
                val name = networkInterface.name?.lowercase() ?: return@forEach
                val isUp = networkInterface.isUp
                val hasAddresses = networkInterface.inetAddresses.hasMoreElements()

                vpnInterfacePrefixes.forEach { prefix ->
                    if (name.startsWith(prefix) && isUp && hasAddresses) {
                        return true
                    }
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Parse /proc/net/route for VPN routing entries
     * Very reliable low-level check
     */
    private fun checkVpnRouteTable(): Boolean {
        return try {
            val routeFile = File("/proc/net/route")
            if (!routeFile.exists() || !routeFile.canRead()) return false

            val vpnInterfaces = listOf("tun", "tap", "ppp", "ipsec")

            BufferedReader(FileReader(routeFile)).use { reader ->
                reader.lineSequence().drop(1).forEach { line ->
                    val parts = line.split("\\s+".toRegex())
                    if (parts.isNotEmpty()) {
                        val iface = parts[0].lowercase()
                        vpnInterfaces.forEach { vpnIface ->
                            if (iface.startsWith(vpnIface)) {
                                return true
                            }
                        }
                    }
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Iterate all networks and check for VPN type
     * Fallback for older Android versions
     */
    @Suppress("DEPRECATION")
    private fun checkVpnAllNetworks(): Boolean {
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return false

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                cm.allNetworks.forEach { network ->
                    val networkInfo = cm.getNetworkInfo(network)
                    if (networkInfo?.type == ConnectivityManager.TYPE_VPN &&
                        networkInfo.isConnectedOrConnecting) {
                        return true
                    }
                }
            } else {
                val vpnInfo = cm.getNetworkInfo(ConnectivityManager.TYPE_VPN)
                if (vpnInfo?.isConnectedOrConnecting == true) {
                    return true
                }
            }

            false
        } catch (_: Exception) {
            false
        }
    }

    // ==================== NATIVE METHODS ====================

    private external fun nativeIsRooted(): Boolean
    private external fun nativeIsEmulator(): Boolean
    private external fun nativeIsDebuggerAttached(): Boolean
    private external fun nativeIsHooked(): Boolean

    private inline fun nativeCheck(check: () -> Boolean): Boolean {
        return if (nativeLibLoaded) {
            try { check() } catch (_: Exception) { false }
        } else false
    }
}
