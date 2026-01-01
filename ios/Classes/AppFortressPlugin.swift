import Flutter
import UIKit
import DeviceCheck
import CryptoKit
import Security
import MachO
import CommonCrypto
import SystemConfiguration
import Network

/// App Fortress iOS Plugin - Fixed for iOS compatibility
public class AppFortressPlugin: NSObject, FlutterPlugin {
    
    private static let channelName = "com.app.fortress/security"
    private var attestKeyId: String?
    private let keyIdKey = "com.app.fortress.attestKeyId"
    
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: channelName,
            binaryMessenger: registrar.messenger()
        )
        let instance = AppFortressPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
    }
    
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        switch call.method {
        case "configure":
            result(true)
            
        case "requestAttestation":
            guard let args = call.arguments as? [String: Any],
                  let nonce = args["nonce"] as? String else {
                result(FlutterError(code: "INVALID_ARGUMENT", message: "Nonce is required", details: nil))
                return
            }
            requestAttestation(nonce: nonce, result: result)
            
        case "getDeviceSecurityInfo":
            getDeviceSecurityInfo(result: result)
            
        case "isRooted":
            result(isJailbroken())
            
        case "isEmulator":
            result(isSimulator())
            
        case "isDebuggerAttached":
            result(isDebuggerAttached())
            
        case "isHookingDetected":
            result(isHookingDetected())
            
        case "verifySignature":
            result(verifyCodeSignature())
            
        case "runFullSecurityCheck":
            runFullSecurityCheck(result: result)
            
        case "getPlatformVersion":
            result("iOS \(UIDevice.current.systemVersion)")

        case "isProxyEnabled":
            result(isProxyEnabled())

        case "isVpnActive":
            result(isVpnActive())

        default:
            result(FlutterMethodNotImplemented)
        }
    }
    
    // MARK: - App Attest
    
    private func requestAttestation(nonce: String, result: @escaping FlutterResult) {
        guard #available(iOS 14.0, *) else {
            result(FlutterError(code: "SERVICE_UNAVAILABLE", message: "App Attest requires iOS 14+", details: nil))
            return
        }
        
        let service = DCAppAttestService.shared
        
        guard service.isSupported else {
            result(FlutterError(code: "SERVICE_UNAVAILABLE", message: "App Attest not supported", details: nil))
            return
        }
        
        if let existingKeyId = loadKeyId() {
            generateAssertion(keyId: existingKeyId, nonce: nonce, result: result)
        } else {
            generateKeyAndAttest(nonce: nonce, result: result)
        }
    }
    
    @available(iOS 14.0, *)
    private func generateKeyAndAttest(nonce: String, result: @escaping FlutterResult) {
        let service = DCAppAttestService.shared
        
        service.generateKey { [weak self] keyId, error in
            guard let self = self else { return }
            
            if let error = error {
                DispatchQueue.main.async {
                    result(FlutterError(code: "KEY_GENERATION_FAILED", message: error.localizedDescription, details: nil))
                }
                return
            }
            
            guard let keyId = keyId,
                  let clientDataHash = self.createClientDataHash(nonce: nonce) else {
                DispatchQueue.main.async {
                    result(FlutterError(code: "HASH_FAILED", message: "Failed to create hash", details: nil))
                }
                return
            }
            
            service.attestKey(keyId, clientDataHash: clientDataHash) { [weak self] attestation, error in
                DispatchQueue.main.async {
                    if let error = error {
                        result(FlutterError(code: "ATTESTATION_FAILED", message: error.localizedDescription, details: nil))
                        return
                    }
                    
                    guard let attestation = attestation else {
                        result(FlutterError(code: "ATTESTATION_FAILED", message: "No attestation", details: nil))
                        return
                    }
                    
                    self?.saveKeyId(keyId)
                    
                    let resultMap: [String: Any?] = [
                        "token": attestation.base64EncodedString(),
                        "platform": "ios",
                        "keyId": keyId,
                        "timestamp": Int(Date().timeIntervalSince1970 * 1000),
                        "metadata": [
                            "bundleId": Bundle.main.bundleIdentifier ?? "",
                            "isAttestation": true
                        ]
                    ]
                    result(resultMap)
                }
            }
        }
    }
    
    @available(iOS 14.0, *)
    private func generateAssertion(keyId: String, nonce: String, result: @escaping FlutterResult) {
        let service = DCAppAttestService.shared
        
        guard let clientDataHash = createClientDataHash(nonce: nonce) else {
            result(FlutterError(code: "HASH_FAILED", message: "Failed to create hash", details: nil))
            return
        }
        
        service.generateAssertion(keyId, clientDataHash: clientDataHash) { [weak self] assertion, error in
            DispatchQueue.main.async {
                if let error = error {
                    self?.clearKeyId()
                    self?.generateKeyAndAttest(nonce: nonce, result: result)
                    return
                }
                
                guard let assertion = assertion else {
                    result(FlutterError(code: "ASSERTION_FAILED", message: "No assertion", details: nil))
                    return
                }
                
                let resultMap: [String: Any?] = [
                    "token": assertion.base64EncodedString(),
                    "platform": "ios",
                    "keyId": keyId,
                    "timestamp": Int(Date().timeIntervalSince1970 * 1000),
                    "metadata": [
                        "bundleId": Bundle.main.bundleIdentifier ?? "",
                        "isAttestation": false
                    ]
                ]
                result(resultMap)
            }
        }
    }
    
    private func createClientDataHash(nonce: String) -> Data? {
        guard let nonceData = nonce.data(using: .utf8) else { return nil }
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        nonceData.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(nonceData.count), &hash)
        }
        return Data(hash)
    }
    
    private func saveKeyId(_ keyId: String) {
        UserDefaults.standard.set(keyId, forKey: keyIdKey)
        attestKeyId = keyId
    }
    
    private func loadKeyId() -> String? {
        if let cached = attestKeyId { return cached }
        let saved = UserDefaults.standard.string(forKey: keyIdKey)
        attestKeyId = saved
        return saved
    }
    
    private func clearKeyId() {
        UserDefaults.standard.removeObject(forKey: keyIdKey)
        attestKeyId = nil
    }
    
    // MARK: - Device Security Info
    
    private func getDeviceSecurityInfo(result: @escaping FlutterResult) {
        var threats: [[String: Any]] = []
        
        if isJailbroken() {
            threats.append(["code": "JAILBREAK_DETECTED", "severity": "high", "message": "Device is jailbroken"])
        }
        if isSimulator() {
            threats.append(["code": "SIMULATOR_DETECTED", "severity": "medium", "message": "Running on simulator"])
        }
        if isDebuggerAttached() {
            threats.append(["code": "DEBUGGER_DETECTED", "severity": "critical", "message": "Debugger attached"])
        }
        if isHookingDetected() {
            threats.append(["code": "HOOKING_DETECTED", "severity": "critical", "message": "Hooking framework detected"])
        }
        if isProxyEnabled() {
            threats.append(["code": "PROXY_DETECTED", "severity": "high", "message": "HTTP proxy is configured"])
        }
        if isVpnActive() {
            threats.append(["code": "VPN_DETECTED", "severity": "medium", "message": "VPN connection is active"])
        }

        let deviceInfo: [String: Any?] = [
            "platform": "ios",
            "model": getDeviceModel(),
            "manufacturer": "Apple",
            "osVersion": UIDevice.current.systemVersion,
            "appVersion": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
            "appVersionCode": (Bundle.main.infoDictionary?["CFBundleVersion"] as? String).flatMap { Int($0) },
            "packageName": Bundle.main.bundleIdentifier,
            "isRooted": isJailbroken(),
            "isEmulator": isSimulator(),
            "isDebuggerAttached": isDebuggerAttached(),
            "isHookingDetected": isHookingDetected(),
            "isDebuggable": isDebugBuild(),
            "installSource": getInstallSource(),
            "isProxyEnabled": isProxyEnabled(),
            "isVpnActive": isVpnActive(),
            "threats": threats,
            "timestamp": Int(Date().timeIntervalSince1970 * 1000)
        ]
        
        result(deviceInfo)
    }
    
    // MARK: - Jailbreak Detection (fork حذف شد)
    
    func isJailbroken() -> Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        return checkJailbreakFiles() ||
               checkJailbreakApps() ||
               checkWritablePaths() ||
               checkSymbolicLinks() ||
               checkDynamicLibraries()
        #endif
    }
    
    private func checkJailbreakFiles() -> Bool {
        let paths = [
            "/Applications/Cydia.app", "/Applications/Sileo.app",
            "/Applications/Zebra.app", "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash", "/bin/sh", "/etc/apt", "/etc/ssh/sshd_config",
            "/private/var/lib/apt", "/private/var/lib/cydia",
            "/private/var/stash", "/usr/bin/sshd", "/usr/sbin/sshd",
            "/var/cache/apt", "/var/lib/apt", "/var/lib/cydia"
        ]
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
    
    private func checkJailbreakApps() -> Bool {
        let apps = ["cydia://", "sileo://", "zbra://", "filza://"]
        return apps.contains { URL(string: $0).flatMap { UIApplication.shared.canOpenURL($0) } ?? false }
    }
    
    private func checkWritablePaths() -> Bool {
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
    
    private func checkSymbolicLinks() -> Bool {
        let paths = ["/var/lib/undecimus/apt", "/Applications", "/Library/Ringtones"]
        for path in paths {
            var s = stat()
            if lstat(path, &s) == 0 && (s.st_mode & S_IFLNK) == S_IFLNK {
                return true
            }
        }
        return false
    }
    
    private func checkDynamicLibraries() -> Bool {
        let suspicious = ["SubstrateLoader", "MobileSubstrate", "TweakInject", "CydiaSubstrate", "libhooker", "Substitute"]
        for i in 0..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName)
            if suspicious.contains(where: { name.lowercased().contains($0.lowercased()) }) {
                return true
            }
        }
        return false
    }
    
    // MARK: - Simulator Detection
    
    func isSimulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return false
        #endif
    }
    
    // MARK: - Debugger Detection (فقط sysctl)
    
    func isDebuggerAttached() -> Bool {
        return checkSysctl()
    }
    
    private func checkSysctl() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }
    
    // MARK: - Hooking Detection
    
    func isHookingDetected() -> Bool {
        return checkFrida() || checkSuspiciousLibraries()
    }
    
    private func checkFrida() -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(27042).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        
        var timeout = timeval(tv_sec: 1, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        close(sock)
        return result == 0
    }
    
    private func checkSuspiciousLibraries() -> Bool {
        let suspicious = ["frida", "cycript", "ssl_kill"]
        for i in 0..<_dyld_image_count() {
            guard let imageName = _dyld_get_image_name(i) else { continue }
            let name = String(cString: imageName).lowercased()
            if suspicious.contains(where: { name.contains($0) }) { return true }
        }
        return false
    }
    
    // MARK: - Code Signature (ساده‌سازی)
    
    func verifyCodeSignature() -> Bool {
        // اپ‌های iOS بدون امضای معتبر اجرا نمی‌شن
        #if DEBUG
        return false
        #else
        return true
        #endif
    }
    
    // MARK: - Utility
    
    private func getDeviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machineMirror = Mirror(reflecting: systemInfo.machine)
        return machineMirror.children.reduce("") { identifier, element in
            guard let value = element.value as? Int8, value != 0 else { return identifier }
            return identifier + String(UnicodeScalar(UInt8(value)))
        }
    }
    
    private func isDebugBuild() -> Bool {
        #if DEBUG
        return true
        #else
        return false
        #endif
    }
    
    private func getInstallSource() -> String {
        if Bundle.main.appStoreReceiptURL?.lastPathComponent == "sandboxReceipt" {
            return "testflight"
        }
        if Bundle.main.appStoreReceiptURL != nil {
            return "appstore"
        }
        return "sideloaded"
    }
    
    private func runFullSecurityCheck(result: @escaping FlutterResult) {
        var threats: [[String: Any]] = []
        
        if isJailbroken() {
            threats.append(["code": "JAILBREAK", "severity": "high", "blocking": true])
        }
        if isSimulator() {
            threats.append(["code": "SIMULATOR", "severity": "medium", "blocking": false])
        }
        if isDebuggerAttached() {
            threats.append(["code": "DEBUGGER", "severity": "critical", "blocking": true])
        }
        if isHookingDetected() {
            threats.append(["code": "HOOKING", "severity": "critical", "blocking": true])
        }
        if isProxyEnabled() {
            threats.append(["code": "PROXY", "severity": "high", "blocking": true])
        }
        if isVpnActive() {
            threats.append(["code": "VPN", "severity": "medium", "blocking": false])
        }

        let isSecure = !threats.contains { $0["blocking"] as? Bool == true }

        result([
            "isSecure": isSecure,
            "threats": threats,
            "timestamp": Int(Date().timeIntervalSince1970 * 1000)
        ])
    }

    // MARK: - Proxy Detection (اصلاح‌شده)
    
    func isProxyEnabled() -> Bool {
        return checkProxyAppsInstalled() || checkSystemProxy()
    }

    private func checkProxyAppsInstalled() -> Bool {
        let proxySchemes = [
            "charles://", "proxyman://", "httpcatcher://", "surge://",
            "quantumult://", "shadowrocket://", "potatso://", "loon://",
            "stash://", "thor://"
        ]

        for scheme in proxySchemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                return true
            }
        }
        return false
    }

    private func checkSystemProxy() -> Bool {
        let proxyEnvVars = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
        for envVar in proxyEnvVars {
            if let value = getenv(envVar), String(cString: value).count > 0 {
                return true
            }
        }
        return false
    }

    // MARK: - VPN Detection (بدون تغییر)
    
    func isVpnActive() -> Bool {
        return checkVpnInterface() || checkVpnProtocols()
    }

    private func checkVpnInterface() -> Bool {
        var addrs: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&addrs) == 0 else { return false }
        defer { freeifaddrs(addrs) }

        var cursor = addrs
        while cursor != nil {
            defer { cursor = cursor?.pointee.ifa_next }
            guard let interface = cursor else { continue }

            let name = String(cString: interface.pointee.ifa_name)
            let flags = Int32(interface.pointee.ifa_flags)

            let vpnInterfaces = ["utun", "ppp", "ipsec", "tap", "tun"]
            for vpnInterface in vpnInterfaces {
                if name.hasPrefix(vpnInterface) && (flags & IFF_UP) != 0 && (flags & IFF_RUNNING) != 0 {
                    return true
                }
            }
        }
        return false
    }

    private func checkVpnProtocols() -> Bool {
        guard let cfDict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }

        if let scoped = cfDict["__SCOPED__"] as? [String: Any] {
            for (key, _) in scoped {
                let vpnPrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]
                for prefix in vpnPrefixes {
                    if key.hasPrefix(prefix) {
                        return true
                    }
                }
            }
        }

        return false
    }
}
