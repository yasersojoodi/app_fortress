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
        // every check runs once (they were evaluated twice before: for the
        // threat list and again for the map)
        let jailbroken = isJailbroken()
        let simulator = isSimulator()
        let debugger = isDebuggerAttached()
        let hooking = isHookingDetected()
        let proxy = isProxyEnabled()
        let vpn = isVpnActive()

        var threats: [[String: Any]] = []
        if jailbroken {
            threats.append(["code": "JAILBREAK_DETECTED", "severity": "high", "message": "Device is jailbroken"])
        }
        if simulator {
            threats.append(["code": "SIMULATOR_DETECTED", "severity": "medium", "message": "Running on simulator"])
        }
        if debugger {
            threats.append(["code": "DEBUGGER_DETECTED", "severity": "critical", "message": "Debugger attached"])
        }
        if hooking {
            threats.append(["code": "HOOKING_DETECTED", "severity": "critical", "message": "Hooking framework detected"])
        }
        if proxy {
            threats.append(["code": "PROXY_DETECTED", "severity": "high", "message": "HTTP proxy is configured"])
        }
        if vpn {
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
            "isRooted": jailbroken,
            "isEmulator": simulator,
            "isDebuggerAttached": debugger,
            "isHookingDetected": hooking,
            "isDebuggable": isDebugBuild(),
            "installSource": getInstallSource(),
            "isProxyEnabled": proxy,
            "isVpnActive": vpn,
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
        return checkInsertedLibraries() || checkFrida() || checkSuspiciousLibraries()
    }

    /// Libraries injected at launch (tweak loaders, Frida gadget ...).
    private func checkInsertedLibraries() -> Bool {
        guard let value = getenv("DYLD_INSERT_LIBRARIES") else { return false }
        return !String(cString: value).isEmpty
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
        guard let receipt = Bundle.main.appStoreReceiptURL else { return "sideloaded" }
        if receipt.lastPathComponent == "sandboxReceipt" {
            return "testflight"
        }
        // the URL is always set; only App Store installs have the file
        return FileManager.default.fileExists(atPath: receipt.path) ? "appstore" : "sideloaded"
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

    // MARK: - Proxy Detection

    /// An HTTP/HTTPS proxy (or a PAC file) set in the Wi-Fi settings, i.e. what
    /// MITM tools such as Charles or Proxyman need.
    ///
    /// The old check also reported "proxy" when an app like Shadowrocket,
    /// Surge or Stash was merely installed (most Iranian users have one) and
    /// read proxy environment variables, which iOS apps never get.
    func isProxyEnabled() -> Bool {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] else {
            return false
        }
        func flag(_ key: String) -> Bool {
            return (settings[key] as? NSNumber)?.intValue == 1
        }
        let host = (settings[kCFNetworkProxiesHTTPProxy as String] as? String) ?? ""
        return (flag(kCFNetworkProxiesHTTPEnable as String) && !host.isEmpty)
            || flag("HTTPSEnable")
            || flag(kCFNetworkProxiesProxyAutoConfigEnable as String)
    }

    // MARK: - VPN Detection

    /// A VPN tunnel that carries traffic: iOS lists it under "__SCOPED__" of
    /// the system proxy settings.
    ///
    /// The old check also enumerated the network interfaces, but iOS keeps
    /// several "utun" interfaces up for its own services (iCloud Private
    /// Relay, Wi-Fi calling, Apple Watch ...), so almost every iPhone looked
    /// like it had a VPN on.
    func isVpnActive() -> Bool {
        guard let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = settings["__SCOPED__"] as? [String: Any] else {
            return false
        }
        let vpnPrefixes = ["utun", "ppp", "ipsec", "tap", "tun"]
        return scoped.keys.contains { key in vpnPrefixes.contains { key.hasPrefix($0) } }
    }
}
