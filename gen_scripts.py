import os
from pathlib import Path

out_dir = Path("androidaudit/modules/dynamic/scripts")
out_dir.mkdir(parents=True, exist_ok=True)

scripts = {
    "ssl_pinning_bypass.js": """// Script: ssl_pinning_bypass.js
// Target: All SSL pinning implementations on Android
// Bypasses: OkHttp3, TrustManager, Conscrypt, WebViewClient

Java.perform(function () {
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
            send("[SSL-BYPASS] OkHttp3 CertificatePinner bypassed for: " + hostname);
            return;
        };
    } catch(e) { send("[SSL-BYPASS] OkHttp3 not found: " + e); }

    try {
        var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            send("[SSL-BYPASS] Conscrypt TrustManagerImpl bypassed for: " + host);
            return untrustedChain;
        };
    } catch (e) { send("[SSL-BYPASS] Conscrypt TrustManagerImpl not found: " + e); }
});
""",
    "root_detection_bypass.js": """// Script: root_detection_bypass.js
// Target: Common root detection libraries
// Bypasses: RootBeer, Su binaries checks

Java.perform(function () {
    try {
        var File = Java.use("java.io.File");
        var suPaths = ["/system/app/Superuser.apk", "/sbin/su", "/system/bin/su", "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su"];
        File.exists.implementation = function () {
            var name = this.getAbsolutePath();
            if (suPaths.indexOf(name) !== -1) {
                send("[ROOT-BYPASS] Faking non-existence for root binary: " + name);
                return false;
            }
            return this.exists();
        };
    } catch (e) { send("[ROOT-BYPASS] Error hooking java.io.File: " + e); }
});
""",
    "biometric_bypass.js": """// Script: biometric_bypass.js
// Target: Android BiometricPrompt
// Bypasses: Fingerprint checks returning success

Java.perform(function () {
    try {
        var BiometricPrompt = Java.use("android.hardware.biometrics.BiometricPrompt");
        BiometricPrompt.authenticate.overload('android.os.CancellationSignal', 'java.util.concurrent.Executor', 'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function (cancel, executor, callback) {
            send("[BIO-BYPASS] Bypassing BiometricPrompt.authenticate()");
            callback.onAuthenticationSucceeded(null);
        };
    } catch (e) { send("[BIO-BYPASS] Error hooking BiometricPrompt: " + e); }
});
""",
    "method_tracer.js": """// Script: method_tracer.js
// Target: Application methods
// Bypasses: N/A - Diagnostic trace

Java.perform(function () {
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        StringBuilder.toString.implementation = function () {
            var result = this.toString();
            send("[TRACE] StringBuilder: " + result);
            return result;
        };
    } catch(e) { send("[TRACE] Error hooking StringBuilder: " + e); }
});
""",
    "crypto_interceptor.js": """// Script: crypto_interceptor.js
// Target: javax.crypto classes
// Bypasses: N/A - Intercepts Keys and IVs

Java.perform(function () {
    try {
        var Cypher = Java.use("javax.crypto.Cipher");
        Cypher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
            send("[CRYPTO] Cipher.init called with spec key");
            this.init(opmode, key, params);
        };
    } catch (e) { send("[CRYPTO] Error hooking Cipher: " + e); }
});
""",
    "intent_monitor.js": """// Script: intent_monitor.js
// Target: Intents
// Bypasses: N/A - logs activities starting

Java.perform(function () {
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload('android.content.Intent').implementation = function (intent) {
            send("[INTENT] Activity starting: " + intent.toString());
            this.startActivity(intent);
        };
    } catch (e) { send("[INTENT] Error hooking Activity: " + e); }
});
"""
}

for name, body in scripts.items():
    (out_dir / name).write_text(body, encoding="utf-8")

print("Frida JS scripts created successfully.")
