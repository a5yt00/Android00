// Script: crypto_interceptor.js
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
