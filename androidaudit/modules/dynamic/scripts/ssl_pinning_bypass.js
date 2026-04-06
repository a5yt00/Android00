// Script: ssl_pinning_bypass.js
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
