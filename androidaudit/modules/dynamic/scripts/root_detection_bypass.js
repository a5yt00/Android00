// Script: root_detection_bypass.js
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
