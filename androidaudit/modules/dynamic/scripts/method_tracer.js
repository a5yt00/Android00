// Script: method_tracer.js
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
