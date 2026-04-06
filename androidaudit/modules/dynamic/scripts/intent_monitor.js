// Script: intent_monitor.js
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
