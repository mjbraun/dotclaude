// ABOUTME: Frida script to enumerate Java classes matching a pattern
// ABOUTME: Used to discover SSL pinning implementations

Java.perform(function() {
    var Log = Java.use("android.util.Log");

    function log(msg) {
        Log.d("FridaEnum", msg);
    }

    log("[*] Starting class enumeration...");

    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            // Look for SSL-related classes
            var lower = className.toLowerCase();
            if (lower.indexOf("sslguard") !== -1 ||
                lower.indexOf("pinning") !== -1 ||
                lower.indexOf("certificate") !== -1 ||
                lower.indexOf("trustmanager") !== -1 ||
                lower.indexOf("okhttp") !== -1) {
                log("[CLASS] " + className);
            }
        },
        onComplete: function() {
            log("[*] Class enumeration complete");
        }
    });
});
