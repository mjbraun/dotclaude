// ABOUTME: Frida agent for enumerating SSL-related classes on Android
// ABOUTME: Uses frida-java-bridge to access Java VM

import Java from "frida-java-bridge";
import { log } from "./logger.js";

log("[*] Agent loaded, waiting for Java...");

Java.performNow(() => {
    log("[*] Java.performNow executing");

    log("[*] Enumerating SSL-related classes...");

    Java.enumerateLoadedClasses({
        onMatch(className: string) {
            const lower = className.toLowerCase();
            if (lower.indexOf("sslguard") !== -1 ||
                lower.indexOf("pinning") !== -1 ||
                lower.indexOf("trustkit") !== -1 ||
                (lower.indexOf("ssl") !== -1 && lower.indexOf("certificate") !== -1) ||
                lower.indexOf("hmc") !== -1) {
                log(`[CLASS] ${className}`);
            }
        },
        onComplete() {
            log("[*] Class enumeration complete");
        }
    });
});
