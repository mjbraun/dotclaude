// ABOUTME: Comprehensive SSL bypass including CertPathValidator
// ABOUTME: Hooks all known certificate validation paths

Java.perform(function() {
    var Log = Java.use("android.util.Log");

    function log(msg) {
        Log.d("FridaSSL", msg);
        console.log(msg);
    }

    log("[*] Full SSL Bypass loading...");

    function tryGetClass(className) {
        try {
            return Java.use(className);
        } catch (e) {
            return null;
        }
    }

    // ===== CORE: TrustManager =====
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustAllManager = Java.registerClass({
        name: "com.frida.TrustAllManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {
                log("[+] TrustAllManager.checkClientTrusted");
            },
            checkServerTrusted: function(chain, authType) {
                log("[+] TrustAllManager.checkServerTrusted");
            },
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });

    // ===== SSLContext.init =====
    try {
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(km, tm, sr) {
            log("[+] SSLContext.init - injecting TrustAllManager");
            var trustAll = Java.array("javax.net.ssl.TrustManager", [TrustAllManager.$new()]);
            this.init(km, trustAll, sr);
        };
        log("[*] SSLContext.init hooked");
    } catch (e) {
        log("[-] SSLContext.init: " + e);
    }

    // ===== CertPathValidator - KEY FOR THIS APP =====
    try {
        var CertPathValidator = Java.use("java.security.cert.CertPathValidator");
        CertPathValidator.validate.overload("java.security.cert.CertPath", "java.security.cert.CertPathParameters").implementation = function(certPath, params) {
            log("[+] CertPathValidator.validate bypassed");
            // Return a valid result
            return null;
        };
        log("[*] CertPathValidator.validate hooked");
    } catch (e) {
        log("[-] CertPathValidator.validate: " + e);
    }

    // ===== TrustManagerImpl =====
    try {
        var TrustManagerImpl = tryGetClass("com.android.org.conscrypt.TrustManagerImpl");
        if (TrustManagerImpl) {
            try {
                TrustManagerImpl.verifyChain.overload(
                    "java.util.List", "java.util.List", "java.lang.String", "boolean", "[B", "[B"
                ).implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                    log("[+] TrustManagerImpl.verifyChain bypassed: " + host);
                    return untrustedChain;
                };
                log("[*] TrustManagerImpl.verifyChain (v1) hooked");
            } catch (e) {}

            try {
                TrustManagerImpl.checkTrustedRecursive.implementation = function() {
                    log("[+] TrustManagerImpl.checkTrustedRecursive bypassed");
                    return Java.use("java.util.ArrayList").$new();
                };
                log("[*] TrustManagerImpl.checkTrustedRecursive hooked");
            } catch (e) {}

            try {
                TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function(chain, authType) {
                    log("[+] TrustManagerImpl.checkServerTrusted bypassed");
                };
                log("[*] TrustManagerImpl.checkServerTrusted hooked");
            } catch (e) {}

            try {
                TrustManagerImpl.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String").implementation = function(chain, authType, host) {
                    log("[+] TrustManagerImpl.checkServerTrusted (host) bypassed: " + host);
                };
                log("[*] TrustManagerImpl.checkServerTrusted (host) hooked");
            } catch (e) {}
        }
    } catch (e) {}

    // ===== Conscrypt sockets =====
    try {
        var ConscryptFileDescriptorSocket = tryGetClass("com.android.org.conscrypt.ConscryptFileDescriptorSocket");
        if (ConscryptFileDescriptorSocket) {
            ConscryptFileDescriptorSocket.verifyCertificateChain.implementation = function(certChain, authMethod) {
                log("[+] ConscryptFileDescriptorSocket.verifyCertificateChain bypassed");
            };
            log("[*] ConscryptFileDescriptorSocket hooked");
        }
    } catch (e) {}

    try {
        var ConscryptEngineSocket = tryGetClass("com.android.org.conscrypt.ConscryptEngineSocket");
        if (ConscryptEngineSocket) {
            ConscryptEngineSocket.verifyCertificateChain.implementation = function(certChain, authMethod) {
                log("[+] ConscryptEngineSocket.verifyCertificateChain bypassed");
            };
            log("[*] ConscryptEngineSocket hooked");
        }
    } catch (e) {}

    // ===== Platform.checkServerTrusted =====
    try {
        var Platform = tryGetClass("com.android.org.conscrypt.Platform");
        if (Platform) {
            try {
                Platform.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.AbstractConscryptSocket").implementation = function(tm, chain, authType, socket) {
                    log("[+] Platform.checkServerTrusted (socket) bypassed");
                };
                log("[*] Platform.checkServerTrusted (socket) hooked");
            } catch (e) {}

            try {
                Platform.checkServerTrusted.overload("javax.net.ssl.X509TrustManager", "[Ljava.security.cert.X509Certificate;", "java.lang.String", "com.android.org.conscrypt.ConscryptEngine").implementation = function(tm, chain, authType, engine) {
                    log("[+] Platform.checkServerTrusted (engine) bypassed");
                };
                log("[*] Platform.checkServerTrusted (engine) hooked");
            } catch (e) {}
        }
    } catch (e) {}

    // ===== NetworkSecurityConfig =====
    // These methods return List<X509Certificate>, so we must return the chain
    try {
        var NetworkSecurityTrustManager = tryGetClass("android.security.net.config.NetworkSecurityTrustManager");
        if (NetworkSecurityTrustManager) {
            try {
                NetworkSecurityTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function(chain, authType) {
                    log("[+] NetworkSecurityTrustManager.checkServerTrusted bypassed");
                    // Return chain as List
                    var ArrayList = Java.use("java.util.ArrayList");
                    var list = ArrayList.$new();
                    for (var i = 0; i < chain.length; i++) {
                        list.add(chain[i]);
                    }
                    return list;
                };
            } catch (e) {}
            try {
                NetworkSecurityTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String").implementation = function(chain, authType, host) {
                    log("[+] NetworkSecurityTrustManager.checkServerTrusted (host) bypassed: " + host);
                    var ArrayList = Java.use("java.util.ArrayList");
                    var list = ArrayList.$new();
                    for (var i = 0; i < chain.length; i++) {
                        list.add(chain[i]);
                    }
                    return list;
                };
            } catch (e) {}
            log("[*] NetworkSecurityTrustManager hooked");
        }
    } catch (e) {}

    try {
        var RootTrustManager = tryGetClass("android.security.net.config.RootTrustManager");
        if (RootTrustManager) {
            try {
                RootTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function(chain, authType) {
                    log("[+] RootTrustManager.checkServerTrusted bypassed");
                    var ArrayList = Java.use("java.util.ArrayList");
                    var list = ArrayList.$new();
                    for (var i = 0; i < chain.length; i++) {
                        list.add(chain[i]);
                    }
                    return list;
                };
            } catch (e) {}
            try {
                RootTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String", "java.lang.String").implementation = function(chain, authType, host) {
                    log("[+] RootTrustManager.checkServerTrusted (host) bypassed: " + host);
                    var ArrayList = Java.use("java.util.ArrayList");
                    var list = ArrayList.$new();
                    for (var i = 0; i < chain.length; i++) {
                        list.add(chain[i]);
                    }
                    return list;
                };
            } catch (e) {}
            log("[*] RootTrustManager hooked");
        }
    } catch (e) {}

    // ===== OkHttp CertificatePinner =====
    try {
        var CertificatePinner = tryGetClass("okhttp3.CertificatePinner");
        if (CertificatePinner) {
            try {
                CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCerts) {
                    log("[+] CertificatePinner.check bypassed: " + hostname);
                };
                log("[*] CertificatePinner.check (List) hooked");
            } catch (e) {}
            try {
                CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, peerCerts) {
                    log("[+] CertificatePinner.check (array) bypassed: " + hostname);
                };
                log("[*] CertificatePinner.check (array) hooked");
            } catch (e) {}
            try {
                CertificatePinner["check$okhttp"].overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function(hostname, peerCerts) {
                    log("[+] CertificatePinner.check$okhttp bypassed: " + hostname);
                };
                log("[*] CertificatePinner.check$okhttp hooked");
            } catch (e) {}
        }
    } catch (e) {}

    // ===== OkHttp HostnameVerifier =====
    try {
        var OkHostnameVerifier = tryGetClass("okhttp3.internal.tls.OkHostnameVerifier");
        if (OkHostnameVerifier) {
            try {
                OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function(host, session) {
                    log("[+] OkHostnameVerifier.verify bypassed: " + host);
                    return true;
                };
            } catch (e) {}
            try {
                OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function(host, cert) {
                    log("[+] OkHostnameVerifier.verify (cert) bypassed: " + host);
                    return true;
                };
            } catch (e) {}
            log("[*] OkHostnameVerifier hooked");
        }
    } catch (e) {}

    // ===== OkHttpClient.Builder =====
    try {
        var OkHttpClientBuilder = tryGetClass("okhttp3.OkHttpClient$Builder");
        if (OkHttpClientBuilder) {
            try {
                OkHttpClientBuilder.certificatePinner.implementation = function(pinner) {
                    log("[+] OkHttpClient.Builder.certificatePinner bypassed");
                    return this;
                };
                log("[*] OkHttpClient.Builder.certificatePinner hooked");
            } catch (e) {}
        }
    } catch (e) {}

    // ===== Standard HostnameVerifier =====
    try {
        var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
        var AllHostsVerifier = Java.registerClass({
            name: "com.frida.AllHostsVerifier",
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    log("[+] AllHostsVerifier.verify: " + hostname);
                    return true;
                }
            }
        });

        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            log("[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
            this.setDefaultHostnameVerifier(AllHostsVerifier.$new());
        };
        HttpsURLConnection.setHostnameVerifier.implementation = function(verifier) {
            log("[+] HttpsURLConnection.setHostnameVerifier bypassed");
            this.setHostnameVerifier(AllHostsVerifier.$new());
        };
        log("[*] HttpsURLConnection HostnameVerifier hooked");
    } catch (e) {}

    // ===== Debug: Track network calls =====
    try {
        var OkHttpClient = tryGetClass("okhttp3.OkHttpClient");
        if (OkHttpClient) {
            OkHttpClient.newCall.implementation = function(request) {
                log("[>] OkHttpClient.newCall: " + request.url().toString());
                return this.newCall(request);
            };
            log("[*] OkHttpClient.newCall hooked");
        }
    } catch (e) {}

    // ===== Cronet (Google's network stack) =====
    // Cronet uses native code, but we can try to hook the Java interface
    try {
        var CronetEngine = tryGetClass("org.chromium.net.CronetEngine");
        if (CronetEngine) {
            log("[*] Cronet detected - attempting bypass");
        }
    } catch (e) {}

    // Hook CronetEngine.Builder to disable certificate verification
    try {
        var CronetEngineBuilder = tryGetClass("org.chromium.net.CronetEngine$Builder");
        if (CronetEngineBuilder) {
            try {
                CronetEngineBuilder.enablePublicKeyPinningBypassForLocalTrustAnchors.implementation = function(value) {
                    log("[+] CronetEngine.Builder.enablePublicKeyPinningBypassForLocalTrustAnchors(true)");
                    return this.enablePublicKeyPinningBypassForLocalTrustAnchors(true);
                };
                log("[*] CronetEngine.Builder.enablePublicKeyPinningBypassForLocalTrustAnchors hooked");
            } catch (e) {}
        }
    } catch (e) {}

    // Try to hook GMS Cronet
    try {
        var GmsCronetProviderInstaller = tryGetClass("com.google.android.gms.net.CronetProviderInstaller");
        if (GmsCronetProviderInstaller) {
            log("[*] GMS Cronet detected");
        }
    } catch (e) {}

    // Hook the native SSL verification callback if possible
    try {
        var X509Util = tryGetClass("org.chromium.net.X509Util");
        if (X509Util) {
            try {
                X509Util.verifyServerCertificates.implementation = function() {
                    log("[+] X509Util.verifyServerCertificates bypassed");
                    return Java.use("org.chromium.net.AndroidNetworkLibrary").VERIFY_OK.value;
                };
                log("[*] X509Util.verifyServerCertificates hooked");
            } catch (e) {
                log("[-] X509Util.verifyServerCertificates: " + e);
            }
        }
    } catch (e) {}

    // Hook AndroidNetworkLibrary for Cronet cert verification
    try {
        var AndroidNetworkLibrary = tryGetClass("org.chromium.net.AndroidNetworkLibrary");
        if (AndroidNetworkLibrary) {
            try {
                AndroidNetworkLibrary.verifyServerCertificates.implementation = function(certChain, authType, host) {
                    log("[+] AndroidNetworkLibrary.verifyServerCertificates bypassed: " + host);
                    // Return VERIFY_OK (0)
                    return Java.use("org.chromium.net.AndroidCertVerifyResult").$new(0, false, Java.array("java.lang.String", []));
                };
                log("[*] AndroidNetworkLibrary.verifyServerCertificates hooked");
            } catch (e) {
                log("[-] AndroidNetworkLibrary.verifyServerCertificates: " + e);
            }
        }
    } catch (e) {}

    // Alternative: Hook at BoringSSL level via JNI
    // This is complex and may require native hooks

    log("[*] Full SSL Bypass installed");
});
