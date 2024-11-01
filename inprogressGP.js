Java.perform(function() {
    // Spoof Android Build properties to mimic a Pixel 9 device
    var Build = Java.use("android.os.Build");

    // Device properties commonly checked by applications
    Build.DEVICE.value = "pixel9";             // Realistic, friendly device code name
    Build.MODEL.value = "Pixel 9";             // Model name of the device
    Build.PRODUCT.value = "pixel9";            // Product name that matches the model
    Build.BRAND.value = "google";              // Brand of the device
    Build.MANUFACTURER.value = "Google";       // Manufacturer name
    Build.FINGERPRINT.value = "google/pixel9/pixel9:14.0/UPB2.240305.014/7894561:user/release-keys";
    Build.HARDWARE.value = "pixel9";           // Hardware name set to match the device model
    Build.SERIAL.value = "XYZ12345ABC67890";   // Example serial number

    console.log("[*] Device properties spoofed to mimic Pixel 9.");

    // Hook into SafetyNetClient and modify the attest response
    try {
        var SafetyNetClient = Java.use("com.google.android.gms.safetynet.SafetyNetClient");

        // Intercept the `attest` method to return a spoofed result
        SafetyNetClient.attest.implementation = function (nonce, apiKey) {
            console.log("[*] Intercepting SafetyNet attest call");

            var originalResponse = this.attest(nonce, apiKey);
            return originalResponse.then(function (response) {
                var responseObj = Java.cast(response, Java.use("com.google.android.gms.safetynet.SafetyNetApi$AttestationResponse"));
                
                // Modify the JWS result to return a 'pass' status
                responseObj.getJwsResult.overload().implementation = function() {
                    console.log("[*] Returning spoofed SafetyNet response");

                    // Example of a spoofed JWS payload; this token should indicate a passing SafetyNet status
                    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiAiU2FmZXR5TmV0IiwgInBhc3NlZCI6IHRydWV9";
                };
                return response;
            });
        };
    } catch (err) {
        console.log("Error spoofing SafetyNet attest response: " + err);
    }

    console.log("[*] Frida script executed: Device properties and SafetyNet attestation spoofed.");
});