import frida
import sys
import time

# Target process name
PROCESS_NAME = "RootBeer Sample"

# Frida script to enumerate and hook RootBeer methods
ENUM_AND_HOOK_SCRIPT = """
Java.perform(function() {
    console.log('Java environment active, starting enumeration and hooking');

    // Define RootBeer-related packages
    var rootbeerPrefix = 'com.scottyab.rootbeer';
    var classesHooked = 0;

    // Enumerate all loaded classes
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes(rootbeerPrefix)) {
                console.log('[+] Found class: ' + className);

                try {
                    var cls = Java.use(className);
                    var methods = cls.class.getDeclaredMethods();

                    methods.forEach(function(method) {
                        var methodName = method.getName();
                        console.log('[*] Found method: ' + className + '.' + methodName);

                        // Hook the method dynamically
                        if (cls[methodName]) {
                            cls[methodName].implementation = function() {
                                console.log('[*] ' + className + '.' + methodName + ' called, returning false');
                                return false;  // Override return value to bypass check
                            };
                            console.log('[+] Hooked: ' + className + '.' + methodName);
                            classesHooked++;
                        }
                    });
                } catch (e) {
                    console.error('Error accessing class ' + className + ': ' + e);
                }
            }
        },
        onComplete: function() {
            if (classesHooked > 0) {
                console.log('[+] Enumeration and hooking complete. Total hooks: ' + classesHooked);
            } else {
                console.log('[-] No methods found to hook.');
            }
        }
    });
});
"""

def on_message(message, data):
    """ Handle messages from Frida """
    if message['type'] == 'send':
        print(f"[LOG] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def attach_to_process():
    try:
        device = frida.get_usb_device(timeout=5)
        pid = device.get_process(PROCESS_NAME).pid
        session = device.attach(pid)
        print(f"[*] Attached to process '{PROCESS_NAME}' (PID: {pid})")

        # Create and load the Frida script
        script = session.create_script(ENUM_AND_HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()

        print("[*] Frida script loaded. Monitoring output...\n")
        
        # Keep the script running
        sys.stdin.read()

    except frida.ProcessNotFoundErro
