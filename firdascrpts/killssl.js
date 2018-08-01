/*
	****************************************
	 killSSL.js Frida script
	 by Dima Kovalenko
	****************************************
	
	Usage:
		
		1. Run Viber on the device
		
		2. Inject the script to the process:
			$ frida -U -n Viber  -l path/to/killSSL.js
		
		3. SSL pinning in Viber HTTPs is
		   disabled. Now you can intercept
		   Viber HTTPs requests, e.g. with
		   mitmproxy.
*/


// Are we debugging it?
DEBUG = true;

function main() {
		
	// Get SecTrustEvaluate address
	var SecTrustEvaluate_prt = Module.findExportByName("Security", "SecTrustEvaluate");
	if (SecTrustEvaluate_prt == null) {
		console.log("[!] Security!SecTrustEvaluate(...) not found!");
		return;
	}
		
	// Create native function wrappers for SecTrustEvaluate
	var SecTrustEvaluate = new NativeFunction(SecTrustEvaluate_prt, "int", ["pointer", "pointer"]);
	
	// Hook SecTrustEvaluate
	Interceptor.replace(SecTrustEvaluate_prt, new NativeCallback(function(trust, result) {
		// Show "hit!" message if we are in debugging mode
		if (DEBUG) console.log("[*] SecTrustEvaluate(...) hit!");
		// Call original function
		var osstatus = SecTrustEvaluate(trust, result);
		// Change the result to kSecTrustResultProceed
		Memory.writeU8(result, 1);
		// Return errSecSuccess
		return 0;
	}, "int", ["pointer", "pointer"]));
	// It's done!
	console.log("[*] SecTrustEvaluate(...) hooked. SSL should be pinning disabled.");	
}

// Run the script
main();