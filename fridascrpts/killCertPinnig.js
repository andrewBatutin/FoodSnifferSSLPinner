/*
	****************************************
	 killCertPinnig.js Frida script
	 by Andrew Batutin
	 based on
	 killSSL.js (Dima Kovalenko)
	****************************************
	
	Usage:

		0. Use 
			$ frida-trace -R -f re.frida.Gadget -s "*validateTrust*"
			to get the correct function name for ValidateTrustCertificateList_prt variable (line 29)
		
		1. Run FoodSniffer on the simulator
		
		2. Inject the script to the process:
			$ frida -R -f re.frida.Gadget -l ./killCertPinnig.js
		
		3. SSL pinning in disabled
*/


// Are we debugging it?
DEBUG = true;

function main() {
	
	var ValidateTrustCertificateList_prt = Module.findExportByName(null, "_T016FoodSnifferFrida0A15ListAPIConsumerC024validateTrustCertificateD0SbSo03SecG0CF");
	if (ValidateTrustCertificateList_prt == null) {
		console.log("[!] FoodSniffer!validateTrustCertificateList(...) not found!");
		return;
	}

	var ValidateTrustCertificateList = new NativeFunction(ValidateTrustCertificateList_prt, "int", ["pointer"]);

	Interceptor.replace(ValidateTrustCertificateList_prt, new NativeCallback(function(trust) {
		
		if (DEBUG) console.log("[*] ValidateTrustCertificateList(...) hit!");
		return 1;

	}, "int", ["pointer"]));
	console.log("[*] ValidateTrustCertificateList(...) hooked. SSL pinnig is disabled.");	

}

// Run the script
main();