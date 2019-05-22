# dal-keystore
1. Introduction:
----------------
	dal-keystore includes Intel DAL keystore solution's user space library, keystore applet binary and the tool to install the binary.
	1.1 keystore_applet: the keystore applet binary
	1.2 keystore_lib: APIs for keystore application
	1.3 keystore_daemon : the tool to install keystore binary

2. Prerequisites:
-----------------
	2.1. dal keystore driver
		"CONFIG_KEYSTORE" and "CONFIG_INTEL_MEI_DAL" needs to be configured as either "m" or "y" in kernel config file.
	2.2. User/OEM has obtained a DAL Security Domain package from Intel, please contact Intel platform AE for the request.
	2.3. DAL JHI package is installed on the platform
		run "ps -aux | grep jhi" to check if "jhid" is available. 
	2.4  libxml2 library is available
		cd /lib64; ls -l libxml2*

3. How to Build and Install: 
---------------------------------------
	3.1 Clone the source code:
		git clone https://github.com/dal-keystore/dal-keystore.git
	3.2 Build and install from source code:
		cd dal-keystore; make; sudo make install 
	3.2 Below Binaries and header file will be installed by any above option.
		a. /usr/sbin/ksutil : test utility
		b. /lib64/libias-security-keystore_lib_static.a : keystore library
		c. /usr/include/IasKeystoreLib.hpp : header file of keystore library
		d. /usr/sbin/dal_ks_initd : daemon to install keystore applet
		e. /usr/lib/dal/applets/Keystore.dalp : keystore applet

4. Installing the Security Domain(SD):
-------------------------------------
	4.1. if the Security Domain is named as 'OEM-SD.acp', it can be installed on the platform
	by executing the following command.
		/usr/sbin/DAL-Tool installSD -sd OEM-SD.acp


5. Preparing the DAL keystore applet file:
-----------------------------------------
	5.1. Use prebuilt Keystore.dalp installed in "/usr/lib/dal/applets/Keystore.dalp" 


6. Signing the applet by OEM keys:
----------------------------------
	It is assumed that, as an example, OEM SD has an ID equals to 'faa5db69eb0545f0ad48079b456986ea'
	6.1 execute the following command to attach the OEM signature to the applet, use the 
	private key and public key generated for SD request(2.2), change their names as below.
	(assuming all inputs are in "/usr/lib/dal/applets/)
		./DAL-OEM-Signer sign Keystore.dalp private-key.pem public-key.pem faa5db69eb0545f0ad48079b456986ea

		private-key.pem ---- (input)OEM RSA private 2048-bit key in pem format.
		public-key.pem  ---- (input)OEM RSA public 2048-bit key in pem format.
		faa5db69eb0545f0ad48079b456986ea ---- (input)OEM SD ID

6.2 Now Keystore.dalp is attached with OEM signature. Don't forget to copy signed applet to "/usr/lib/dal/applets/",
if signing is not performed in this folder.


7. Install Keystore.dalp to production platform:
-----------------------------------------------
	7.1 Go to "test/install" and run:
		./dal_ks_initd.sh dal_ks_initd.conf
		Notes: the "SD UUID" in "dal_ks_initd.sh" needs to be replaced with the ID of SD installed on the platform


8. Testing: 
----------
	8.1 chmod +x /usr/sbin/ksutil
	8.2 run "ksutil test" for basic APIs verification
	8.3 test cases in "test" folder(optional)
		a. ksutil-wrap.sh - Wrap a 256-bit random key.
		b. ksutil-encrypt.sh - Use the wrapped key to encrypt/decrypt a plain text.   
		c. ksutil-encrypt2.sh - Load the wrapped key by another application
