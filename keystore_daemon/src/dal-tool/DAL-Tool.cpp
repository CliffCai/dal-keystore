#include <stdint.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <teemanagement.h>
#include <jhi.h>
#include <jhi_version.h>
#include <dbg.h>

using namespace std;
//using namespace intel_dal;
#define SD_ID_MAX_LEN  	64

#define CMD_INSTALLSD	1
#define CMD_INSTALLTA	2
#define CMD_UNINSTALLSD 3
#define CMD_LISTTA	4
#define CMD_INSTALLOMK	5
#define CMD_INSTALLDEK	6
#define CMD_LISTSD	7

static bool succinct = false;

int Install(const char *sdId, uint8_t* package, uint32_t packageSize);
int List(const char *sdId, uint32_t cmd = CMD_LISTTA);
int Provision(const char *sdId, uint8_t* keyBlob, uint32_t cmd);
void printErr(TEE_STATUS status, int no);
void printUUIDs(UUID_LIST& uuidList);

int parseArginstallSD(int argc, char* argv[], char **sd, char **id)
{
	int ind = 2;
	int ret = 0;
	while (ind < argc) {
		if (!strcmp(argv[ind], "-sd")) {
			*sd = argv[++ind];
		} else if (!strcmp(argv[ind], "-id")) {
			*id = argv[++ind];
		} else {
			cout << "invalid command option\n";
			return -1;
		}
		++ind;
	}
	if (!(*sd)) {
		cout << "invalid command options\n";
		ret = -1;
	}

	return ret;
}

int parseArginstallTA(int argc, char* argv[], char **ta, char **id)
{
	int ind = 2;
	int ret = 0;
	while (ind < argc) {
		if (!strcmp(argv[ind], "-ta")) {
			*ta = argv[++ind];
		} else if (!strcmp(argv[ind], "-id")) {
			*id = argv[++ind];
		} else {
			cout << "invalid command option\n";
			return -1;
		}
		++ind;
	}
	if (!(*ta)) {
		cout << "invalid command options\n";
		ret = -1;
	}

	return ret;
}

int parseArgListTA(int argc, char* argv[], char **id)
{
	int ind = 2;
	int ret = 0;
	while (ind < argc) {
		if (!strcmp(argv[ind], "-id")) {
			*id = argv[++ind];
		} else if (!strcmp(argv[ind], "-s")) {
			succinct = true;
		} else {
			cout << "invalid command option\n";
			return -1;
		}
		++ind;
	}

	return ret;
}

int parseArgListSD(int argc, char* argv[], char **id)
{
	int ind = 2;
	int ret = 0;
	while (ind < argc) {
		if (!strcmp(argv[ind], "-s")) {
			succinct = true;
		} else {
			cout << "invalid command option\n";
			return -1;
		}
		++ind;
	}

	return ret;
}

int parseArgInstallOMK(int argc, char* argv[], char **omk)
{
	int ind = 2;
	int ret = 0;
	while (ind < argc) {
		if (!strcmp(argv[ind], "-key")) {
			*omk = argv[++ind];
		} else {
			cout << "invalid command option\n";
			return -1;
		}
		++ind;
	}

	return ret;
}

int parseArgInstallDEK(int argc, char* argv[], char **dek)
{
	int ind = 2;
	int ret = 0;
	while (ind < argc) {
		if (!strcmp(argv[ind], "-key")) {
			*dek = argv[++ind];
		} else {
			cout << "invalid command option\n";
			return -1;
		}
		++ind;
	}

	return ret;
}

const char installSD_usage[] = "installSD <args>\n"
		"\t-sd SD name  - name of the SD pacakge\n"
		"\t-id SD ID    - The UUID of the SD (default 'BD2FBA36A2D64DAB9390FF6DA2FEF31C')\n";

const char installTA_usage[] = "installTA <args>\n"
		"\t-ta TA name  - name of the TA(DAL Applet)\n"
		"\t-id SD ID    - The UUID of the SD (default 'BD2FBA36A2D64DAB9390FF6DA2FEF31C')\n";

const char uninstallSD_usage[] = "uninstallSD <args>\n"
		"\t-sd SD name  - name of the SD pacakge\n"
		"\t-id SD ID    - The UUID of the SD (default 'BD2FBA36A2D64DAB9390FF6DA2FEF31C')\n";

const char listTA_usage[] = "listTA <args>\n"
		"\t-id SD ID    - The UUID of the SD (default 'BD2FBA36A2D64DAB9390FF6DA2FEF31C')\n"
		"\t-s           - Enable succinct output\n";

const char listSD_usage[] = "listSD <args>\n"
		"\t-s           - Enable succinct output\n";

const char installOMK_usage[] = "installOMK <args>\n"
		"\t-key OMK     - The file name of OMK blob\n";

const char installDEK_usage[] = "installDEK <args>\n"
		"\t-key DEK     - The file name of DEK blob\n";

int parseArgs(int argc, char* argv[], char **sd, char **ta, char **id)
{
	int ret = 0;

	if (argv[1] == NULL) {
		ret = -1;
	} else if (!strcmp(argv[1], "installSD")) {
		ret = parseArginstallSD(argc, argv, sd, id);
		if (!ret)
			ret = CMD_INSTALLSD;
		else
			cout << installSD_usage;
	} else if (!strcmp(argv[1], "installTA")) {
		ret = parseArginstallTA(argc, argv, ta, id);
		if (!ret)
			ret = CMD_INSTALLTA;
		else
			cout << installTA_usage;
	} else if (!strcmp(argv[1], "uninstallSD")) {
		ret = parseArginstallSD(argc, argv, sd, id);
		if (!ret)
			ret = CMD_UNINSTALLSD;
		else
			cout << uninstallSD_usage;
	} else if (!strcmp(argv[1], "listTA")) {
		ret = parseArgListTA(argc, argv, id);
		if (!ret)
			ret = CMD_LISTTA;
		else
			cout << listTA_usage;
	} else if (!strcmp(argv[1], "listSD")) {
		ret = parseArgListSD(argc, argv, id);
		if (!ret)
			ret = CMD_LISTSD;
		else
			cout << listSD_usage;
	} else if (!strcmp(argv[1], "installOMK")) {
		ret = parseArgInstallOMK(argc, argv, ta);
		if (!ret)
			ret = CMD_INSTALLOMK;
		else
			cout << installOMK_usage;
	} else if (!strcmp(argv[1], "installDEK")) {
		ret = parseArgInstallDEK(argc, argv, ta);
		if (!ret)
			ret = CMD_INSTALLDEK;
		else
			cout << installDEK_usage;
	} else {
		cout << "invalid command\n" << "list of commands:\n";
		cout << installSD_usage << installTA_usage << uninstallSD_usage << listTA_usage
			 << listSD_usage << installOMK_usage << installDEK_usage << endl;
		ret = -1;
	}

	return ret;
}

int readData(char *file_name, unsigned char **buf, int *len)
{
	*buf = NULL;

	*len = 0;
	fstream data_file(file_name, ios::binary | ios::in);

	data_file.seekg(0, data_file.end);
	uint32_t data_size = (uint32_t) data_file.tellg();
	data_file.seekp(0, data_file.beg);

	try {
		*buf = new uint8_t[data_size];
	} catch (bad_alloc&) {
		cerr << "Memory Allocation Failure" << endl;
		data_file.close();
		return -1;
	}

	data_file.read((char*) *buf, data_size);

	if (data_file.bad() || data_file.fail()) {
		cerr << "File read failed" << endl;
		delete[] (*buf);
		*buf = NULL;
		data_file.close();
		return -1;
	}
	*len = data_size;
	data_file.close();
	return 0;
}

int main(int argc, char* argv[])
{
	uint8_t* buf = NULL;
	int cmd = 0;
	int len = 0;

	char *sd = NULL, *ta = NULL, *id = NULL;
	char default_id[] = "BD2FBA36A2D64DAB9390FF6DA2FEF31C";
	const char *id1 = NULL;
	int ret = 0;

	if ((cmd = parseArgs(argc, argv, &sd, &ta, &id)) < 0)
		return -1;

	if (cmd == CMD_INSTALLSD) {
		if (readData(sd, &buf, &len) < 0)
			return -1;
		cout << "SD file len: " << len << endl;
	} else if (cmd == CMD_INSTALLTA) {
		if (readData(ta, &buf, &len) < 0)
			return -1;
		cout << "TA file len: " << len << endl;
	} else if (cmd == CMD_UNINSTALLSD) {
		if (readData(sd, &buf, &len) < 0)
			return -1;
		cout << "SD file len: " << len << endl;
	} else if (cmd == CMD_INSTALLOMK) {
		if (readData(ta, &buf, &len) < 0)
			return -1;
		cout << "OMK file len: " << len << endl;
	} else if (cmd == CMD_INSTALLDEK) {
		if (readData(ta, &buf, &len) < 0)
			return -1;
		cout << "DEK file len: " << len << endl;
	}

	if (!id)
		id1 = default_id;
	else
		id1 = id;

	if (strlen(id1) > SD_ID_MAX_LEN) {
		cerr << "SD id length exceeds max limit" << endl;
		delete[] buf;
		return -1;
	}

	if (cmd == CMD_INSTALLSD) {
		ret = Install(id1, buf, len);
		if (!ret)
			cout << "Install SD is Successful" << endl;
		else
			cout << "Install SD Failed" << endl;
	} else if (cmd == CMD_UNINSTALLSD) {
		ret = Install(id1, buf, len);
		if (!ret)
			cout << "Uninstall SD is Successful" << endl;
		else
			cout << "Uninstall SD Failed" << endl;
	} else if (cmd == CMD_INSTALLTA) {
		ret = Install(id1, buf, len);
		if (!ret)
			cout << "Install TA is Successful" << endl;
		else
			cout << "Install TA Failed" << endl;
	} else if (cmd == CMD_LISTTA) {
		ret = List(id1);
		if (ret)
			cout << "List TA Failed" << endl;
		else if (!succinct)
			cout << "List TA is Successful" << endl;
	} else if (cmd == CMD_LISTSD) {
		ret = List(id1, cmd);
		if (ret)
			cout << "List SD Failed" << endl;
		else if (!succinct)
			cout << "List SD is Successful" << endl;
	} else if (cmd == CMD_INSTALLOMK) {
		ret = Provision(default_id, buf, CMD_INSTALLOMK);
		if (!ret)
			cout << "Install OMK is Successful" << endl;
		else
			cout << "Install OMK Failed" << endl;
	} else if (cmd == CMD_INSTALLDEK) {
		ret = Provision(default_id, buf, CMD_INSTALLDEK);
		if (!ret)
			cout << "Install DEK is Successful" << endl;
		else
			cout << "Install DEK Failed" << endl;
	}

	if (buf)
		delete[] buf;
	return ret;
}

bool getFWVersion(VERSION* fw_version)
{
	JHI_HANDLE hJOM = 0;
	JHI_VERSION_INFO info;
	JHI_RET status;

	status = JHI_Initialize(&hJOM, NULL, 0); // Check for Success
	if (status != JHI_SUCCESS) {
		fprintf(stdout, "JHI init failed. error code: 0x%x\n", status);
		return false;
	}

	status = JHI_GetVersionInfo(hJOM, &info);
	if (status != JHI_SUCCESS) {
		fprintf(stdout, "\nJHI get version info failed, error code: 0x%x \n", status);
		return false;
	}

	JHI_Deinit(hJOM);

	if (sscanf(info.fw_version, "%hu.%hu.%hu.%hu", &fw_version->Major, &fw_version->Minor, &fw_version->Hotfix, &fw_version->Build) != 4) {
		cerr << "recieved invalid fw version format from devplatform" << endl;
		return false;
	}
	return true;
}

int Install(const char *sdId, uint8_t* package, uint32_t packageSize)
{
	TEE_STATUS status;
	SD_SESSION_HANDLE hdl;

	VERSION version;

	if (!getFWVersion(&version)) {
		fprintf(stdout, "Get version failed, aborting Install.\n");
		return -1;
	}

	if (version.Major < 11 && version.Major != 3) {
		fprintf(stdout, "FW isn't CSE or BXT, skipping Install.\n");
		return -1;
	}

	if ((status = TEE_OpenSDSession(sdId, &hdl)) != TEE_STATUS_SUCCESS) {
		printErr(status, 1);
		return -1;
	}

	if ((status = TEE_SendAdminCmdPkg(hdl, package, packageSize)) != TEE_STATUS_SUCCESS) {
		printErr(status, 2);
		return -1;
	}

	if ((status = TEE_CloseSDSession(&hdl)) != TEE_STATUS_SUCCESS) {
		printErr(status, 4);
		return -1;
	}

	TEE_DEALLOC(hdl);

	return 0;
}

int List(const char *sdId, uint32_t cmd /*= CMD_LISTTA*/)
{
	TEE_STATUS status;
	SD_SESSION_HANDLE hdl;

	VERSION version;
	UUID_LIST uuidList;

	if (!getFWVersion(&version)) {
		fprintf(stdout, "Get version failed, aborting list TA.\n");
		return -1;
	}

	if (version.Major < 11 && version.Major < 3) {
		fprintf(stdout, "FW isn't CSE or BXT, skipping list TA.\n");
		return -1;
	}

	if ((status = TEE_OpenSDSession(sdId, &hdl)) != TEE_STATUS_SUCCESS) {
		printErr(status, 1);
		return -1;
	}

	if (cmd == CMD_LISTTA) {
		status = TEE_ListInstalledTAs(hdl, &uuidList);
	} else if (cmd == CMD_LISTSD) {
		status = TEE_ListInstalledSDs(hdl, &uuidList);
	}

	if (status != TEE_STATUS_SUCCESS) {
		printErr(status, 2);
		return -1;
	}
	printUUIDs(uuidList);
	TEE_DEALLOC(uuidList.uuids);

	if ((status = TEE_CloseSDSession(&hdl)) != TEE_STATUS_SUCCESS) {
		printErr(status, 4);
		return -1;
	}

	TEE_DEALLOC(hdl);

	return 0;
}


int Provision(const char *sdId, uint8_t* keyBlob, uint32_t cmd)
{
	TEE_STATUS status;
	SD_SESSION_HANDLE hdl;

	VERSION version;

	if (!getFWVersion(&version)) {
		fprintf(stdout, "Get version failed, aborting Provision.\n");
		return -1;
	}

	if (version.Major < 11 && version.Major != 3) {
		fprintf(stdout, "FW isn't CSE or BXT, skipping Provision.\n");
		return -1;
	}

	if ((status = TEE_OpenSDSession(sdId, &hdl)) != TEE_STATUS_SUCCESS) {
		printErr(status, 1);
		return -1;
	}

	if (cmd == CMD_INSTALLOMK) {
		if ((status = TEE_ProvisionOemMasterKey(hdl, (const tee_asym_key_material *)keyBlob)) != TEE_STATUS_SUCCESS) {
			printErr(status, 5);
			return -1;
		}
	} else if (cmd == CMD_INSTALLDEK)	{
		if ((status = TEE_SetTAEncryptionKey(hdl, (const tee_key_material *)keyBlob)) != TEE_STATUS_SUCCESS) {
			printErr(status, 6);
			return -1;
		}
	}

	if ((status = TEE_CloseSDSession(&hdl)) != TEE_STATUS_SUCCESS) {
		printErr(status, 4);
		return -1;
	}

	TEE_DEALLOC(hdl);

	return 0;
}

void printUUIDs(UUID_LIST& uuidList)
{
	if (!succinct) cout << "UUIDs found - " << std::to_string(uuidList.uuidCount) << '\n';
	for (uint32_t i = 0; i < uuidList.uuidCount; ++i) {
		if (!succinct) cout << "UUID #" << i << " - ";
		cout << uuidList.uuids[i] << endl;
	}
}

void printErr(TEE_STATUS status, int no)
{
	cerr << "TEE API Failed: " << no << endl;
	cerr << "status code: " << status << endl <<
			TEEErrorToString(status) << endl;
}
