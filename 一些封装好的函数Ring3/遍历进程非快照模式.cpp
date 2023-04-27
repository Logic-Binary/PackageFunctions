#include<Windows.h>
#include<iostream>
#include<Psapi.h>
#include<tchar.h>



VOID PrintProcessNameAndID(DWORD id) {
	TCHAR szProcessName[MAX_PATH] = _T("<unknow>");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);

	GetProcessImageFileName(hProcess, szProcessName, sizeof(szProcessName));
	_tprintf(_T("%s  (PID: %u)\n"), szProcessName, id);
	if (!strcmp((const char*)szProcessName, "Panda.exe")) {
		system("pause");
	}
	if (hProcess!=NULL) {
		HMODULE hMod;
		DWORD cbNeeded;
		//枚举模块
		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
	}
	_tprintf(_T("%s  (PID: %u)\n"), szProcessName, id);
	if (!strcmp((const char*)szProcessName, "Panda.exe")) {
		system("pause");
	}
	CloseHandle(hProcess);

}


int _tmain(char* argv, char* args[]) {

	//分别是存放id的数组，实际存放了多少字节，以及等会要求的进程个数
	DWORD pPid[1024], cbNeeded, cProcesses;
	//枚举进程，存放进pPid中
	if (!EnumProcesses(pPid, sizeof(pPid), &cbNeeded)) {
		//失败了则退出
		return -1;
	}
	//计算有多少进程
	cProcesses = cbNeeded / 4;
	//循环遍历
	for (int i = 0; i < cProcesses; i++) {
		if (pPid[i] != 0) {
			PrintProcessNameAndID(pPid[i]);
		}
	}

	return 0;
}