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
		//ö��ģ��
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

	//�ֱ��Ǵ��id�����飬ʵ�ʴ���˶����ֽڣ��Լ��Ȼ�Ҫ��Ľ��̸���
	DWORD pPid[1024], cbNeeded, cProcesses;
	//ö�ٽ��̣���Ž�pPid��
	if (!EnumProcesses(pPid, sizeof(pPid), &cbNeeded)) {
		//ʧ�������˳�
		return -1;
	}
	//�����ж��ٽ���
	cProcesses = cbNeeded / 4;
	//ѭ������
	for (int i = 0; i < cProcesses; i++) {
		if (pPid[i] != 0) {
			PrintProcessNameAndID(pPid[i]);
		}
	}

	return 0;
}