#include<Windows.h>
#include<tchar.h>
#include<iostream>
#include <locale.h>
#define path1 L"C:\\Users\\�޼�\\Desktop\\Test.exe"
#define path2 L"C:\\Users\\�޼�\\Desktop\\111.exe"

//�������һ����
DWORD AddSection2(LPVOID buf, DWORD size, HANDLE hFile, PCHAR section_name, DWORD section_size);
//�Ƴ�dos_stub,����ͷ��ǰ��,���һ����
DWORD AddSection(PCHAR section_name, DWORD section_size);

DWORD AddSection(PCHAR section_name, DWORD section_size) {
	HANDLE hFile = CreateFile(path1, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile2 = CreateFile(path2, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (((DWORD)hFile == INVALID_FILE_ATTRIBUTES) || ((DWORD)hFile2 == INVALID_FILE_ATTRIBUTES)) {
		printf("�ļ���ʧ��");
		return 0;
	}
	DWORD size = GetFileSize(hFile, NULL);
	LPVOID buf = new char[size] {0};
	DWORD readSize = 0;
	DWORD err_t = ReadFile(hFile, buf, size, &readSize, NULL);
	if (!err_t) {
		printf("��ȡ�ļ�ʧ��");
		CloseHandle(hFile);
		CloseHandle(hFile2);
		return 0;
	}
	//�Ϲ��
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER optional_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//��ӽڵĵ�һ�����Ƚ�NTͷ��+���α�ȫ��ǰ��
	DWORD dos_size = sizeof(IMAGE_DOS_HEADER);
	//1.��¼һ��dos_sub�Ĵ�С
	DWORD dos_sub_size = dos_header->e_lfanew - dos_size;
	if (dos_sub_size > 40) {
		DWORD val = AddSection2(buf, size, hFile2, section_name, section_size);
		if (buf != NULL) {
			delete[] buf;
			buf = NULL;
		}
		CloseHandle(hFile);
		CloseHandle(hFile2);
		return val;
	}
	//2.PE��־��ʼ����Ĵ�С--һֱ��������Ϣ����
	//NT�Ĵ�С+���α��С
	DWORD all_size = sizeof(IMAGE_NT_HEADERS) + (file_header->NumberOfSections) * 40;
	//����ǰ��
	memcpy(LPVOID((DWORD)buf + dos_size), nt_header, all_size);
	//��e_lfanew�޸�
	dos_header->e_lfanew = dos_size;
	//���м��ƫ�Ʋ��ֲ�0
	memset(LPVOID((DWORD)buf + all_size + dos_size), 0, dos_sub_size);

	//���»�ȡ�����ڵ���Ϣ
	nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	optional_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//׼��������ɺ�׼����ӽ�
	IMAGE_SECTION_HEADER sh = { 0 };
	//����(����section_name��̬����)
	char name[8] = "123";
	memcpy(sh.Name, name, 8);
	//���δ�С
	sh.Misc.VirtualSize = section_size;
	//����RVA
	//���һ�����ε�RVA+���һ�����εĴ�С���ٶ���
	PIMAGE_SECTION_HEADER temp = section_header + file_header->NumberOfSections - 1;
	DWORD bigger = temp->Misc.VirtualSize > temp->SizeOfRawData ? temp->Misc.VirtualSize : temp->SizeOfRawData;
	sh.VirtualAddress = (temp->VirtualAddress + bigger + 0x1000) & 0xFFFFF000;
	//�������ļ��д�С
	sh.SizeOfRawData = section_size;
	//���ε��ļ�ƫ��
	sh.PointerToRawData = size;
	//��������
	sh.Characteristics = (section_header + 1)->Characteristics;
	//д��
	memcpy(LPVOID((DWORD)buf + dos_size + all_size), &sh, 40);
	//��������+1
	file_header->NumberOfSections += 1;
	//sizeofimage+0x1000
	optional_header->SizeOfImage += 0x1000;
	DWORD writeSize = 0;
	WriteFile(hFile2, buf, size, &writeSize, NULL);
	err_t = GetLastError();
	//����ƫ��Ϊ�ļ�ĩβ
	OVERLAPPED overlapped = { 0 };
	overlapped.Offset = size;
	char tempBuf[0x1000] = { 0 };
	WriteFile(hFile2, tempBuf, 0x1000, &writeSize, &overlapped);

	if (buf != NULL) {
		delete[] buf;
		buf = NULL;
	}
	CloseHandle(hFile);
	CloseHandle(hFile2);
	return 1;
}

DWORD AddSection2(LPVOID buf, DWORD size, HANDLE hFile, PCHAR section_name, DWORD section_size) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER optional_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//˼����������
	//1.������λ���������Ҫ����Щ��Ϣ��
	//a.���һ�����εĴ�С(���ļ��к����ڴ���)
	section_header += file_header->NumberOfSections - 1;
	section_header->Misc.VirtualSize += 0x1000;			//�����С������section_size
	section_header->SizeOfRawData += 0x1000;			//�����С������section_size
	//b.sizeofimage��С
	optional_header->SizeOfImage += 0x1000;				//�����С������section_size
	DWORD writeSize = 0;
	WriteFile(hFile, buf, size, &writeSize, NULL);
	OVERLAPPED ol = { 0 };
	//�����ļ�ƫ��Ϊ�ļ�ĩβ
	ol.Offset = size;
	char temp[0x1000] = { 0 };
	WriteFile(hFile, temp, 0x1000, &writeSize, &ol);
	return 1;
}


int _tmain(char* argv, char* args[]) {

	setlocale(LC_ALL, NULL);
	CHAR szName[10] = { 0 };
	//����1---������
	//����2---�����ڴ�С
	AddSection(szName, 0x1000);

	return 0;
}