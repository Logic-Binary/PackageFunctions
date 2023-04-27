#include<Windows.h>
#include<tchar.h>
#include<iostream>
#include <locale.h>
#define path1 L"C:\\Users\\罗辑\\Desktop\\Test.exe"
#define path2 L"C:\\Users\\罗辑\\Desktop\\111.exe"

//扩大最后一个节
DWORD AddSection2(LPVOID buf, DWORD size, HANDLE hFile, PCHAR section_name, DWORD section_size);
//移除dos_stub,整个头部前移,添加一个节
DWORD AddSection(PCHAR section_name, DWORD section_size);

DWORD AddSection(PCHAR section_name, DWORD section_size) {
	HANDLE hFile = CreateFile(path1, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile2 = CreateFile(path2, GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (((DWORD)hFile == INVALID_FILE_ATTRIBUTES) || ((DWORD)hFile2 == INVALID_FILE_ATTRIBUTES)) {
		printf("文件打开失败");
		return 0;
	}
	DWORD size = GetFileSize(hFile, NULL);
	LPVOID buf = new char[size] {0};
	DWORD readSize = 0;
	DWORD err_t = ReadFile(hFile, buf, size, &readSize, NULL);
	if (!err_t) {
		printf("读取文件失败");
		CloseHandle(hFile);
		CloseHandle(hFile2);
		return 0;
	}
	//老规矩
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER optional_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//添加节的第一步，先将NT头部+区段表全部前移
	DWORD dos_size = sizeof(IMAGE_DOS_HEADER);
	//1.记录一下dos_sub的大小
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
	//2.PE标志开始往后的大小--一直到区段信息结束
	//NT的大小+区段表大小
	DWORD all_size = sizeof(IMAGE_NT_HEADERS) + (file_header->NumberOfSections) * 40;
	//整体前移
	memcpy(LPVOID((DWORD)buf + dos_size), nt_header, all_size);
	//将e_lfanew修改
	dos_header->e_lfanew = dos_size;
	//将中间的偏移部分补0
	memset(LPVOID((DWORD)buf + all_size + dos_size), 0, dos_sub_size);

	//重新获取各个节点信息
	nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	optional_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//准备工作完成后准备添加节
	IMAGE_SECTION_HEADER sh = { 0 };
	//名字(可用section_name动态设置)
	char name[8] = "123";
	memcpy(sh.Name, name, 8);
	//区段大小
	sh.Misc.VirtualSize = section_size;
	//区段RVA
	//最后一个区段的RVA+最后一个区段的大小，再对齐
	PIMAGE_SECTION_HEADER temp = section_header + file_header->NumberOfSections - 1;
	DWORD bigger = temp->Misc.VirtualSize > temp->SizeOfRawData ? temp->Misc.VirtualSize : temp->SizeOfRawData;
	sh.VirtualAddress = (temp->VirtualAddress + bigger + 0x1000) & 0xFFFFF000;
	//区段在文件中大小
	sh.SizeOfRawData = section_size;
	//区段的文件偏移
	sh.PointerToRawData = size;
	//区段属性
	sh.Characteristics = (section_header + 1)->Characteristics;
	//写入
	memcpy(LPVOID((DWORD)buf + dos_size + all_size), &sh, 40);
	//区段数量+1
	file_header->NumberOfSections += 1;
	//sizeofimage+0x1000
	optional_header->SizeOfImage += 0x1000;
	DWORD writeSize = 0;
	WriteFile(hFile2, buf, size, &writeSize, NULL);
	err_t = GetLastError();
	//设置偏移为文件末尾
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

	//思考几个问题
	//1.在最后的位置扩大节需要改哪些信息？
	//a.最后一个区段的大小(在文件中和在内存中)
	section_header += file_header->NumberOfSections - 1;
	section_header->Misc.VirtualSize += 0x1000;			//这个大小可以是section_size
	section_header->SizeOfRawData += 0x1000;			//这个大小可以是section_size
	//b.sizeofimage大小
	optional_header->SizeOfImage += 0x1000;				//这个大小可以是section_size
	DWORD writeSize = 0;
	WriteFile(hFile, buf, size, &writeSize, NULL);
	OVERLAPPED ol = { 0 };
	//设置文件偏移为文件末尾
	ol.Offset = size;
	char temp[0x1000] = { 0 };
	WriteFile(hFile, temp, 0x1000, &writeSize, &ol);
	return 1;
}


int _tmain(char* argv, char* args[]) {

	setlocale(LC_ALL, NULL);
	CHAR szName[10] = { 0 };
	//参数1---区段名
	//参数2---新增节大小
	AddSection(szName, 0x1000);

	return 0;
}