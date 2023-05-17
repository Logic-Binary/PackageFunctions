#include<iostream>
#include<Windows.h>
#include<tchar.h>
#define path L"C:\\Users\\罗辑\\Desktop\\Dll1.dll"

VOID EnumExport(DWORD buf);
DWORD RVA2FOA(DWORD buf, DWORD RVA);
DWORD GetProcAddressByName(DWORD buf, PCHAR name);
DWORD GetProcAddressByOridinal(DWORD buf, DWORD order);


DWORD RVA2FOA(DWORD buf, DWORD RVA) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	for (int i = 0; i < file_header->NumberOfSections; i++) {
		if (RVA >= section_header->VirtualAddress &&
			RVA < section_header->VirtualAddress + section_header->SizeOfRawData) {
			return (RVA - section_header->VirtualAddress + section_header->PointerToRawData);
		}
		section_header++;
	}
	return 0;
}

VOID EnumExport(DWORD buf) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	DWORD export_table_RVA = option_header->DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY export_table = PIMAGE_EXPORT_DIRECTORY(RVA2FOA((DWORD)buf, export_table_RVA) + (DWORD)buf);

	printf("***函数地址表***\n");
	DWORD FunAddressTable = RVA2FOA((DWORD)buf, export_table->AddressOfFunctions) + (DWORD)buf;
	for (int i = 0; i < export_table->NumberOfFunctions; i++) {
		printf("%08X\n", ((PDWORD)FunAddressTable)[i]);
	}
	printf("***函数名称表***\n");
	DWORD FunNameTableRVA = RVA2FOA((DWORD)buf, export_table->AddressOfNames) + (DWORD)buf;
	DWORD FunNameTable = 0;
	for (int i = 0; i < export_table->NumberOfNames; i++) {
		FunNameTable = RVA2FOA((DWORD)buf, *(PDWORD)FunNameTableRVA) + (DWORD)buf;
		printf("%s\n", (PCHAR)FunNameTable);
		FunNameTableRVA += 4;
	}
	printf("***函数序号表***\n");
	DWORD FunNameOrdinal = RVA2FOA((DWORD)buf, export_table->AddressOfNameOrdinals) + (DWORD)buf;
	DWORD base = export_table->Base;
	for (int i = 0; i < export_table->NumberOfNames; i++) {
		printf("%d\n", (PWORD(FunNameOrdinal))[i]+base);
	}
}

DWORD GetProcAddressByName(DWORD buf, PCHAR name) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	DWORD export_table_RVA = option_header->DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY export_table = PIMAGE_EXPORT_DIRECTORY(RVA2FOA((DWORD)buf, export_table_RVA) + (DWORD)buf);

	DWORD FunNameTableRVA = RVA2FOA((DWORD)buf, export_table->AddressOfNames)+(DWORD)buf;
	DWORD FunName = 0;
	DWORD FunOridinalsTable = RVA2FOA((DWORD)buf, export_table->AddressOfNameOrdinals) + (DWORD)buf;
	WORD val = 0;
	DWORD FunAddressTable = RVA2FOA((DWORD)buf, export_table->AddressOfFunctions) + (DWORD)buf;
	for (int i = 0; i < export_table->NumberOfFunctions; i++) {
		FunName = RVA2FOA((DWORD)buf, *(PDWORD)FunNameTableRVA)+(DWORD)buf;
		FunNameTableRVA += 4;
		if (strcmp(name, (PCHAR)FunName) == 0) {
			//用这个下标去找序号表
			val = ((PDWORD)FunOridinalsTable)[i];
			//用val去找函数地址表里找地址
			return ((PDWORD)FunAddressTable)[val];
		}
	}
	return 0;
}

DWORD GetProcAddressByOridinal(DWORD buf, DWORD order) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	DWORD export_table_RVA = option_header->DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY export_table = PIMAGE_EXPORT_DIRECTORY(RVA2FOA((DWORD)buf, export_table_RVA) + (DWORD)buf);

	DWORD FunAddressTable = RVA2FOA((DWORD)buf, export_table->AddressOfFunctions) + (DWORD)buf;
	DWORD FunCount = export_table->NumberOfFunctions;
	DWORD Base = export_table->Base;
	if ((order - Base >= FunCount) || (order - Base < 0)) {
		return 0;
	}
	else {
		return ((PDWORD)FunAddressTable)[order-Base];
	}

}


int _tmain(char argc, char* argv[]) {
	HANDLE hFile = CreateFile(path, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD size = GetFileSize(hFile, NULL);
	LPVOID buf = new char[size] {0};
	DWORD readSize = 0;
	ReadFile(hFile, buf, size, &readSize, NULL);

	EnumExport((DWORD)buf);
	DWORD temp1 = GetProcAddressByName((DWORD)buf, (PCHAR)"fun1");
	DWORD temp2 = GetProcAddressByOridinal((DWORD)buf, 6);

	int a = 0;
	return 0;
}
