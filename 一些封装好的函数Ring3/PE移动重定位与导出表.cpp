#include<Windows.h>
#include<tchar.h>
#include<iostream>
#define path1 L"C:\\Users\\�޼�\\Desktop\\Dll1.dll"
#define path2 L"C:\\Users\\�޼�\\Desktop\\REL_EXP.dll"

//*********************************************************************
//���ζ��� ����1��ַ ����2��������
DWORD align(DWORD address, DWORD ratio);
//*********************************************************************

//*********************************************************************
//����һ���� ����1Դ�ļ���� ����2Ŀ���ļ����
BOOL AddSection(HANDLE hSrcFile1, HANDLE hDstFile2);
//*********************************************************************

//*********************************************************************
//RVAתFOA ����1��ַ��������RVA
DWORD RVA2FOA(LPVOID buf, LPVOID RVA);
//*********************************************************************

//*********************************************************************
//�ƶ����Ƶ����� ����1Ŀ���ļ���� ����ֵ���������ֽ���
DWORD MoveEXPORT(HANDLE hFile);
//*********************************************************************

//**************************************************************************
//�ƶ������ض�λ�� ����1Ŀ���ļ���� ����2���½��е�ƫ��λ�� ����ֵ���������ֽ���
DWORD MoveReloc(HANDLE hFile,DWORD offset);
//**************************************************************************

DWORD align(DWORD address, DWORD ratio) {
	if (address / ratio == 0) {
		return ratio;
	}
	if (address % ratio == 0) {
		return (address / ratio) * ratio;
	}
	else {
		return (address / ratio + 1) * ratio;
	}
}
BOOL AddSection(HANDLE hSrcFile1, HANDLE hDstFile2) {
	if ((DWORD)hSrcFile1 == INVALID_FILE_SIZE || (DWORD)hDstFile2 == INVALID_FILE_SIZE) {
		return FALSE;
	}
	DWORD size = GetFileSize(hSrcFile1, NULL);
	LPVOID buf = new char[size] {0};
	DWORD writeSzie = 0;
	DWORD err_t = ReadFile(hSrcFile1, buf, size, &writeSzie, NULL);
	if (!err_t) {
		return FALSE;
	}

	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	//����ֱ�ӿ��Ǹ�����������κ�����ݲ����޸ģ���dos_stub�Ƴ���PEͷ������ǰ��
	//����dos_stub�Ĵ�С
	DWORD dos_stub_size = dos_header->e_lfanew - sizeof(dos_header);
	//����nt�����һ��section�Ĵ�С
	DWORD all_header_size = sizeof(IMAGE_NT_HEADERS) + file_header->NumberOfSections * 0x28;
	memcpy(LPVOID((DWORD)buf + sizeof(IMAGE_DOS_HEADER)), nt_header, all_header_size);
	memset(LPVOID((DWORD)buf + sizeof(IMAGE_DOS_HEADER) + all_header_size), 0, dos_stub_size);
	//���»�ȡ�����ڵ�ֵ
	dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	//�޸ļ����������ε�ֵ
	file_header->NumberOfSections += 1;
	option_header->SizeOfHeaders += 0x28;
	//����һ����������
	BYTE name[8] = "NewSec";
	IMAGE_SECTION_HEADER newsec = { 0 };
	//������
	memcpy(newsec.Name, name, 8);
	//�������ļ��д�С(����ǰ)
	newsec.Misc.VirtualSize = 0x1000;
	//����RVA  ���һ�����ε�RVA+�������ļ��еĴ�С�ٶ���
	section_header += (file_header->NumberOfSections - 2);
	newsec.VirtualAddress = align(section_header->VirtualAddress + section_header->SizeOfRawData, option_header->SectionAlignment);
	//�������ļ��д�С
	newsec.SizeOfRawData = 0x1000;
	//����FOA ���һ�����ε�FOA+�������ļ��д�С�ٶ���
	newsec.PointerToRawData = align(section_header->PointerToRawData + section_header->SizeOfRawData, option_header->FileAlignment);
	//�������ض�λ�ڵ�������ͬ
	newsec.Characteristics = section_header->Characteristics;
	//��buf�����
	memcpy(LPVOID((DWORD)buf + sizeof(IMAGE_DOS_HEADER) + all_header_size), &newsec, 0x28);

	//д���ļ�
	DWORD writeSize = 0;
	WriteFile(hDstFile2, buf, size, &writeSize, NULL);
	char temp[0x1000] = { 0 };
	WriteFile(hDstFile2, temp, 0x1000, &writeSize, NULL);
	//�ͷſռ�
	if (buf != NULL) {
		delete[] buf;
		buf = NULL;
	}
	return true;

}
DWORD RVA2FOA(LPVOID buf, LPVOID RVA) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);

	for (int i = 0; i < file_header->NumberOfSections; i++) {
		if ((DWORD)RVA >= section_header->VirtualAddress &&
			(DWORD)RVA < section_header->VirtualAddress + section_header->SizeOfRawData) {
			return ((DWORD)RVA - section_header->VirtualAddress + section_header->PointerToRawData);
		}
		section_header++;
	}
	return 0;
}
DWORD MoveEXPORT(HANDLE hFile) {
	if ((DWORD)hFile == INVALID_FILE_SIZE) {
		return 0;
	}
	DWORD size = GetFileSize(hFile, NULL);
	LPVOID buf = new char[size] {0};
	DWORD ReadSize = 0;
	OVERLAPPED ol = { 0 };
	ol.Offset = 0;
	DWORD err_t = ReadFile(hFile, buf, size, &ReadSize, &ol);
	if (!err_t) {
		return FALSE;
	}
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));

	section_header += (file_header->NumberOfSections - 1);
	//�½����ļ��е�λ��
	DWORD newSectionFOA = section_header->PointerToRawData;
	//�ҵ�ԭ�ȵ������λ�ã���ԭ�ⲻ���Ŀ������½ڿ�ͷλ��
	PIMAGE_EXPORT_DIRECTORY export_table = PIMAGE_EXPORT_DIRECTORY(RVA2FOA(buf, LPVOID(option_header->DataDirectory[0].VirtualAddress)) + (DWORD)buf);
	DWORD newSectionVA = (DWORD)buf + newSectionFOA;
	memcpy(LPVOID(newSectionVA), export_table, sizeof(IMAGE_EXPORT_DIRECTORY));
	export_table = (PIMAGE_EXPORT_DIRECTORY)newSectionVA;

	//��һ�εĿ�����ַ
	DWORD CopyAddress = newSectionFOA + sizeof(IMAGE_EXPORT_DIRECTORY) + (DWORD)buf;
	//��¼��ַ��������㿽�����ܴ�С
	DWORD TempAddress = CopyAddress;

	//----------------------------------------------------------------------------------------------
	//�ȿ���PE��
	DWORD len = strlen(PCHAR(RVA2FOA(buf, LPVOID(export_table->Name)) + (DWORD)buf));
	memcpy(LPVOID(CopyAddress), PCHAR(RVA2FOA(buf, LPVOID(export_table->Name)) + (DWORD)buf), len + 1);
	//PE�ļ���RVA
	DWORD PENameRVA = section_header->VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY);
	//RVAд���½ڵĵ�������
	export_table->Name = PENameRVA;
	//���ݳ���
	DWORD Size_PEName = len + 1;
	//-----------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------
	//����������ַ��
	//��ַ��RVA = �ļ���RVA+�ļ�������+1(�ַ�����0��β)
	DWORD FunAddressRVA = PENameRVA + Size_PEName;
	CopyAddress += Size_PEName;
	DWORD OldFunAddressTable = RVA2FOA(buf, LPVOID(export_table->AddressOfFunctions)) + DWORD(buf);
	//ѭ������������ַ
	for (DWORD i = 0; i < export_table->NumberOfFunctions; i++) {
		memcpy(LPVOID(CopyAddress), LPVOID(OldFunAddressTable), 4);
		CopyAddress += 4;
		OldFunAddressTable += 4;
	}
	//RVAд���½ڵĺ�����ַ����
	export_table->AddressOfFunctions = FunAddressRVA;
	//д��ĳ���
	DWORD Size_FunAddress = export_table->NumberOfFunctions * 4;
	//-----------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------
	//�������Ʊ�Ŀ���
	//���Ʊ�RVA = ��ַ��RVA+������ַ����
	DWORD FunNamesRVA = FunAddressRVA + Size_FunAddress;
	//1.ȷ��RVA���Ʊ�ĳ���
	DWORD Size_FunNameRVA = export_table->NumberOfNames * 4;
	//2.ȷ����������һ���Ŀ�ʼλ��
	DWORD FirstFunNameAdd = CopyAddress + Size_FunNameRVA;
	//ѭ������(˳����¼�ܳ���)
	DWORD AllNameLen = 0;
	DWORD NameLen = 0;
	DWORD OldNameRVATable = RVA2FOA(buf, LPVOID(export_table->AddressOfNames)) + (DWORD)buf;
	//������RVA
	DWORD TempNameRVA = FunNamesRVA + Size_FunNameRVA;
	for (DWORD i = 0; i < export_table->NumberOfNames; i++) {
		LPVOID oldName = (LPVOID)(RVA2FOA(buf, (LPVOID)((PDWORD)OldNameRVATable)[i]) + (DWORD)buf);
		NameLen = strlen((PCHAR)oldName) + 1;
		//�����ƿ������µĵ�ַ��
		memcpy((LPVOID)FirstFunNameAdd, (LPVOID)oldName, NameLen);
		FirstFunNameAdd += NameLen;
		//�������Ƶ�ַ��RVA����������RVA��
		*(PDWORD)CopyAddress = TempNameRVA;
		CopyAddress += 4;
		TempNameRVA += NameLen;
		//�����ܳ���
		AllNameLen += NameLen;
	}
	//RVAд���½ڵĺ�����ַ����
	export_table->AddressOfNames = FunNamesRVA;
	//д��ĳ���
	DWORD Size_AllFunTable = Size_FunNameRVA + AllNameLen;
	//��ʱ�ȴ������ĵ�ַ
	CopyAddress += AllNameLen;
	//-----------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------
	//������ű�
	DWORD OrdinalsRVA = FunNamesRVA + Size_AllFunTable;
	DWORD OrdinalTable = RVA2FOA((LPVOID)buf, LPVOID(export_table->AddressOfNameOrdinals)) + (DWORD)buf;
	for (DWORD i = 0; i < export_table->NumberOfNames; i++) {
		WORD Ordinal = (PWORD(OrdinalTable)[i]);
		*PWORD(CopyAddress) = Ordinal;
		CopyAddress += 2;
	}
	//RVAд���½ڵĺ�����ַ����
	export_table->AddressOfNameOrdinals = OrdinalsRVA;
	//-----------------------------------------------------------------------------------------------

	//ԭ�ȵ������RVA��Ҫ����
	option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_DATA_DIRECTORY data_dir = (PIMAGE_DATA_DIRECTORY)&(option_header->DataDirectory[0]);
	ol.Offset = (DWORD)data_dir - (DWORD)buf;
	DWORD writeSize = 0;
	WriteFile(hFile, &(section_header->VirtualAddress), 4, &writeSize, &ol);

	//�ܳ��� 
	DWORD ALLSize = CopyAddress - TempAddress + sizeof(IMAGE_EXPORT_DIRECTORY);
	ol.Offset = newSectionFOA;
	writeSize = 0;
	//д���ļ�
	WriteFile(hFile, (LPVOID)((DWORD)buf + newSectionFOA), ALLSize,&writeSize,&ol);
	if (buf != NULL) {
		delete[] buf;
		buf = NULL;
	}
	return ALLSize;
}
DWORD MoveReloc(HANDLE hFile, DWORD offset) {
	if ((DWORD)hFile == INVALID_FILE_SIZE) {
		return 0;
	}
	DWORD size = GetFileSize(hFile, NULL);
	LPVOID buf = new char[size] {0};
	DWORD ReadSize = 0;
	OVERLAPPED ol = { 0 };
	ol.Offset = 0;
	DWORD err_t = ReadFile(hFile, buf, size, &ReadSize, &ol);
	if (!err_t) {
		return FALSE;
	}
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_SECTION_HEADER section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	section_header += file_header->NumberOfSections - 1;
	PIMAGE_BASE_RELOCATION reloc = PIMAGE_BASE_RELOCATION(RVA2FOA(buf, LPVOID(option_header->DataDirectory[5].VirtualAddress)) + (DWORD)buf);
	DWORD AllSize = 0;
	//�����ǿ�����
	DWORD CopyAddress = section_header->PointerToRawData + offset + (DWORD)buf;
	while ((reloc->SizeOfBlock)&&(reloc->VirtualAddress)) {
		memcpy((LPVOID)CopyAddress,reloc, reloc->SizeOfBlock);
		//��һ��������
		CopyAddress += reloc->SizeOfBlock;
		//�ض�λ��Ĵ�С
		AllSize += reloc->SizeOfBlock;
		//��һ���ض�λ��
		reloc = PIMAGE_BASE_RELOCATION((DWORD)reloc + reloc->SizeOfBlock);
	}
	//��ԭ�ȵ��ض�λ��ַ����
	PIMAGE_DATA_DIRECTORY data = (PIMAGE_DATA_DIRECTORY)&(option_header->DataDirectory[5]);

	data->VirtualAddress = section_header->VirtualAddress + offset;
	ol.Offset = (DWORD)data - (DWORD)buf;
	DWORD writeSize = 0;
	WriteFile(hFile, &(data->VirtualAddress), 4, &writeSize, &ol);

	//���ض�λ�����Ϣд���½���
	ol.Offset = section_header->PointerToRawData + offset;
	WriteFile(hFile, LPVOID((DWORD)buf + ol.Offset), AllSize, &writeSize, &ol);

	//��8��0
	return AllSize+8;
	
}

int _tmain(char* argv, char* args[]) {

	HANDLE hFile1 = CreateFile(path1, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile2 = CreateFile(path2, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	//����һ����
	AddSection(hFile1, hFile2);
	//�ƶ���������Ϣ���µĽ���
	DWORD size = MoveEXPORT(hFile2);
	//�ƶ��ض�λ�����µĽ���
	size += MoveReloc(hFile2, size);


	CloseHandle(hFile1);
	CloseHandle(hFile2);
	return 0;
}