#include<Windows.h>
#include<tchar.h>
#include<iostream>
#define path1 L"C:\\Users\\罗辑\\Desktop\\Dll1.dll"
#define path2 L"C:\\Users\\罗辑\\Desktop\\REL_EXP.dll"

//*********************************************************************
//区段对齐 参数1地址 参数2对齐粒度
DWORD align(DWORD address, DWORD ratio);
//*********************************************************************

//*********************************************************************
//新增一个节 参数1源文件句柄 参数2目标文件句柄
BOOL AddSection(HANDLE hSrcFile1, HANDLE hDstFile2);
//*********************************************************************

//*********************************************************************
//RVA转FOA 参数1基址，参数二RVA
DWORD RVA2FOA(LPVOID buf, LPVOID RVA);
//*********************************************************************

//*********************************************************************
//移动复制导出表 参数1目标文件句柄 返回值是新增的字节数
DWORD MoveEXPORT(HANDLE hFile);
//*********************************************************************

//**************************************************************************
//移动复制重定位表 参数1目标文件句柄 参数2在新节中的偏移位置 返回值是新增的字节数
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

	//这里直接考虑复杂情况，区段后的内容不可修改，将dos_stub移除，PE头部整体前移
	//计算dos_stub的大小
	DWORD dos_stub_size = dos_header->e_lfanew - sizeof(dos_header);
	//计算nt至最后一个section的大小
	DWORD all_header_size = sizeof(IMAGE_NT_HEADERS) + file_header->NumberOfSections * 0x28;
	memcpy(LPVOID((DWORD)buf + sizeof(IMAGE_DOS_HEADER)), nt_header, all_header_size);
	memset(LPVOID((DWORD)buf + sizeof(IMAGE_DOS_HEADER) + all_header_size), 0, dos_stub_size);
	//重新获取各个节点值
	dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
	nt_header = PIMAGE_NT_HEADERS(dos_header->e_lfanew + (DWORD)buf);
	option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	section_header = PIMAGE_SECTION_HEADER(IMAGE_FIRST_SECTION(nt_header));
	//修改几个关于区段的值
	file_header->NumberOfSections += 1;
	option_header->SizeOfHeaders += 0x28;
	//构造一个区段属性
	BYTE name[8] = "NewSec";
	IMAGE_SECTION_HEADER newsec = { 0 };
	//区段名
	memcpy(newsec.Name, name, 8);
	//区段在文件中大小(对齐前)
	newsec.Misc.VirtualSize = 0x1000;
	//区段RVA  最后一个区段的RVA+区段在文件中的大小再对齐
	section_header += (file_header->NumberOfSections - 2);
	newsec.VirtualAddress = align(section_header->VirtualAddress + section_header->SizeOfRawData, option_header->SectionAlignment);
	//区段在文件中大小
	newsec.SizeOfRawData = 0x1000;
	//区段FOA 最后一个区段的FOA+区段在文件中大小再对齐
	newsec.PointerToRawData = align(section_header->PointerToRawData + section_header->SizeOfRawData, option_header->FileAlignment);
	//属性与重定位节的属性相同
	newsec.Characteristics = section_header->Characteristics;
	//在buf中添加
	memcpy(LPVOID((DWORD)buf + sizeof(IMAGE_DOS_HEADER) + all_header_size), &newsec, 0x28);

	//写入文件
	DWORD writeSize = 0;
	WriteFile(hDstFile2, buf, size, &writeSize, NULL);
	char temp[0x1000] = { 0 };
	WriteFile(hDstFile2, temp, 0x1000, &writeSize, NULL);
	//释放空间
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
	//新节在文件中的位置
	DWORD newSectionFOA = section_header->PointerToRawData;
	//找到原先导出表的位置，先原封不动的拷贝入新节开头位置
	PIMAGE_EXPORT_DIRECTORY export_table = PIMAGE_EXPORT_DIRECTORY(RVA2FOA(buf, LPVOID(option_header->DataDirectory[0].VirtualAddress)) + (DWORD)buf);
	DWORD newSectionVA = (DWORD)buf + newSectionFOA;
	memcpy(LPVOID(newSectionVA), export_table, sizeof(IMAGE_EXPORT_DIRECTORY));
	export_table = (PIMAGE_EXPORT_DIRECTORY)newSectionVA;

	//第一次的拷贝地址
	DWORD CopyAddress = newSectionFOA + sizeof(IMAGE_EXPORT_DIRECTORY) + (DWORD)buf;
	//记录地址，方便计算拷贝的总大小
	DWORD TempAddress = CopyAddress;

	//----------------------------------------------------------------------------------------------
	//先拷贝PE名
	DWORD len = strlen(PCHAR(RVA2FOA(buf, LPVOID(export_table->Name)) + (DWORD)buf));
	memcpy(LPVOID(CopyAddress), PCHAR(RVA2FOA(buf, LPVOID(export_table->Name)) + (DWORD)buf), len + 1);
	//PE文件名RVA
	DWORD PENameRVA = section_header->VirtualAddress + sizeof(IMAGE_EXPORT_DIRECTORY);
	//RVA写到新节的导出表中
	export_table->Name = PENameRVA;
	//内容长度
	DWORD Size_PEName = len + 1;
	//-----------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------
	//拷贝函数地址表
	//地址表RVA = 文件名RVA+文件名长度+1(字符串以0结尾)
	DWORD FunAddressRVA = PENameRVA + Size_PEName;
	CopyAddress += Size_PEName;
	DWORD OldFunAddressTable = RVA2FOA(buf, LPVOID(export_table->AddressOfFunctions)) + DWORD(buf);
	//循环拷贝函数地址
	for (DWORD i = 0; i < export_table->NumberOfFunctions; i++) {
		memcpy(LPVOID(CopyAddress), LPVOID(OldFunAddressTable), 4);
		CopyAddress += 4;
		OldFunAddressTable += 4;
	}
	//RVA写到新节的函数地址表中
	export_table->AddressOfFunctions = FunAddressRVA;
	//写入的长度
	DWORD Size_FunAddress = export_table->NumberOfFunctions * 4;
	//-----------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------
	//函数名称表的拷贝
	//名称表RVA = 地址表RVA+函数地址表长度
	DWORD FunNamesRVA = FunAddressRVA + Size_FunAddress;
	//1.确定RVA名称表的长度
	DWORD Size_FunNameRVA = export_table->NumberOfNames * 4;
	//2.确定函数名第一个的开始位置
	DWORD FirstFunNameAdd = CopyAddress + Size_FunNameRVA;
	//循环拷贝(顺带记录总长度)
	DWORD AllNameLen = 0;
	DWORD NameLen = 0;
	DWORD OldNameRVATable = RVA2FOA(buf, LPVOID(export_table->AddressOfNames)) + (DWORD)buf;
	//函数名RVA
	DWORD TempNameRVA = FunNamesRVA + Size_FunNameRVA;
	for (DWORD i = 0; i < export_table->NumberOfNames; i++) {
		LPVOID oldName = (LPVOID)(RVA2FOA(buf, (LPVOID)((PDWORD)OldNameRVATable)[i]) + (DWORD)buf);
		NameLen = strlen((PCHAR)oldName) + 1;
		//将名称拷贝到新的地址上
		memcpy((LPVOID)FirstFunNameAdd, (LPVOID)oldName, NameLen);
		FirstFunNameAdd += NameLen;
		//将新名称地址的RVA赋给新名称RVA表
		*(PDWORD)CopyAddress = TempNameRVA;
		CopyAddress += 4;
		TempNameRVA += NameLen;
		//计算总长度
		AllNameLen += NameLen;
	}
	//RVA写到新节的函数地址表中
	export_table->AddressOfNames = FunNamesRVA;
	//写入的长度
	DWORD Size_AllFunTable = Size_FunNameRVA + AllNameLen;
	//此时等待拷贝的地址
	CopyAddress += AllNameLen;
	//-----------------------------------------------------------------------------------------------

	//-----------------------------------------------------------------------------------------------
	//拷贝序号表
	DWORD OrdinalsRVA = FunNamesRVA + Size_AllFunTable;
	DWORD OrdinalTable = RVA2FOA((LPVOID)buf, LPVOID(export_table->AddressOfNameOrdinals)) + (DWORD)buf;
	for (DWORD i = 0; i < export_table->NumberOfNames; i++) {
		WORD Ordinal = (PWORD(OrdinalTable)[i]);
		*PWORD(CopyAddress) = Ordinal;
		CopyAddress += 2;
	}
	//RVA写到新节的函数地址表中
	export_table->AddressOfNameOrdinals = OrdinalsRVA;
	//-----------------------------------------------------------------------------------------------

	//原先导出表的RVA需要更改
	option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_DATA_DIRECTORY data_dir = (PIMAGE_DATA_DIRECTORY)&(option_header->DataDirectory[0]);
	ol.Offset = (DWORD)data_dir - (DWORD)buf;
	DWORD writeSize = 0;
	WriteFile(hFile, &(section_header->VirtualAddress), 4, &writeSize, &ol);

	//总长度 
	DWORD ALLSize = CopyAddress - TempAddress + sizeof(IMAGE_EXPORT_DIRECTORY);
	ol.Offset = newSectionFOA;
	writeSize = 0;
	//写入文件
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
	//这里是拷贝点
	DWORD CopyAddress = section_header->PointerToRawData + offset + (DWORD)buf;
	while ((reloc->SizeOfBlock)&&(reloc->VirtualAddress)) {
		memcpy((LPVOID)CopyAddress,reloc, reloc->SizeOfBlock);
		//下一个拷贝点
		CopyAddress += reloc->SizeOfBlock;
		//重定位表的大小
		AllSize += reloc->SizeOfBlock;
		//下一个重定位表
		reloc = PIMAGE_BASE_RELOCATION((DWORD)reloc + reloc->SizeOfBlock);
	}
	//将原先的重定位地址更换
	PIMAGE_DATA_DIRECTORY data = (PIMAGE_DATA_DIRECTORY)&(option_header->DataDirectory[5]);

	data->VirtualAddress = section_header->VirtualAddress + offset;
	ol.Offset = (DWORD)data - (DWORD)buf;
	DWORD writeSize = 0;
	WriteFile(hFile, &(data->VirtualAddress), 4, &writeSize, &ol);

	//将重定位表的信息写入新节中
	ol.Offset = section_header->PointerToRawData + offset;
	WriteFile(hFile, LPVOID((DWORD)buf + ol.Offset), AllSize, &writeSize, &ol);

	//补8个0
	return AllSize+8;
	
}

int _tmain(char* argv, char* args[]) {

	HANDLE hFile1 = CreateFile(path1, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hFile2 = CreateFile(path2, GENERIC_READ | GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	//新增一个节
	AddSection(hFile1, hFile2);
	//移动导出表信息至新的节中
	DWORD size = MoveEXPORT(hFile2);
	//移动重定位表至新的节中
	size += MoveReloc(hFile2, size);


	CloseHandle(hFile1);
	CloseHandle(hFile2);
	return 0;
}