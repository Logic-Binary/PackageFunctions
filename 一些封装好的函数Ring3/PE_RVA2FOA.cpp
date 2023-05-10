DWORD RVA2FOA(LPVOID buf, LPVOID RVA) {
	PIMAGE_DOS_HEADER dos_header = PIMAGE_DOS_HEADER(buf);
	PIMAGE_NT_HEADERS nt_header = PIMAGE_NT_HEADERS((DWORD)buf + dos_header->e_lfanew);
	PIMAGE_FILE_HEADER file_header = PIMAGE_FILE_HEADER(&(nt_header->FileHeader));
	PIMAGE_OPTIONAL_HEADER option_header = PIMAGE_OPTIONAL_HEADER(&(nt_header->OptionalHeader));
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);
	
	if ((DWORD)RVA < section_header->VirtualAddress) {
		return (DWORD)RVA;
	}
	for (int i = 0; i < file_header->NumberOfSections; i++) {
		if ((DWORD)RVA >= section_header->VirtualAddress &&
			(DWORD)RVA < section_header->VirtualAddress + section_header->SizeOfRawData) {
			return ((DWORD)RVA - section_header->VirtualAddress + section_header->PointerToRawData);
		}
		section_header++;
	}
}
