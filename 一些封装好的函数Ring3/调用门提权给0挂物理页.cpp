#include<iostream>
#include<Windows.h>
#include<tchar.h>

UCHAR buf1[] = { 0x00,0x00,0x00,0x00,0x48,0x00 };
UCHAR buf2[] = { 0x00,0x00,0x00,0x00,0x48,0x00 };
DWORD pde = 0, pte = 0, pde0 = 0, pte0 = 0;
DWORD flag = 0;

void __declspec(naked) fun1() {
	//�۲��ջ�仯
	__asm {

		//�ж�0��PDE�Ƿ�Ϊ0
		mov eax, pde0;
		mov eax, [eax];
		test eax, eax;
		je end;
		//�ó�buf��PTE
		mov eax, pte;
		mov eax, [eax];
		//�޸�0��PTE
		mov ebx, pte0;
		mov dword ptr ds:[ebx], eax;

		mov eax, 1;
		mov flag, eax;
		retf;
	end:
		mov eax, 0;
		mov flag, eax;
		retf;
	}
}


//��0������ҳ
void physicalAddress() {
	LPVOID buf = VirtualAlloc(NULL, 4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	*(PDWORD)buf = 10;
	printf("%p\n", buf);
	//����buf��PDE��PTE(���ǵ�ַ����Ȩ����������������ֵ)
	pde = (DWORD)((((DWORD)buf >> 20) & 0xFFC) - 0x3FD00000);
	pte = (DWORD)((((DWORD)buf >> 10) & 0x3FFFFC) - 0x40000000);

	//����0��PDE��PTE(��ַ����Ȩ����������������ֵ)
	pde0 = 0xC0300000;
	pte0 = 0xC0000000;

}



int _tmain(char argc, char* argv[]) {

	//fun1();		//0x0041122b
	//������������DGT���±�Ϊ9�ĵط� 
	//0041EC00  0018   1212  ͬ��
	//		 3�������

	//�޲�
	/*__asm{
		int 3;
		call fword ptr ds:[buf1];
	}*/

	//�в�
	//����������        
	//eq 80b95048 0041EC000008122b     Խ��


	physicalAddress();
	getchar();



	__asm {
		int 3;
		call fword ptr ds : [buf1] ;
	}

	if (!flag) {
		system("pause");
		return 0;
	}

	*((PDWORD)0) = 100;
	printf("%d\n", *(PDWORD)0);
	system("pause");

	return 0;
}



