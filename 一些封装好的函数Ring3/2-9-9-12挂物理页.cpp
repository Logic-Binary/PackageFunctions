#include<iostream>
#include<Windows.h>
#include<tchar.h>

DWORD PDE = 0, PTE = 0, PDE0 = 0, PTE0 = 0;
BOOLEAN isPS = FALSE;


//��0������ҳ
void fun1() {

	//����һ��ռ䣬�Ȼ���Ҹ�0�ŵ�ַ
	DWORD buf = (DWORD)VirtualAlloc(NULL, 1, MEM_COMMIT, PAGE_READWRITE);
	*(PDWORD)buf = 10;

	PDE = ((buf >> 18) & 0x3FF8) - 0x3FA00000;
	isPS = PDE & 0x80;					//�Ƿ���ps,�����������һ���㷨
	int temp1 = buf >> 9;
	temp1 &= 0x7FFFF8;
	PTE = temp1 - 0x40000000;		//����ʲô�㷨����̫������
	//int v7 = temp1 - 0x3FFFFFFC;		//�����ж�PAT�ģ����Բ�д

	PDE0 = ((0 >> 18) & 0x3FF8) - 0x3FA00000;
	PTE0 = ((0 >> 9) & 0x7FFFF8) - 0x40000000;


}

//��Ȩ������
void __declspec(naked) fun2() {
	__asm {

		//��Լ�棬���ж�PDE�ˣ�һ������
		//���ж�PS�ˣ�һ����Сҳ
		mov eax, PTE;
		mov eax, [eax];
		mov ebx, PTE0;
		mov [ebx], eax;


		retf;
	}

}


int _tmain(char argc, char* argv[]) {

	fun1();
	//fun2();		//00411320
	//eq 80b95048 0041EC0000081320
	printf("%p\n", fun1);
	getchar();
	char door[] = { 0x00,0x00,0x00,0x00,0x48,0x00 };
	__asm {
		int 3;
		call fword ptr ds : [door] ;
	}
	printf("%d\n", *(PDWORD)0);
	system("pause");

	return 0;
}