#include<iostream>
#include<Windows.h>
#include<tchar.h>

DWORD PDE = 0, PTE = 0, PDE0 = 0, PTE0 = 0;
BOOLEAN isPS = FALSE;


//给0挂物理页
void fun1() {

	//开辟一块空间，等会儿挂给0号地址
	DWORD buf = (DWORD)VirtualAlloc(NULL, 1, MEM_COMMIT, PAGE_READWRITE);
	*(PDWORD)buf = 10;

	PDE = ((buf >> 18) & 0x3FF8) - 0x3FA00000;
	isPS = PDE & 0x80;					//是否开启ps,如果开启是另一种算法
	int temp1 = buf >> 9;
	temp1 &= 0x7FFFF8;
	PTE = temp1 - 0x40000000;		//这是什么算法，这太离谱了
	//int v7 = temp1 - 0x3FFFFFFC;		//用来判断PAT的，可以不写

	PDE0 = ((0 >> 18) & 0x3FF8) - 0x3FA00000;
	PTE0 = ((0 >> 9) & 0x7FFFF8) - 0x40000000;


}

//提权调用门
void __declspec(naked) fun2() {
	__asm {

		//简约版，不判断PDE了，一定存在
		//不判断PS了，一定是小页
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