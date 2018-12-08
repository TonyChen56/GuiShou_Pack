
#include "stub.h"
// 合并.data到.text段
#pragma comment(linker,"/merge:.data=.text")
// 合并.rdata到.text段
#pragma comment(linker,"/merge:.rdata=.text")
// 将.text改成可读可写可执行
#pragma comment(linker, "/section:.text,RWE")



//导出一个全局变量
extern "C" __declspec(dllexport)StubConf g_conf = {0};

//定义函数指针和变量
typedef void* (WINAPI *FnGetProcAddress)(HMODULE, const char*);
FnGetProcAddress MyGetProcAddress;

typedef void* (WINAPI *FnLoadLibraryA)(char*);
FnLoadLibraryA MyLoadLibraryA;

typedef void* (WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FnVirtualProtect MyVirtualProtect;


//************************************************************
// 函数名称: Decrypt
// 函数说明: 解密代码段
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数: void
// 返 回 值: void
//************************************************************
void Decrypt()
{
	unsigned char* pText = (unsigned char*)g_conf.textScnRVA + 0x400000;
	//修改代码段的属性
	DWORD old = 0;
	MyVirtualProtect(pText,g_conf.textScnSize,PAGE_READWRITE,&old);
	//解密代码段
	for (DWORD i = 0; i < g_conf.textScnSize; i++)
	{
		pText[i] ^= g_conf.key;
	}
	//把属性修改回去
	MyVirtualProtect(pText,g_conf.textScnSize,old,&old);

}


//************************************************************
// 函数名称: GetApis
// 函数说明: 获取API函数地址
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数: void
// 返 回 值: void
//************************************************************
void GetApis()
{
	HMODULE hKernel32;

	_asm
	{
		pushad;
		; //获取kernel32.dll的加载基址;
		;// 1. 找到PEB的首地址;
		mov eax, fs:[0x30]; eax = > peb首地址;
		; 2. 得到PEB.Ldr的值;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
		mov eax, [eax + 0ch]; eax = > PEB.Ldr的值;
		; 3. 得到_PEB_LDR_DATA.InLoadOrderMoudleList.Flink的值, 实际得到的就是主模块节点的首地址;
		mov eax, [eax]; eax = > _PEB_LDR_DATA.InLoadOrderMoudleList.Flink(NTDLL);
		; 4. 再获取下一个;
		mov eax, [eax]; _LDR_DATA_TABLE_ENTRY.InLoadOrderMoudleList.Flink(kernel32), ;
		mov eax, [eax + 018h]; _LDR_DATA_TABLE_ENTRY.DllBase;
		mov hKernel32, eax;;
		; 遍历导出表;
		; 1. dos头-- > nt头-- > 扩展头-- > 数据目录表;
		mov ebx, [eax + 03ch]; eax = > 偏移到NT头;
		add ebx, eax; ebx = > NT头的首地址;
		add ebx, 078h; ebx = >
			; 2. 得到导出表的RVA;
		mov ebx, [ebx];
		add ebx, eax; ebx == > 导出表首地址(VA);
		; 3. 遍历名称表找到GetProcAddress;
		; 3.1 找到名称表的首地址;
		lea ecx, [ebx + 020h];
		mov ecx, [ecx]; // ecx => 名称表的首地址(rva);
		add ecx, eax; // ecx => 名称表的首地址(va);
		xor edx, edx; // 作为index来使用.
		; 3.2 遍历名称表;
	_WHILE:;
		mov esi, [ecx + edx * 4]; esi = > 名称的rva;
		lea esi, [esi + eax]; esi = > 名称首地址;
		cmp dword ptr[esi], 050746547h; 47657450 726F6341 64647265 7373;
		jne _LOOP;
		cmp dword ptr[esi + 4], 041636f72h;
		jne _LOOP;
		cmp dword ptr[esi + 8], 065726464h;
		jne _LOOP;
		cmp word  ptr[esi + 0ch], 07373h;
		jne _LOOP;
		; 找到之后;
		mov edi, [ebx + 024h]; edi = > 名称的序号表的rva;
		add edi, eax; edi = > 名称的序号表的va;

		mov di, [edi + edx * 2]; 序号表是2字节的元素, 因此是 * 2;
		; edi保存的是GetProcAddress的在;
		; 地址表中的下标;
		and edi, 0FFFFh;
		; 得到地址表首地址;
		mov edx, [ebx + 01ch]; edx = > 地址表的rva;
		add edx, eax; edx = > 地址表的va;
		mov edi, [edx + edi * 4]; edi = > GetProcAddress的rva;
		add edi, eax; ; edx = > GetProcAddress的va;
		mov MyGetProcAddress, edi;
		jmp _ENDWHILE;
	_LOOP:;
		inc edx; // ++index;
		jmp _WHILE;
	_ENDWHILE:;
		popad;
 	}

	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibrary");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");

	//测试调用API

}



//************************************************************
// 函数名称: Start
// 函数说明: dll的OEP
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数: void
// 返 回 值: void
//************************************************************
extern "C" __declspec(dllexport) __declspec(naked)
void Start()
{
	//获取函数的API地址
	GetApis();
	//解密代码段
	Decrypt();
	//跳转到原始OEP
	__asm
	{
		mov eax, g_conf.srcOep;
		add eax,0x400000
		jmp eax
	}
}
