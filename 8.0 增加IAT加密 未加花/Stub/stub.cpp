
#include "stub.h"
#include "AES.h"
// 合并.data到.text段
#pragma comment(linker,"/merge:.data=.text")
// 合并.rdata到.text段
#pragma comment(linker,"/merge:.rdata=.text")
// 将.text改成可读可写可执行
#pragma comment(linker, "/section:.text,RWE")




IMAGE_DOS_HEADER* GetDosHeader(char* pFileData)
{
	return (IMAGE_DOS_HEADER *)pFileData;
}
DosStub* GetDosSubHeader(char* pFileData)
{
	return (DosStub*)(pFileData + sizeof(IMAGE_DOS_HEADER));
}
IMAGE_NT_HEADERS* GetNtHeader(char* pFileData)
{
	return (IMAGE_NT_HEADERS*)(GetDosHeader(pFileData)->e_lfanew + (SIZE_T)pFileData);
}
IMAGE_FILE_HEADER* GetFileHeader(char* pFileData)
{
	return &GetNtHeader(pFileData)->FileHeader;
}
IMAGE_OPTIONAL_HEADER* GetOptionHeader(char* pFileData)
{
	return &GetNtHeader(pFileData)->OptionalHeader;
}


//导出一个全局变量
extern "C" __declspec(dllexport)StubConf g_conf = {0};



HINSTANCE g_hInstance;	//密码窗口实例句柄
HWND hEdit;				//输入密码窗口
BOOL bSuccess;			//密码验证	

//定义函数指针和变量
//Kernel32
typedef void* (WINAPI *FnGetProcAddress)(HMODULE, const char*);
FnGetProcAddress MyGetProcAddress;

typedef void* (WINAPI *FnLoadLibraryA)(char*);
FnLoadLibraryA MyLoadLibraryA;

typedef void* (WINAPI *FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
FnVirtualProtect MyVirtualProtect;

typedef HMODULE(WINAPI *fnGetMoudleHandleA)(_In_ LPCWSTR lpMoudleName);
fnGetMoudleHandleA pfnGetMoudleHandleA;


//User32
typedef ATOM(WINAPI *fnRegisterClassEx)(_In_ const WNDCLASSEX *lpwcx);
fnRegisterClassEx pfnRegisterClassEx;

typedef HWND(WINAPI *fnCreateWindowEx)(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCTSTR lpClassName,
	_In_opt_ LPCTSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int x,
	_In_ int y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam
	);
fnCreateWindowEx pfnCreateWindowEx;

typedef BOOL(*fnUpdateWindow)(HWND hWnd);
fnUpdateWindow pfnUpdateWindow;

typedef BOOL (WINAPI* fnShowWindow)(_In_ HWND hWnd,_In_ int nCmdShow);
fnShowWindow pfnShowWindow;

typedef BOOL (WINAPI* fnGetMessage)(_Out_ LPMSG lpMsg,_In_opt_ HWND hWnd,_In_ UINT wMsgFilterMin,_In_ UINT wMsgFilterMax);
fnGetMessage pfnGetMessage;

typedef BOOL (WINAPI* fnTranslateMessage)(_In_ CONST MSG *lpMsg);
fnTranslateMessage pfnTranslateMessage;

typedef LRESULT (WINAPI* fnDispatchMessageW)(_In_ CONST MSG *lpMsg);
fnDispatchMessageW pfnDispatchMessageW;

typedef int (WINAPI* fnGetWindowTextW)(_In_ HWND hWnd,_Out_writes_(nMaxCount) LPWSTR lpString,_In_ int nMaxCount);
fnGetWindowTextW pfnGetWindowTextW;

typedef void (WINAPI* fnExitProcess)(_In_ UINT uExitCode);
fnExitProcess pfnExitProcess;

typedef LRESULT (WINAPI* fnSendMessageW)(
	_In_ HWND hWnd,
	_In_ UINT Msg,
	_Pre_maybenull_ _Post_valid_ WPARAM wParam,
	_Pre_maybenull_ _Post_valid_ LPARAM lParam);
fnSendMessageW pfnSendMessageW;

typedef LRESULT (WINAPI* fnDefWindowProcW)(_In_ HWND hWnd,_In_ UINT Msg,_In_ WPARAM wParam,_In_ LPARAM lParam);
fnDefWindowProcW pfnDefWindowProcW;

typedef void (WINAPI* fnPostQuitMessage)(_In_ int nExitCode);
fnPostQuitMessage pfnPostQuitMessage;

typedef HWND (WINAPI* fnFindWindowW)(_In_opt_ LPCWSTR lpClassName,_In_opt_ LPCWSTR lpWindowName);
fnFindWindowW pfnFindWindowW;

typedef int (WINAPI* fnMessageBoxW)(_In_opt_ HWND hWnd,_In_opt_ LPCWSTR lpText,_In_opt_ LPCWSTR lpCaption,_In_ UINT uType);
fnMessageBoxW pfnMessageBoxW;

typedef HDC (WINAPI* fnBeginPaint)(_In_ HWND hWnd,_Out_ LPPAINTSTRUCT lpPaint);
fnBeginPaint pfnBeginPaint;

typedef BOOL (WINAPI* fnEndPaint)(_In_ HWND hWnd,_In_ CONST PAINTSTRUCT *lpPaint);
fnEndPaint pfnEndPaint;

typedef LPVOID(WINAPI* FnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
FnVirtualAlloc pfnVirtualAlloc;

typedef VOID(WINAPI* FnRtlMoveMemory)(LPVOID, LPVOID, SIZE_T);
FnRtlMoveMemory pfnRtlMoveMemory;

//窗口消息回调函数
LRESULT CALLBACK WndPrco(HWND,UINT,WPARAM,LPARAM);

//************************************************************
// 函数名称: Decrypt
// 函数说明: 解密代码段
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数: void
// 返 回 值: void
//************************************************************
void  Decrypt()
{
	//获取当前程序的基址
	DWORD dwBase = (DWORD)pfnGetMoudleHandleA(NULL);

	AES aes(g_conf.key);
	//循环解密所有区段
	DWORD old = 0;
	for (int i = 0; i < g_conf.index-1; i++)
	{
		//拿到所有区段的首地址和大小
		unsigned char* pSection = (unsigned char*)g_conf.data[i][0]+ dwBase;
		DWORD dwSectionSize = g_conf.data[i][1];

		//修改区段属性
		MyVirtualProtect(pSection, dwSectionSize, PAGE_EXECUTE_READWRITE, &old);

		//解密代码段
		aes.InvCipher(pSection, dwSectionSize);

		//把属性修改回去
		MyVirtualProtect(pSection, dwSectionSize, old, &old);
	}
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
	//给函数指针变量赋值
	//Kernel32
	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibraryA");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");
	pfnGetMoudleHandleA = (fnGetMoudleHandleA)MyGetProcAddress(hKernel32, "GetModuleHandleA");
	pfnExitProcess = (fnExitProcess)MyGetProcAddress(hKernel32, "ExitProcess");
	pfnVirtualAlloc = (FnVirtualAlloc)MyGetProcAddress(hKernel32, "VirtualAlloc");
	pfnRtlMoveMemory = (FnRtlMoveMemory)MyGetProcAddress(hKernel32, "RtlMoveMemory");
	HMODULE hUser32 = (HMODULE)MyLoadLibraryA((char*)"user32.dll");

	//User32
	pfnRegisterClassEx = (fnRegisterClassEx)MyGetProcAddress(hUser32, "RegisterClassExW");
	pfnCreateWindowEx = (fnCreateWindowEx)MyGetProcAddress(hUser32, "CreateWindowExW");
	pfnUpdateWindow = (fnUpdateWindow)MyGetProcAddress(hUser32, "UpdateWindow");
	pfnShowWindow=(fnShowWindow)MyGetProcAddress(hUser32, "ShowWindow");
	pfnGetMessage=(fnGetMessage)MyGetProcAddress(hUser32, "GetMessageW");
	pfnTranslateMessage=(fnTranslateMessage)MyGetProcAddress(hUser32, "TranslateMessage");
	pfnDispatchMessageW =(fnDispatchMessageW)MyGetProcAddress(hUser32, "DispatchMessageW");
	pfnGetWindowTextW =(fnGetWindowTextW)MyGetProcAddress(hUser32, "GetWindowTextW");
	pfnSendMessageW =(fnSendMessageW)MyGetProcAddress(hUser32, "SendMessageW");
	pfnDefWindowProcW =(fnDefWindowProcW)MyGetProcAddress(hUser32, "DefWindowProcW");
	pfnPostQuitMessage =(fnPostQuitMessage)MyGetProcAddress(hUser32, "PostQuitMessage");
	pfnFindWindowW =(fnFindWindowW)MyGetProcAddress(hUser32, "FindWindowW");
	pfnMessageBoxW =(fnMessageBoxW)MyGetProcAddress(hUser32, "MessageBoxW");
	pfnBeginPaint =(fnBeginPaint)MyGetProcAddress(hUser32, "BeginPaint");
	pfnEndPaint =(fnEndPaint)MyGetProcAddress(hUser32, "EndPaint");

}



//************************************************************
// 函数名称: MyWcscmp
// 函数说明: 自己实现的一个字符串比较函数
// 作	 者: GuiShou
// 时	 间: 2018/12/4
// 参	 数: const wchar_t * src, const wchar_t * dst
// 返 回 值: int 相等返回0 不相等返回1
//************************************************************
int MyWcscmp(const wchar_t * src, const wchar_t * dst)
{
	int ret = 0;
	while (!(ret = *(wchar_t *)src - *(wchar_t *)dst) && *dst)
		++src, ++dst;
	if (ret < 0)
		ret = -1;
	else if (ret > 0)
		ret = 1;
	return(ret);
}


//************************************************************
// 函数名称: AlertPasswordBox
// 函数说明: 密码弹框
// 作	 者: GuiShou
// 时	 间: 2018/12/4
// 参	 数: void
// 返 回 值: void
//************************************************************
void AlertPasswordBox()
{
	//注册窗口类
	g_hInstance = (HINSTANCE)pfnGetMoudleHandleA(NULL);
	WNDCLASSEX ws;
	ws.cbSize = sizeof(WNDCLASSEX);
	ws.hInstance = g_hInstance;
	ws.cbWndExtra = ws.cbClsExtra = NULL;
	ws.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
	ws.hIcon = NULL;
	ws.hIconSm = NULL;
	ws.hCursor = NULL;
	ws.style = CS_VREDRAW | CS_HREDRAW;
	ws.lpszMenuName = NULL;
	ws.lpfnWndProc = (WNDPROC)WndPrco;		//	回调函数
	ws.lpszClassName = TEXT("GuiShou");
	pfnRegisterClassEx(&ws);
	//创建窗口
	HWND hWnd = pfnCreateWindowEx(0,TEXT("GuiShou"),TEXT("密码弹框"),
		WS_OVERLAPPED|WS_VISIBLE,
		100,100,400,200,NULL,NULL,g_hInstance,NULL);
	//更新窗口
	//pfnUpdateWindow(hWnd);
	pfnShowWindow(hWnd, SW_SHOW);
	//消息处理
	MSG msg = { 0 };
	while (pfnGetMessage(&msg,NULL,NULL,NULL))
	{
		pfnTranslateMessage(&msg);
		pfnDispatchMessageW(&msg);
	}
}


//************************************************************
// 函数名称: AntiDebug
// 函数说明: 反调试
// 作	 者: GuiShou
// 时	 间: 2018/12/4
// 参	 数: void
// 返 回 值: void
//************************************************************
void AntiDebug()
{

	bool BeingDugged = false;
	__asm
	{
		mov eax, DWORD ptr fs : [0x30];//获取peb
		mov al, byte ptr ds : [eax + 0x02];//获取peb.beingdugged
		mov BeingDugged, al;
	}
	if (BeingDugged)
	{
		pfnMessageBoxW(NULL, L"镇定一下 你被调试了", L"注意", MB_OK);
	}

}


//************************************************************
// 函数名称: MixFun
// 函数说明: 混淆函数
// 作	 者: GuiShou
// 时	 间: 2018/12/4
// 参	 数: DWORD funcAddress 函数地址
// 返 回 值: void
//************************************************************
void _stdcall FusedFunc(DWORD funcAddress)
{
	_asm
	{
		jmp label1
		label2 :
		_emit 0xeb; //跳到下面的call
		_emit 0x04;
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //执行EB 02  也就是跳到下一句

														  //	call Init;// 获取一些基本函数的地址

														  // call下一条,用于获得eip
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		//-------跳到下面的call
		_emit 0xEB;
		_emit 0x0E;

		//-------花
		PUSH 0x0;
		PUSH 0x0;
		MOV EAX, DWORD PTR FS : [0];
		PUSH EAX;
		//-------花


		// fused:
		//作用push下一条语句的地址
		//pop eax;
		//add eax, 0x1b;
		/*push eax;*/
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];

		push funcAddress; //这里如果是参数传入的需要注意上面的add eax,??的??
		retn;

		jmp label3

			// 花
			_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		// 花


	label1:
		jmp label2
			label3 :
	}
}




//设置属性可写
void SetFileHeaderProtect(bool nWrite)
{
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);
	DWORD nOldProtect = 0;
	if (nWrite)
		MyVirtualProtect((LPVOID)ImageBase, 0x400, PAGE_EXECUTE_READWRITE, &nOldProtect);
	else
		MyVirtualProtect((LPVOID)ImageBase, 0x400, nOldProtect, &nOldProtect);
}



//************************************************************
// 函数名称: FixImportTable_Normal
// 函数说明: 修复IAT
// 作	 者: GuiShou
// 时	 间: 2018/12/7
// 参	 数: void
// 返 回 值: void
//************************************************************
void FixImportTable_Normal()
{
	//设置文件属性为可写
	SetFileHeaderProtect(true);
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptionHeader((char*)ImageBase)->DataDirectory[1].VirtualAddress)return;

	//导入表=导入表偏移+加载基址
	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptionHeader((char*)ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImp->Name)
	{
		//IAT=偏移加加载基址
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + ImageBase);
		if (pImp->OriginalFirstThunk == 0) // 如果不存在INT则使用IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + ImageBase);
		}

		// 加载dll
		hImpModule = (HMODULE)MyLoadLibraryA((char*)(pImp->Name + ImageBase));
		//导入函数地址
		while (pInt->u1.Function)
		{
			//判断导入的方式、序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (IMAGE_IMPORT_BY_NAME*)(pInt->u1.Function + ImageBase);
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);


			pIat->u1.Function = impAddress;
			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);
			++pInt;
			++pIat;
		}
		++pImp;
	}
	SetFileHeaderProtect(false);
}



DWORD EncryptFun(DWORD dwFunAddr)
{
	// 1.申请内存空间
	DWORD dwNewMem = (DWORD)pfnVirtualAlloc(NULL, 0x20, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// 2.加密函数地址
	//DWORD dwEncryptFunAddr = dwFunAddr ^ 0x15151515;
	DWORD dwEncryptFunAddr = 0;
	_asm
	{
		push eax;
		mov eax, dwFunAddr;
		xor eax, 0x15151515;
		mov dwEncryptFunAddr, eax;
		pop eax;
	}

	// 3.对OpCode[11]处的地址进行改写
	BYTE OpCode[] = {
					0xE8, 0x01, 0x00, 0x00,
					0x00, 0xE9, 0x58, 0xEB,
					0x01, 0xE8, 0xB8, 0x85,
					0xEE, 0xCB, 0x60, 0xEB,
					0x01, 0x15, 0x35, 0x15,
					0x15, 0x15, 0x15, 0xEB,
					0x01, 0xFF, 0x50, 0xEB,
					0x02, 0xFF, 0x15, 0xC3
	};
	OpCode[11] = dwEncryptFunAddr;					// 0x85
	OpCode[12] = dwEncryptFunAddr >> 0x08;			// 0xEE
	OpCode[13] = dwEncryptFunAddr >> 0x10;			// 0xCB
	OpCode[14] = dwEncryptFunAddr >> 0x18;			// 0x60

	// 4.将数据拷贝到申请的内存
	pfnRtlMoveMemory((LPVOID)dwNewMem, OpCode, 0x20);

	// 5.返回新的函数地址
	return dwNewMem;
}



//************************************************************
// 函数名称: EncodeIAT
// 函数说明: 加密IAT
// 作	 者: GuiShou
// 时	 间: 2018/12/7
// 参	 数: void
// 返 回 值: void
//************************************************************
void EncodeIAT()
{
	//设置文件属性为可写
	SetFileHeaderProtect(true);
	//获取当前程序的加载基址
	DWORD ImageBase = (DWORD)pfnGetMoudleHandleA(NULL);

	IMAGE_THUNK_DATA* pInt = NULL;
	IMAGE_THUNK_DATA* pIat = NULL;
	SIZE_T impAddress = 0;
	HMODULE	hImpModule = 0;
	DWORD dwOldProtect = 0;
	IMAGE_IMPORT_BY_NAME* pImpName = 0;

	if (!GetOptionHeader((char*)ImageBase)->DataDirectory[1].VirtualAddress)return;

	//导入表=导入表偏移+加载基址
	IMAGE_IMPORT_DESCRIPTOR* pImp = (IMAGE_IMPORT_DESCRIPTOR*)(GetOptionHeader((char*)ImageBase)->DataDirectory[1].VirtualAddress + ImageBase);


	while (pImp->Name)
	{
		//IAT=偏移加加载基址
		pIat = (IMAGE_THUNK_DATA*)(pImp->FirstThunk + ImageBase);
		if (pImp->OriginalFirstThunk == 0) // 如果不存在INT则使用IAT
		{
			pInt = pIat;
		}
		else
		{
			pInt = (IMAGE_THUNK_DATA*)(pImp->OriginalFirstThunk + ImageBase);
		}

		// 加载dll
		hImpModule = (HMODULE)MyLoadLibraryA((char*)(pImp->Name + ImageBase));
		//导入函数地址
		while (pInt->u1.Function)
		{
			//判断导入的方式、序号还是名称
			if (!IMAGE_SNAP_BY_ORDINAL(pInt->u1.Ordinal))
			{
				pImpName = (IMAGE_IMPORT_BY_NAME*)(pInt->u1.Function + ImageBase);
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)pImpName->Name);
			}
			else
			{
				impAddress = (SIZE_T)MyGetProcAddress(hImpModule, (char*)(pInt->u1.Function & 0xFFFF));
			}

			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), PAGE_READWRITE, &dwOldProtect);


			pIat->u1.Function = EncryptFun(impAddress);
			MyVirtualProtect(&pIat->u1.Function, sizeof(pIat->u1.Function), dwOldProtect, &dwOldProtect);
			++pInt;
			++pIat;
		}
		++pImp;
	}
	SetFileHeaderProtect(false);
}




//************************************************************
// 函数名称: RecoverDataDir
// 函数说明: 恢复数据目录表
// 作	 者: GuiShou
// 时	 间: 2018/12/4
// 参	 数: DWORD funcAddress 函数地址
// 返 回 值: void
//************************************************************
void RecoverDataDir()
{	
	//获取当前程序的加载基址
	char* dwBase = (char*)pfnGetMoudleHandleA(NULL);
	//获取数据目录表的个数
	DWORD dwNumOfDataDir = g_conf.dwNumOfDataDir;

	DWORD dwOldAttr = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = (GetOptionHeader(dwBase)->DataDirectory);
	//遍历数据目录表
	for (DWORD i = 0; i < dwNumOfDataDir; i++)
	{
		if (i == 2)
		{
			pDataDirectory++;
			continue;
		}

		//修改属性为可读可写
		MyVirtualProtect(pDataDirectory, 0x8, PAGE_EXECUTE_READWRITE, &dwOldAttr);

		//还原数据目录表项
		pDataDirectory->VirtualAddress = g_conf.dwDataDir[i][0];
		pDataDirectory->Size = g_conf.dwDataDir[i][1];

		//把属性修改回去
		MyVirtualProtect(pDataDirectory, 0x8, dwOldAttr, &dwOldAttr);

		pDataDirectory++;
	}
}




void CallTls()
{
	//获取当前程序的加载基址
	DWORD dwBase = (DWORD)pfnGetMoudleHandleA(NULL);
	//获取Tls表
	DWORD dwTlsRva = GetOptionHeader((char*)dwBase)->DataDirectory[9].VirtualAddress;
	if (dwTlsRva != 0)
	{
		PIMAGE_TLS_DIRECTORY pTlsTab = (PIMAGE_TLS_DIRECTORY)(dwTlsRva + dwBase);
		if (pTlsTab->AddressOfCallBacks == 0)
		{
			return;
		}
		DWORD nTlsCallBacks = *(DWORD*)pTlsTab->AddressOfCallBacks;
		__asm
		{
			cmp nTlsCallBacks, 0
			je ENDCALL
			push 0
			push 1
			push dwBase
			call nTlsCallBacks
			ENDCALL :
		}
	}
	
}



// 壳程序
int g_num11 = 10;
void AllFunc()
{
	// 递归执行10次后执行壳程序
	if (!g_num11)
	{
		_asm
		{
			nop
			mov   ebp, esp
			push - 1
			push   0
			push   0
			mov   eax, fs:[0]
			push   eax
			mov   fs : [0], esp
			sub   esp, 0x68
			push   ebx
			push   esi
			push   edi
			pop   eax
			pop   eax
			pop   eax
			add   esp, 0x68
			pop   eax
			mov   fs : [0], eax
			pop   eax

			sub g_num11, 1

			pop   eax
			pop   eax
			pop   eax
			mov   ebp, eax

			push AllFunc
			call FusedFunc
		}
	}

	//获取函数的API地址
	//FusedFunc((DWORD)GetApis);
	//
	////解密代码段
	//FusedFunc((DWORD)Decrypt);
	//
	////恢复数据目录表
	//FusedFunc((DWORD)RecoverDataDir);
	//
	////反调试
	//FusedFunc((DWORD)AntiDebug);
	//
	////密码弹框
	//FusedFunc((DWORD)AlertPasswordBox);
	//
	////调用Tls回调函数
	//FusedFunc((DWORD)CallTls);
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

	// 花指令
	//_asm
	//{
	//	PUSH - 1
	//	PUSH 0
	//	PUSH 0
	//	MOV EAX, DWORD PTR FS : [0]
	//	PUSH EAX
	//	MOV DWORD PTR FS : [0], ESP
	//	SUB ESP, 0x68
	//	PUSH EBX
	//	PUSH ESI
	//	PUSH EDI
	//	POP EAX
	//	POP EAX
	//	POP EAX
	//	ADD ESP, 0x68
	//	POP EAX
	//	MOV DWORD PTR FS : [0], EAX
	//	POP EAX
	//	POP EAX
	//	POP EAX
	//	POP EAX
	//	MOV EBP, EAX
	//}
	//
	//// 执行壳
	//FusedFunc((DWORD)AllFunc);

	//获取函数的API地址
	GetApis();
	//解密代码段
	Decrypt();
	//恢复数据目录表
	RecoverDataDir();
	//修复IAT
	FixImportTable_Normal();
	//反调试
	AntiDebug();
	//密码弹框
	AlertPasswordBox();
	//调用Tls回调函数
	CallTls();
	//加密IAT
	EncodeIAT();

	//跳转到原始OEP
	__asm
	{
		mov eax, g_conf.srcOep;
		add eax,0x400000
		jmp eax
	}
}


//************************************************************
// 函数名称: WndPrco
// 函数说明: 窗口回调函数
// 作	 者: GuiShou
// 时	 间: 2018/12/4
// 参	 数: HWND, UINT, WPARAM, LPARAM
// 返 回 值: LRESULT
//************************************************************
LRESULT CALLBACK WndPrco(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	HDC hdc;
	PAINTSTRUCT ps;
	switch (msg)
	{
	case WM_CREATE:
	{
		pfnCreateWindowEx(0,L"button",L"确定",WS_CHILD|WS_VISIBLE,
			70,115,60,30,hWnd,(HMENU)10001,g_hInstance,NULL);
		pfnCreateWindowEx(0, L"button", L"取消", WS_CHILD | WS_VISIBLE,
			270, 115, 60, 30, hWnd, (HMENU)10002, g_hInstance, NULL);
		hEdit = pfnCreateWindowEx(0, L"edit", L"", WS_CHILD | WS_VISIBLE|WS_BORDER,
			150, 50, 100, 30, hWnd, (HMENU)10003, g_hInstance, NULL);
		HWND hBit = pfnCreateWindowEx(0, L"static", L"密码", WS_CHILD | WS_VISIBLE,
			70, 50, 70, 30, hWnd, (HMENU)10004, g_hInstance, NULL);
		bSuccess = FALSE;
		break;
	}
	case  WM_COMMAND:
	{
		WORD wHigh = HIWORD(wParam);
		WORD wLow = LOWORD(wParam);
		switch (wLow)
		{
		case 10001:
		{
			TCHAR GetKey[10] = { 0 };
			pfnGetWindowTextW(hEdit,GetKey,10);
			//如果密码等于123
			if (MyWcscmp(GetKey,L"123")==0)
			{
				bSuccess = TRUE;
				//如果密码匹配 正常运行
				pfnSendMessageW(hWnd,WM_CLOSE,NULL,NULL);
			}
			else
			{
				//密码不匹配退出程序
				pfnExitProcess(1);
			}
			break;
		}
		case 10002:		//取消按钮
		{
			pfnExitProcess(1);
			break;
		}
			
		default:
			break;
		}
		break;
	}
	case WM_PAINT:
	{
		hdc = pfnBeginPaint(hWnd, &ps);
		// TODO:  在此添加任意绘图代码...
		pfnEndPaint(hWnd, &ps);
		break;
	}
	case WM_CLOSE:case WM_QUIT:case WM_DESTROY:
	{
		if (bSuccess)
		{
			pfnPostQuitMessage(0);
		}
		else
		{
			pfnExitProcess(1);
		}
	}

	default:
		return pfnDefWindowProcW(hWnd,msg,wParam,lParam);
	}
	return 0;
}

