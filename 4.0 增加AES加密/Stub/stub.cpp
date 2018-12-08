
#include "stub.h"
#include "AES.h"
// 合并.data到.text段
#pragma comment(linker,"/merge:.data=.text")
// 合并.rdata到.text段
#pragma comment(linker,"/merge:.rdata=.text")
// 将.text改成可读可写可执行
#pragma comment(linker, "/section:.text,RWE")



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
extern "C" __declspec(dllexport) void  Decrypt()
{
	//拿到代码段的首地址
	unsigned char* pText = (unsigned char*)g_conf.textScnRVA + 0x400000;

	//修改代码段的属性
	DWORD old = 0;
	MyVirtualProtect(pText,g_conf.textScnSize,PAGE_READWRITE,&old);

	//解密代码段
	AES aes(g_conf.key);
	aes.InvCipher(pText, g_conf.textScnSize);

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
	//给函数指针变量赋值
	//Kernel32
	MyLoadLibraryA = (FnLoadLibraryA)MyGetProcAddress(hKernel32, "LoadLibraryA");
	MyVirtualProtect = (FnVirtualProtect)MyGetProcAddress(hKernel32, "VirtualProtect");
	pfnGetMoudleHandleA = (fnGetMoudleHandleA)MyGetProcAddress(hKernel32, "GetModuleHandleA");
	pfnExitProcess = (fnExitProcess)MyGetProcAddress(hKernel32, "ExitProcess");
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
	HWND hWnd1 = pfnFindWindowW(NULL,L"吾愛破解 - FileCleaner2.0_pack.exe - [LCG -  主线程, 模块 - FileClea]");
	HWND hWnd2 = pfnFindWindowW(NULL,L"OllyDbg");
	HWND hWnd3 = pfnFindWindowW(NULL,L"15PBOD");
	if (hWnd1|| hWnd2|| hWnd3)
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
void _stdcall MixFun(DWORD funcAddress)
{
	__asm 
	{
		
	}
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
	//反调试
	AntiDebug();
	//密码弹框
	AlertPasswordBox();
	
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

