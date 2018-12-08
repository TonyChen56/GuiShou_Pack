#pragma once
#include <windows.h>

typedef struct _StubConf
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小
	DWORD key;			//解密密钥
}StubConf;

//保存stub.dll信息的结构体
struct StubInfo
{
	char* dllbase;			//stub.dll的加载基址
	DWORD pfnStart;			//stub.dll(start)导出函数的地址
	StubConf* pStubConf;	//stub.dll(g_conf)导出全局变量的地址
};