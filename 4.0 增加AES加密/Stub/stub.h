#pragma once
#include <windows.h>

typedef struct _StubConf
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小
	unsigned char key[16] = {};//解密密钥
}StubConf;
