#pragma once
#include <windows.h>

typedef struct _StubConf
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小
	unsigned char key[16] = {};//解密密钥
}StubConf;



typedef struct DosStub
{
	DWORD nOldImageBass;//被加壳程序运行前默认的加载基址
	DWORD nStubTextSectionRva;//壳在壳自身的text段Rva
	DWORD nStubRelocSectionRva;//壳的重定位表与text段合并后在被加壳程序的Rva

}DosSub;
