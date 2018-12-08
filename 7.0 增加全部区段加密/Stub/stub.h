#pragma once
#include <windows.h>

typedef struct _StubConf
{
	DWORD srcOep;		//入口点
	DWORD textScnRVA;	//代码段RVA
	DWORD textScnSize;	//代码段的大小

	unsigned char key[16] = {};//解密密钥
	int index = 0;			  //加密的区段数量 用的时候需要-1
	int data[20][2];  //加密的区段RVA和Size	

	DWORD dwDataDir[20][2];  //数据目录表的RVA和Size	
	DWORD dwNumOfDataDir;	//数据目录表的个数

	DWORD oep;
	DWORD nImportVirtual;
	DWORD nImportSize;
	DWORD nRelocVirtual;
	DWORD nRelocSize;
	DWORD nResourceVirtual;
	DWORD nResourceSize;
	DWORD nTlsVirtual;
	DWORD nTlsSize;

}StubConf;



typedef struct DosStub
{
	DWORD nOldImageBass;//被加壳程序运行前默认的加载基址
	DWORD nStubTextSectionRva;//壳在壳自身的text段Rva
	DWORD nStubRelocSectionRva;//壳的重定位表与text段合并后在被加壳程序的Rva

}DosSub;
