#pragma once
#include <windows.h>
#include "data.h"

class CPeFileOper
{
public:
	CPeFileOper();
	~CPeFileOper();
	//获取文件大小和内容
	char* GetFileData(_In_ const char* pFilePath, _Out_opt_ int* nFileSize = NULL);

	//打开磁盘中的一个PE文件
	HANDLE OpenPeFile(_In_ const char* path);

	//添加一个新区段
	void AddSection(char*& pFileBuff,int& fileSize,const char* scnName,int scnSize);

	//获取文件头
	IMAGE_FILE_HEADER* GetFileHead(_In_  char* pFileData);

	//获取Nt头
	IMAGE_NT_HEADERS* GetNtHeader(_In_ char* pFileData);

	//获取Dos头
	IMAGE_DOS_HEADER* GetDosHeader(_In_ char* pFileData);

	//获取可选头
	IMAGE_OPTIONAL_HEADER* GetOptionHeader(_In_ char* pFileData);

	//获取最后一个区段
	IMAGE_SECTION_HEADER* GetLastSection(_In_ char* pFileData);

	//计算对齐后的大小
	int AlignMent(_In_ int size,_In_ int alignment);

	//获取指定名字的区段头
	IMAGE_SECTION_HEADER* GetSection(_In_ char* pFileData,_In_ const char* scnName);

	//保存被加壳的程序
	BOOL SavePEFile(_In_ const char* pFileData,_In_ int size, _In_ const char*path);

	//加载stub.dll
	void LoadStub(StubInfo* pStub);

	//加密目标程序的所有区段
	void Encrypt(_In_ char* pFileData, _In_  StubInfo pStub);

	//清除数据目录表
	void ClearDataDir(_In_ char* pFileData, _In_  StubInfo pStub);

	//修复重定位
	void FixStubRelocation(DWORD stubDllbase,DWORD stubTextRva,DWORD targetDllbase,DWORD targetNewScnRva);
};

