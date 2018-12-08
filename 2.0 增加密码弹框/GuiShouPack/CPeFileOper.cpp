#include "CPeFileOper.h"



CPeFileOper::CPeFileOper()
{
}


CPeFileOper::~CPeFileOper()
{
}





//************************************************************
// 函数名称: OpenPeFile
// 函数说明: 打开PE文件
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_ const char* path 文件路径 
// 返 回 值: HANDLE 文件句柄
HANDLE CPeFileOper::OpenPeFile(_In_ const char* path) {
	return CreateFileA(path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}

//************************************************************
// 函数名称: GetFileData
// 函数说明: 获取文件内容和大小
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_ const char* pFilePath 文件路径 _Out_opt_ int* nFileSize 文件大小
// 返 回 值: char* 文件句柄
//************************************************************
char* CPeFileOper::GetFileData(_In_ const char* pFilePath,
	_Out_opt_ int* nFileSize) {
	// 打开文件
	HANDLE hFile = OpenPeFile(pFilePath);
	if (hFile == INVALID_HANDLE_VALUE)
		return NULL;
	// 获取文件大小
	DWORD dwSize = GetFileSize(hFile, NULL);
	if (nFileSize)
		*nFileSize = dwSize;
	// 申请对空间
	char* pFileBuff = new char[dwSize]{0};

	// 读取文件内容到堆空间
	DWORD dwRead = 0;
	ReadFile(hFile, pFileBuff, dwSize, &dwRead, NULL);
	CloseHandle(hFile);
	// 将堆空间返回
	return pFileBuff;
}


//************************************************************
// 函数名称: GetDosHeader
// 函数说明: 获取Dos头
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_  char* pFileData 文件首地址
// 返 回 值: IMAGE_DOS_HEADER* Dos头
//************************************************************
IMAGE_DOS_HEADER* CPeFileOper::GetDosHeader(_In_ char* pFileData)
{
	return (IMAGE_DOS_HEADER*)pFileData;
}

//************************************************************
// 函数名称: GetNtHeader
// 函数说明: 获取Nt头
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_  char* pFileData 文件首地址
// 返 回 值: IMAGE_FILE_HEADER* Nt头
//************************************************************
IMAGE_NT_HEADERS* CPeFileOper::GetNtHeader(_In_ char* pFileData)
{
	return (IMAGE_NT_HEADERS*)(GetDosHeader(pFileData)->e_lfanew+(SIZE_T)pFileData);
}

//************************************************************
// 函数名称: GetFileHead
// 函数说明: 获取文件头
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_  char* pFileData 文件首地址
// 返 回 值: IMAGE_FILE_HEADER* 文件头
//************************************************************
IMAGE_FILE_HEADER* CPeFileOper::GetFileHead(_In_ char* pFileData)
{
	return &GetNtHeader(pFileData)->FileHeader;
}



//************************************************************
// 函数名称: GetOptionHeader
// 函数说明: 获取可选头
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_  char* pFileData 文件首地址
// 返 回 值: IMAGE_OPTIONAL_HEADER* 可选头
//************************************************************
IMAGE_OPTIONAL_HEADER* CPeFileOper::GetOptionHeader(_In_ char* pFileData)
{
	return &GetNtHeader(pFileData)->OptionalHeader;
}

//************************************************************
// 函数名称: GetLastSection
// 函数说明: 获取最后一个区段
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数: _In_  char* pFileData 文件首地址
// 返 回 值: IMAGE_SECTION_HEADER* 区段头
//************************************************************
IMAGE_SECTION_HEADER* CPeFileOper::GetLastSection(_In_ char* pFileData)
{
	//获取区段个数
	DWORD dwScnCount = GetFileHead(pFileData)->NumberOfSections;
	//获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	//得到最后一个有效区段
	return pScn + (dwScnCount - 1);
}


//************************************************************
// 函数名称: AlignMent
// 函数说明: 计算对齐后的大小
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数1: _In_ int size 大小
// 参	 数2: _In_ int alignment 对齐粒度
// 返 回 值: int 对齐后的大小
//************************************************************
int CPeFileOper::AlignMent(_In_ int size, _In_ int alignment)
{
	return (size) % (alignment) == 0 ? (size) : ((size) / (alignment)+ 1)*(alignment);
}



//************************************************************
// 函数名称: GetSection
// 函数说明: 获取指定名字的区段头
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数1: _In_ char* pFileData 目标文件首地址
// 参	 数2:  _In_ const char* scnName 区段名
// 返 回 值: IMAGE_SECTION_HEADER* 区段头
//************************************************************
IMAGE_SECTION_HEADER* CPeFileOper::GetSection(_In_ char* pFileData, _In_ const char* scnName)
{
	//获取区段格式
	DWORD dwScnCount = GetFileHead(pFileData)->NumberOfSections;
	//获取第一个区段
	IMAGE_SECTION_HEADER* pScn = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));
	char buf[10] = { 0 };
	//遍历区段
	for (DWORD i=0;i< dwScnCount;i++)
	{
		memcpy_s(buf,8,(char*)pScn[i].Name,8);
		//判断是否有相同的名字
		if (strcmp(buf,scnName)==0)
		{
			return pScn + i;
		}
	}
	return nullptr;
}



//************************************************************
// 函数名称: AddSection
// 函数说明: 添加一个新的区段
// 作	 者: GuiShou
// 时	 间: 2018/12/1
// 参	 数1: char*& pFileBuff 文件缓冲区首地址
// 参	 数2: int& fileSize 文件大小
// 参	 数3: const char* scnName 要添加的区段名
// 参	 数4: int scnSize		 要添加的区段大小
// 返 回 值: void
//************************************************************
void CPeFileOper::AddSection(char*& pFileBuff, int& fileSize, const char* scnName, int scnSize)
{
	//增加文件头的区段个数
	GetFileHead(pFileBuff)->NumberOfSections++;
	//配置新区段的区段头
	IMAGE_SECTION_HEADER* pNewScn = NULL;
	pNewScn = GetLastSection(pFileBuff);
	//区段的名字
	memcpy(pNewScn->Name,scnName,8);
	//区段的大小(实际大小/对齐后的大小)
	pNewScn->Misc.VirtualSize = scnSize;
	pNewScn->SizeOfRawData = AlignMent(scnSize,GetOptionHeader(pFileBuff)->FileAlignment);
	//区段的位置(RVA/FOA)
	pNewScn->PointerToRawData = AlignMent(fileSize, GetOptionHeader(pFileBuff)->FileAlignment);
	//新区段的内存偏移=上一个区段的内存偏移+上一个区段的大小(内存对齐后的大小)------------------

	pNewScn->VirtualAddress = (pNewScn - 1)->VirtualAddress + AlignMent((pNewScn-1)->SizeOfRawData,GetOptionHeader(pFileBuff)->SectionAlignment);
	
	//区段的属性
	pNewScn->Characteristics = 0xE00000E0;

	//修改扩展头的映像大小
	GetOptionHeader(pFileBuff)->SizeOfImage =pNewScn->VirtualAddress + pNewScn->SizeOfRawData;

	//扩充文件数据的堆空间大小
	int newSize = pNewScn->PointerToRawData + pNewScn->SizeOfRawData;
	char* pNewBuff = new char[newSize]{0};
	memcpy(pNewBuff,pFileBuff,fileSize);
	//释放旧的缓冲区
	delete pFileBuff;

	//将新的缓冲区首地址和新文件的大小赋给形参(修改实参)
	fileSize = newSize;
	pFileBuff = pNewBuff;
}


//************************************************************
// 函数名称: SavePEFile
// 函数说明: 将文件保存到指定路径
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数1: char*& pFileBuff 文件缓冲区首地址
// 参	 数2: int& size 文件大小
// 参	 数3: _In_ const char*path 文件名
// 返 回 值: BOOL 保存文件是否成功
//************************************************************
BOOL CPeFileOper::SavePEFile(_In_ const char* pFileData, _In_ int size, _In_ const char*path)
{
	HANDLE hFile = CreateFileA( 
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile==INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	DWORD dwWrite = 0;
	//将内容写入到文件
	WriteFile(hFile,pFileData,size,&dwWrite,NULL);
	//关闭文件句柄
	CloseHandle(hFile);
	return dwWrite == size;

}


//************************************************************
// 函数名称: LoadStub
// 函数说明: 加载stub.dll
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数1: StubInfo* pStub 保存stub信息的结构体
// 返 回 值: void
//************************************************************
void CPeFileOper::LoadStub(StubInfo* pStub)
{
	//通过LoadLibarary加载stub.dll
	pStub->dllbase = (char*)LoadLibraryEx(L"stub.dll",NULL,DONT_RESOLVE_DLL_REFERENCES);

	//获取Dll导出函数
	pStub->pfnStart = (DWORD)GetProcAddress((HMODULE)pStub->dllbase,"Start");
	//获取StubConf结构体地址
	pStub->pStubConf = (StubConf*)GetProcAddress((HMODULE)pStub->dllbase,"g_conf");
}


//************************************************************
// 函数名称: Encrypt
// 函数说明: 加密目标程序的代码段
// 作	 者: GuiShou
// 时	 间: 2018/12/2
// 参	 数: _In_ const char* pFileData 目标文件缓冲区首地址
// 参	 数: _In_  StubInfo* pStub 保存stub配置信息的结构体
// 返 回 值: void
//************************************************************
void CPeFileOper::Encrypt(_In_ char* pFileData,_In_  StubInfo pStub)
{
	//代码段数据缓冲区的首地址
	 BYTE* pTargetText = GetSection(pFileData, ".text")->PointerToRawData + (BYTE*)pFileData;

	 //代码段大小
	 DWORD dwTargetTextSize = GetSection(pFileData,".text")->Misc.VirtualSize;
	 //加密代码段
	 for (DWORD i = 0; i < dwTargetTextSize; i++)
	 {
		 pTargetText[i] ^= 0x15;
	 }
	 //保存代码段开始的RVA和大小 以及加密密钥
	 pStub.pStubConf->textScnRVA = GetSection(pFileData,".text")->VirtualAddress;
	 pStub.pStubConf->textScnSize = dwTargetTextSize;
	 pStub.pStubConf->key = 0x15;
}



//************************************************************
// 函数名称: FixStubRelocation
// 函数说明: 修复stub.dll的重定位表
// 作	 者: GuiShou
// 时	 间: 2018/12/3
// 参	 数: DWORD stubDllbase stub.dll的基址
// 参	 数: DWORD stubTextRva stub.dll的代码段RVA
// 参	 数: DWORD targetDllbase 目标文件的默认加载基址
// 参	 数: DWORD targetNewScnRva 目标文件新区段的RVA
// 返 回 值: void
//************************************************************
 void CPeFileOper::FixStubRelocation(DWORD stubDllbase, DWORD stubTextRva, DWORD targetDllbase, DWORD targetNewScnRva)
 {
	//找到stub.dll的重定位表
	 DWORD dwRelRva = GetOptionHeader((char*)stubDllbase)->DataDirectory[5].VirtualAddress;
	 IMAGE_BASE_RELOCATION* pRel = (IMAGE_BASE_RELOCATION*)(dwRelRva+stubDllbase);
	
	 //遍历重定位表
	 while (pRel->SizeOfBlock)
	 {
		 struct TypeOffset
		 {
			 WORD offset : 12;
			 WORD type : 4;

		 };
		 TypeOffset* pTypeOffset = (TypeOffset*)(pRel + 1);
		 DWORD dwCount = (pRel->SizeOfBlock-8)/2;	//需要重定位的数量
		 for (DWORD i = 0; i < dwCount; i++)
		 {
			 if (pTypeOffset[i].type!=3)
			 {
				 continue;
			 }
			 //需要重定位的地址
			 DWORD* pFixAddr = (DWORD*)(pRel->VirtualAddress + pTypeOffset[i].offset + stubDllbase);

			 DWORD dwOld;
			 //修改属性为可写
			 VirtualProtect(pFixAddr,4,PAGE_READWRITE,&dwOld);
			 //去掉dll当前加载基址
			 *pFixAddr -= stubDllbase;
			 //去掉默认的段首RVA
			 *pFixAddr -= stubTextRva;
			 //换上目标文件的加载基址
			 *pFixAddr += targetDllbase;
			 //加上新区段的段首RVA
			 *pFixAddr += targetNewScnRva;
			 //把属性修改回去
			 VirtualProtect(pFixAddr, 4, dwOld, &dwOld);
		 }
		 //切换到下一个重定位块
		 pRel = (IMAGE_BASE_RELOCATION*)((DWORD)pRel + pRel->SizeOfBlock);
	 }

 }




 //************************************************************
// 函数名称: CompressPE
// 函数说明: 压缩PE文件
// 作	 者: GuiShou
// 时	 间: 2018/12/3
// 参	 数: _In_ char* pFileData 目标文件首地址
// 参	 数: StubInfo &pStubInfo stub区段的信息
// 返 回 值: void
//************************************************************
 void CPeFileOper::CompressPE(_In_ char* pFileData, StubInfo &pStubInfo)
 {
	 PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileData;
	 PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew+ pFileData);
	 PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	 //用于记录压缩区段的个数
	 pStubInfo.PackSectionNumber = 0;
	 //获取文件头的大小 并获取除资源段 .tls断之外段的文件的总大小
	 DWORD SecSizeWithoutResAndTls = 0;
	 PIMAGE_SECTION_HEADER pSectionTmp1 = pSection;
	 BOOL isFirstNoEmptySec = TRUE;
	 DWORD dwHeaderSize = 0;

	 //遍历所有区段
	 for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	 {
		 //用于获得第一个非空区段的文件偏移 也就是文件头的大小
		 if (isFirstNoEmptySec&&pSectionTmp1->SizeOfRawData!=0)
		 {
			 dwHeaderSize = pSectionTmp1->PointerToRawData;
			 isFirstNoEmptySec = FALSE;
		 }
		 //用于获取非rsrc/tls段的总大小
		 
	 }


 }


