#include <windows.h>
#include <stdio.h>
#include "CPeFileOper.h"



int main()
{
	CPeFileOper m_Pe;		//PE文件操作类对象

	char path[MAX_PATH] = "E:\\FileCleaner2.0.exe";
	// 1. 打开被加壳程序
	int nTargetSize = 0;
	char* pTargetBuff = m_Pe.GetFileData(path, &nTargetSize);
		
	//加载stub.dll
	StubInfo stub = { 0 };
	m_Pe.LoadStub(&stub);

	//加密所有区段
	m_Pe.Encrypt(pTargetBuff, stub);

	//清除数据目录表项
	m_Pe.ClearDataDir(pTargetBuff, stub);

	//添加新区段
	char cNewSectionName[] = {"GuiShou"};		//新区段名
	m_Pe.AddSection(pTargetBuff, nTargetSize, cNewSectionName,
		m_Pe.GetSection(stub.dllbase,".text")->Misc.VirtualSize);

	//修复重定位
	m_Pe.FixStubRelocation((DWORD)stub.dllbase,
		m_Pe.GetSection(stub.dllbase,".text")->VirtualAddress,
		m_Pe.GetOptionHeader(pTargetBuff)->ImageBase,
		m_Pe.GetSection(pTargetBuff, cNewSectionName)->VirtualAddress);

	//保存目标文件的OEP到stub的全局变量中
	stub.pStubConf->srcOep = m_Pe.GetOptionHeader(pTargetBuff)->AddressOfEntryPoint;

	//将stub.dll的代码段复制到新加的GuiShou段中
	memcpy(m_Pe.GetSection(pTargetBuff, cNewSectionName)->PointerToRawData+pTargetBuff,
		m_Pe.GetSection(stub.dllbase,".text")->VirtualAddress+stub.dllbase,
		m_Pe.GetSection(stub.dllbase,".text")->Misc.VirtualSize);

	//修改OEP OEP=start(VA)-dll加载基址-段首RVA+新区段的段首RVA
	m_Pe.GetOptionHeader(pTargetBuff)->AddressOfEntryPoint=
		stub.pfnStart-(DWORD)stub.dllbase
		-m_Pe.GetSection(stub.dllbase,".text")->VirtualAddress
		+m_Pe.GetSection(pTargetBuff, cNewSectionName)->VirtualAddress;

	//去掉随机基址
	m_Pe.GetOptionHeader(pTargetBuff)->DllCharacteristics &= (~0x40);

	//保存被加壳的程序
	m_Pe.SavePEFile(pTargetBuff,nTargetSize,"E:\\GuiShou_pack.exe");

	return 0;
}