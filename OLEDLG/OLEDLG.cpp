////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 头文件
#include "pch.h"
#include "OLEDLG.h"
#include "PEB.h"
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 原函数地址指针
PVOID pfnOleUIAddVerbMenuA;
PVOID pfnOleUICanConvertOrActivateAs;
PVOID pfnOleUIInsertObjectA;
PVOID pfnOleUIPasteSpecialA;
PVOID pfnOleUIEditLinksA;
PVOID pfnOleUIChangeIconA;
PVOID pfnOleUIConvertA;
PVOID pfnOleUIBusyA;
PVOID pfnOleUIUpdateLinksA;
PVOID pfnOleUIPromptUserA;
PVOID pfnOleUIObjectPropertiesA;
PVOID pfnOleUIChangeSourceA;
PVOID pfnOleUIAddVerbMenuW;
PVOID pfnOleUIBusyW;
PVOID pfnOleUIChangeIconW;
PVOID pfnOleUIChangeSourceW;
PVOID pfnOleUIConvertW;
PVOID pfnOleUIEditLinksW;
PVOID pfnOleUIInsertObjectW;
PVOID pfnOleUIObjectPropertiesW;
PVOID pfnOleUIPasteSpecialW;
PVOID pfnOleUIPromptUserW;
PVOID pfnOleUIUpdateLinksW;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 自定义函数
//int dword_20002000; // weak
LPVOID vax_hMem = NULL;
//int dword_20002004; // weak
INT vax_dwSize = 0;
//int dword_20002008; // weak
HMODULE ole_hModule = NULL;	// oledlg 原始模块句柄
//char byte_2000200C; // weak
INT vax_index = 0;
//int dword_20002010; // weak
LPVOID vax_lpMem = NULL;
//int dword_20002014; // weak
HMODULE vax_hModule = NULL;	// VA_X 模块句柄
//int dword_20002018; // weak
HMODULE curr_hModule = NULL;	// 进程句柄

CONST CHAR* oPublicKeyX = "4065234961,2221233238252903594850812155620126,3175203956977476891557515669668792";
CONST CHAR* oPublicKeyY = "1329115615,9626603984703850283064885442292035,3463780848057510008753765087591958";
CONST CHAR* cPublicKeyX = "2127088620,2558213661223504372788100802238141,2694097057723490910395353919176313";
CONST CHAR* cPublicKeyY = "2127088620,8809976404932220599325753072055172,1929719295914332726580392022338415";

#define OUTPUT_DEBUG_PRINTF(str) DebugOut(str)
#define PUT_PUT_DEBUG_BUF_LEN 255
void DebugOut(const char* strOutputString, ...)
{
	CHAR strBuffer[PUT_PUT_DEBUG_BUF_LEN] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	_vsnprintf_s(strBuffer, sizeof(strBuffer) - 1, strOutputString, vlArgs);  //_vsnprintf_s  _vsnprintf
	//vsprintf(strBuffer,strOutputString,vlArgs);
	va_end(vlArgs);
	OutputDebugStringA(strBuffer);  //OutputDebugString    // OutputDebugStringW
}

VOID HideModule()
{
	PEB* peb;
	PLIST_ENTRY Head, Cur;
	PPEB_LDR_DATA ldr;
	PLDR_MODULE ldm;
	
	//获取PEB结构
	//__asm
	//{
	//	mov eax, fs:[0x30]
	//	mov peb, eax
	//}
	
#if defined(_M_X64)
	peb = (PEB*)__readgsqword(0x60);
#elif defined(_M_IX86)
	peb = (PEB*)__readfsdword(0x30);
#endif

	ldr = peb->Ldr;                                                      //获取_PEB_LDR_DATA结构
	Head = &(ldr->InMemoryOrderModuleList);                              //获取模块链表地址
	Cur = Head->Flink;                                                   //获取指向的结点.

	do
	{
		ldm = CONTAINING_RECORD(Cur, LDR_MODULE, InMemoryOrderModuleList);//获取 _LDR_DATA_TABLE_ENTRY结构体地址
																		 //printf("EntryPoint [0x%X]\n",ldm->BaseAddress);
		if (ldm->BaseAddress == curr_hModule)                            //判断要隐藏的DLL基址跟结构中的基址是否一样
		{                                                                //如果进入.则标志置为1,表示已经开始进行隐藏了.
			*(CHAR*)ldm->BaseDllName.Buffer = '_';
			break;
		}
		Cur = Cur->Flink;
	} while (Head != Cur);
}

INT EncryptName(LPCSTR lpProcName)
{
	INT result = 0;
	while (*lpProcName)
		result = _rotl((*lpProcName++ | 0x20) + result, 0x0D);

	return result;
}

#pragma warning (disable:4996)
VOID repl_PublicKey(LPVOID lpMem)
{
	//DebugOut("lpMem | 0x%08X | %hs", lpMem, lpMem);
	//DebugOut("vax_hMem | 0x%08X | %hs", vax_hMem, vax_hMem);

	if (vax_hMem && lpMem && *(CHAR*)lpMem == 'x'/*0x78*/)	// 'x'
	{
		DebugOut("rpl_PublicKey : [lpMem][0x%.8X][%hs]", lpMem, lpMem);
		DebugOut("rpl_PublicKey : [vax_hMem][0x%.8X],[vax_dwSize][0x%.8X]", vax_hMem, vax_dwSize);

		INT szcp = 0;

		do
		{
			if (*(CHAR*)vax_hMem == '1')
			{
				if (!strnicmp((CONST CHAR*)vax_hMem, oPublicKeyY, 11))
				{
					DebugOut("rpl_PublicKey : [oPublicKeyY][0x%.8X][%.80hs]", vax_hMem, vax_hMem);
					vax_index++;
					strcpy((CHAR*)vax_hMem, cPublicKeyY);
					*(DWORD*)&vax_hMem += 0x50;
					szcp++;
					if (szcp >= 2) break;
				}
			}

			if (*(CHAR*)vax_hMem == '4')
			{
				if (!strnicmp((CONST CHAR*)vax_hMem, oPublicKeyX, 11))
				{
					DebugOut("rpl_PublicKey : [oPublicKeyX][0x%.8X][%.80hs]", vax_hMem, vax_hMem);
					vax_index++;
					strcpy((CHAR*)vax_hMem, cPublicKeyX);
					*(DWORD*)&vax_hMem += 0x50;
					szcp++;
					if (szcp >= 2) break;
				}
			}

			*(DWORD*)&vax_hMem += 1;
			vax_dwSize--;
		} while (vax_dwSize >= 0x50);

		vax_hMem = NULL;
		vax_dwSize = 0;
	}
}
#pragma warning (default:4996)

VOID rem_HookModule()
{
	RemoveImport(vax_hModule, "kernel32.dll", "GetProcAddress", (INT_PTR)fn_GetProcAddress);
	RemoveImport(vax_hModule, "kernel32.dll", "VirtualAlloc", (INT_PTR)fn_VirtualAlloc);
}

//WINBASEAPI
_Ret_maybenull_
HMODULE WINAPI fn_LoadLibraryA(_In_ LPCSTR lpLibFileName)
{
	//DebugOut("fn_LoadLibraryA : [%hs]", lpLibFileName);
	HMODULE hModule = LoadLibraryA(lpLibFileName);

	if (hModule && hModule == curr_hModule)
	{
		FreeLibrary(hModule);
		rem_HookModule();
		HideModule();
		hModule = ole_hModule;
	}

	return hModule;
}

//WINBASEAPI
FARPROC WINAPI fn_GetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName)
{
	FARPROC fpAddress = GetProcAddress(hModule, lpProcName);
	//DebugOut("fn_GetProcAddress | 0x%08X | %hs", fpAddress, lpProcName);

	if (fpAddress && (UINT)lpProcName > 0xFFFF)
	{
		//DebugOut("fn_GetProcAddress : [%hs]", lpProcName);

		INT EnCrc = EncryptName(lpProcName);
		switch (EnCrc)
		{
		case 0xFEECC773:	// LoadLibraryA
			//DebugOut("fn_GetProcAddress : [Hook][LoadLibraryA]");
			fpAddress = (FARPROC)&fn_LoadLibraryA;
			break;
		case 0xD7E8FBC6:	// HeapAlloc
			//DebugOut("fn_GetProcAddress : [Hook][HeapAlloc]");
			fpAddress = (FARPROC)&fn_HeapAlloc;
			break;
		case 0xC28581E4:	// HeapFree
			//DebugOut("fn_GetProcAddress : [Hook][HeapFree]");
			fpAddress = (FARPROC)&fn_HeapFree;
			break;
		}
	}

	return fpAddress;
}

//WINBASEAPI
_Ret_maybenull_
_Post_writable_byte_size_(dwSize)
LPVOID WINAPI fn_VirtualAlloc(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect)
{
	LPVOID lpMem = VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	//DebugOut("fn_VirtualAlloc | 0x%08X | %hs", lpMem, lpMem);
	
	if (!vax_lpMem && lpMem)
		vax_lpMem = lpMem;

	return lpMem;
}

//WINBASEAPI
_Ret_maybenull_
_Post_writable_byte_size_(dwBytes)
LPVOID WINAPI fn_HeapAlloc(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes)
{
	LPVOID icmpbuf = HeapAlloc(hHeap, dwFlags, dwBytes);
	//DebugOut("fn_HeapAlloc | 0x%08X | 0x%08X | %hs", icmpbuf, dwBytes, icmpbuf);
	
	if (!vax_index && icmpbuf && dwBytes == 0xFFFF)
	{
		vax_hMem = icmpbuf;
		vax_dwSize = (INT)dwBytes;
	}
	return icmpbuf;
}

////NTSYSAPI
//PVOID fn_RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
//{
//}

//WINBASEAPI
_Success_(return != FALSE)
BOOL WINAPI fn_HeapFree(_Inout_ HANDLE hHeap, _In_ DWORD dwFlags, __drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem)
{
	//DebugOut("fn_HeapFree | 0x%08X", lpMem);

	repl_PublicKey(lpMem);
	return HeapFree(hHeap, dwFlags, lpMem);
}

//BOOLEAN RtlFreeHeap(_In_ PVOID HeapHandle, _In_opt_ ULONG Flags, _In_ PVOID HeapBase)
//{
//}

// 调用代码
//HookImage("ZwSetInformationFile", (DWORD)MyZwSetInformationFile);
//HookImage("NtTerminateProcess", (DWORD)MyNtTerminateProcess);
//HookImage("NtTerminateThread", (DWORD)MyNtTerminateThread);
//HookImport("kernel32.dll", "ExitProcess", (DWORD)MyNtTerminateProcess);
//RemoveImage("NtTerminateProcess");

/********************************************
挂钩目标程序kernel32.dll里面输入的ntdll.dll的函数
********************************************/
BOOL HookImage(LPCSTR szName, DWORD Newfunc)
{
	HMODULE hMod = LoadLibrary(TEXT("NTDLL"));
	DWORD RealAddr = (DWORD)GetProcAddress(hMod, szName);
	ULONG Size = 0;
	DWORD protect;

	hMod = LoadLibrary(TEXT("kernel32.dll"));
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size);
	if (pImport == NULL)
	{
		return FALSE;
	}

	PIMAGE_THUNK_DATA32 Pthunk = (PIMAGE_THUNK_DATA32)((DWORD)hMod + pImport->FirstThunk);
	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(Pthunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

	while (Pthunk->u1.Function)
	{
		if (RealAddr == Pthunk->u1.Function)
		{
			Pthunk->u1.Function = Newfunc;
			break;
		}
		Pthunk++;
	}

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &protect);

	return TRUE;
}

/********************************************
清除目标程序的ntdll的函数名字
********************************************/
BOOL RemoveImage(LPCSTR szName)
{
	HMODULE hMod = LoadLibrary(TEXT("kernel32.dll"));
	ULONG Size = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hMod, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size);
	DWORD* pName = (DWORD*)((DWORD)hMod + pImport->OriginalFirstThunk);

	while (pName)
	{
		LPSTR pAddr = (LPSTR)(*pName + (DWORD)hMod + 2);
		if (_stricmp(pAddr, szName) == 0)
		{
			DWORD Protect;
			VirtualProtect(pAddr, strlen(pAddr), PAGE_READWRITE, &Protect);
			memset(pAddr, 0, strlen(pAddr));
			VirtualProtect(pAddr, strlen(pAddr), Protect, pName);
			break;
		}
		pName++;
	}

	return TRUE;
}

/********************************************
挂钩目标程序输入表里面的函数
********************************************/
BOOL HookImport(HMODULE hModule, LPCSTR szDLL, LPCSTR szName, INT_PTR Newfunc)
{
	ULONG Size = 0;
	DWORD protect;
	MEMORY_BASIC_INFORMATION mbi;
	if (!hModule) return FALSE;

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size);

	////改写内存保护，以便转换大小写 
	VirtualQuery(pImport, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

	while (pImport->Name)
	{
		LPCSTR pszModName = (LPCSTR)((PBYTE)hModule + pImport->Name);
		if (_stricmp(pszModName, szDLL) == 0)
		{
			break;
		}
		pImport++;
	}

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &protect);
	////改写内存保护结束，改回原来的保护

	HMODULE m_hModule = LoadLibraryA(szDLL);
	if (!pImport || !m_hModule) return FALSE;

	INT_PTR RealAddr = (INT_PTR)GetProcAddress(m_hModule, szName);

	PIMAGE_THUNK_DATA Pthunk = (PIMAGE_THUNK_DATA)((INT_PTR)hModule + pImport->FirstThunk);

	////改写内存保护，以便写入函数地址
	VirtualQuery(Pthunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

	while (Pthunk->u1.Function)
	{
		if (RealAddr == Pthunk->u1.Function)
		{
			Pthunk->u1.Function = Newfunc;
			break;
		}
		Pthunk++;
	}

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &protect);
	////改写内存保护，改回原来的保护

	return TRUE;
}

BOOL RemoveImport(HMODULE hModule, LPCSTR szDLL, LPCSTR szName, INT_PTR Newfunc)
{
	ULONG Size = 0;
	DWORD protect;
	MEMORY_BASIC_INFORMATION mbi;
	if (!hModule) return FALSE;

	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &Size);

	////改写内存保护，以便转换大小写 
	VirtualQuery(pImport, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

	while (pImport->Name)
	{
		LPCSTR pszModName = (LPCSTR)((PBYTE)hModule + pImport->Name);
		if (_stricmp(pszModName, szDLL) == 0)
		{
			break;
		}
		pImport++;
	}

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &protect);
	////改写内存保护结束，改回原来的保护

	HMODULE m_hModule = LoadLibraryA(szDLL);
	if (!pImport || !m_hModule) return FALSE;

	INT_PTR RealAddr = (INT_PTR)GetProcAddress(m_hModule, szName);

	PIMAGE_THUNK_DATA Pthunk = (PIMAGE_THUNK_DATA)((INT_PTR)hModule + pImport->FirstThunk);

	////改写内存保护，以便写入函数地址
	VirtualQuery(Pthunk, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &mbi.Protect);

	while (Pthunk->u1.Function)
	{
		if (Newfunc == Pthunk->u1.Function)
		{
			Pthunk->u1.Function = RealAddr;
			break;
		}
		Pthunk++;
	}

	VirtualProtect(mbi.BaseAddress, mbi.RegionSize, mbi.Protect, &protect);
	////改写内存保护，改回原来的保护

	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// OLEDLG 命名空间
namespace OLEDLG
{
	// 获取原始函数地址
	FARPROC WINAPI GetAddress(PCSTR pszProcName)
	{
		FARPROC fpAddress;
		CHAR szProcName[16];
		TCHAR tzTemp[MAX_PATH];

		fpAddress = GetProcAddress(ole_hModule, pszProcName);
		if (fpAddress == NULL)
		{
			if (HIWORD(pszProcName) == 0)
			{
#pragma warning(disable: 6273)
				wsprintfA(szProcName, "%d", pszProcName);
#pragma warning(default: 6273)
				pszProcName = szProcName;
			}

			wsprintf(tzTemp, TEXT("无法找到函数 %hs，程序无法正常运行。"), pszProcName);
			MessageBox(NULL, tzTemp, TEXT("OLEDLG"), MB_ICONSTOP);
			ExitProcess(-2);
		}

		return fpAddress;
	}

	// 初始化原始函数地址指针
	inline VOID WINAPI InitializeAddresses()
	{
		pfnOleUIAddVerbMenuA = GetAddress("OleUIAddVerbMenuA");
		pfnOleUICanConvertOrActivateAs = GetAddress("OleUICanConvertOrActivateAs");
		pfnOleUIInsertObjectA = GetAddress("OleUIInsertObjectA");
		pfnOleUIPasteSpecialA = GetAddress("OleUIPasteSpecialA");
		pfnOleUIEditLinksA = GetAddress("OleUIEditLinksA");
		pfnOleUIChangeIconA = GetAddress("OleUIChangeIconA");
		pfnOleUIConvertA = GetAddress("OleUIConvertA");
		pfnOleUIBusyA = GetAddress("OleUIBusyA");
		pfnOleUIUpdateLinksA = GetAddress("OleUIUpdateLinksA");
		pfnOleUIPromptUserA = GetAddress("OleUIPromptUserA");
		pfnOleUIObjectPropertiesA = GetAddress("OleUIObjectPropertiesA");
		pfnOleUIChangeSourceA = GetAddress("OleUIChangeSourceA");
		pfnOleUIAddVerbMenuW = GetAddress("OleUIAddVerbMenuW");
		pfnOleUIBusyW = GetAddress("OleUIBusyW");
		pfnOleUIChangeIconW = GetAddress("OleUIChangeIconW");
		pfnOleUIChangeSourceW = GetAddress("OleUIChangeSourceW");
		pfnOleUIConvertW = GetAddress("OleUIConvertW");
		pfnOleUIEditLinksW = GetAddress("OleUIEditLinksW");
		pfnOleUIInsertObjectW = GetAddress("OleUIInsertObjectW");
		pfnOleUIObjectPropertiesW = GetAddress("OleUIObjectPropertiesW");
		pfnOleUIPasteSpecialW = GetAddress("OleUIPasteSpecialW");
		pfnOleUIPromptUserW = GetAddress("OleUIPromptUserW");
		pfnOleUIUpdateLinksW = GetAddress("OleUIUpdateLinksW");
	}
	
	// 加载原始模块
	inline BOOL WINAPI Load(HMODULE hModule)
	{
		TCHAR tzPath[MAX_PATH];
		TCHAR tzTemp[MAX_PATH * 2];

		GetSystemDirectory(tzPath, MAX_PATH);
		lstrcat(tzPath, TEXT("\\oledlg.dll"));
		ole_hModule = LoadLibrary(tzPath);
		if (ole_hModule == NULL)
		{
			wsprintf(tzTemp, TEXT("无法加载 %s，程序无法正常运行。"), tzPath);
			MessageBox(NULL, tzTemp, TEXT("OLEDLG"), MB_ICONSTOP);
		}
		else
		{
			InitializeAddresses();

			curr_hModule = hModule;
			vax_hModule = GetModuleHandle(TEXT("VA_X"));

			HookImport(vax_hModule, "kernel32.dll", "GetProcAddress", (INT_PTR)fn_GetProcAddress);
			HookImport(vax_hModule, "kernel32.dll", "VirtualAlloc", (INT_PTR)fn_VirtualAlloc);
		}

		return (ole_hModule != NULL);
	}
		
	// 释放原始模块
	inline VOID WINAPI Free()
	{
		if (ole_hModule)
		{
			FreeLibrary(ole_hModule);
		}
	}
}
using namespace OLEDLG;
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 入口函数
#ifdef _DEBUG
int main(int argc, PTSTR argv[])
{
	TCHAR tzTemp[MAX_PATH * 2];

	vax_hModule = LoadLibrary(TEXT("C:\\Users\\lvtx\\AppData\\Local\\Microsoft\\VisualStudio\\16.0_fff0df99\\Extensions\\lamnofad.jeo\\VA_X"));

	wsprintf(tzTemp, TEXT("VA_X.dll hModule: 0x%08X"), vax_hModule);
	MessageBox(NULL, tzTemp, TEXT("OLEDLG"), MB_ICONSTOP);

	HookImport(vax_hModule, "kernel32.dll", "GetProcAddress", (INT_PTR)fn_GetProcAddress);
	HookImport(vax_hModule, "kernel32.dll", "VirtualAlloc", (INT_PTR)fn_VirtualAlloc);

	system("pause");

	return 0;
}
#else
BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, PVOID pvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		return Load(hModule);
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		Free();
	}

	return TRUE;
}
#endif // _DEBUG
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIAddVerbMenuA(void)
{
	prevFunc();
	setFunc(&pfnOleUIAddVerbMenuA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUICanConvertOrActivateAs(void)
{
	prevFunc();
	setFunc(&pfnOleUICanConvertOrActivateAs);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIInsertObjectA(void)
{
	prevFunc();
	setFunc(&pfnOleUIInsertObjectA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIPasteSpecialA(void)
{
	prevFunc();
	setFunc(&pfnOleUIPasteSpecialA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIEditLinksA(void)
{
	prevFunc();
	setFunc(&pfnOleUIEditLinksA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIChangeIconA(void)
{
	prevFunc();
	setFunc(&pfnOleUIChangeIconA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIConvertA(void)
{
	prevFunc();
	setFunc(&pfnOleUIConvertA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIBusyA(void)
{
	prevFunc();
	setFunc(&pfnOleUIBusyA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIUpdateLinksA(void)
{
	prevFunc();
	setFunc(&pfnOleUIUpdateLinksA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIPromptUserA(void)
{
	prevFunc();
	setFunc(&pfnOleUIPromptUserA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIObjectPropertiesA(void)
{
	prevFunc();
	setFunc(&pfnOleUIObjectPropertiesA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIChangeSourceA(void)
{
	prevFunc();
	setFunc(&pfnOleUIChangeSourceA);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIAddVerbMenuW(void)
{
	prevFunc();
	setFunc(&pfnOleUIAddVerbMenuW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIBusyW(void)
{
	prevFunc();
	setFunc(&pfnOleUIBusyW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIChangeIconW(void)
{
	prevFunc();
	setFunc(&pfnOleUIChangeIconW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIChangeSourceW(void)
{
	prevFunc();
	setFunc(&pfnOleUIChangeSourceW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIConvertW(void)
{
	prevFunc();
	setFunc(&pfnOleUIConvertW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIEditLinksW(void)
{
	prevFunc();
	setFunc(&pfnOleUIEditLinksW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIInsertObjectW(void)
{
	prevFunc();
	setFunc(&pfnOleUIInsertObjectW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIObjectPropertiesW(void)
{
	prevFunc();
	setFunc(&pfnOleUIObjectPropertiesW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIPasteSpecialW(void)
{
	prevFunc();
	setFunc(&pfnOleUIPasteSpecialW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIPromptUserW(void)
{
	prevFunc();
	setFunc(&pfnOleUIPromptUserW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
ALCDECL AheadLib_OleUIUpdateLinksW(void)
{
	prevFunc();
	setFunc(&pfnOleUIUpdateLinksW);
	endFunc();
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
