#pragma once
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 头文件
#include <Windows.h>
#ifdef _DEBUG
#include <stdlib.h>
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 导出函数
#if defined(_M_X64)
#pragma comment(linker, "/EXPORT:OleUIAddVerbMenuA=AheadLib_OleUIAddVerbMenuA,@1")
#pragma comment(linker, "/EXPORT:OleUICanConvertOrActivateAs=AheadLib_OleUICanConvertOrActivateAs,@2")
#pragma comment(linker, "/EXPORT:OleUIInsertObjectA=AheadLib_OleUIInsertObjectA,@3")
#pragma comment(linker, "/EXPORT:OleUIPasteSpecialA=AheadLib_OleUIPasteSpecialA,@4")
#pragma comment(linker, "/EXPORT:OleUIEditLinksA=AheadLib_OleUIEditLinksA,@5")
#pragma comment(linker, "/EXPORT:OleUIChangeIconA=AheadLib_OleUIChangeIconA,@6")
#pragma comment(linker, "/EXPORT:OleUIConvertA=AheadLib_OleUIConvertA,@7")
#pragma comment(linker, "/EXPORT:OleUIBusyA=AheadLib_OleUIBusyA,@8")
#pragma comment(linker, "/EXPORT:OleUIUpdateLinksA=AheadLib_OleUIUpdateLinksA,@9")
#pragma comment(linker, "/EXPORT:OleUIPromptUserA=AheadLib_OleUIPromptUserA,@10")
#pragma comment(linker, "/EXPORT:OleUIObjectPropertiesA=AheadLib_OleUIObjectPropertiesA,@11")
#pragma comment(linker, "/EXPORT:OleUIChangeSourceA=AheadLib_OleUIChangeSourceA,@12")
#pragma comment(linker, "/EXPORT:OleUIAddVerbMenuW=AheadLib_OleUIAddVerbMenuW,@13")
#pragma comment(linker, "/EXPORT:OleUIBusyW=AheadLib_OleUIBusyW,@14")
#pragma comment(linker, "/EXPORT:OleUIChangeIconW=AheadLib_OleUIChangeIconW,@15")
#pragma comment(linker, "/EXPORT:OleUIChangeSourceW=AheadLib_OleUIChangeSourceW,@16")
#pragma comment(linker, "/EXPORT:OleUIConvertW=AheadLib_OleUIConvertW,@17")
#pragma comment(linker, "/EXPORT:OleUIEditLinksW=AheadLib_OleUIEditLinksW,@18")
#pragma comment(linker, "/EXPORT:OleUIInsertObjectW=AheadLib_OleUIInsertObjectW,@19")
#pragma comment(linker, "/EXPORT:OleUIObjectPropertiesW=AheadLib_OleUIObjectPropertiesW,@20")
#pragma comment(linker, "/EXPORT:OleUIPasteSpecialW=AheadLib_OleUIPasteSpecialW,@21")
#pragma comment(linker, "/EXPORT:OleUIPromptUserW=AheadLib_OleUIPromptUserW,@22")
#pragma comment(linker, "/EXPORT:OleUIUpdateLinksW=AheadLib_OleUIUpdateLinksW,@23")
#elif defined(_M_IX86)
#pragma comment(linker, "/EXPORT:OleUIAddVerbMenuA=_AheadLib_OleUIAddVerbMenuA,@1")
#pragma comment(linker, "/EXPORT:OleUICanConvertOrActivateAs=_AheadLib_OleUICanConvertOrActivateAs,@2")
#pragma comment(linker, "/EXPORT:OleUIInsertObjectA=_AheadLib_OleUIInsertObjectA,@3")
#pragma comment(linker, "/EXPORT:OleUIPasteSpecialA=_AheadLib_OleUIPasteSpecialA,@4")
#pragma comment(linker, "/EXPORT:OleUIEditLinksA=_AheadLib_OleUIEditLinksA,@5")
#pragma comment(linker, "/EXPORT:OleUIChangeIconA=_AheadLib_OleUIChangeIconA,@6")
#pragma comment(linker, "/EXPORT:OleUIConvertA=_AheadLib_OleUIConvertA,@7")
#pragma comment(linker, "/EXPORT:OleUIBusyA=_AheadLib_OleUIBusyA,@8")
#pragma comment(linker, "/EXPORT:OleUIUpdateLinksA=_AheadLib_OleUIUpdateLinksA,@9")
#pragma comment(linker, "/EXPORT:OleUIPromptUserA=_AheadLib_OleUIPromptUserA,@10")
#pragma comment(linker, "/EXPORT:OleUIObjectPropertiesA=_AheadLib_OleUIObjectPropertiesA,@11")
#pragma comment(linker, "/EXPORT:OleUIChangeSourceA=_AheadLib_OleUIChangeSourceA,@12")
#pragma comment(linker, "/EXPORT:OleUIAddVerbMenuW=_AheadLib_OleUIAddVerbMenuW,@13")
#pragma comment(linker, "/EXPORT:OleUIBusyW=_AheadLib_OleUIBusyW,@14")
#pragma comment(linker, "/EXPORT:OleUIChangeIconW=_AheadLib_OleUIChangeIconW,@15")
#pragma comment(linker, "/EXPORT:OleUIChangeSourceW=_AheadLib_OleUIChangeSourceW,@16")
#pragma comment(linker, "/EXPORT:OleUIConvertW=_AheadLib_OleUIConvertW,@17")
#pragma comment(linker, "/EXPORT:OleUIEditLinksW=_AheadLib_OleUIEditLinksW,@18")
#pragma comment(linker, "/EXPORT:OleUIInsertObjectW=_AheadLib_OleUIInsertObjectW,@19")
#pragma comment(linker, "/EXPORT:OleUIObjectPropertiesW=_AheadLib_OleUIObjectPropertiesW,@20")
#pragma comment(linker, "/EXPORT:OleUIPasteSpecialW=_AheadLib_OleUIPasteSpecialW,@21")
#pragma comment(linker, "/EXPORT:OleUIPromptUserW=_AheadLib_OleUIPromptUserW,@22")
#pragma comment(linker, "/EXPORT:OleUIUpdateLinksW=_AheadLib_OleUIUpdateLinksW,@23")
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// 宏定义
#define EXTERNC extern "C"
#ifdef _M_X64
#define NAKED
#else
#define NAKED __declspec(naked)
#endif
#define EXPORT __declspec(dllexport)

#define ALCPP EXPORT NAKED
#define ALSTD EXTERNC EXPORT NAKED void __stdcall
#define ALCFAST EXTERNC EXPORT NAKED void __fastcall
#define ALCDECL EXTERNC NAKED void __cdecl
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


INT EncryptName(LPCSTR lpProcName);

_Ret_maybenull_
HMODULE WINAPI fn_LoadLibraryA(_In_ LPCSTR lpLibFileName);

FARPROC WINAPI fn_GetProcAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName);

_Ret_maybenull_
_Post_writable_byte_size_(dwSize)
LPVOID WINAPI fn_VirtualAlloc(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize, _In_ DWORD flAllocationType, _In_ DWORD flProtect);

_Ret_maybenull_
_Post_writable_byte_size_(dwBytes)
LPVOID WINAPI fn_HeapAlloc(_In_ HANDLE hHeap, _In_ DWORD dwFlags, _In_ SIZE_T dwBytes);

_Success_(return != FALSE)
BOOL WINAPI fn_HeapFree(_Inout_ HANDLE hHeap, _In_ DWORD dwFlags, __drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem);

BOOL HookImage(LPCSTR szName, DWORD Newfunc);
BOOL RemoveImage(LPCSTR szName);

BOOL HookImport(HMODULE hModule, LPCSTR szDLL, LPCSTR szName, INT_PTR Newfunc);
BOOL RemoveImport(HMODULE hModule, LPCSTR szDLL, LPCSTR szName, INT_PTR Newfunc);

extern "C" extern void prevFunc();
extern "C" extern void setFunc(LPVOID p);
extern "C" extern void endFunc();

#pragma optimize( "", off )

template<class T> T* retT()
{
	return new T;
}