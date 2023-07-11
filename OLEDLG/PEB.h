#pragma once
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Í·ÎÄ¼þ
#include <Windows.h>
#ifdef _DEBUG
#include <stdlib.h>
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//===============================================================================================//
typedef struct _UNICODE_STRING
{
	USHORT                 Length;
	USHORT                 MaximumLength;
	PWSTR                  Buffer;
} UNICODE_STRING, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) ) 
typedef struct _LDR_DATA_TABLE_ENTRY
{
	//LIST_ENTRY             InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first entry.
	LIST_ENTRY             InMemoryOrderModuleList;
	LIST_ENTRY             InInitializationOrderModuleList;
	PVOID                  DllBase;
	PVOID                  EntryPoint;
	ULONG                  SizeOfImage;
	UNICODE_STRING         FullDllName;
	UNICODE_STRING         BaseDllName;
	ULONG                  Flags;
	SHORT                  LoadCount;
	SHORT                  TlsIndex;
	LIST_ENTRY             HashTableEntry;
	ULONG                  TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
	DWORD                  dwLength;
	DWORD                  dwInitialized;
	LPVOID                 lpSsHandle;
	LIST_ENTRY             InLoadOrderModuleList;
	LIST_ENTRY             InMemoryOrderModuleList;
	LIST_ENTRY             InInitializationOrderModuleList;
	LPVOID                 lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
	struct _PEB_FREE_BLOCK * pNext;
	DWORD                  dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct _PEB // 65 elements, 0x210 bytes
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	BOOLEAN SpareBool;
#ifdef _M_X64
	UCHAR Padding0[4];
#endif
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr; // PEB_LDR_DATA*
	PVOID ProcessParameters; // RTL_USER_PROCESS_PARAMETERS*
	PVOID SubSystemData;
	HANDLE ProcessHeap;
	RTL_CRITICAL_SECTION* FastPebLock;
	PVOID unreliable_member_1;
	PVOID unreliable_member_2;
	ULONG unreliable_member_3;
#ifdef _M_X64
	UCHAR Padding1[4];
#endif
	PVOID KernelCallbackTable;
	ULONG SystemReserved[2];
	PVOID unreliable_member_4;
	ULONG TlsExpansionCounter;
#ifdef _M_X64
	UCHAR Padding2[4];
#endif
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID unreliable_member_5;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	LARGE_INTEGER CriticalSectionTimeout;
	ULONG_PTR HeapSegmentReserve;
	ULONG_PTR HeapSegmentCommit;
	ULONG_PTR HeapDeCommitTotalFreeThreshold;
	ULONG_PTR HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID* ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper;
	ULONG GdiDCAttributeList;
#ifdef _M_X64
	UCHAR Padding3[4];
#endif
	RTL_CRITICAL_SECTION* LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	union {
		USHORT OSCSDVersion;
		struct {
			BYTE OSCSDMajorVersion;
			BYTE OSCSDMinorVersion;
		};
	};
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
#ifdef _M_X64
	UCHAR Padding4[4];
#endif
	KAFFINITY unreliable_member_6;
#ifdef _M_X64
	ULONG GdiHandleBuffer[0x3C];
#else
	ULONG GdiHandleBuffer[0x22];
#endif
	VOID(*PostProcessInitRoutine)(VOID);
	PVOID TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[0x20];
	ULONG SessionId;
#ifdef _M_X64
	UCHAR Padding5[4];
#endif
} PEB, *PPEB;

typedef struct _LDR_MODULE
{
	LIST_ENTRY              InLoadOrderModuleList;   //+0x00
	LIST_ENTRY              InMemoryOrderModuleList; //+0x08  
	LIST_ENTRY              InInitializationOrderModuleList; //+0x10
	void*                   BaseAddress;  //+0x18
	void*                   EntryPoint;   //+0x1c
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	HANDLE                  SectionHandle;
	ULONG                   CheckSum;
	ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;