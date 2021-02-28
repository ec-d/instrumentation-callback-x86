#define WIN32_NO_STATUS

#include <Windows.h>

#undef WIN32_NO_STATUS

#include <DbgHelp.h>
#include <ntstatus.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment (lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")

#define NtCurrentProcess() ((HANDLE)-1)
#define ProcessInstrumentationCallback (PROCESS_INFORMATION_CLASS)0x28

typedef void(*CallbackFn)();

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
	ULONG Version;
	ULONG Reserved;
	CallbackFn Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

NTSTATUS DECLSPEC_IMPORT NTAPI NtQueryVirtualMemory(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);
NTSTATUS DECLSPEC_IMPORT NTAPI NtSetInformationProcess(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);

void InstrumentationCallbackProxy();

NTSTATUS InstrumentationCallback(ULONG_PTR ReturnAddress, ULONG_PTR ReturnVal)
{
	if (ReturnVal != STATUS_SUCCESS)
		return ReturnVal;

	NTSTATUS Status = ReturnVal;
	TEB* Teb = NtCurrentTeb();
	BOOLEAN* InstrumentationCallbackDisabled = (BOOLEAN*)((ULONG_PTR)Teb + 0x01B8);
	if (!*InstrumentationCallbackDisabled) // Prevent recursion
	{
		*InstrumentationCallbackDisabled = TRUE;

		DWORD64 Displacement;
		BYTE SymbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME] = { 0 };
		PSYMBOL_INFO SymbolInfo = (PSYMBOL_INFO)SymbolBuffer;
		SymbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
		SymbolInfo->MaxNameLen = MAX_SYM_NAME;

		SymFromAddr(NtCurrentProcess(), ReturnAddress, &Displacement, SymbolInfo);
		printf("Symbol name: %s\n", SymbolInfo->Name);

		if (SymbolInfo->Address == (ULONG_PTR)NtQueryVirtualMemory)
		{
			ULONG_PTR* InstrumentationCallbackPreviousSp = *(ULONG_PTR**)((ULONG_PTR)Teb + 0x01B4);
			ULONG_PTR* SysArgs = InstrumentationCallbackPreviousSp + 1; // Skip return address
			**(PSIZE_T*)(SysArgs + 5) = 1337;

			Status = STATUS_ACCESS_DENIED;
		}

		*InstrumentationCallbackDisabled = FALSE;
	}

	return Status;
}

// Code from ScyllaHide
NTSTATUS SetInstrumentationCallbackHook(HANDLE ProcessHandle, BOOL Enable)
{
	CallbackFn Callback = Enable ? InstrumentationCallbackProxy : NULL;

	// Windows 10
	PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo;
#ifdef _WIN64
	Info.Version = 0;
#else
	// Native x86 instrumentation callbacks don't work correctly
	BOOL Wow64Process = FALSE;
	if (!IsWow64Process(ProcessHandle, &Wow64Process) || !Wow64Process)
	{
		//Info.Version = 1; // Value to use if they did
		return STATUS_NOT_SUPPORTED;
	}

	// WOW64: set the callback pointer in the version field
	CallbackInfo.Version = (ULONG)Callback;
#endif
	CallbackInfo.Reserved = 0;
	CallbackInfo.Callback = Callback;

	return NtSetInformationProcess(ProcessHandle, ProcessInstrumentationCallback,
		&CallbackInfo, sizeof(CallbackInfo));
}

int main()
{
	SymSetOptions(SYMOPT_UNDNAME);
	SymInitialize(NtCurrentProcess(), NULL, TRUE);

	if (!NT_SUCCESS(SetInstrumentationCallbackHook(NtCurrentProcess(), TRUE)))
	{
		printf("Failed to set hook\n");
		return EXIT_FAILURE;
	}
	
	MEMORY_BASIC_INFORMATION Mbi = { 0 };
	SIZE_T ReturnLength = 0;
	NTSTATUS Status = NtQueryVirtualMemory(NtCurrentProcess(), GetModuleHandle(NULL),
		MemoryBasicInformation, &Mbi, sizeof(Mbi), &ReturnLength);

	printf("Status: 0x%08X\n", Status);
	printf("Return length: %u\n", ReturnLength);

	SetInstrumentationCallbackHook(NtCurrentProcess(), FALSE);

	return EXIT_SUCCESS;
}
