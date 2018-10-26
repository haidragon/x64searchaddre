#pragma once

typedef struct _HOOK_INFO
{
	ULONG_PTR Function;	// Address of the original function

	ULONG_PTR Hook;		// Address of the function to call 
	// instead of the original

	PVOID Bridge;

} HOOK_INFO, *PHOOK_INFO;
KIRQL WPOFFx64();
void WPONx64(KIRQL irql);
VOID WriteJump(VOID *pAddress, ULONG_PTR JumpTo);
UINT SizeOfCode(ULONG_PTR Address);
ULONG_PTR FindCode(PVOID Address, PVOID CodeBuffer, UINT CodeSize, UINT MaxSize);
VOID WriteCall(VOID *pAddress, ULONG_PTR JumpTo);
BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, PHOOK_INFO pHook);
VOID __cdecl UnhookFunction(ULONG_PTR Function, PHOOK_INFO pHook);