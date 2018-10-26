#include "stdafx.h"
#include "../src/mnemonics.c"
#include "../src/wstring.c"
#include "../src/textdefs.c"
#include "../src/prefix.c"
#include "../src/operands.c"
#include "../src/insts.c"
#include "../src/instructions.c"
#include "../src/distorm.c"
#include "../src/decoder.c"

#ifdef _X86_

#define JUMP_WORST		10		// Worst case scenario
#define PTE_BASE 0xc0000000

#elif _AMD64_

#define JUMP_WORST		14		// Worst case scenario
#define PTE_BASE          0xFFFFF68000000000UI64

#endif

#define MiGetPteAddress(va) ((PULONG_PTR)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))


KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

UINT GetJumpSize(ULONG_PTR PosA, ULONG_PTR PosB)
{
	ULONG_PTR res = max(PosA, PosB) - min(PosA, PosB);
	return JUMP_WORST;
}
VOID WriteJump(VOID *pAddress, ULONG_PTR JumpTo)
{
	KIRQL oldIrql;
	BYTE *pCur;
	pCur = (BYTE *)pAddress;

#ifdef _X86_

	*pCur = 0xff;     // jmp [addr]
	*(++pCur) = 0x25;
	pCur++;
	*((DWORD *)pCur) = (DWORD)(((ULONG_PTR)pCur) + sizeof(DWORD));
	pCur += sizeof(DWORD);
	*((ULONG_PTR *)pCur) = JumpTo;

#elif _AMD64_
	oldIrql = WPOFFx64();
	*pCur = 0xff;		// jmp [rip+addr]
	*(++pCur) = 0x25;
	*((DWORD *) ++pCur) = 0; // addr = 0
	pCur += sizeof(DWORD);
	*((ULONG_PTR *)pCur) = JumpTo;
	WPONx64(oldIrql);
#endif

}
NTSTATUS CreateBridge(ULONG_PTR Function, const UINT JumpSize, PHOOK_INFO pHook)
{

#define MAX_INSTRUCTIONS 100

	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;

#ifdef _X86_

	_DecodeType dt = Decode32Bits;

#elif _AMD64_

	_DecodeType dt = Decode64Bits;

#endif

	_OffsetType offset = 0;
	DWORD InstrSize = 0;
	BYTE *pBridge = (BYTE *)pHook->Bridge;
	UINT nBridgeIndex = 0;
	UINT x;
	res = distorm_decode(offset,	// offset for buffer
		(const BYTE *)Function,	// buffer to disassemble
		50,							// function size (code size to disasm) 
		// 50 instr should be _quite_ enough
		dt,							// x86 or x64?
		decodedInstructions,		// decoded instr
		MAX_INSTRUCTIONS,			// array size
		&decodedInstructionsCount	// how many instr were disassembled?
		);

	if (res == DECRES_INPUTERR)
		return STATUS_UNSUCCESSFUL;

	for (x = 0; x < decodedInstructionsCount; x++)
	{
		BYTE *pCurInstr = NULL;
		if (InstrSize >= JumpSize)
			break;
		pCurInstr = (BYTE *)(InstrSize + (ULONG_PTR)Function);
		RtlCopyMemory(&pBridge[nBridgeIndex], (VOID *)pCurInstr, decodedInstructions[x].size);
		nBridgeIndex += decodedInstructions[x].size;
		InstrSize += decodedInstructions[x].size;
	}
	//LogDebug("len %d,index %d\r\n",InstrSize,nBridgeIndex);
	WriteJump(&pBridge[nBridgeIndex], (ULONG_PTR)Function + InstrSize);

	return STATUS_SUCCESS;
}
BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, PHOOK_INFO pHook)
{
	if (pHook)
	{
#ifdef _AMD64_
		PULONG64 pul;
#endif // _AMD64_

		PVOID pHookBrige = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'sysq');
		pHook->Bridge = pHookBrige;
		RtlFillMemory(pHook->Bridge, 0x100, 0x90);
		CreateBridge(OriginalFunction, GetJumpSize(OriginalFunction, NewFunction), pHook);
		pHook->Function = OriginalFunction;
		pHook->Hook = NewFunction;
		WriteJump((VOID *)OriginalFunction, NewFunction);
		return TRUE;
	}
	return FALSE;
}


VOID __cdecl UnhookFunction(ULONG_PTR Function, PHOOK_INFO pHook)
{
	if (pHook)
	{
		WriteJump((VOID *)pHook->Function, (ULONG_PTR)pHook->Bridge);
	}
}

UINT SizeOfCode(ULONG_PTR Address)
{
#define MAX_INSTRUCTIONS 100

	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;

#ifdef _X86_

	_DecodeType dt = Decode32Bits;

#elif _AMD64_

	_DecodeType dt = Decode64Bits;

#endif

	_OffsetType offset = 0;
	DWORD InstrSize = 0;
	UINT nBridgeIndex = 0;
	UINT x;
	res = distorm_decode(offset,	// offset for buffer
		(const BYTE *)Address,	// buffer to disassemble
		50,							// function size (code size to disasm) 
		// 50 instr should be _quite_ enough
		dt,							// x86 or x64?
		decodedInstructions,		// decoded instr
		MAX_INSTRUCTIONS,			// array size
		&decodedInstructionsCount	// how many instr were disassembled?
		);

	if (res == DECRES_INPUTERR)
		return 0;
	if (decodedInstructionsCount >= 1)
	{
		return decodedInstructions[0].size;
	}
	return 0;
}

ULONG_PTR FindCode(PVOID Address, PVOID CodeBuffer, UINT CodeSize, UINT MaxSize)
{
	ULONG_PTR NewAddress = 0;
	UINT CodeLen = 0;
	__try
	{
		for (NewAddress = (ULONG_PTR)Address; NewAddress< (ULONG_PTR)Address + MaxSize; NewAddress += CodeLen)
		{
			if (RtlCompareMemory((const void *)NewAddress,
				(const void *)CodeBuffer, CodeSize) == CodeSize)
			{
				return NewAddress;
			}
			CodeLen = SizeOfCode(NewAddress);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{

	}
	return 0;
}


VOID WriteCall(VOID *pAddress, ULONG_PTR JumpTo)
{
	KIRQL oldIrql;
	BYTE *pCur;
	pCur = (BYTE *)pAddress;

#ifdef _X86_

	*pCur = 0xff;     // jmp [addr]
	*(++pCur) = 0x15;
	pCur++;
	*((DWORD *)pCur) = (DWORD)(((ULONG_PTR)pCur) + sizeof(DWORD));
	pCur += sizeof(DWORD);
	*((ULONG_PTR *)pCur) = JumpTo;

#elif _AMD64_
	oldIrql = WPOFFx64();
	*pCur = 0xff;		// jmp [rip+addr]
	*(++pCur) = 0x15;
	*((DWORD *) ++pCur) = 0; // addr = 0
	pCur += sizeof(DWORD);
	*((ULONG_PTR *)pCur) = JumpTo;
	WPONx64(oldIrql);
#endif

}
