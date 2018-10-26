#include "stdafx.h"

KDPC  g_TempDpc;

extern VOID getespaddress();
PVOID64 address = NULL;
PSYMBOL_FILE pCfgData = NULL;

PVOID64 tempeax = NULL;
PVOID64 tempaddress = NULL;

extern HOOK_INFO OrgRtlCaptureContext;
extern HOOK_INFO OrgKiRetireDpcList;
extern VOID getespaddress();

PDRIVER_OBJECT g_DriverObject = NULL;
PDRIVER_OBJECT	pTargetDrvObj = NULL;
// 变速基数
const DWORD g_dwSpeedBase = 100;
// 变速数值
DWORD g_dwSpeed_X = 400;
HOOK_INFO updatetime;
HOOK_INFO queryfor;
extern InitDisablePatchGuard();
extern fixedx();
extern BOOL __cdecl HookFunction(ULONG_PTR OriginalFunction, ULONG_PTR NewFunction, PHOOK_INFO pHook);
extern VOID __cdecl UnhookFunction(ULONG_PTR Function, PHOOK_INFO pHook);
extern KIRQL WPOFFx64();
extern void WPONx64(KIRQL irql);
typedef NTSTATUS (__cdecl *PKeUpdateSystemTime)(IN PKTRAP_FRAME TrapFrame, IN ULONG64 Increment);

UCHAR jmp_code[] = "\x48\x89\x5c\x24\x10\x57\x48\x83\xec\x20\xba\x05\x00\x00\x00\x90";
UCHAR backcode[] = "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
// 前一个查询到的性能指标数
LARGE_INTEGER g_liPreOriginalCounter;

// 变化后的性能指标数值
LARGE_INTEGER g_liPreReturnCounter;
INT speedx;
typedef struct _KLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64 InLoadOrderLinks;
	ULONG64 __Undefined1;
	ULONG64 __Undefined2;
	ULONG64 __Undefined3;
	ULONG64 NonPagedDebugInfo;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT  __Undefined5;
	ULONG64 __Undefined6;
	ULONG   CheckSum;
	ULONG   __padding1;
	ULONG   TimeDateStamp;
	ULONG   __padding2;
}KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;

#pragma LOCKEDCODE
VOID getkelistdpc(
	IN struct _KDPC *Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	)
{
	getespaddress();
	DbgPrint("%p", address);
	DbgPrint("enter the dpc\n");
	return;
}

NTSTATUS hookupdatetime(IN PKTRAP_FRAME TrapFrame, IN ULONG64 Increment)
{
	NTSTATUS st;
	ULONG64 test = Increment * speedx;
	PKeUpdateSystemTime orgin = (PKeUpdateSystemTime)updatetime.Bridge;
	st = orgin(TrapFrame, test);
	return st;
}
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	//g_dwSpeed_X = 100;
	//LARGE_INTEGER	lDelay;
	//lDelay = RtlConvertLongToLargeInteger(5 * (-10) * 1000);
//	KeDelayExecutionThread(KernelMode, FALSE, &lDelay);
	speedx = 1;
	KIRQL temprql = WPOFFx64();
	memcpy((PVOID)(updatetime.Function), (PVOID)(updatetime.Bridge), 15);
	memcpy((PVOID)(queryfor.Function), (PVOID)backcode, 16);
	memcpy((PVOID)(OrgKiRetireDpcList.Function), (PVOID)(OrgKiRetireDpcList.Bridge), 17);
	memcpy((PVOID)(OrgRtlCaptureContext.Function), (PVOID)(OrgRtlCaptureContext.Bridge), 14);
	WPONx64(temprql);
	DbgPrint("unloading...\n");
	ExSetTimerResolution(0, FALSE);
	return STATUS_SUCCESS;
}

typedef VOID (__cdecl *PMiProcessLoaderEntry)(PKLDR_DATA_TABLE_ENTRY section, IN LOGICAL Insert);
typedef LARGE_INTEGER(__cdecl *PKeQueryPerformanceCounter)(PLARGE_INTEGER performancefrequency);
LARGE_INTEGER hookqueryperfor(PLARGE_INTEGER performancefrequency)
{
	LARGE_INTEGER liResult;
	LARGE_INTEGER liCurrent;
	PKeQueryPerformanceCounter orgin = (PKeQueryPerformanceCounter)queryfor.Bridge;
	liCurrent = orgin(performancefrequency);
	liResult.QuadPart = g_liPreReturnCounter.QuadPart + (liCurrent.QuadPart - g_liPreOriginalCounter.QuadPart) *speedx;

	// 保存当前的原始数值
	g_liPreOriginalCounter.QuadPart = liCurrent.QuadPart;
	// 保持返回值
	g_liPreReturnCounter.QuadPart = liResult.QuadPart;
	return liResult;
}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegPath)
{
	KeInitializeDpc(&g_TempDpc,
		getkelistdpc,
		NULL);
	KeInsertQueueDpc(&g_TempDpc, NULL, NULL);
	PVOID hidedirver = NULL;
	speedx =10;//变速基数 默认是10倍，自己可以通过IO控制 修改这个全局变量。
	DbgPrint("enter the dirver..\n");
	g_liPreReturnCounter.QuadPart = 0;
	g_liPreReturnCounter.QuadPart = g_liPreOriginalCounter.QuadPart;
	ExSetTimerResolution(0, TRUE);
	UNICODE_STRING hookname1 = RTL_CONSTANT_STRING(L"KeUpdateSystemTime");
	UNICODE_STRING hookname2 = RTL_CONSTANT_STRING(L"KeQueryPerformanceCounter");
	PVOID hookspeed1 = MmGetSystemRoutineAddress(&hookname1);
	PVOID hookspeed2 = MmGetSystemRoutineAddress(&hookname2);
	pDriverObject->DriverUnload = DriverUnload;
	pDriverObject->DriverUnload = DriverUnload;
	if (address != NULL)
	{
		InitDisablePatchGuard();
	}

	BOOL at = HookFunction((ULONG_PTR)hookspeed1, (ULONG_PTR)hookupdatetime, &updatetime);
	if (at == FALSE)
	{
		DbgPrint("hook failed...\n");
		return STATUS_SUCCESS;
	}
	BOOL st = HookFunction((ULONG_PTR)hookspeed2, (ULONG_PTR)hookqueryperfor, &queryfor);
	PVOID testaddre = queryfor.Bridge;
	memcpy(backcode, testaddre, 16);
	memcpy(testaddre, jmp_code, 16);
	if (st == FALSE)
	{
		DbgPrint("hook failed...\n");
		return STATUS_SUCCESS;
	}
	return STATUS_SUCCESS;
}




