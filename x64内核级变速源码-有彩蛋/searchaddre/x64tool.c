#include "stdafx.h"

BOOL LocateSSDTTable64(PULONG_PTR pKeSystemServiceDispatchTable, PULONG_PTR pKeSystemShadowServiceDispatchTable)
{
	ULONG_PTR g_ulpKiSystemCall64 = __readmsr(0xC0000082);
	ULONG_PTR g_ulpAddr;
	for (g_ulpAddr = g_ulpKiSystemCall64; g_ulpAddr != g_ulpKiSystemCall64 + PAGE_SIZE / 2; ++g_ulpAddr)
	{
		if (!MmIsAddressValid((PVOID)g_ulpAddr)
			|| !MmIsAddressValid((PVOID)(g_ulpAddr + 32 * sizeof(ULONG_PTR))))
		{
			break;
		}

		if (*(PUSHORT)g_ulpAddr == 0x8d4c && *(PUSHORT)(g_ulpAddr + 7) == 0x8d4c) {
			*pKeSystemServiceDispatchTable = g_ulpAddr + *(PULONG)(g_ulpAddr + 3) + 7;
			*pKeSystemShadowServiceDispatchTable = (g_ulpAddr + 7) + *(PULONG)(g_ulpAddr + 7 + 3) + 7;
		}
	}
	if (*pKeSystemServiceDispatchTable&&*pKeSystemShadowServiceDispatchTable)
	{
		return TRUE;
	}
	return FALSE;
}

typedef UINT64(__fastcall *SCFN)(UINT64, UINT64);
SCFN xfn = NULL;
PVOID MakeMemEXEC(PVOID pMem)
{
	PULONG64 pul;
	pul = (PULONG64)((((ULONG64)pMem >> 12) & 0xFFFFFFFFF) * 8 + 0xFFFFF68000000000);
	(*pul) = (*pul) & 0x7FFFFFFFFFFFFFFF;
	return pMem;
}
void GetXFN()
{
	UCHAR strShellCode[36] = "\x48\x8B\xC1\x4C\x8D\x12\x8B\xF8\xC1\xEF\x07\x83\xE7\x20\x4E\x8B\x14\x17\x4D\x63\x1C\x82\x49\x8B\xC3\x49\xC1\xFB\x04\x4D\x03\xD3\x49\x8B\xC2\xC3";
	xfn = (SCFN)ExAllocatePool(NonPagedPool, PAGE_SIZE);
	RtlCopyMemory((VOID *)xfn, strShellCode, 36);
	xfn = MakeMemEXEC((PVOID)xfn);
}
ULONG_PTR GetSSDTFuncCurAddr(UINT64 id, UINT64 pTable)
{
	if (!xfn)
	{
		GetXFN();
	}
	return xfn(id, (UINT64)pTable);
}
ULONG_PTR __stdcall GetCALLByName(PCWSTR SourceString)
{
	UNICODE_STRING DestinationString; // [sp+0h] [bp-8h]@1
	RtlInitUnicodeString(&DestinationString, SourceString);
	return (ULONG_PTR)MmGetSystemRoutineAddress(&DestinationString);
}
BOOLEAN ValidateUnicodeString(PUNICODE_STRING usStr)
{
	ULONG i;
	if (!MmIsAddressValid(usStr))
	{
		return FALSE;
	}

	if (usStr->Buffer == NULL || usStr->Length == 0)
	{
		return FALSE;
	}

	for (i = 0; i < usStr->Length; i++)
	{
		if (!MmIsAddressValid((PUCHAR)usStr->Buffer + i))
		{
			return FALSE;
		}
	}

	return TRUE;
}
BOOLEAN RegSetValueKey(HANDLE hKey, PWSTR lpwcName, ULONG Type, PVOID Data, ULONG DataSize)
{
	UNICODE_STRING usValueName;
	NTSTATUS ns;
	RtlInitUnicodeString(&usValueName, lpwcName);
	ns = ZwSetValueKey(hKey, &usValueName, 0, Type, Data, DataSize);
	if (!NT_SUCCESS(ns))
	{
		return FALSE;
	}
	return TRUE;
}
BOOLEAN RegQueryValueKey(HANDLE hKey, PWSTR lpwcName, PVOID *Data, PULONG DataSize)
{
	BOOLEAN bRet = FALSE;
	PKEY_VALUE_FULL_INFORMATION ValueInformation = NULL;
	ULONG ResultLen = 0;
	UNICODE_STRING usValueName;
	NTSTATUS ns;
	RtlInitUnicodeString(&usValueName, lpwcName);

	if (Data && DataSize)
	{
		*Data = NULL;
		*DataSize = 0;
	}

	// get required buffer size
	ns = ZwQueryValueKey(
		hKey,
		&usValueName,
		KeyValueFullInformation,
		&ValueInformation,
		0,
		&ResultLen
		);
	if ((ns == STATUS_BUFFER_TOO_SMALL ||
		ns == STATUS_BUFFER_OVERFLOW) && ResultLen > 0)
	{
		// allocate memory for key information
		ValueInformation = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePool(NonPagedPool, ResultLen + 0x100);
		if (ValueInformation)
		{
			memset(ValueInformation, 0, ResultLen);

			// query key information
			ns = ZwQueryValueKey(
				hKey,
				&usValueName,
				KeyValueFullInformation,
				ValueInformation,
				ResultLen,
				&ResultLen
				);
			if (NT_SUCCESS(ns))
			{
				//if (Type == REG_NONE || Type == ValueInformation->Type)
				{
					if (Data && DataSize)
					{
						// allocate memory for value data
						if (*Data = ExAllocatePool(NonPagedPool, ValueInformation->DataLength + MAX_PATH * 2))
						{
							RtlCopyMemory(
								*Data,
								(PUCHAR)ValueInformation + ValueInformation->DataOffset,
								ValueInformation->DataLength
								);

							*DataSize = ValueInformation->DataLength;
							bRet = TRUE;
						}
					}
					else
					{
						// just say about value existance
						bRet = TRUE;
					}
				}
			}
			ExFreePool(ValueInformation);
		}
	}
	return bRet;
}
NTSTATUS
OpenRegistryKey(
OUT PHANDLE Handle,
IN PUNICODE_STRING KeyName,
IN ACCESS_MASK DesiredAccess,
IN BOOLEAN Create
)
{
	OBJECT_ATTRIBUTES objectAttributes;
	ULONG disposition;
	//
	// Initialize the object for the key.
	//

	InitializeObjectAttributes(&objectAttributes,
		KeyName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		(PSECURITY_DESCRIPTOR)NULL);

	//
	// Create the key or open it, as appropriate based on the caller's
	// wishes.
	//

	if (Create) {
		return ZwCreateKey(Handle,
			DesiredAccess,
			&objectAttributes,
			0,
			(PUNICODE_STRING)NULL,
			REG_OPTION_VOLATILE,
			&disposition);
	}
	else {
		return ZwOpenKey(Handle,
			DesiredAccess,
			&objectAttributes);
	}
}
BOOLEAN
KCopyFile(
IN WCHAR *   strDestFile,
IN WCHAR *   strSrcFile
)
{
	HANDLE    hSrcFile, hDestFile=NULL;
	PVOID    buffer = NULL;
	ULONG    length = 0;
	LARGE_INTEGER    offset = { 0 };
	IO_STATUS_BLOCK Io_Status_Block = { 0 };
	OBJECT_ATTRIBUTES obj_attrib;
	NTSTATUS status;
	BOOLEAN bRet = FALSE;
	UNICODE_STRING ustrDestFile, ustrSrcFile;
	RtlInitUnicodeString(&ustrDestFile, strDestFile);
	RtlInitUnicodeString(&ustrSrcFile, strSrcFile);
	do
	{
		// 打开源文件
		InitializeObjectAttributes(&obj_attrib,
			&ustrSrcFile,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		status = ZwCreateFile(&hSrcFile,
			GENERIC_READ,
			&obj_attrib,
			&Io_Status_Block,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			goto END;
		}

		// 打开目标文件
		InitializeObjectAttributes(&obj_attrib,
			&ustrDestFile,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		status = ZwCreateFile(&hDestFile,
			GENERIC_WRITE,
			&obj_attrib,
			&Io_Status_Block,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN_IF,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,
			0);
		if (!NT_SUCCESS(status))
		{
			bRet = FALSE;
			goto END;
		}

		// 为buffer分配4KB空间
		buffer = ExAllocatePool(NonPagedPool, 1024 * 4 + 0x1000);
		if (buffer == NULL)
		{
			bRet = FALSE;
			goto END;
		}

		// 复制文件
		while (1)
		{
			length = 4 * 1024;
			// 读取源文件
			status = ZwReadFile(hSrcFile,
				NULL,
				NULL,
				NULL,
				&Io_Status_Block,
				buffer,
				length,
				&offset,
				NULL);
			if (!NT_SUCCESS(status))
			{
				// 如果状态为STATUS_END_OF_FILE，说明文件已经读取到末尾
				if (status == STATUS_END_OF_FILE)
				{
					bRet = TRUE;
					goto END;
				}
			}

			// 获得实际读取的长度
			length = Io_Status_Block.Information;

			// 写入到目标文件
			status = ZwWriteFile(hDestFile,
				NULL,
				NULL,
				NULL,
				&Io_Status_Block,
				buffer,
				length,
				&offset,
				NULL);
			if (!NT_SUCCESS(status))
			{
				bRet = FALSE;
				goto END;
			}

			// 移动文件指针
			offset.QuadPart += length;
		}

	} while (0);

END:
	if (hSrcFile)
	{
		ZwClose(hSrcFile);
	}
	if (hDestFile)
	{
		ZwClose(hDestFile);
	}
	if (buffer)
	{
		ExFreePool(buffer);
	}
	return bRet;
}

BOOLEAN KiSleep(ULONG MillionSecond)
{
	NTSTATUS st;
	LARGE_INTEGER DelayTime;
	DelayTime = RtlConvertLongToLargeInteger(-10000 * MillionSecond);
	st = KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	return (NT_SUCCESS(st));
}

VOID DeleteFile(LPCWSTR lpszFileName)
{
	OBJECT_ATTRIBUTES OA;
	UNICODE_STRING usfilename;
	RtlInitUnicodeString(&usfilename, lpszFileName);
	InitializeObjectAttributes(&OA,
		&usfilename,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);
//	ZwDeleteFile(&OA);
}

PVOID LoadAndReadFile(WCHAR * szFileName)
{
	HANDLE hListFile = NULL;
	NTSTATUS ns;
	IO_STATUS_BLOCK	iosb;
	LARGE_INTEGER fileoffset;
	UNICODE_STRING uniFileName;
	OBJECT_ATTRIBUTES oba;
	FILE_STANDARD_INFORMATION filestandinfo;
	PVOID FilePool;
	DWORD dwSize = 0;
	BOOL bRet = FALSE;
	RtlInitUnicodeString(&uniFileName, szFileName);
	InitializeObjectAttributes(&oba,
		&uniFileName,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		0,
		0);
	ns = IoCreateFile(&hListFile,
		GENERIC_READ | SYNCHRONIZE,
		&oba,
		&iosb,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
		CreateFileTypeNone,
		0,
		IO_NO_PARAMETER_CHECKING
		);

	if (!NT_SUCCESS(ns))
	{
		return NULL;
	}
	ns = ZwQueryInformationFile(hListFile,
		&iosb,
		&filestandinfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation
		);

	if (!NT_SUCCESS(ns))
	{
		ZwClose(hListFile);
		return NULL;
	}

	//get file len 


	dwSize = (ULONG)filestandinfo.AllocationSize.QuadPart;

	FilePool = ExAllocatePool(NonPagedPool,
		dwSize);

	if (!FilePool)
	{
		ZwClose(hListFile);
		return NULL;
	}

	//allocate pool for read file

	ns = ZwReadFile(hListFile,
		NULL,
		NULL,
		NULL,
		&iosb,
		FilePool,
		dwSize,
		NULL,
		NULL
		);

	if (!NT_SUCCESS(ns))
	{
		ExFreePool(FilePool);
		ZwClose(hListFile);
		return NULL;
	}
	//read file
	ZwClose(hListFile);
	return FilePool;
}



#define DELAY_ONE_MICROSECOND 	(-10)
#define DELAY_ONE_MILLISECOND	(DELAY_ONE_MICROSECOND*1000)
VOID ObSleep(LONG msec)
{
	LARGE_INTEGER my_interval;
	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= msec;
	KeDelayExecutionThread(KernelMode, 0, &my_interval);
}
