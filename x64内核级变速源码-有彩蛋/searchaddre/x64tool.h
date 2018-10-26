#pragma once
ULONG_PTR __stdcall GetCALLByName(PCWSTR SourceString);
ULONG_PTR GetSSDTFuncCurAddr(UINT64 id, UINT64 pTable);
BOOL LocateSSDTTable64(PULONG_PTR pKeSystemServiceDispatchTable, PULONG_PTR pKeSystemShadowServiceDispatchTable);
NTSTATUS
OpenRegistryKey(
OUT PHANDLE Handle,
IN PUNICODE_STRING KeyName,
IN ACCESS_MASK DesiredAccess,
IN BOOLEAN Create
);
BOOLEAN RegQueryValueKey(HANDLE hKey, PWSTR lpwcName, PVOID *Data, PULONG DataSize);
BOOLEAN RegSetValueKey(HANDLE hKey, PWSTR lpwcName, ULONG Type, PVOID Data, ULONG DataSize);
BOOLEAN
KCopyFile(
IN WCHAR *   strDestFile,
IN WCHAR *   strSrcFile
);
BOOLEAN KiSleep(ULONG MillionSecond);
BOOLEAN ValidateUnicodeString(PUNICODE_STRING usStr);
PVOID MakeMemEXEC(PVOID pMem);
VOID DeleteFile(LPCWSTR lpszFileName);

PVOID LoadAndReadFile(WCHAR * szFileName);

VOID ObSleep(LONG msec);
