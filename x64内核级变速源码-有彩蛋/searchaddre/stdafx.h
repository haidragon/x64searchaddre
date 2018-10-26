#pragma once
#include <ntddk.h>
#include <stdio.h>
#include <stdarg.h>
#include <wchar.h>
#include <ntddscsi.h>
#include <srb.h>
#include <ntimage.h>
#include <windef.h>
#include <aux_klib.h>
#include "x64detour.h"
#include "x64tool.h"

typedef struct _SYMBOL_FILE_
{
	UINT64 _KiRetireDpcList;
	UINT64 _MiProcessLoaderEntry;
}SYMBOL_FILE, *PSYMBOL_FILE;

#define CONFIG_FILE L"\\??\\C:\\pgx64.cfg"

extern PSYMBOL_FILE pCfgData;
