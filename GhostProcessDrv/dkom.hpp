#pragma once
#include <intrin.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <ntstrsafe.h>

VOID UnlinkActiveProcessLists(PEPROCESS PE);
VOID UnlinkProcessListEntry(PEPROCESS PE);
VOID UnlinkHandleTableList(PEPROCESS PE);
BOOLEAN get_PspCidTable(ULONG64* tableAddr);
unsigned __int64  ExpLookupHandleTableEntry(unsigned int* a1, __int64 a2);
VOID NullPspCidTable(ULONG64 Pid);