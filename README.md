# Overview
GhostProcess is a PoC that hides process in Windows kernel. 

# Environment
* PoC is developed in Visual Studio 2022 and tested on Windows 10 1909.

# Features
* Hide Process
    * DKOM
        * Unlink ActiveProcessLinks
        * Unlink HandleTableList
        * Unlink ProcessListEntry
        * Null out PspCidTable
    * Infinity Hook
        * Hook NtQuerySystemInformation

# Usage
Load GhostProcessDrv.sys and run GhostProcess.exe.
```
# GhostProcess.exe
Manipulated pid: 4294967295
[0] set manipulated pid
[1] unlink ActiveProcessLinks (in EPROCESS)
[2] unlink ProcessListEntry (in EPROCESS's PCB)
[3] unlink HandleTableList (in EPROCESS's ObjectTable)
[4] null PspCidTable
[5] 1 + 2 + 3 + 4
[6] infinity hook on
[7] infinity hook off
```
