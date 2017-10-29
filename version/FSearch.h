#ifndef __DEF_SEARCH_H__
#define __DEF_SEARCH_H__
#include <windows.h>

ULONG FastSearchVirtualMemory(ULONG VirtualAddress, ULONG VirtualLength, PUCHAR SigPattern, PCHAR SigMask);
PVOID FindTarget(PVOID addr, DWORD len, PUCHAR target, DWORD target_len);

#endif