#include "KernelCore.h"

bool RC_CallConv ReadRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	return Kernel().ReadMemory((DWORD)handle, (DWORD_PTR)address, (PVOID)((DWORD_PTR)buffer + (DWORD_PTR)offset), size);
}

bool RC_CallConv WriteRemoteMemory(RC_Pointer handle, RC_Pointer address, RC_Pointer buffer, int offset, int size)
{
	return Kernel().WriteMemory((DWORD)handle, (DWORD_PTR)address, (PVOID)((DWORD_PTR)buffer + (DWORD_PTR)offset), size);
}
