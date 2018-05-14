#pragma once

#if defined( _M_IX86 )
#define _X86_
#elif defined( _M_AMD64 )
#define _AMD64_
#else
#error Unknown Build Target
#endif

#define _CRT_SECURE_NO_WARNINGS

#include <ntifs.h>
#include <intrin.h>
#include "structs.h"
#include "enums.h"

#define DEVICE_MONIKER L"ReClassKernel"

#define RECLASS_DOS_NAME RTL_CONSTANT_STRING(L"\\DosDevices\\"DEVICE_MONIKER);
#define RECLASS_DEVICE_NAME RTL_CONSTANT_STRING(L"\\Device\\"DEVICE_MONIKER);

extern PDEVICE_OBJECT ReClassDeviceObject;

#define DPRINT(fmt, ...) {\
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ReClassKernel] "); \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, fmt, __VA_ARGS__); \
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "\n");\
	}

__kernel_code NTSYSCALLAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
                                                              PEPROCESS TargetProcess, PVOID TargetAddress,
                                                              SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
                                                              PSIZE_T ReturnSize);

__kernel_code NTSYSCALLAPI PCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);
__kernel_code NTSYSCALLAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
__kernel_code NTSYSCALLAPI PPEB32 NTAPI PsGetProcessWow64Process(PEPROCESS Process);
__kernel_code NTSYSCALLAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
__kernel_code NTSYSCALLAPI NTSTATUS NTAPI PsReferenceProcessFilePointer(PEPROCESS Process, PFILE_OBJECT* FileObject);
__kernel_code NTSYSCALLAPI NTSTATUS NTAPI PsSuspendProcess(PEPROCESS Process);
__kernel_code NTSYSCALLAPI NTSTATUS NTAPI PsResumeProcess(PEPROCESS Process);

__kernel_code NTSYSCALLAPI NTSTATUS ZwQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                                         MEMORY_INFORMATION_CLASS MemoryInformationClass,
                                                         PVOID MemoryInformation, SIZE_T MemoryInformationLength,
                                                         PSIZE_T ReturnLength);
