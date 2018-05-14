#include "Dispatch.h"

const char* name_from_ioctl(ULONG ioctl)
{
	switch(ioctl)
	{
	case RECLASS_KERNEL_IOCTL_READ_VIRTUAL_MEMORY:
		return "RECLASS_KERNEL_IOCTL_READ_VIRTUAL_MEMORY";
	case RECLASS_KERNEL_IOCTL_WRITE_VIRTUAL_MEMORY:
		return "RECLASS_KERNEL_IOCTL_WRITE_VIRTUAL_MEMORY";
	case RECLASS_KERNEL_IOCTL_PROCESS_INFORMATION:
		return "RECLASS_KERNEL_IOCTL_PROCESS_INFORMATION";
	case RECLASS_KERNEL_IOCTL_QUERY_VIRTUAL_MEMORY:
		return "RECLASS_KERNEL_IOCTL_QUERY_VIRTUAL_MEMORY";
	case RECLASS_KERNEL_IOCTL_SUSPEND_PROCESS:
		return "RECLASS_KERNEL_IOCTL_SUSPEND_PROCESS";
	case RECLASS_KERNEL_IOCTL_RESUME_PROCESS:
		return "RECLASS_KERNEL_IOCTL_RESUME_PROCESS";
	case RECLASS_KERNEL_IOCTL_TERMINATE_PROCESS:
		return "RECLASS_KERNEL_IOCTL_TERMINATE_PROCESS";
	default:
		return "unknown ioctl code";
	}
}

NTSTATUS ReClassHandleDispatch(HANDLE calllerProcessId, ULONG ioctlCode, PVOID paramBuffer, ULONG paramSizeIn, ULONG paramSizeOut, BOOLEAN kernelRequest)
{
	NTSTATUS status;

	if (paramBuffer == NULL)
		return STATUS_INVALID_PARAMETER_2;

	switch (ioctlCode)
	{
	case RECLASS_KERNEL_IOCTL_READ_VIRTUAL_MEMORY:
	{
		if (paramSizeIn >= sizeof(RC_PROCESS_VIRTUAL_MEMORY))
		{
			PRC_PROCESS_VIRTUAL_MEMORY paramInfo = (PRC_PROCESS_VIRTUAL_MEMORY)paramBuffer;
			status = ReClassReadVirtualMemory((HANDLE)paramInfo->ProcessId, (PVOID)paramInfo->Address, (PVOID)paramInfo->Buffer, (SIZE_T)paramInfo->Size);
		}
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	case RECLASS_KERNEL_IOCTL_WRITE_VIRTUAL_MEMORY:
	{
		if (paramSizeIn >= sizeof(RC_PROCESS_VIRTUAL_MEMORY))
		{
			PRC_PROCESS_VIRTUAL_MEMORY paramInfo = (PRC_PROCESS_VIRTUAL_MEMORY)paramBuffer;
			status = ReClassWriteVirtualMemory((HANDLE)paramInfo->ProcessId, (PVOID)paramInfo->Address, (PVOID)paramInfo->Buffer, (SIZE_T)paramInfo->Size);
		}
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	case RECLASS_KERNEL_IOCTL_PROCESS_INFORMATION:
	{
		if (paramSizeIn >= sizeof(ULONG) && paramSizeOut >= sizeof(RC_PROCESS_INFORMATION))
			status = ReClassGetProcessInformation((HANDLE)*(PULONG)paramBuffer, (PRC_PROCESS_INFORMATION)paramBuffer);
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	case RECLASS_KERNEL_IOCTL_QUERY_VIRTUAL_MEMORY:
	{
		if (paramSizeIn >= sizeof(RC_QUERY_VIRTUAL_MEMORY) && paramSizeOut >= sizeof(RC_QUERY_VIRTUAL_MEMORY))
		{
			PRC_QUERY_VIRTUAL_MEMORY paramInfo = (PRC_QUERY_VIRTUAL_MEMORY)paramBuffer;

			MEMORY_BASIC_INFORMATION memoryInfo;
			RtlZeroMemory(&memoryInfo, sizeof(MEMORY_BASIC_INFORMATION));

			if (NT_SUCCESS(status = ReClassQueryVirtualMemory((HANDLE)paramInfo->ProcessId, (PVOID)paramInfo->BaseAddress, &memoryInfo)))
			{
				paramInfo->BaseAddress = (ULONGLONG)memoryInfo.BaseAddress;
				paramInfo->AllocationBase = (ULONGLONG)memoryInfo.AllocationBase;
				paramInfo->AllocationProtect = memoryInfo.AllocationProtect;
				paramInfo->RegionSize = (ULONGLONG)memoryInfo.RegionSize;
				paramInfo->State = memoryInfo.State;
				paramInfo->Protect = memoryInfo.Protect;
				paramInfo->Type = memoryInfo.Type;
			}
		}
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	case RECLASS_KERNEL_IOCTL_SUSPEND_PROCESS:
	{
		if (paramSizeIn >= sizeof(ULONG))
			status = ReClassSuspendProcess((HANDLE)*(PULONG)paramBuffer);
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	case RECLASS_KERNEL_IOCTL_RESUME_PROCESS:
	{
		if (paramSizeIn >= sizeof(ULONG))
			status = ReClassResumeProcess((HANDLE)*(PULONG)paramBuffer);
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	case RECLASS_KERNEL_IOCTL_TERMINATE_PROCESS:
	{
		if (paramSizeIn >= sizeof(ULONG))
			status = ReClassTerminateProcess((HANDLE)*(PULONG)paramBuffer, STATUS_SUCCESS);
		else
			status = STATUS_INVALID_BUFFER_SIZE;
		break;
	}
	default:
		DPRINT("Unknown ioctl passed: %d", ioctlCode);
		status = STATUS_INVALID_PARAMETER_2;
		break;
	}

	// if(!NT_SUCCESS(status))
	// 	DPRINT("%s Failed: 0x%X", name_from_ioctl(ioctlCode), status);

	return status;
}

NTSTATUS ReClassReadVirtualMemory(HANDLE processId, PVOID virtualAddress, PVOID bufferPtr, SIZE_T bufferSize)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		__try
		{
			ProbeForRead(virtualAddress, bufferSize, 1);
			ProbeForWrite(bufferPtr, bufferSize, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_ACCESS_VIOLATION;
			goto cleanup;
		}

		SIZE_T numRet = 0;
		status = MmCopyVirtualMemory(targetProcess, virtualAddress, PsGetCurrentProcess(), bufferPtr, bufferSize, KernelMode, &numRet);

	cleanup:
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS ReClassWriteVirtualMemory(HANDLE processId, PVOID virtualAddress, PVOID bufferPtr, SIZE_T bufferSize)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		__try
		{
			ProbeForRead(bufferPtr, bufferSize, 1);
			ProbeForWrite(virtualAddress, bufferSize, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_ACCESS_VIOLATION;
			goto cleanup;
		}

		SIZE_T numRet = 0;
		status = MmCopyVirtualMemory(PsGetCurrentProcess(), bufferPtr, targetProcess, virtualAddress, bufferSize, KernelMode, &numRet);

	cleanup:
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS ReClassGetProcessInformation(HANDLE processId, PRC_PROCESS_INFORMATION information)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;

	if (information == NULL)
		return STATUS_INVALID_PARAMETER_2;

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		information->IsWow64 = PsGetProcessWow64Process(targetProcess) != NULL;

		if (information->IsWow64)
			information->PebAddress = (ULONGLONG)PsGetProcessWow64Process(targetProcess);
		else
			information->PebAddress = (ULONGLONG)PsGetProcessPeb(targetProcess);

		information->Eprocess = (ULONGLONG)targetProcess;
		information->ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(targetProcess);

		PFILE_OBJECT processFileObject = NULL;
		POBJECT_NAME_INFORMATION processFileNameInfo = NULL;

		if (NT_SUCCESS(status = PsReferenceProcessFilePointer(targetProcess, &processFileObject)))
		{
			if (NT_SUCCESS(status = IoQueryFileDosDeviceName(processFileObject, &processFileNameInfo)))
				wcscpy_s(information->ImagePath, processFileNameInfo->Name.MaximumLength, processFileNameInfo->Name.Buffer);
			ObDereferenceObject(processFileObject);
		}
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS ReClassQueryVirtualMemory(HANDLE processId, PVOID baseAddress, PMEMORY_BASIC_INFORMATION memoryInfo)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;
	KAPC_STATE savedAPCState;
	SIZE_T retSize = 0ULL;

	RtlZeroMemory(&savedAPCState, sizeof(KAPC_STATE));

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		KeStackAttachProcess(targetProcess, &savedAPCState);
		status = ZwQueryVirtualMemory(ZwCurrentProcess(), baseAddress, MemoryBasicInformation, memoryInfo, sizeof(MEMORY_BASIC_INFORMATION), &retSize);
		KeUnstackDetachProcess(&savedAPCState);
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS ReClassSuspendProcess(HANDLE processId)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		status = PsSuspendProcess(targetProcess);
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS ReClassResumeProcess(HANDLE processId)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		status = PsResumeProcess(targetProcess);
		ObDereferenceObject(targetProcess);
	}

	return status;
}

NTSTATUS ReClassTerminateProcess(HANDLE processId, NTSTATUS exitStatus)
{
	NTSTATUS status;
	PEPROCESS targetProcess = NULL;
	KAPC_STATE apcState;

	RtlZeroMemory(&apcState, sizeof(KAPC_STATE));

	if (NT_SUCCESS(status = PsLookupProcessByProcessId(processId, &targetProcess)))
	{
		KeStackAttachProcess(targetProcess, &apcState);
		status = ZwTerminateProcess(ZwCurrentProcess(), exitStatus);
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
	}

	return status;
}
