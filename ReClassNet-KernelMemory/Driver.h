#pragma once

#include "nttypes.h"

#include <string>

#define DEVICE_INTERFACE_NAME	L"ReClassKernel"

/*
	Device specific
*/
#define RECLASS_FILE_DEVICE_ID 0x8011
#define RECLASS_FUNCTION_INDEX 0x940

#define RECLASS_REGISTER_IOCTL(index) (ULONG)CTL_CODE(RECLASS_FILE_DEVICE_ID, RECLASS_FUNCTION_INDEX + index, METHOD_BUFFERED, FILE_ANY_ACCESS)

/*
	IOCTL Codes
*/
#define RECLASS_KERNEL_IOCTL_READ_VIRTUAL_MEMORY			RECLASS_REGISTER_IOCTL(1)
#define RECLASS_KERNEL_IOCTL_WRITE_VIRTUAL_MEMORY			RECLASS_REGISTER_IOCTL(2)
#define RECLASS_KERNEL_IOCTL_PROCESS_INFORMATION			RECLASS_REGISTER_IOCTL(3)
#define RECLASS_KERNEL_IOCTL_QUERY_VIRTUAL_MEMORY			RECLASS_REGISTER_IOCTL(4)
#define RECLASS_KERNEL_IOCTL_SUSPEND_PROCESS				RECLASS_REGISTER_IOCTL(5)
#define RECLASS_KERNEL_IOCTL_RESUME_PROCESS					RECLASS_REGISTER_IOCTL(6)
#define RECLASS_KERNEL_IOCTL_TERMINATE_PROCESS				RECLASS_REGISTER_IOCTL(7)

/*
	IOCTL Structures
*/
typedef struct _RC_PROCESS_VIRTUAL_MEMORY
{
	ULONG ProcessId;
	ULONGLONG Address;
	ULONGLONG Buffer;
	ULONGLONG Size;
} RC_PROCESS_VIRTUAL_MEMORY, *PRC_PROCESS_VIRTUAL_MEMORY;

typedef struct _RC_PROCESS_INFORMATION
{
	BOOLEAN IsWow64;
	ULONGLONG ImageBase;
	ULONGLONG PebAddress;
	ULONGLONG Eprocess;
	WCHAR ImagePath[260];
} RC_PROCESS_INFORMATION, *PRC_PROCESS_INFORMATION;

typedef struct _RC_QUERY_VIRTUAL_MEMORY
{
	ULONG ProcessId;
	ULONGLONG BaseAddress;
	ULONGLONG AllocationBase;
	ULONG AllocationProtect;
	ULONGLONG RegionSize;
	ULONG State;
	ULONG Protect;
	ULONG Type;
} RC_QUERY_VIRTUAL_MEMORY, *PRC_QUERY_VIRTUAL_MEMORY;

/*
	Driver class impl
 */

struct KernelProcessInfo
{
	wchar_t Path[MAX_PATH + 1];
	ULONGLONG BaseAddress;
	ULONGLONG PebAddress;
	ULONGLONG Eprocess;
	bool IsWow64;
};

class CReclassDriver
{
	CReclassDriver() : m_Loaded(false) {}
	~CReclassDriver() { Unload(); }

public:
	CReclassDriver(const CReclassDriver&) = delete;
	CReclassDriver(CReclassDriver&&) = delete;
	CReclassDriver& operator=(const CReclassDriver&) = delete;
	CReclassDriver& operator=(CReclassDriver&&) = delete;

	static CReclassDriver& Instance();

	bool Load(std::wstring driver_path, DWORD* extender_error_info = nullptr);
	bool Unload();

	bool ReadMemory(DWORD process_id, DWORD_PTR address, void* data, size_t size_of_data) const;
	template<typename T> bool ReadMemory(DWORD process_id, DWORD_PTR address, T* data) {
		return ReadMemory(process_id, address, data, sizeof T);
	}
	bool WriteMemory(DWORD process_id, DWORD_PTR address, const void* data, size_t size_of_data) const;
	template<typename T> bool WriteMemory(DWORD process_id, DWORD_PTR address, T* data) {
		return WriteMemory(process_id, address, data, sizeof T);
	}

	bool QueryMemory(DWORD process_id, DWORD_PTR address, MEMORY_BASIC_INFORMATION* memory_query_info) const;
	bool ProcessInfo(DWORD process_id, KernelProcessInfo* process_info) const;

	bool SuspendProcess(DWORD process_id) const;
	bool ResumeProcess(DWORD process_id) const;
	bool TerminateProcess(DWORD process_id) const;

private:
	UNICODE_STRING m_registry_entry{};
	HANDLE m_driver_handle{};
	bool m_Loaded;
};

namespace { CReclassDriver& Kernel() { return CReclassDriver::Instance(); } }
