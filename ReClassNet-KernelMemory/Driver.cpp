#include "Driver.h"

#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

DWORD __byte_ret_dummy = 0;

CReclassDriver& CReclassDriver::Instance()
{
	static CReclassDriver __driver_instance;
	return __driver_instance;
}

bool CReclassDriver::Load(std::wstring driver_path, DWORD* extender_error_info)
{
	if (m_Loaded) return false;

	HKEY services_key = NULL;
	HKEY driver_key = NULL;

	if (extender_error_info != nullptr)
		*extender_error_info = 0UL;

	if (RegOpenKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", &services_key) != ERROR_SUCCESS)
		return false;

	if (RegCreateKeyW(services_key, DEVICE_INTERFACE_NAME, &driver_key) != ERROR_SUCCESS) {
		RegCloseKey(services_key);
		return false;
	}

	if (driver_path[0] != '\\')
		driver_path = L"\\??\\" + driver_path;

	if (RegSetValueExW(driver_key, L"ImagePath", 0, REG_SZ, reinterpret_cast<const BYTE*>(driver_path.c_str()), static_cast<DWORD>(driver_path.size()) * sizeof(wchar_t)) != ERROR_SUCCESS)
	{
		RegCloseKey(driver_key);
		RegCloseKey(services_key);
		return false;
	}

	DWORD service_type = SERVICE_KERNEL_DRIVER;
	if (RegSetValueExW(driver_key, L"Type", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&service_type), sizeof(DWORD)) != ERROR_SUCCESS)
	{
		RegCloseKey(driver_key);
		RegCloseKey(services_key);
		return false;
	}

	RegCloseKey(driver_key);
	RegCloseKey(services_key);

	NTSTATUS status;
	RtlInitUnicodeString(&m_registry_entry, L"\\registry\\machine\\SYSTEM\\CurrentControlSet\\Services\\" DEVICE_INTERFACE_NAME);
	if (!NT_SUCCESS(status = NtLoadDriver(&m_registry_entry))) {
		if (extender_error_info != nullptr)
			*extender_error_info = status;
		return false;
	}

	m_driver_handle = CreateFileW(L"\\\\.\\" DEVICE_INTERFACE_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
	if (m_driver_handle == INVALID_HANDLE_VALUE)
		return false;

	return m_Loaded = true;
}

bool CReclassDriver::Unload()
{
	if (!m_Loaded) return false;
	CloseHandle(m_driver_handle);
	NtUnloadDriver(&m_registry_entry);
	SHDeleteKeyW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" DEVICE_INTERFACE_NAME);
	m_Loaded = false;
	return true;
}

bool CReclassDriver::ReadMemory(DWORD process_id, DWORD_PTR address, void* data, size_t size_of_data) const
{
	if (!m_Loaded) return false;

	RC_PROCESS_VIRTUAL_MEMORY vmem;
	vmem.ProcessId = process_id;
	vmem.Address = (ULONGLONG)address;
	vmem.Buffer = (ULONGLONG)data;
	vmem.Size = (SIZE_T)size_of_data;

	return DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_READ_VIRTUAL_MEMORY, &vmem, sizeof vmem, NULL, 0, &__byte_ret_dummy, NULL) == TRUE;
}

bool CReclassDriver::WriteMemory(DWORD process_id, DWORD_PTR address, const void* data, size_t size_of_data) const
{
	if (!m_Loaded) return false;

	RC_PROCESS_VIRTUAL_MEMORY vmem;
	vmem.ProcessId = process_id;
	vmem.Address = (ULONGLONG)address;
	vmem.Buffer = (ULONGLONG)data;
	vmem.Size = (SIZE_T)size_of_data;

	return DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_WRITE_VIRTUAL_MEMORY, &vmem, sizeof vmem, NULL, 0, &__byte_ret_dummy, NULL) == TRUE;
}

bool CReclassDriver::QueryMemory(DWORD process_id, DWORD_PTR address, MEMORY_BASIC_INFORMATION* memory_query_info) const
{
	if (!m_Loaded) return false;

	RC_QUERY_VIRTUAL_MEMORY vquery{};
	vquery.ProcessId = process_id;
	vquery.BaseAddress = (ULONGLONG)address;

	if(DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_QUERY_VIRTUAL_MEMORY, &vquery, sizeof vquery, &vquery, sizeof vquery, &__byte_ret_dummy, NULL) == TRUE && memory_query_info != nullptr)
	{
		memory_query_info->BaseAddress = (PVOID)vquery.BaseAddress;
		memory_query_info->AllocationBase = (PVOID)vquery.AllocationBase;
		memory_query_info->AllocationProtect = vquery.AllocationProtect;
		memory_query_info->RegionSize = (SIZE_T)vquery.RegionSize;
		memory_query_info->State = vquery.State;
		memory_query_info->Protect = vquery.Protect;
		memory_query_info->Type = vquery.Type;

		return true;
	}
	return false;
}

bool CReclassDriver::ProcessInfo(DWORD process_id, KernelProcessInfo* process_info) const
{
	if (!m_Loaded) return false;

	RC_PROCESS_INFORMATION proc{};

	if(DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_PROCESS_INFORMATION, &process_id, sizeof(DWORD), &proc, sizeof proc, &__byte_ret_dummy, NULL) == TRUE)
	{
		process_info->BaseAddress = proc.ImageBase;
		process_info->Eprocess = proc.Eprocess;
		process_info->IsWow64 = proc.IsWow64 == TRUE;
		process_info->PebAddress = proc.PebAddress;
		wcscpy_s(process_info->Path, proc.ImagePath);

		return true;
	}

	return false;
}

bool CReclassDriver::SuspendProcess(DWORD process_id) const
{
	if (!m_Loaded) return false;
	return DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_SUSPEND_PROCESS, &process_id, sizeof(DWORD), NULL, 0, &__byte_ret_dummy, NULL) == TRUE;
}

bool CReclassDriver::ResumeProcess(DWORD process_id) const
{
	if (!m_Loaded) return false;
	return DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_RESUME_PROCESS, &process_id, sizeof(DWORD), NULL, 0, &__byte_ret_dummy, NULL) == TRUE;
}

bool CReclassDriver::TerminateProcess(DWORD process_id) const
{
	if (!m_Loaded) return false;
	return DeviceIoControl(m_driver_handle, RECLASS_KERNEL_IOCTL_TERMINATE_PROCESS, &process_id, sizeof(DWORD), NULL, 0, &__byte_ret_dummy, NULL) == TRUE;
}

