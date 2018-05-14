#include "KernelCore.h"
#include <TlHelp32.h>

void RC_CallConv EnumerateProcesses(EnumerateProcessCallback callbackProcess)
{
	if (callbackProcess)
	{
		HANDLE snapshot_handle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot_handle != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32W proc = { 0 };
			proc.dwSize = sizeof(proc);
			::Process32FirstW(snapshot_handle, &proc);

			do
			{
				if (proc.th32ProcessID == 0 || proc.th32ProcessID == 4)
					continue;

				//system process to consume (compressing) physical pages not used
				if (_wcsicmp(proc.szExeFile, L"Memory Compression") == 0)
					continue;

				EnumerateProcessData data = { 0 };
				KernelProcessInfo info = { 0 };
				
				if (Kernel().ProcessInfo(proc.th32ProcessID, &info) &&
#ifdef _WIN64
				
				!info.IsWow64
#else
				info.IsWow64
#endif
				)
				{
					data.Id = proc.th32ProcessID;
					std::memcpy(data.Name, proc.szExeFile, PATH_MAXIMUM_LENGTH * sizeof(RC_UnicodeChar));
					std::memcpy(data.Path, info.Path, PATH_MAXIMUM_LENGTH * sizeof(RC_UnicodeChar));

					callbackProcess(&data);
				}
			} while (::Process32NextW(snapshot_handle, &proc));
			
			::CloseHandle(snapshot_handle);
		}
	}
}

void RC_CallConv EnumerateRemoteSectionsAndModules(RC_Pointer handle, EnumerateRemoteSectionsCallback callbackSection, EnumerateRemoteModulesCallback callbackModule)
{
	if (callbackSection == nullptr && callbackModule == nullptr)
		return;

	DWORD process_id = (DWORD)handle;

	std::vector<EnumerateRemoteSectionData> memory_sections{};

	MEMORY_BASIC_INFORMATION memInfo = { 0 };
	memInfo.RegionSize = 0x1000;
	uintptr_t current_address = 0;
	
	while (Kernel().QueryMemory(process_id, current_address, &memInfo) && (current_address + memInfo.RegionSize) > current_address)
	{
		if (memInfo.State == MEM_COMMIT)
		{
			EnumerateRemoteSectionData section = { 0 };
			section.BaseAddress = memInfo.BaseAddress;
			section.Size = memInfo.RegionSize;

			section.Protection = SectionProtection::NoAccess;
			if ((memInfo.Protect & PAGE_EXECUTE) == PAGE_EXECUTE) section.Protection |= SectionProtection::Execute;
			if ((memInfo.Protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ) section.Protection |= SectionProtection::Execute | SectionProtection::Read;
			if ((memInfo.Protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) section.Protection |= SectionProtection::Execute | SectionProtection::Read | SectionProtection::Write;
			if ((memInfo.Protect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_READWRITE) section.Protection |= SectionProtection::Execute | SectionProtection::Read | SectionProtection::CopyOnWrite;
			if ((memInfo.Protect & PAGE_READONLY) == PAGE_READONLY) section.Protection |= SectionProtection::Read;
			if ((memInfo.Protect & PAGE_READWRITE) == PAGE_READWRITE) section.Protection |= SectionProtection::Read | SectionProtection::Write;
			if ((memInfo.Protect & PAGE_WRITECOPY) == PAGE_WRITECOPY) section.Protection |= SectionProtection::Read | SectionProtection::CopyOnWrite;
			if ((memInfo.Protect & PAGE_GUARD) == PAGE_GUARD) section.Protection |= SectionProtection::Guard;

			switch (memInfo.Type)
			{
			case MEM_IMAGE:
				section.Type = SectionType::Image;
				break;
			case MEM_MAPPED:
				section.Type = SectionType::Mapped;
				break;
			case MEM_PRIVATE:
				section.Type = SectionType::Private;
				break;
			default: 
				break;
			}
			
			section.Category = section.Type == SectionType::Private ? SectionCategory::HEAP : SectionCategory::Unknown;

			memory_sections.push_back(section);
		}
		current_address = reinterpret_cast<uintptr_t>(memInfo.BaseAddress) + memInfo.RegionSize;
	}

	HANDLE module_snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
	if (module_snapshot != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32W module_entry = { 0 };
		module_entry.dwSize = sizeof MODULEENTRY32W;
		::Module32FirstW(module_snapshot, &module_entry);
		
		do
		{
			if (callbackModule != nullptr)
			{
				EnumerateRemoteModuleData data = { 0 };
				data.BaseAddress = module_entry.modBaseAddr;
				data.Size = module_entry.modBaseSize;
				std::memcpy(data.Path, module_entry.szExePath, PATH_MAXIMUM_LENGTH * sizeof(RC_UnicodeChar));
				callbackModule(&data);
			}

			if (callbackSection != nullptr)
			{
				auto module_first_section = std::lower_bound(memory_sections.begin(), memory_sections.end(), (LPVOID)module_entry.modBaseAddr,
					[](const EnumerateRemoteSectionData& lhs, const LPVOID& rhs) { return lhs.BaseAddress < rhs; });

				IMAGE_DOS_HEADER dos_head = { 0 };
				IMAGE_NT_HEADERS32 nt_heads = { 0 };

				Kernel().ReadMemory(process_id, (DWORD_PTR)module_entry.modBaseAddr, &dos_head);
				Kernel().ReadMemory(process_id, (DWORD_PTR)module_entry.modBaseAddr + dos_head.e_lfanew, &nt_heads);

				std::vector<IMAGE_SECTION_HEADER> sections{ nt_heads.FileHeader.NumberOfSections };
				LPVOID section_start_address = module_entry.modBaseAddr + dos_head.e_lfanew + FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) + nt_heads.FileHeader.SizeOfOptionalHeader;
				Kernel().ReadMemory(process_id, (DWORD_PTR)section_start_address, sections.data(), sizeof(IMAGE_SECTION_HEADER) * nt_heads.FileHeader.NumberOfSections);
				
				for (auto&& section : sections)
				{
					const uintptr_t section_address = (uintptr_t)module_entry.modBaseAddr + section.VirtualAddress;

					for (auto current_section = module_first_section; current_section != memory_sections.end(); ++current_section)
					{
						if (section_address >= (uintptr_t)current_section->BaseAddress && section_address < (uintptr_t)current_section->BaseAddress + current_section->Size)
						{
							// Copy the name because it is not null padded.
							char section_name_buffer[IMAGE_SIZEOF_SHORT_NAME + 1] = { 0 };
							memcpy(section_name_buffer, section.Name, IMAGE_SIZEOF_SHORT_NAME);

							if (section.Characteristics & IMAGE_SCN_CNT_CODE)
								current_section->Category = SectionCategory::CODE;
							else if (section.Characteristics & (IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA))
								current_section->Category = SectionCategory::DATA;

							MultiByteToUnicode(section_name_buffer, current_section->Name, IMAGE_SIZEOF_SHORT_NAME);
							memcpy(current_section->ModulePath, module_entry.szExePath, PATH_MAXIMUM_LENGTH);

							break;
						}
					}
				}
			}
		} while (::Module32NextW(module_snapshot, &module_entry));

		::CloseHandle(module_snapshot);

		if (callbackSection != nullptr)
			for (auto&& section : memory_sections)
				callbackSection(&section);
	}
}

RC_Pointer RC_CallConv OpenRemoteProcess(RC_Pointer id, ProcessAccess)
{
	return id;
}

bool RC_CallConv IsProcessValid(RC_Pointer handle)
{
	return (DWORD)handle != 0;
}

void RC_CallConv CloseRemoteProcess(RC_Pointer)
{

}

void RC_CallConv ControlRemoteProcess(RC_Pointer handle, ControlRemoteProcessAction action)
{
	switch (action)
	{
	case ControlRemoteProcessAction::Suspend:
		Kernel().SuspendProcess((DWORD)handle);
		break;
	case ControlRemoteProcessAction::Resume:
		Kernel().ResumeProcess((DWORD)handle);
		break;
	case ControlRemoteProcessAction::Terminate:
		Kernel().TerminateProcess((DWORD)handle);
		break;
	}
}
