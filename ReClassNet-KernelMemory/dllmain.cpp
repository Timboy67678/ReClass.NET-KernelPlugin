#include "KernelCore.h"

BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH: 
		{
			SetPrivilege(SE_LOAD_DRIVER_NAME, TRUE);
			std::wstring driver_path = fs::current_path().wstring() + L"\\Plugins\\ReClassKernel64.sys";
			if (!Kernel().Load(driver_path))
				return FALSE;
		}
		break;
	case DLL_PROCESS_DETACH:
		Kernel().Unload();
		break;
	default: 
		break;
	}

	return TRUE;
}
