/*
    eduLibsodium - .NET Framework-libsodium bridge

    Copyright: 2017 The Commons Conservancy
    SPDX-License-Identifier: GPL-3.0+
*/

#include "pch.h"

#pragma comment(lib, "libsodium.lib")

#pragma unmanaged
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpReserved);

	switch (fdwReason)
	{ 
		case DLL_PROCESS_ATTACH:
			sodium_init();
			break;
	}
	return TRUE;
}
