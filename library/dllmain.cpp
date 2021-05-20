// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string>
#include <iostream>
#include <Windows.h>
//#include <easyhook.h>

bool hook(std::string password) {
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        MessageBox(nullptr, _T("This message is NOT from notepad"), _T("Injected"), MB_OK);

        /*HOOK_TRACE_INFO hHook = { NULL };
        LhInstallHook(
            GetProcAddress(GetModuleHandle(NULL), "isPasswordCorrect"),
            hook,
            NULL,
            &hHook
        );*/
    }
    return TRUE;
}

