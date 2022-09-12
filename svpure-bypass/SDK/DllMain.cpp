#include <Windows.h>`
#include <thread>
#include <process.h>
#include <iostream>
#include <Psapi.h>
#include "hooking/minhook.h"
#include "hooking/trampoline.h"
#include "hooking/detour.hpp"
#include "hooks/svpure.h"
#include "Hooks.h"

#define INRANGE(x,a,b)   (x >= a && x <= b)
#define GET_BYTE( x )    (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))

static uintptr_t PatternScan(const char* szModule, const char* szSignature)
{
    const char* pattern = szSignature;
    DWORD firstMatch = 0;
    DWORD rangeStart = (DWORD)GetModuleHandleA(szModule);
    MODULEINFO miModInfo;
    GetModuleInformation(GetCurrentProcess(), (HMODULE)rangeStart, &miModInfo, sizeof(MODULEINFO));
    DWORD rangeEnd = rangeStart + miModInfo.SizeOfImage;
    for (DWORD pCur = rangeStart; pCur < rangeEnd; pCur++)
    {
        if (!*pattern)
            return firstMatch;

        if (*(PBYTE)pattern == '\?' || *(BYTE*)pCur == GET_BYTE(pattern))
        {
            if (!firstMatch) {
                firstMatch = pCur;
            }
            if (!pattern[2]) {
                return firstMatch;
            }
            if (*(PWORD)pattern == '\?\?' || *(PBYTE)pattern != '\?') {
                pattern += 3;
            }
            else {
                pattern += 2;
            }
        }
        else {
            pattern = szSignature;
            firstMatch = 0;
        }
    }
    return 0u;
}

bool pressed = false;
void Main(HINSTANCE DLLInstance) {
    while (true) {
        while (!GetModuleHandleA("serverbrowser.dll"))
            Sleep(200);
        break;
    }

    const auto EngineDLL = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("engine.dll"));
    const auto ClientDLL = reinterpret_cast<std::uintptr_t>(GetModuleHandleA("client.dll"));

    MH_init();

    uintptr_t g_FileSystem = PatternScan("engine.dll", "8B 0D ? ? ? ? 83 C1 04 8B 01 FF 37 FF 50 1C 89 47 10") + 2;
    uintptr_t f_sendNetMsg = PatternScan("engine.dll", "55 8B EC 83 EC 08 56 8B F1 8B 4D 04");

    while (true) {
        using namespace std::literals::chrono_literals;
        std::this_thread::sleep_for(0.25s);

        if (!Hooks::SendNetMSG.IsHooked()) {
            Hooks::SendNetMSG.Create((void*)f_sendNetMsg, &hkSendNetMsg);
        }
        if (!Hooks::UnverifiedFileHashes.IsHooked()) {
            Hooks::UnverifiedFileHashes.Create((void*)(g_FileSystem + 101), &hkGetUnverifiedFileHashes);
        }
        if (!Hooks::ThirdPartyLoad.IsHooked()) {
            Hooks::ThirdPartyLoad.Create((void*)(g_FileSystem + 128), &hkCanLoadThirdPartyFiles);
        }
        if (!Hooks::LooseFiles.IsHooked()) {
            Hooks::LooseFiles.Create((void*)(g_FileSystem + 129), &hkAllowLooseFileLoads);
        }
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE Thread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(Main), hinstDLL, 0, nullptr);
        if (Thread) {
            CloseHandle(Thread);
        }
    }
    return TRUE;
}