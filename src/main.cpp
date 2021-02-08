#include "binary_utils.h"
#include "logger.h"

#include <LIEF/LIEF.hpp>
#include <Windows.h>
#include <algorithm>
#include <chrono>
#include <codecvt>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <locale>
#include <psapi.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <vector>

using namespace LIEF;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

extern "C" __declspec(dllexport) int Moo(void)
{
    return 0;
}

std::vector<std::string> kBlacklist = {"SspiCli.dll",
                                       "cfgmgr32.dll",
                                       "WindowsCodecs.dll",
                                       "kernel.appcore.dll",
                                       "VCRUNTIME140.dll",
                                       "Wldp.dll",
                                       "MSASN1.dll",
                                       "amdihk64.dll",
                                       "WINNSI.DLL"};

bool IsInBlacklist(const std::string& filename)
{
    return std::find(kBlacklist.begin(), kBlacklist.end(), filename) != kBlacklist.end();
}

std::vector<fs::path> GetModules()
{
    HMODULE modules_handle[1024];
    HANDLE process_handle;
    DWORD needed;
    unsigned int i;
    std::vector<fs::path> modules;

    process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, GetCurrentProcessId());
    if (process_handle == nullptr)
        return modules;

    if (EnumProcessModules(process_handle, modules_handle, sizeof(modules_handle), &needed))
    {
        for (i = 0; i < (needed / sizeof(HMODULE)); i++)
        {
            CHAR module_name[MAX_PATH];

            // Ignore the process' executable file
            if (GetModuleHandle(NULL) != modules_handle[i])
            {
                if (GetModuleFileNameEx(process_handle, modules_handle[i], module_name, sizeof(module_name) / sizeof(CHAR)))
                {
                    // Print the module name and handle value.
                    modules.push_back(fs::path{module_name});
                }
            }
        }
    }

    CloseHandle(process_handle);

    return modules;
}

void YieldThread(std::chrono::microseconds us)
{
    auto start = std::chrono::high_resolution_clock::now();
    auto end   = start + us;
    do
    {
        std::this_thread::yield();
    } while (std::chrono::high_resolution_clock::now() < end);
}

void ScanAllModule()
{
    Log("Start scan...");
    auto modules = GetModules();
    Log("Number of modules found: %d", modules.size());
    for (auto& module : modules)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::string module_path     = converter.to_bytes(module.c_str());
        std::string module_filename = converter.to_bytes(module.filename().c_str());

        if (IsInBlacklist(module_filename))
            continue;

        Log("Scanning %s @ %s...\n", module_filename.c_str(), module_path.c_str());

        auto dll_obj = DllObject::LoadFromFile(module_path);
        auto pe      = dll_obj->Get();
        for (auto& section : pe->sections())
        {
            bool is_executable = section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
            bool is_writable   = section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

            if (is_executable && !is_writable)
            {
                auto file_content = section.content();
                auto va           = section.virtual_address();

                uintptr_t base_address     = dll_obj->GetBaseAddress();
                const uint8_t* section_ptr = reinterpret_cast<uint8_t*>(base_address + section.virtual_address());

                for (size_t i = 0; i < std::min((uint64_t)section.virtual_size(), section.size()); i++)
                {
                    uintptr_t cur_addr = (uintptr_t)section_ptr;

                    // The address should not be modifier by the linker to be checked against the DLL on disk.
                    if (!dll_obj->IsAddressModifiedByLinker(cur_addr))
                    {
                        if (*section_ptr != file_content[i])
                        {
                            auto export_name = dll_obj->GetExportNameFromAddress(cur_addr);
                            Log("Byte at %s+%p [Export name: %s] differs (orig: %#x != %#x)",
                                module_filename.c_str(),
                                dll_obj->VaToRva(cur_addr),
                                export_name.c_str(),
                                file_content[i],
                                *section_ptr);
                        }
                    }

                    if (i % 0x10000 == 0)
                    {
                        // Yield thread every 0x10 pages
                        YieldThread(std::chrono::microseconds(10000));
                    }
                    section_ptr++;
                }
            }
        }
    }
    Log("End of scan...");
}

DWORD WINAPI ScanThread(LPVOID lp_param)
{
    ScanAllModule();

    return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    DWORD thread_id;
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // ScanAllModule();
            CreateThread(NULL, 0, ScanThread, NULL, 0, &thread_id);
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}

int main()
{
    auto handle = GetModuleHandle("kernel32.dll");
    if (handle == nullptr)
        return -1;

    auto address = GetProcAddress(handle, "IsDebuggerPresent");
    if (address == nullptr)
        return -1;


    std::cout << "Export found" << std::endl;

    DWORD old_prot;
    if (!VirtualProtect(address, 0x1, PAGE_EXECUTE_READWRITE, &old_prot))
        return -1;

    memcpy(address, "\x33\xc0\xc3", 3);
    DWORD saved_prot = old_prot;
    VirtualProtect(address, 0x1, saved_prot, &old_prot);

    ScanAllModule();
}