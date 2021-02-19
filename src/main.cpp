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
                auto section_offset              = section.virtual_address();
                auto section_vector              = section.content();
                const size_t section_size        = section_vector.size();
                const uintptr_t module_base_addr = dll_obj->GetBaseAddress();

                const uint64_t* mem_section_ptr  = reinterpret_cast<uint64_t*>(module_base_addr + section_offset);
                const uint64_t* file_section_ptr = reinterpret_cast<uint64_t*>(&section_vector[0]);

                for (size_t offset = 0; offset < section_size; offset += sizeof(*mem_section_ptr))
                {
                    // Perform checks 64-bit at a time
                    if (*mem_section_ptr != *file_section_ptr)
                    {
                        // Check the diff byte by byte
                        const uint8_t* mem_section  = reinterpret_cast<const uint8_t*>(mem_section_ptr);
                        const uint8_t* file_section = reinterpret_cast<const uint8_t*>(file_section_ptr);

                        const size_t nb_bytes_to_check = std::min(section_size - offset, sizeof(*mem_section_ptr));

                        for (size_t i = 0; i < nb_bytes_to_check; i++)
                        {
                            uintptr_t cur_addr = (uintptr_t)&mem_section[i];
                            // Check if this address was modified by the loader
                            if (!dll_obj->IsAddressModifiedByLoader(cur_addr))
                            {
                                if (mem_section[i] != file_section[i])
                                {
                                    auto export_name = dll_obj->GetExportNameFromAddress(cur_addr);
                                    Log("Byte at %s+%p [Export name: %s] differs (orig: %#x != %#x)",
                                        module_filename.c_str(),
                                        dll_obj->VaToRva(cur_addr),
                                        export_name.c_str(),
                                        file_section[i],
                                        mem_section[i]);
                                }
                            }
                        }
                    }

                    if (offset % 0x10000 == 0)
                    {
                        // Yield thread every 0x10 pages
                        YieldThread(std::chrono::microseconds(10000));
                    }
                    mem_section_ptr++;
                    file_section_ptr++;
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
            ScanAllModule();
            // CreateThread(NULL, 0, ScanThread, NULL, 0, &thread_id);
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