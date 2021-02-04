#include <LIEF/LIEF.hpp>
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
#include <windows.h>

using namespace LIEF;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

extern "C" __declspec(dllexport) int Moo(void)
{
    return 0;
}

template<typename... Args>
std::string format(const std::string& format_str, Args... args)
{
    size_t size = snprintf(nullptr, 0, format_str.c_str(), args...) + 1;
    std::string out(size, '\0');
    snprintf(out.data(), size, format_str.c_str(), args...);
    return {out.c_str()};
}

template<typename... Args>
void Log(const std::string& format_str, Args... args)
{
    std::ofstream file;
    file.open("log.txt", std::ios_base::app);
    file << format(format_str, std::forward<Args>(args)...) << std::endl;
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


void ScanAllModule()
{
    Log("Start scan...");
    auto modules = GetModules();
    Log("Number of modules found: %d", modules.size());
    for (auto& module : modules)
    {
        try
        {
            std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
            std::string module_path     = converter.to_bytes(module.c_str());
            std::string module_filename = converter.to_bytes(module.filename().c_str());

            Log("Scanning %s", module_filename.c_str());

            auto pe = LIEF::PE::Parser::parse(module_path);
            for (auto& section : pe->sections())
            {
                bool is_executable = section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_EXECUTE);
                bool is_writable   = section.has_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_WRITE);

                if (is_executable && !is_writable)
                {
                    auto file_content = section.content();
                    auto va           = section.virtual_address();

                    uintptr_t base_addr       = (uintptr_t)GetModuleHandleW(module.filename().c_str());
                    const uint8_t* section_va = reinterpret_cast<uint8_t*>(base_addr + section.virtual_address());

                    for (size_t i = 0; i < std::min((uint64_t)section.virtual_size(), section.size()); i++)
                    {
                        if (section_va[i] != file_content[i])
                        {
                            Log("Byte differs at %s+%p (orig: %#x != %#x)",
                                module_filename.c_str(),
                                (uintptr_t)(&section_va[i] - base_addr),
                                file_content[i],
                                section_va[i]);
                        }
                    }
                }
            }
        }
        catch (const LIEF::exception& err)
        {
            std::cerr << err.what() << std::endl;
        }
    }
    Log("End of scan...");
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "DLL Injection successful!", "DLL Injection", MB_ICONEXCLAMATION);
            ScanAllModule();
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}