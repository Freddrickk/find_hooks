#ifndef _BINARY_UTILS_H_
#define _BINARY_UTILS_H_

#include "LIEF/LIEF.hpp"

#include <string>

class DllObject
{
public:
    static std::unique_ptr<DllObject> LoadFromFile(const std::string& path);
    std::string GetExportNameFromAddress(uintptr_t address) const;

    uintptr_t GetBaseAddress() const;
    uintptr_t VaToRva(uintptr_t virual_address) const;
    uintptr_t RvaToVa(uintptr_t rva) const;

    bool IsRelocatedMemory(uintptr_t address);
    bool IsAddressInIAT(uintptr_t address);
    bool IsAddressModifiedByLinker(uintptr_t address);

    void InitializeRelocationCache();

    std::string GetModuleName() const;


    std::shared_ptr<LIEF::PE::Binary> Get() const;

private:
    std::shared_ptr<LIEF::PE::Binary> m_binary;
    uintptr_t m_base_address;
    std::unordered_map<uintptr_t, bool> m_relocations;
    bool m_reloc_initialized = false;
};

#endif