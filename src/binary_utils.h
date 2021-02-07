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

    std::string GetModuleName() const;


    std::shared_ptr<LIEF::PE::Binary> Get() const;

private:
    std::shared_ptr<LIEF::PE::Binary> m_binary;
    uintptr_t m_base_address;
};

#endif