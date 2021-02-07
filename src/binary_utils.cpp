#include "binary_utils.h"

#include "logger.h"

#include <LIEF/LIEF.hpp>
#include <memory>

std::unique_ptr<DllObject> DllObject::LoadFromFile(const std::string& path)
{
    std::unique_ptr<DllObject> result = nullptr;
    try
    {
        auto pe                = LIEF::PE::Parser::parse(path);
        result                 = std::make_unique<DllObject>();
        result->m_binary       = std::shared_ptr<LIEF::PE::Binary>(pe.release());
        result->m_base_address = (uintptr_t)GetModuleHandleA(result->m_binary->name().c_str());
    }
    catch (const LIEF::exception& err)
    {
        std::cerr << err.what() << std::endl;
    }

    return result;
}

std::string DllObject::GetExportNameFromAddress(uintptr_t address) const
{
    uintptr_t target_rva = address - GetBaseAddress();
    for (auto& function : m_binary->exported_functions())
    {
        // printf("m_binary->name().c_str() == %s", m_binary->name().c_str());
        uint32_t export_rva = function.address();
        // printf("Export entry %s @ %x\n", function.name().c_str(), export_rva);
        if (target_rva == export_rva)
            return function.name();
    }
    return "";
}

uintptr_t DllObject::GetBaseAddress() const
{
    return m_base_address;
}

std::string DllObject::GetModuleName() const
{
    return m_binary->name();
}

uintptr_t DllObject::VaToRva(uintptr_t virual_address) const
{
    return virual_address - GetBaseAddress();
}

uintptr_t DllObject::RvaToVa(uintptr_t rva) const
{
    return GetBaseAddress() + rva;
}

std::shared_ptr<LIEF::PE::Binary> DllObject::Get() const
{
    return m_binary;
}