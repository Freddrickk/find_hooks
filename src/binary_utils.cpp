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
        result->m_base_address = (uintptr_t)GetModuleHandleA(path.c_str());
    }
    catch (const LIEF::exception& err)
    {
        result = nullptr;
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

bool DllObject::IsAddressInIAT(uintptr_t address)
{
    auto iat = m_binary->data_directory(LIEF::PE::DATA_DIRECTORY::IAT);
    auto beg = GetBaseAddress() + iat.RVA();
    auto end = beg + iat.size();
    return address >= beg && address < end;
}

bool DllObject::IsAddressModifiedByLinker(uintptr_t address)
{
    return IsAddressInIAT(address) || IsRelocatedMemory(address);
}

bool DllObject::IsRelocatedMemory(uintptr_t address)
{
    if (!m_binary->has_relocations())
        return false;

    if (!m_reloc_initialized)
        InitializeRelocationCache();

    return m_relocations.find(address) != m_relocations.end();
}

void DllObject::InitializeRelocationCache()
{
    if (m_reloc_initialized)
        return;

    for (const auto& reloc_entries : m_binary->relocations())
    {
        auto base_address = reloc_entries.virtual_address();
        for (const auto& reloc : reloc_entries.entries())
        {
            auto beg = GetBaseAddress() + base_address + reloc.position();


            // Size is in bits
            size_t reloc_size = reloc.size() / 8;
            uintptr_t end_ptr = beg + reloc_size;
            // if (m_binary->name() == "D3DCOMPILER_43.dll")
            // Log("Relocation @ 0x%p of size %d", beg, reloc_size);
            for (uintptr_t relocated_addr = beg; relocated_addr != end_ptr; relocated_addr++)
            {
                // if (m_binary->name() == "D3DCOMPILER_43.dll")
                // Log("Relocated address: 0x%p (RVA: 0x%p)", relocated_addr, relocated_addr - base_address);
                m_relocations[relocated_addr] = true;
            }
        }
    }

    m_reloc_initialized = true;
}