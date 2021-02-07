#ifndef _LOGGER_H_
#define _LOGGER_H_

#include <cstdlib>
#include <fstream>
#include <string>

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

#endif