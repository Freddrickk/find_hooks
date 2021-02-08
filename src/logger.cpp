#include "logger.h"

std::string GetLogfileName()
{
    time_t rawtime;
    struct tm* timeinfo;
    char buffer[0x80];

    time(&rawtime);
    timeinfo = localtime(&rawtime);

    strftime(buffer, sizeof(buffer), "%F_%H-%M-%S_log_hooks.txt", timeinfo);
    static std::string kLogFilePath{buffer};
    return kLogFilePath;
}