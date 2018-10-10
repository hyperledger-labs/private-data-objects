#include <stdarg.h>
#include <stdio.h>
#include "log.h"
#include "c11_support.h"

void pdo::Log(
        pdo_log_level_t logLevel,
        const char* message,
        ...)
{
    const size_t BUFFER_SIZE = 2048;
    char msg[BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, message);
    vsnprintf_s(msg, BUFFER_SIZE, message, ap);
    va_end(ap);
//    puts(msg);
} // Log

void pdo::Log(
        pdo_log_level_t logLevel,
        const char* message)
{
//    puts(message);
}

void Log(int level, const char* fmt, ...) {
    const size_t BUFFER_SIZE = 2048;
    char msg[BUFFER_SIZE] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf_s(msg, BUFFER_SIZE, fmt, ap);
    va_end(ap);
//    puts(msg);
}
