#pragma once

#include "pdo_error.h"
namespace pdo
{
void Log(
        pdo_log_level_t logLevel,
        const char* message,
        ...);

void Log(
        pdo_log_level_t logLevel,
        const char* message);
}

void Log(int level, const char* fmt, ...);
