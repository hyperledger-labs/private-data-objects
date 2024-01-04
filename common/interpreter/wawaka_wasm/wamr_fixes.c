#include "platform_internal.h"

bool
os_is_handle_valid(os_file_handle *handle)
{
    assert(handle != NULL);
    return *handle > -1;
}
