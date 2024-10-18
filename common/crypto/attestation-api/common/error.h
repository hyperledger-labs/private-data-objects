/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef COND2ERR
#define COND2ERR(b)                                            \
    do                                                         \
    {                                                          \
        if (b)                                                 \
        {                                                      \
            LOG_DEBUG("error at %s:%d\n", __FILE__, __LINE__); \
            goto err;                                          \
        }                                                      \
    } while (0)
#endif //COND2ERR

#ifndef COND2LOGERR
#define COND2LOGERR(b, fmt, ...)                                        \
    do                                                                  \
    {                                                                   \
        if (b)                                                          \
        {                                                               \
            LOG_ERROR("error at %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
            goto err;                                                   \
        }                                                               \
    } while (0)
#endif //COND2LOGERR

#ifndef CATCH
#define CATCH(b, expr) \
    do                 \
    {                  \
        try            \
        {              \
            expr;      \
            b = true;  \
        }              \
        catch (const std::exception &exc)                                           \
        {              \
            LOG_ERROR("exception at %s:%d: %s\n", __FILE__, __LINE__, exc.what());  \
            b = false; \
        }              \
    } while (0);
#endif //CATCH
