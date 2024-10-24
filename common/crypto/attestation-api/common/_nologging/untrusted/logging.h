/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef logging_h
#define logging_h

#include <stdio.h>

#define LOG_DEBUG(fmt, ...)     printf("DEBUG: %s-%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)      printf("INFO: %s-%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_WARNING(fmt, ...)   printf("WARNING: %s-%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...)     printf("ERROR: %s-%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define LOG(fmt, ...)           printf(fmt, ##__VA_ARGS__)

#endif  // logging_h
