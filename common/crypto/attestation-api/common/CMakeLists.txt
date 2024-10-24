# Copyright 2024 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0


SET(JWT_PATCHED_FILENAME .jwt-cpp-patched)
SET(JWT_PATCHED_FILEPATH ${CMAKE_CURRENT_SOURCE_DIR}/${JWT_PATCHED_FILENAME} PARENT_SCOPE)

ADD_CUSTOM_COMMAND(
	OUTPUT ${JWT_PATCHED_FILENAME}
    COMMAND [ ! -f ${JWT_PATCHED_FILENAME} ] && cd jwt-cpp && patch -f -p1 < ../jwt-cpp.patch && touch ../${JWT_PATCHED_FILENAME} || true
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)

ADD_CUSTOM_TARGET(patch_jwt DEPENDS ${JWT_PATCHED_FILENAME})

# TODO: devise better strategy for clean up; usually the build folder is removed so the clean is not called
ADD_CUSTOM_TARGET(clean_patch_jwt
    COMMAND [ -f ${JWT_PATCHED_FILENAME} ] && cd jwt-cpp && patch -f -p1 -R < ../jwt-cpp.patch && rm ../${JWT_PATCHED_FILENAME}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
	)

