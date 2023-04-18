# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Make sure we get the right python library version
FIND_PACKAGE(Python3 REQUIRED COMPONENTS Interpreter Development)
IF(NOT Python3_FOUND)
  MESSAGE(FATAL_ERROR "Python3 not found")
ENDIF()

FILE(READ ${PDO_SOURCE_ROOT}/VERSION PKG_VERSION)
STRING(STRIP ${PKG_VERSION} PKG_VERSION) # bc VERSION ends with \n
SET(WHEEL_NAME_SUFFIX ${PKG_VERSION}-py3-none-any)

# Generates a python wheel given a WHEEL_SRC_DIR and optional cmake target-
# level dependencies; if the WHEEL_WITH_DEPS options is on, the function
# expects at least one WHEEL_TARGET_DEPS argument to be specified.
FUNCTION(BUILD_PYTHON_WHEEL)
  SET(OPTS WITH_DEPS)
  SET(ONE_VAL_ARGS SRC_DIR NAME)
  SET(MULTI_VAL_ARGS TARGET_DEPS)
  CMAKE_PARSE_ARGUMENTS(WHEEL
    "${OPTS}" "${ONE_VAL_ARGS}" "${MULTI_VAL_ARGS}"
    ${ARGN})

  IF(NOT DEFINED WHEEL_SRC_DIR)
    MESSAGE(FATAL_ERROR
      "Need to specify the source directory from which to build the .whl")
  ENDIF()

  IF(NOT DEFINED WHEEL_NAME)
    MESSAGE(FATAL_ERROR
      "Need to specify the name for the .whl")
  ENDIF()

  ADD_CUSTOM_COMMAND(
    OUTPUT "${WHEEL_NAME}-${WHEEL_NAME_SUFFIX}.whl"
    COMMAND "${Python3_EXECUTABLE}" -m build --wheel "${WHEEL_SRC_DIR}"
    )

  # this triggers the wheel build every time this function is called
  ADD_CUSTOM_TARGET(build-wheel ALL
    DEPENDS ${WHEEL_NAME}-${WHEEL_NAME_SUFFIX}.whl
    )

  IF(NOT WHEEL_WITH_DEPS)
    MESSAGE(STATUS "Building .whl at ${WHEEL_SRC_DIR} without dependencies")
  ELSE()
    # adds the dependencies if they were specified
    MESSAGE(STATUS "Building .whl at ${WHEEL_SRC_DIR} with dependencies ${WHEEL_TARGET_DEPS}")
    IF(NOT DEFINED WHEEL_TARGET_DEPS)
      MESSAGE(FATAL_ERROR
        "Need to specify one or more target-level dependencies")
    ENDIF()

    # this ensures that the wheel dependencies are built before the wheel
    ADD_DEPENDENCIES(build-wheel ${WHEEL_TARGET_DEPS})
  ENDIF()

ENDFUNCTION()
