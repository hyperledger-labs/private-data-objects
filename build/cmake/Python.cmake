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

# assumes that project variables have been
# set including PDO_INSTALL_ROOT and PDO_CONTRACT_VERSION

IF (NOT DEFINED PDO_INSTALL_ROOT)
  MESSAGE(FATAL_ERROR "PDO_INSTALL_ROOT not defined")
ENDIF()

IF (NOT DEFINED PDO_VERSION)
  MESSAGE(FATAL_ERROR "PDO_VERSION not defined")
ENDIF()

SET(PIP "${PDO_INSTALL_ROOT}/bin/pip3" CACHE STRING "Pip executable in virtual environment")
SET(PYTHON "${PDO_INSTALL_ROOT}/bin/python3" CACHE STRING "Python executable in virtual environment")
SET(RESOURCE_INSTALLER "${PDO_INSTALL_ROOT}/bin/pdo-install-plugin-resources" CACHE STRING "PDO resource installer")
SET(WHEEL_PATH "${CMAKE_BINARY_DIR}/dist" CACHE STRING "Path where python wheels will be placed")

FUNCTION(BUILD_WHEEL package)
  SET(SOURCE ${CMAKE_CURRENT_SOURCE_DIR})
  SET(WHEEL_FILE "${WHEEL_PATH}/${package}-${PDO_VERSION}-py3-none-any.whl")
  FILE(STRINGS "${SOURCE}/MANIFEST" MANIFEST)

  # adding the build and egg-info directories to the output means that
  # they will be cleaned up with the global clean target
  ADD_CUSTOM_COMMAND(
    OUTPUT ${WHEEL_FILE} ${SOURCE}/${package}.egg-info
    COMMAND ${PYTHON}
    ARGS -m build --wheel --outdir ${WHEEL_PATH}
    WORKING_DIRECTORY ${SOURCE}
    DEPENDS ${MANIFEST})

  ADD_CUSTOM_TARGET(${package}-package ALL DEPENDS ${WHEEL_FILE})

  STRING(JOIN "\n" INSTALL_COMMAND
    "MESSAGE(\"INSTALL ${package}\")"
    "EXECUTE_PROCESS(COMMAND ${PIP} uninstall --yes ${WHEEL_FILE})"
    "EXECUTE_PROCESS(COMMAND ${PIP} install ${WHEEL_FILE})" )

  INSTALL(CODE ${INSTALL_COMMAND})
ENDFUNCTION()
