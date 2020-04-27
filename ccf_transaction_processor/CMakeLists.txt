#

cmake_minimum_required(VERSION 3.11)

include(${CCF_DIR}/cmake/preproject.cmake)

project(pdoenc LANGUAGES C CXX)

include(${CCF_DIR}/cmake/ccf.cmake)
include(${CCF_DIR}/cmake/ccf_app.cmake)

# Add the PDO transaction processor target
add_ccf_app(pdoenc
  SRCS transaction_processor/pdo_tp.cpp transaction_processor/verify_signatures.cpp
  INCLUDE_DIRS ${CCF_DIR}/include/ccf ${CCF_DIR}/include/3rdparty ${CCF_DIR}/include}
)

install(TARGETS pdoenc.virtual DESTINATION lib)
sign_app_library(pdoenc.enclave ../etc/oe_sign.conf ../etc/sample_key.pem)
