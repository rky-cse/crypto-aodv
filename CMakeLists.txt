cmake_minimum_required(VERSION 3.16)
project(crypto-aodv LANGUAGES CXX)

# -----------------------------------------------------------------------------
# User-tunable options
# -----------------------------------------------------------------------------
option(BUILD_TESTS "Build unit tests (Catch2)" ON)
set(CRYPTO_BACKEND "sodium" CACHE STRING "Crypto backend to use: sodium or openssl")
set(NS3_BUILD_DIR "/home/rky_cse/ns-3.46/build" CACHE PATH "Path to your ns-3.46 build directory (e.g. /home/rky_cse/ns-3.46/build)")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message(STATUS "🔧 CRYPTO_BACKEND = ${CRYPTO_BACKEND}")
message(STATUS "📦 NS3_BUILD_DIR  = ${NS3_BUILD_DIR}")

# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------
set(PROJ_ROOT /mnt/e/minor-crypto-aodv/crypto-aodv)
set(CRYPTO_DIR   ${PROJ_ROOT}/crypto)
set(AUTH_DIR     ${PROJ_ROOT}/auth)
set(AODV_DIR     ${PROJ_ROOT}/aodv_bridge)
set(METRICS_DIR  ${PROJ_ROOT}/metrics)
set(SIMS_DIR     ${PROJ_ROOT}/simulations)
set(TESTS_DIR    ${PROJ_ROOT}/tests)

# Add project root to include path so includes like "crypto/icrypto.h" work
include_directories(${PROJ_ROOT} ${CRYPTO_DIR} ${AUTH_DIR} ${AODV_DIR} ${METRICS_DIR} ${SIMS_DIR})

# -----------------------------------------------------------------------------
# Gather Sources
# -----------------------------------------------------------------------------
file(GLOB CRYPTO_SRC  "${CRYPTO_DIR}/*.cpp" "${CRYPTO_DIR}/*.cc")
file(GLOB AUTH_SRC    "${AUTH_DIR}/*.cpp" "${AUTH_DIR}/*.cc")
file(GLOB AODV_SRC    "${AODV_DIR}/*.cpp" "${AODV_DIR}/*.cc")
file(GLOB METRICS_SRC "${METRICS_DIR}/*.cpp" "${METRICS_DIR}/*.cc")

# -----------------------------------------------------------------------------
# Find and Configure Crypto Backend (libsodium / OpenSSL)
# -----------------------------------------------------------------------------
if("${CRYPTO_BACKEND}" STREQUAL "sodium")
  find_path(SODIUM_INCLUDE_DIR sodium.h)
  find_library(SODIUM_LIB sodium)
  if(NOT SODIUM_LIB OR NOT SODIUM_INCLUDE_DIR)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
      pkg_check_modules(PC_SODIUM QUIET libsodium)
      if(PC_SODIUM_FOUND)
        set(SODIUM_INCLUDE_DIR ${PC_SODIUM_INCLUDEDIR})
        set(SODIUM_LIB ${PC_SODIUM_LIBRARIES})
      endif()
    endif()
  endif()
  if(NOT SODIUM_LIB)
    message(FATAL_ERROR "❌ libsodium not found. Install libsodium-dev or specify manually.")
  endif()
  message(STATUS "✅ Using libsodium: include=${SODIUM_INCLUDE_DIR}, lib=${SODIUM_LIB}")
  include_directories(${SODIUM_INCLUDE_DIR})
  add_definitions(-DUSE_SODIUM)
else()
  find_package(OpenSSL REQUIRED)
  message(STATUS "✅ Using OpenSSL: ${OpenSSL_VERSION}")
  include_directories(${OpenSSL_INCLUDE_DIR})
  add_definitions(-DUSE_OPENSSL)
endif()

# -----------------------------------------------------------------------------
# ns-3 Integration
# -----------------------------------------------------------------------------
set(NS3_INCLUDE_DIR "${NS3_BUILD_DIR}/include")
set(NS3_LIB_DIR     "${NS3_BUILD_DIR}/lib")

if(EXISTS "${NS3_INCLUDE_DIR}")
  message(STATUS "✅ ns-3 include dir: ${NS3_INCLUDE_DIR}")
  include_directories(${NS3_INCLUDE_DIR})
else()
  message(WARNING "⚠️ ns-3 include directory not found at ${NS3_INCLUDE_DIR}")
endif()

if(EXISTS "${NS3_LIB_DIR}")
  file(GLOB NS3_LIB_FILES RELATIVE "${NS3_LIB_DIR}" "${NS3_LIB_DIR}/libns3*.a" "${NS3_LIB_DIR}/libns3*.so")
  set(NS3_LIB_PATHS "")
  foreach(f ${NS3_LIB_FILES})
    list(APPEND NS3_LIB_PATHS "${NS3_LIB_DIR}/${f}")
  endforeach()
  message(STATUS "✅ Found ns-3 libs in ${NS3_LIB_DIR}")
else()
  message(WARNING "⚠️ ns-3 lib directory not found: ${NS3_LIB_DIR}")
endif()

# -----------------------------------------------------------------------------
# Core Library
# -----------------------------------------------------------------------------
add_library(uav_core STATIC
  ${CRYPTO_SRC}
  ${AUTH_SRC}
  ${AODV_SRC}
  ${METRICS_SRC}
)

target_include_directories(uav_core PUBLIC
  ${CRYPTO_DIR} ${AUTH_DIR} ${AODV_DIR} ${METRICS_DIR}
)

if("${CRYPTO_BACKEND}" STREQUAL "sodium")
  target_link_libraries(uav_core PUBLIC ${SODIUM_LIB})
else()
  target_link_libraries(uav_core PUBLIC OpenSSL::Crypto OpenSSL::SSL)
endif()

if(NS3_LIB_PATHS)
  target_link_libraries(uav_core PUBLIC ${NS3_LIB_PATHS})
endif()

# -----------------------------------------------------------------------------
# Simulation Executables
# -----------------------------------------------------------------------------
set(SIM_AUTH_SRC ${SIMS_DIR}/auth_scenario.cc)
set(SIM_DATA_SRC ${SIMS_DIR}/uav_data_scenario.cc)

if(EXISTS ${SIM_AUTH_SRC})
  add_executable(auth_scenario ${SIM_AUTH_SRC})
  if("${CRYPTO_BACKEND}" STREQUAL "sodium")
    target_link_libraries(auth_scenario PRIVATE uav_core ${SODIUM_LIB} ${NS3_LIB_PATHS})
  else()
    target_link_libraries(auth_scenario PRIVATE uav_core OpenSSL::Crypto OpenSSL::SSL ${NS3_LIB_PATHS})
  endif()
  target_include_directories(auth_scenario PRIVATE ${SIMS_DIR})
endif()

if(EXISTS ${SIM_DATA_SRC})
  add_executable(uav_data_scenario ${SIM_DATA_SRC})
  if("${CRYPTO_BACKEND}" STREQUAL "sodium")
    target_link_libraries(uav_data_scenario PRIVATE uav_core ${SODIUM_LIB} ${NS3_LIB_PATHS})
  else()
    target_link_libraries(uav_data_scenario PRIVATE uav_core OpenSSL::Crypto OpenSSL::SSL ${NS3_LIB_PATHS})
  endif()
  target_include_directories(uav_data_scenario PRIVATE ${SIMS_DIR})
endif()

# -----------------------------------------------------------------------------
# Unit Tests (Catch2)
# -----------------------------------------------------------------------------
if(BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(
    catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.4.0
  )
  FetchContent_MakeAvailable(catch2)
  enable_testing()

  if(EXISTS "${TESTS_DIR}/crypto_test.cpp")
    add_executable(crypto_test ${TESTS_DIR}/crypto_test.cpp)
    if("${CRYPTO_BACKEND}" STREQUAL "sodium")
      target_link_libraries(crypto_test PRIVATE uav_core Catch2::Catch2WithMain ${SODIUM_LIB})
    else()
      target_link_libraries(crypto_test PRIVATE uav_core Catch2::Catch2WithMain OpenSSL::Crypto OpenSSL::SSL)
    endif()
    add_test(NAME crypto_test COMMAND crypto_test)
  endif()
endif()

# -----------------------------------------------------------------------------
# Messages & Summary
# -----------------------------------------------------------------------------
message(STATUS "")
message(STATUS "✅ Build ready for crypto-aodv project.")
message(STATUS "📁 Project path: ${PROJ_ROOT}")
message(STATUS "📡 ns-3 build dir: ${NS3_BUILD_DIR}")
message(STATUS "")
message(STATUS "To build:")
message(STATUS "  cd /mnt/e/minor-crypto-aodv/crypto-aodv")
message(STATUS "  mkdir -p build && cd build")
message(STATUS "  cmake -DNS3_BUILD_DIR=${NS3_BUILD_DIR} ..")
message(STATUS "  make -j$(nproc)")
message(STATUS "")
message(STATUS "To run simulations:")
message(STATUS "  ./auth_scenario")
message(STATUS "  ./uav_data_scenario")
message(STATUS "")
message(STATUS "To run tests (if enabled):")
message(STATUS "  ctest --output-on-failure")
