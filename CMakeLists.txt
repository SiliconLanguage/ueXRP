# SPDX-License-Identifier: BSD-2-Clause-Patent
#
# Top-level CMakeLists.txt
#
# Builds the three C/C++ components of ueXRP:
#   - metadata  : shared-memory metadata digest library
#   - trampoline: LD_PRELOAD shim (shared library)
#   - xrp_direct: XRP Direct DPU pipeline (mock, for testing)
#
# The uXRP engine (uxrp/) links against SPDK and uBPF which are typically
# built out-of-tree; enable it by setting -DUXRP_BUILD_ENGINE=ON and
# providing SPDK_DIR / UBPF_DIR.

cmake_minimum_required(VERSION 3.18)
project(ueXRP LANGUAGES C CXX)

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(UXRP_BUILD_ENGINE  "Build the SPDK+uBPF engine (requires SPDK_DIR/UBPF_DIR)" OFF)
option(UXRP_BUILD_TESTS   "Build unit tests"                                          ON)

# ---------------------------------------------------------------------------
# Metadata digest library
# ---------------------------------------------------------------------------
add_library(uxrp_metadata STATIC
    metadata/src/metadata_digest.cpp
)
target_include_directories(uxrp_metadata PUBLIC metadata/include)
target_compile_options(uxrp_metadata PRIVATE -Wall -Wextra -Wpedantic)

# ---------------------------------------------------------------------------
# Trampoline shim (shared library – LD_PRELOADable)
# ---------------------------------------------------------------------------
add_library(uxrp_trampoline SHARED
    trampoline/src/trampoline_shim.c
)
target_include_directories(uxrp_trampoline PUBLIC trampoline/include)
target_link_libraries(uxrp_trampoline PRIVATE dl pthread)
target_compile_options(uxrp_trampoline PRIVATE -Wall -Wextra)
set_target_properties(uxrp_trampoline PROPERTIES OUTPUT_NAME "uxrp_trampoline")

# ---------------------------------------------------------------------------
# XRP Direct mock library
# ---------------------------------------------------------------------------
add_library(xrp_direct STATIC
    xrp_direct/src/xrp_direct.cpp
)
target_include_directories(xrp_direct PUBLIC xrp_direct/include)
target_compile_options(xrp_direct PRIVATE -Wall -Wextra -Wpedantic)

# ---------------------------------------------------------------------------
# Optional: uXRP engine (SPDK + uBPF)
# ---------------------------------------------------------------------------
if(UXRP_BUILD_ENGINE)
    if(NOT DEFINED SPDK_DIR)
        message(FATAL_ERROR "SPDK_DIR must be set when UXRP_BUILD_ENGINE=ON")
    endif()
    if(NOT DEFINED UBPF_DIR)
        message(FATAL_ERROR "UBPF_DIR must be set when UXRP_BUILD_ENGINE=ON")
    endif()

    add_library(uxrp_engine STATIC
        uxrp/src/uxrp_engine.cpp
    )
    target_include_directories(uxrp_engine PUBLIC
        uxrp/include
        ${SPDK_DIR}/include
        ${UBPF_DIR}/vm/inc
    )
    target_link_directories(uxrp_engine PUBLIC
        ${SPDK_DIR}/build/lib
        ${UBPF_DIR}/vm
    )
    target_link_libraries(uxrp_engine PUBLIC
        spdk_nvme spdk_env_dpdk ubpf
    )
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(UXRP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
