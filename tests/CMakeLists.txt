# SPDX-License-Identifier: BSD-2-Clause-Patent
# tests/CMakeLists.txt

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(googletest)

# ---------------------------------------------------------------------------
# test_metadata – BPF_disk_trans() extent lookup
# ---------------------------------------------------------------------------
add_executable(test_metadata
    test_metadata.cpp
)
target_link_libraries(test_metadata
    uxrp_metadata
    GTest::gtest_main
)
add_test(NAME test_metadata COMMAND test_metadata)

# ---------------------------------------------------------------------------
# test_xrp_direct – XRP Direct mock pipeline
# ---------------------------------------------------------------------------
add_executable(test_xrp_direct
    test_xrp_direct.cpp
)
target_link_libraries(test_xrp_direct
    xrp_direct
    GTest::gtest_main
)
add_test(NAME test_xrp_direct COMMAND test_xrp_direct)
