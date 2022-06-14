cmake_minimum_required(VERSION 3.5)

project("unit-test")

option(SUPPORT "Include OVS support library" OFF)
option(gtest_disable_pthreads "Disable uses of pthreads in gtest." OFF)

# These reflect the directory paths on my WSL system.
set(P4_DRIVER "$ENV{SDE}")
set(IPDK_OVS "$ENV{OVS}")
set(FRAMEWORK "$ENV{SRC_FOLDER}/P4OVS_DEPS_SRC_CODE")
set(THIRD_PARTY "${P4_DRIVER}/third-party")
set(GOOGLETEST "${FRAMEWORK}/googletest")
set(GMOCK_GLOBAL "${FRAMEWORK}/gmock-global")
set(LIBNL3 "/usr/include/libnl3")

#Adding include directories
include_directories(
  ${GOOGLETEST}/googletest/include
  ${GOOGLETEST}/googlemock/include
  ${GMOCK_GLOBAL}/include/gmock-global
  ${IPDK_OVS}
  ${IPDK_OVS}/include
  ${IPDK_OVS}/lib
  ${THIRD_PARTY}
  ${THIRD_PARTY}/target-utils/third-party/judy-1.0.5/src
  ${THIRD_PARTY}/target-syslibs/include
  ${THIRD_PARTY}/target-utils/include
  ${P4_DRIVER}/include
)

set(CMAKE_CXX_FLAGS "-pthread -fpermissive -std=c++11 -O0 ${CMAKE_CXX_FLAGS}")

#Adding libary link directories
set(CMAKE_EXE_LINKER_FLAGS "-L$ENV{SRC_FOLDER}/P4OVS_DEPS_SRC_CODE/googletest/build/lib -lgtest -lgmock -Wl,--warn-unresolved-symbols")


# Defines cmake_print_variables(), which is useful when you're
# debugging CMake build files.
include(CMakePrintHelpers)


add_executable(test_switchlink
  gtest_main.cpp  test_switchlink_sai.cpp  vlog_mock.c
)
target_link_libraries(test_switchlink ${CMAKE_EXE_LINKER_FLAGS})


target_include_directories(test_switchlink PRIVATE
  ${IPDK_OVS}/switchlink/submodules/SAI/inc
  ${IPDK_OVS}/switchapi
  ${IPDK_OVS}/switchlink
  ${IPDK_OVS}/switchlink/xxhash/include
  ${IPDK_OVS}/switchsai
)
