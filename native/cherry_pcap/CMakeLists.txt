cmake_minimum_required(VERSION 3.20)

project(cherry_pcap VERSION 0.1.0 LANGUAGES CXX)

option(CHERRY_PCAP_BUILD_TESTS "Build the dependency-free parser/analyzer tests" ON)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(cherry_pcap_core
    src/analyzer.cpp
)
target_include_directories(cherry_pcap_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(MSVC)
    target_compile_options(cherry_pcap_core PRIVATE /W4 /permissive-)
else()
    target_compile_options(cherry_pcap_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

add_library(cherry_pcap_capture INTERFACE)

find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET IMPORTED_TARGET libpcap)
endif()

if(TARGET PkgConfig::PCAP)
    target_link_libraries(cherry_pcap_capture INTERFACE PkgConfig::PCAP)
else()
    set(_pcap_hints)
    if(DEFINED ENV{PCAP_ROOT})
        list(APPEND _pcap_hints "$ENV{PCAP_ROOT}")
    endif()
    if(DEFINED PCAP_ROOT)
        list(APPEND _pcap_hints "${PCAP_ROOT}")
    endif()

    find_path(PCAP_INCLUDE_DIR
        NAMES pcap/pcap.h pcap.h
        HINTS ${_pcap_hints}
        PATH_SUFFIXES include Include
    )

    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(_pcap_lib_suffixes lib/x64 Lib/x64 lib64 Lib64 lib Lib)
    else()
        set(_pcap_lib_suffixes lib Lib)
    endif()

    find_library(PCAP_LIBRARY
        NAMES pcap wpcap
        HINTS ${_pcap_hints}
        PATH_SUFFIXES ${_pcap_lib_suffixes}
    )

    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "libpcap/Npcap SDK was not found. Install libpcap-dev/libpcap-devel, "
            "or set PCAP_ROOT to the extracted Npcap SDK directory on Windows.")
    endif()

    target_include_directories(cherry_pcap_capture INTERFACE "${PCAP_INCLUDE_DIR}")
    target_link_libraries(cherry_pcap_capture INTERFACE "${PCAP_LIBRARY}")

    if(WIN32)
        find_library(PACKET_LIBRARY
            NAMES Packet
            HINTS ${_pcap_hints}
            PATH_SUFFIXES ${_pcap_lib_suffixes}
        )
        if(PACKET_LIBRARY)
            target_link_libraries(cherry_pcap_capture INTERFACE "${PACKET_LIBRARY}")
        endif()
        target_link_libraries(cherry_pcap_capture INTERFACE ws2_32)
    endif()
endif()

add_executable(cherry-pcap
    src/main.cpp
)
target_link_libraries(cherry-pcap
    PRIVATE
        cherry_pcap_core
        cherry_pcap_capture
)

if(MSVC)
    target_compile_options(cherry-pcap PRIVATE /W4 /permissive-)
else()
    target_compile_options(cherry-pcap PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

if(CHERRY_PCAP_BUILD_TESTS)
    include(CTest)
    add_executable(cherry_pcap_core_tests tests/analyzer_test.cpp)
    target_link_libraries(cherry_pcap_core_tests PRIVATE cherry_pcap_core)
    if(MSVC)
        target_compile_options(cherry_pcap_core_tests PRIVATE /W4 /permissive-)
    else()
        target_compile_options(cherry_pcap_core_tests PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    endif()
    add_test(NAME cherry_pcap_core_tests COMMAND cherry_pcap_core_tests)
endif()

install(TARGETS cherry-pcap RUNTIME DESTINATION bin)
