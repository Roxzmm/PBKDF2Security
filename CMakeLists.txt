cmake_minimum_required(VERSION 3.27)
project(PBKDF2Security)

add_executable(PBKDF2Security main.cpp)

target_compile_features(PBKDF2Security PRIVATE cxx_std_17)


#include(FetchContent)
#
## Fetch and include cxxopts
#FetchContent_Declare(
#        cxxopts
#        GIT_REPOSITORY https://github.com/jarro2783/cxxopts.git
#        GIT_TAG v3.2.0
#)
#FetchContent_GetProperties(cxxopts)
#if (NOT cxxopts_POPULATED)
#    FetchContent_Populate(cxxopts)
#    add_subdirectory(${cxxopts_SOURCE_DIR} ${cxxopts_BINARY_DIR})
#endif ()
#
## Fetch and include OpenSSL
#FetchContent_Declare(
#        OpenSSL
#        URL https://www.openssl.org/source/openssl-3.2.1.tar.gz
#        URL_HASH SHA256=83c7329fe52c850677d75e5d0b0ca245309b97e8ecbcfdc1dfdc4ab9fac35b39
#)
#FetchContent_Populate(OpenSSL)
#set(BUILD_SHARED_LIBS OFF)
#
## Add the OpenSSL library
#add_library(OpenSSL::SSL UNKNOWN IMPORTED)
#set_target_properties(OpenSSL::SSL PROPERTIES
#        IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/_deps/openssl-src/ssl/libssl.a
#        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/_deps/openssl-src/include
#)
#


# OpenSSL
find_package(OpenSSL REQUIRED)
if (${OPENSSL_FOUND})
    message(STATUS "-----------------OpenSSL founded-----------------------")
    message(STATUS "OpenSSL libraries:  ${OPENSSL_LIBRARIES}")
    message(STATUS "OpenSSL include dir:  ${OPENSSL_INCLUDE_DIR}")
    target_include_directories(PBKDF2Security PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(PBKDF2Security PRIVATE OpenSSL::SSL)
else ()
    message(FATAL_ERROR "OpenSSL libraries not found!!!")
endif ()

find_package(cxxopts CONFIG REQUIRED)
if (${cxxopts_FOUND})
    message(STATUS "-----------------cxxopts founded-----------------------")
    target_link_libraries(PBKDF2Security PRIVATE cxxopts::cxxopts)
else ()
    message(FATAL_ERROR "cxxopts not found!!!")
endif ()


#target_link_libraries(PBKDF2Security PRIVATE cxxopts OpenSSL::SSL)
