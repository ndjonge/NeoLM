cmake_minimum_required(VERSION 3.10)

set (PROJECT_NAME "NeoLM" CXX)
project (${PROJECT_NAME})

add_executable(${PROJECT_NAME} main.cpp)


set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)


find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
include_directories(SYSTEM ${ZLIB_INCLUDE_DIRS})

target_link_libraries( ${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries( ${PROJECT_NAME} ZLIB::ZLIB)

if(WIN32)
  target_link_libraries( ${PROJECT_NAME} wsock32 ws2_32)
endif()

