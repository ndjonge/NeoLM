cmake_minimum_required(VERSION 3.10)

set (PROJECT_NAME "NeoLM" CXX)
project (${PROJECT_NAME})

add_executable(${PROJECT_NAME} main.cpp)

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

find_path(ASIO_INCLUDE_DIR asio.hpp HINTS )
if(ASIO_INCLUDE_DIR STREQUAL "ASIO_INCLUDE_DIR-NOTFOUND")
    message("Asio:" ${ASIO_INCLUDE_DIR})
	add_definitions(ASIO_STANDALONE)
endif()

#find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp HINTS )
#if(NLOHMANN_JSON_INCLUDE_DIR STREQUAL "NLOHMANN_JSON_INCLUDE_DIR-NOTFOUND")
#    message("Json:" ${NLOHMANN_JSON_INCLUDE_DIR})	
#endif()

message("Asio: ${ASIO_INCLUDE_DIR}")
#message("Json: ${NLOHMANN_JSON_INCLUDE_DIR}")	

include_directories(${ASIO_INCLUDE_DIR})
#include_directories(${NLOHMANN_JSON_INCLUDE_DIR})
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
include_directories(SYSTEM ${ZLIB_INCLUDE_DIRS})

target_link_libraries( ${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries( ${PROJECT_NAME} ZLIB::ZLIB)

if(WIN32)
  target_link_libraries( ${PROJECT_NAME} wsock32 ws2_32)
else()
  add_definitions(-std=c++14 -g -fsanitize=thread)
  target_link_libraries( ${PROJECT_NAME} pthread  -fsanitize=thread)
endif()

