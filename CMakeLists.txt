cmake_minimum_required(VERSION 3.10)

project("mir_http_example" VERSION 0.0.1 LANGUAGES CXX)

include_directories("include")

add_executable(${PROJECT_NAME} example/main.cpp)

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)


if(MSVC)
  if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
    string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
  else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
  endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX OR CMAKE_COMPILER_IS_CLANG)
  # Update if necessary
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wno-long-long -pedantic")
endif()

if(MSVC)
	set(MSVC_VERSION 1900)
	set(ignoreMe "${CMAKE_C_COMPILER}")
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

find_package(CURL REQUIRED)
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

find_package(nlohmann_json CONFIG REQUIRED)
message("Json: ${NLOHMANN_JSON_INCLUDE_DIR}")	

include_directories(${ASIO_INCLUDE_DIR})
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
include_directories(SYSTEM ${ZLIB_INCLUDE_DIRS})
include_directories(${CURL_INCLUDE_DIR})

target_link_libraries( ${PROJECT_NAME} OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries( ${PROJECT_NAME} ZLIB::ZLIB)
target_link_libraries( ${PROJECT_NAME} ${CURL_LIBRARIES})

if(WIN32)
  target_link_libraries( ${PROJECT_NAME} wsock32 ws2_32)
else()
  add_definitions(-std=c++11 -Wreorder -g -fsanitize=address -fno-omit-frame-pointer) 
  target_link_libraries( ${PROJECT_NAME} pthread -fsanitize=address -fno-omit-frame-pointer) 
endif()

