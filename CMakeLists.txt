cmake_minimum_required(VERSION 3.7)

set (PROJECT_NAME "NeoLM" CXX)
project (${PROJECT_NAME})

IF (WIN32)
set (BOOST_ROOT "C:\\boost_1_64_0")
link_directories("C:\\boost_1_64_0\\lib64-msvc-14.1")
ENDIF()

find_package(Boost 1.64 REQUIRED system thread)
include_directories(SYSTEM ${Boost_INCLUDE_DIRS})

set (Boost_USE_MULTITHREADED ON)
set (Boost_USE_STATIC_LIBS ON)
set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME} main.cpp)

target_link_libraries (${PROJECT_NAME} ${Boost_LIBRARIES})
